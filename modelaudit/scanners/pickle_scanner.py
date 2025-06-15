import os
import pickletools
import time
from typing import Any, BinaryIO, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Dictionary of suspicious references.
# You can expand as needed.
SUSPICIOUS_GLOBALS = {
    "os": "*",
    "posix": "*",  # posix.system is equivalent to os.system on Unix
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
    # dill's load helpers can execute arbitrary code when unpickling
    # so we specifically flag those functions
    "dill": [
        "load",
        "loads",
        "load_module",
        "load_module_asdict",
        "load_session",
    ],
    # references to the private dill._dill module are also suspicious
    "dill._dill": "*",
}

# Add dangerous builtin functions that might be used in __reduce__ methods
DANGEROUS_BUILTINS = ["eval", "exec", "compile", "open", "input", "__import__"]

# Dangerous opcodes that can lead to code execution
DANGEROUS_OPCODES = [
    "REDUCE",
    "INST",
    "OBJ",
    "NEWOBJ",
    "NEWOBJ_EX",
    "GLOBAL",
    "BUILD",
    "STACK_GLOBAL",
]

# Suspicious string patterns that might indicate encoded payloads
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


def is_suspicious_global(mod: str, func: str) -> bool:
    """Check if a module.function reference is suspicious"""
    if mod in SUSPICIOUS_GLOBALS:
        val = SUSPICIOUS_GLOBALS[mod]
        if val == "*":
            return True
        if isinstance(val, list) and func in val:
            return True
    return False


def is_suspicious_string(s: str) -> Optional[str]:
    """Check if a string contains suspicious patterns"""
    import re

    if not isinstance(s, str):
        return None

    for pattern in SUSPICIOUS_STRING_PATTERNS:
        match = re.search(pattern, s)
        if match:
            return pattern

    # Check for base64-like strings (long strings with base64 charset)
    if len(s) > 40 and re.match(r"^[A-Za-z0-9+/=]+$", s):
        return "potential_base64"

    return None


def is_dangerous_reduce_pattern(opcodes: list[tuple]) -> Optional[dict[str, Any]]:
    """
    Check for patterns that indicate a dangerous __reduce__ method
    Returns details about the dangerous pattern if found, None otherwise
    """
    # Look for common patterns in __reduce__ exploits
    for i, (opcode, arg, pos) in enumerate(opcodes):
        # Check for GLOBAL followed by REDUCE - common in exploits
        if (
            opcode.name == "GLOBAL"
            and i + 1 < len(opcodes)
            and opcodes[i + 1][0].name == "REDUCE"
        ):
            if isinstance(arg, str):
                parts = (
                    arg.split(" ", 1)
                    if " " in arg
                    else arg.rsplit(".", 1) if "." in arg else [arg, ""]
                )
                if len(parts) == 2:
                    mod, func = parts
                    return {
                        "pattern": "GLOBAL+REDUCE",
                        "module": mod,
                        "function": func,
                        "position": pos,
                        "opcode": opcode.name,
                    }

        # Check for INST or OBJ opcodes which can also be used for code execution
        if opcode.name in ["INST", "OBJ", "NEWOBJ"] and isinstance(arg, str):
            return {
                "pattern": f"{opcode.name}_EXECUTION",
                "argument": arg,
                "position": pos,
                "opcode": opcode.name,
            }

        # Check for suspicious attribute access patterns (GETATTR followed by CALL)
        if (
            opcode.name == "GETATTR"
            and i + 1 < len(opcodes)
            and opcodes[i + 1][0].name == "CALL"
        ):
            return {
                "pattern": "GETATTR+CALL",
                "attribute": arg,
                "position": pos,
                "opcode": opcode.name,
            }

        # Check for suspicious strings in STRING or BINSTRING opcodes
        if opcode.name in [
            "STRING",
            "BINSTRING",
            "SHORT_BINSTRING",
            "UNICODE",
        ] and isinstance(arg, str):
            suspicious_pattern = is_suspicious_string(arg)
            if suspicious_pattern:
                return {
                    "pattern": "SUSPICIOUS_STRING",
                    "string_pattern": suspicious_pattern,
                    "string_preview": arg[:50] + ("..." if len(arg) > 50 else ""),
                    "position": pos,
                    "opcode": opcode.name,
                }

    return None


def check_opcode_sequence(opcodes: list[tuple]) -> list[dict[str, Any]]:
    """
    Analyze the full sequence of opcodes for suspicious patterns
    Returns a list of suspicious patterns found
    """
    suspicious_patterns = []

    # Count dangerous opcodes
    dangerous_opcode_count = 0

    for i, (opcode, arg, pos) in enumerate(opcodes):
        # Track dangerous opcodes
        if opcode.name in DANGEROUS_OPCODES:
            dangerous_opcode_count += 1

        # If we see too many dangerous opcodes, that's suspicious
        if dangerous_opcode_count > 5:
            suspicious_patterns.append(
                {
                    "pattern": "MANY_DANGEROUS_OPCODES",
                    "count": dangerous_opcode_count,
                    "position": pos,
                    "opcode": opcode.name,
                },
            )
            # Reset counter to avoid multiple alerts
            dangerous_opcode_count = 0

    return suspicious_patterns


class PickleScanner(BaseScanner):
    """Scanner for Python Pickle files"""

    name = "pickle"
    description = "Scans Python pickle files for suspicious code references"
    supported_extensions = [".pkl", ".pickle"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Additional pickle-specific configuration
        self.max_opcodes = self.config.get("max_opcodes", 1000000)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if the file is a pickle based on extension"""
        file_ext = os.path.splitext(path)[1].lower()
        return file_ext in cls.supported_extensions

    def scan(self, path: str) -> ScanResult:
        """Scan a pickle file for suspicious content"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            with open(path, "rb") as f:
                # Store the file path for use in issue locations
                self.current_file_path = path
                scan_result = self._scan_pickle_bytes(f, file_size)
                result.merge(scan_result)
        except Exception as e:
            result.add_issue(
                f"Error opening pickle file: {str(e)}",
                severity=IssueSeverity.ERROR,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _scan_pickle_bytes(self, file_obj: BinaryIO, file_size: int) -> ScanResult:
        """Scan pickle file content for suspicious opcodes"""
        result = self._create_result()
        opcode_count = 0
        suspicious_count = 0

        try:
            # Process the pickle
            start_pos = file_obj.tell()

            # Store opcodes for pattern analysis
            opcodes = []
            # Track strings on the stack for STACK_GLOBAL opcode analysis
            string_stack = []

            for opcode, arg, pos in pickletools.genops(file_obj):
                opcodes.append((opcode, arg, pos))
                opcode_count += 1

                # Track strings for STACK_GLOBAL analysis
                if opcode.name in [
                    "STRING",
                    "BINSTRING",
                    "SHORT_BINSTRING",
                    "SHORT_BINUNICODE",
                    "UNICODE",
                ] and isinstance(arg, str):
                    string_stack.append(arg)
                    # Keep only the last 10 strings to avoid memory issues
                    if len(string_stack) > 10:
                        string_stack.pop(0)

                # Check for too many opcodes
                if opcode_count > self.max_opcodes:
                    result.add_issue(
                        f"Too many opcodes in pickle (> {self.max_opcodes})",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={
                            "opcode_count": opcode_count,
                            "max_opcodes": self.max_opcodes,
                        },
                    )
                    break

                # Check for timeout
                if time.time() - result.start_time > self.timeout:
                    result.add_issue(
                        f"Scanning timed out after {self.timeout} seconds",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"opcode_count": opcode_count, "timeout": self.timeout},
                    )
                    break

                # Check for GLOBAL opcodes that might reference suspicious modules
                if opcode.name == "GLOBAL":
                    if isinstance(arg, str):
                        # Handle both "module function" and "module.function" formats
                        parts = (
                            arg.split(" ", 1)
                            if " " in arg
                            else arg.rsplit(".", 1) if "." in arg else [arg, ""]
                        )

                        if len(parts) == 2:
                            mod, func = parts
                            if is_suspicious_global(mod, func):
                                suspicious_count += 1
                                result.add_issue(
                                    f"Suspicious reference {mod}.{func}",
                                    severity=IssueSeverity.ERROR,
                                    location=f"{self.current_file_path} (pos {pos})",
                                    details={
                                        "module": mod,
                                        "function": func,
                                        "position": pos,
                                        "opcode": opcode.name,
                                    },
                                )

                # Check for REDUCE opcode which is often used in exploits
                if opcode.name == "REDUCE":
                    result.add_issue(
                        "Found REDUCE opcode - potential __reduce__ method execution",
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (pos {pos})",
                        details={"position": pos, "opcode": opcode.name},
                    )

                # Check for other dangerous opcodes
                if opcode.name in ["INST", "OBJ", "NEWOBJ"]:
                    result.add_issue(
                        f"Found {opcode.name} opcode - potential code execution",
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (pos {pos})",
                        details={
                            "position": pos,
                            "opcode": opcode.name,
                            "argument": str(arg),
                        },
                    )

                # Check for suspicious strings
                if opcode.name in [
                    "STRING",
                    "BINSTRING",
                    "SHORT_BINSTRING",
                    "UNICODE",
                ] and isinstance(arg, str):
                    suspicious_pattern = is_suspicious_string(arg)
                    if suspicious_pattern:
                        result.add_issue(
                            f"Suspicious string pattern: {suspicious_pattern}",
                            severity=IssueSeverity.WARNING,
                            location=f"{self.current_file_path} (pos {pos})",
                            details={
                                "position": pos,
                                "opcode": opcode.name,
                                "pattern": suspicious_pattern,
                                "string_preview": arg[:50]
                                + ("..." if len(arg) > 50 else ""),
                            },
                        )

                # Check for STACK_GLOBAL which uses the last two strings as
                # module and function
                if opcode.name == "STACK_GLOBAL":
                    if len(string_stack) >= 2:
                        # Last two strings should be module and function
                        mod = string_stack[-2]
                        func = string_stack[-1]
                        if is_suspicious_global(mod, func):
                            suspicious_count += 1
                            result.add_issue(
                                f"Suspicious module reference found: {mod}.{func}",
                                severity=IssueSeverity.ERROR,
                                location=f"{self.current_file_path} (pos {pos})",
                                details={
                                    "module": mod,
                                    "function": func,
                                    "position": pos,
                                    "opcode": opcode.name,
                                },
                            )
                    else:
                        result.add_issue(
                            "STACK_GLOBAL opcode found without sufficient "
                            "string context",
                            severity=IssueSeverity.WARNING,
                            location=f"{self.current_file_path} (pos {pos})",
                            details={
                                "position": pos,
                                "opcode": opcode.name,
                                "stack_size": len(string_stack),
                            },
                        )

            # Check for dangerous patterns in the opcodes
            dangerous_pattern = is_dangerous_reduce_pattern(opcodes)
            if dangerous_pattern:
                suspicious_count += 1
                result.add_issue(
                    f"Detected dangerous __reduce__ pattern with "
                    f"{dangerous_pattern.get('module', '')}."
                    f"{dangerous_pattern.get('function', '')}",
                    severity=IssueSeverity.ERROR,
                    location=f"{self.current_file_path} "
                    f"(pos {dangerous_pattern.get('position', 0)})",
                    details=dangerous_pattern,
                )

            # Check for suspicious opcode sequences
            suspicious_sequences = check_opcode_sequence(opcodes)
            for sequence in suspicious_sequences:
                suspicious_count += 1
                result.add_issue(
                    f"Suspicious opcode sequence: {sequence.get('pattern', 'unknown')}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} "
                    f"(pos {sequence.get('position', 0)})",
                    details=sequence,
                )

            # Update metadata
            end_pos = file_obj.tell()
            result.bytes_scanned = end_pos - start_pos
            result.metadata.update(
                {"opcode_count": opcode_count, "suspicious_count": suspicious_count},
            )

        except Exception as e:
            result.add_issue(
                f"Error analyzing pickle ops: {e}",
                severity=IssueSeverity.ERROR,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

        return result
