"""Rust-backed scanner for Python pickle serialized files."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import pickletools
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, ClassVar

from modelaudit_picklescan import PickleScanner as StandalonePickleScanner

from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_GLOBALS
from modelaudit.utils.helpers.code_validation import validate_python_syntax

from ..scanner_results import mark_inconclusive_scan_result
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult, logger
from .picklescan_adapter import pickle_report_to_scan_result, scan_options_from_config

_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES = 64 * 1024
_ROOT_RAW_SCAN_LIMIT_BYTES = 8 * 1024 * 1024
_JAX_PICKLE_CONTEXT_INDICATORS = (
    b"jax",
    b"flax",
    b"haiku",
    b"orbax",
    b"arrayimpl",
    b"jaxlib",
    b"device_array",
)
_DEFAULT_JAX_PICKLE_SCAN_LIMIT_BYTES = 16 * 1024 * 1024
_MIN_JAX_PICKLE_SCAN_LIMIT_BYTES = 1024
_ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
_MAX_METADATA_PICKLE_READ_BYTES = 10 * 1024 * 1024
_KNOWN_PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".dill", ".joblib"})
_PYTORCH_CONTAINER_EXTENSIONS = frozenset({".bin", ".pt", ".pth", ".ckpt", ".pkl"})
_BASE64_TOKEN_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{10,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_TOKEN_RE = re.compile(rb"(?<![A-Fa-f0-9])[A-Fa-f0-9]{20,}(?![A-Fa-f0-9])")
_IPV4_DOT_DIGIT_RE = re.compile(rb"\d\.\d")
_MAX_RAW_ENCODED_TOKENS = 64
_MAX_RAW_ENCODED_BYTES = 1024 * 1024
_MAX_RAW_ENCODED_TOKEN_WITHOUT_SEED_BYTES = 4096
_CALL_TOKEN_SEPARATOR_SCAN_LIMIT_BYTES = 4096
_MAX_RAW_CODE_LITERAL_VALIDATION_CHARS = 8192
_BASE64_CODE_EXECUTION_SEEDS: tuple[bytes, ...] = (
    b"ZXZhbCg",  # eval(
    b"ZXhlYyg",  # exec(
    b"b3Muc3lzdGVt",  # os.system
    b"c3VicHJvY2Vzcw",  # subprocess
    b"X19pbXBvcnRfXw",  # __import__
)
_HEX_CODE_EXECUTION_SEEDS: tuple[bytes, ...] = (
    b"6576616c28",  # eval(
    b"6578656328",  # exec(
    b"6f732e73797374656d",  # os.system
    b"73756270726f63657373",  # subprocess
    b"5f5f696d706f72745f5f",  # __import__
)


def _hex_token_has_execution_seed(token: bytes) -> bool:
    token_lower = token.lower()
    return any(seed in token_lower for seed in _HEX_CODE_EXECUTION_SEEDS)


_ENCODED_CODE_EXECUTION_PATTERNS: tuple[tuple[bytes, str], ...] = (
    (b"eval(", "eval"),
    (b"exec(", "exec"),
    (b"os.system", "os.system"),
    (b"subprocess", "subprocess"),
    (b"__import__", "__import__"),
)
_RAW_READ_CHUNK_BYTES = 1024 * 1024
_BINARY_TAIL_SCAN_BYTES = 1024 * 1024
_BINARY_TAIL_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "Windows executable (PE)", "S501"),
    (b"\x7fELF", "Linux executable (ELF)", "S502"),
    (b"\xfe\xed\xfa\xce", "macOS executable (Mach-O 32-bit)", "S503"),
    (b"\xfe\xed\xfa\xcf", "macOS executable (Mach-O 64-bit)", "S503"),
    (b"\xcf\xfa\xed\xfe", "macOS executable (Mach-O)", "S503"),
    (b"#!/bin/sh", "Shell script", "S504"),
    (b"#!/bin/bash", "Shell script", "S504"),
    (b"powershell", "PowerShell script", "S506"),
    (b"invoke-expression", "PowerShell script", "S506"),
)
_BINARY_TAIL_SIGNATURE_BACKTRACK_BYTES = (
    max(len(signature) for signature, _label, _rule_code in _BINARY_TAIL_SIGNATURES) - 1
)
_RAW_PICKLE_GLOBAL_REFERENCES: tuple[tuple[bytes, bytes, str], ...] = (
    (b"os", b"system", "os.system"),
    (b"posix", b"system", "posix.system"),
    (b"nt", b"system", "nt.system"),
    (b"os", b"popen", "os.popen"),
    (b"posix", b"popen", "posix.popen"),
    (b"nt", b"popen", "nt.popen"),
    (b"os", b"spawnl", "os.spawnl"),
    (b"os", b"spawnle", "os.spawnle"),
    (b"os", b"spawnlp", "os.spawnlp"),
    (b"os", b"spawnlpe", "os.spawnlpe"),
    (b"os", b"spawnv", "os.spawnv"),
    (b"os", b"spawnve", "os.spawnve"),
    (b"os", b"spawnvp", "os.spawnvp"),
    (b"os", b"spawnvpe", "os.spawnvpe"),
    (b"commands", b"getoutput", "commands.getoutput"),
    (b"commands", b"getstatusoutput", "commands.getstatusoutput"),
    (b"subprocess", b"call", "subprocess.call"),
    (b"subprocess", b"run", "subprocess.run"),
    (b"subprocess", b"popen", "subprocess.Popen"),
)
_RAW_TEXT_MODULE_ATTR_INDICATORS: tuple[tuple[bytes, bytes, str], ...] = (
    (b"os", b"system", "os.system"),
    (b"posix", b"system", "posix.system"),
    (b"nt", b"system", "nt.system"),
    (b"os", b"popen", "os.popen"),
)
_RAW_TEXT_REGEX_INDICATORS: tuple[tuple[bytes, str, str], ...] = (
    (rb"(?<![A-Za-z0-9_])os\s*\.\s*spawn", "os.spawn", "os.spawn"),
)
_RAW_TEXT_TOKEN_INDICATORS: tuple[tuple[bytes, str, str], ...] = (
    (b"commands.getoutput", "commands.getoutput", "commands.getoutput"),
    (b"commands.getstatusoutput", "commands.getstatusoutput", "commands.getstatusoutput"),
    (b"subprocess.call", "subprocess.call", "subprocess.call"),
    (b"subprocess.run", "subprocess.run", "subprocess.run"),
    (b"subprocess.popen", "subprocess.popen", "subprocess.popen"),
)
_RAW_IMPORTLIB_METHODS: tuple[bytes, ...] = (b"import_module", b"reload", b"find_loader", b"load_module")
_RAW_WEBBROWSER_METHODS: tuple[bytes, ...] = (b"open", b"open_new", b"open_new_tab")
_RAW_TEXT_SCAN_SEEDS: tuple[bytes, ...] = (
    b"__import__",
    b"commands",
    b"eval",
    b"exec",
    b"find_loader",
    b"getoutput",
    b"getstatusoutput",
    b"import",
    b"import_module",
    b"importlib",
    b"load_module",
    b"popen",
    b"reload",
    b"runpy",
    b"spawn",
    b"subprocess",
    b"system",
    b"webbrowser",
)
_SECRET_SCAN_SEEDS: tuple[bytes, ...] = (
    b"://",
    b"-----begin dsa private key-----",
    b"-----begin ec private key-----",
    b"-----begin openssh private key-----",
    b"-----begin pgp private key block-----",
    b"-----begin rsa private key-----",
    b"akia",
    b"api_key:",
    b"api_key=",
    b"auth_token:",
    b"auth_token=",
    b"aws_",
    b"azure_client_secret:",
    b"azure_client_secret=",
    b"bearer",
    b"client_secret:",
    b"client_secret=",
    b"credential",
    b"eyj",
    b"gcp_api_key:",
    b"gcp_api_key=",
    b"github_pat_",
    b"ghp_",
    b"ghs_",
    b"glpat-",
    b"hooks.slack.com",
    b"mailgun",
    b"mongodb+srv://",
    b"npm_",
    b"openai_api_key:",
    b"openai_api_key=",
    b"passwd:",
    b"passwd=",
    b"password:",
    b"password=",
    b"private_key",
    b"pwd:",
    b"pwd=",
    b"rg_",
    b"secret:",
    b"secret=",
    b"secret_key:",
    b"secret_key=",
    b"seed phrase",
    b"sendgrid",
    b"sk-",
    b"sk_live_",
    b"slack://",
    b"sq0",
    b"stripe_live_",
    b"token:",
    b"token=",
    b"twilio",
    b"xox",
)
_NETWORK_SCAN_SEEDS: tuple[bytes, ...] = (
    b"://",
    b"aiohttp",
    b"backdoor",
    b"beacon_url",
    b"botnet",
    b"callback_url",
    b"c2_server",
    b"command_server",
    b"dns.resolver",
    b"exfil_endpoint",
    b"ftp",
    b"grpc",
    b"http",
    b"imap",
    b"malware",
    b"mongo",
    b"paramiko",
    b"phone_home",
    b"redis",
    b"requests",
    b"s3://",
    b"socket",
    b"smtp",
    b"telnet",
    b"trojan",
    b"urllib",
    b"webhook",
    b"websocket",
    b"zombie",
)
_SECRET_ASSIGNMENT_SHAPE_RE = re.compile(
    rb"(?i)\b[a-z0-9_.-]{0,64}(?:api[_-]?key|secret|token|password|passwd|pwd|credential|access[_-]?key)"
    rb"[a-z0-9_.-]{0,64}\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{8,}"
)
_SECRET_SHAPE_KEYWORDS: tuple[bytes, ...] = (
    b"credential",
    b"password",
    b"passwd",
    b"secret",
    b"token",
    b"key",
    b"pwd",
)
_DOCUMENTATION_LINE_PREFIXES = (b"#", b"//", b"/*", b"*")
_PICKLE_LITERAL_OPCODE_NAMES = frozenset(
    {
        "STRING",
        "UNICODE",
        "BINSTRING",
        "SHORT_BINSTRING",
        "BINUNICODE",
        "SHORT_BINUNICODE",
        "BINUNICODE8",
        "BINBYTES",
        "SHORT_BINBYTES",
        "BINBYTES8",
        "BYTEARRAY8",
    }
)
_JIT_SCAN_SEEDS: tuple[bytes, ...] = (
    b"__import__",
    b"compile",
    b"class meta",
    b"def main",
    b"eval",
    b"exec",
    b"lambda",
    b"os.",
    b"requests.",
    b"socket.",
    b"subprocess.",
    b"tf.",
    b"torch.jit",
    b"torchscript",
    b"urllib.",
)
_EXPENSIVE_RAW_SCAN_SEEDS = tuple(dict.fromkeys(_SECRET_SCAN_SEEDS + _NETWORK_SCAN_SEEDS + _JIT_SCAN_SEEDS))
_CVE_RAW_SCAN_SEEDS: tuple[bytes, ...] = (
    b"__import__",
    b"_rebuild_tensor",
    b"bfloat16storage",
    b"builtins.eval",
    b"builtins.exec",
    b"compile",
    b"deserializ",
    b"element_size",
    b"eval",
    b"exec",
    b"floatstorage",
    b"halfstorage",
    b"jit.annotations",
    b"joblib",
    b"longstorage",
    b"nbytes",
    b"numel",
    b"numpy_pickle",
    b"numpyarraywrapper",
    b"os.system",
    b"parse_type_line",
    b"pickle.load",
    b"pythonudf",
    b"read_array",
    b"remote_module_pickled",
    b"remotemodule",
    b"rpc_async",
    b"rpc_sync",
    b"setitem",
    b"setitems",
    b"sklearn",
    b"storage_offset",
    b"storage_size",
    b"subprocess",
    b"torch._utils",
    b"torch.distributed.rpc",
    b"torch.jit.annotations",
    b"torch.storage",
    b"unpickl",
    b"untyped_storage",
)
_COPYREG_EXTENSION_OPCODES = (b"\x82", b"\x83", b"\x84")


@dataclass(frozen=True)
class _RootStreamPayloadRead:
    payload: bytes
    truncated: bool
    read_limit: int


_BUILTIN_MODULES = frozenset({"builtins", "__builtin__", "__builtins__"})
_SAFE_MODULE_POLICY_PREFIXES = ("os.path",)
_DANGEROUS_FUNCTION_EXPORT_ALIASES = frozenset(
    {
        "__builtins__.execfile",
        "__builtins__.raw_input",
        "__builtins__.reload",
        "marshal.loads",
        "nt.system",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "posix.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
)


def _dangerous_function_exports_from_suspicious_globals() -> frozenset[str]:
    exports: set[str] = set()
    for module, functions in SUSPICIOUS_GLOBALS.items():
        if functions == "*":
            continue
        function_names = (functions,) if isinstance(functions, str) else functions
        for function_name in function_names:
            exports.add(f"{module}.{function_name}")
            if module in _BUILTIN_MODULES:
                exports.add(function_name)
    return frozenset(exports)


def _dangerous_modules_from_suspicious_globals() -> frozenset[str]:
    return frozenset(module for module, functions in SUSPICIOUS_GLOBALS.items() if functions == "*")


# Kept as compatibility exports for callers/tests that inspect the policy. Values
# are derived from the shared suspicious-symbol table, with a small alias layer
# for historical fully-qualified names under wildcard modules.
ALWAYS_DANGEROUS_FUNCTIONS: frozenset[str] = (
    _dangerous_function_exports_from_suspicious_globals() | _DANGEROUS_FUNCTION_EXPORT_ALIASES
)
ALWAYS_DANGEROUS_MODULES: frozenset[str] = _dangerous_modules_from_suspicious_globals()
ML_SAFE_GLOBALS: dict[str, list[str]] = {
    "collections": ["Counter", "OrderedDict", "defaultdict", "deque"],
    "numpy": ["dtype", "ndarray", "scalar"],
    "torch": ["device", "dtype", "Size", "Tensor"],
}

__all__ = [
    "ALWAYS_DANGEROUS_FUNCTIONS",
    "ALWAYS_DANGEROUS_MODULES",
    "ML_SAFE_GLOBALS",
    "PickleScanner",
    "_is_actually_dangerous_global",
    "_is_dangerous_module",
    "_is_legitimate_serialization_file",
    "_looks_like_pickle",
    "is_suspicious_global",
]


def _looks_like_pickle(data: bytes) -> bool:
    """Return whether a bounded byte prefix looks like a pickle stream."""
    if len(data) < 2:
        return False

    first = data[0]
    if first == 0x80:
        return data[1] in {1, 2, 3, 4, 5}

    # Protocol 0 pickles often start directly with GLOBAL/INST/list/dict/tuple
    # structural opcodes. This is intentionally a sniff, not validation.
    return first in {ord("("), ord("]"), ord("}"), ord("c"), ord("i"), ord("l"), ord("d"), ord("t")}


def _is_primarily_documentation(data: bytes) -> bool:
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    if not lines:
        return False
    doc_lines = sum(1 for line in lines if line.startswith(_DOCUMENTATION_LINE_PREFIXES))
    return doc_lines / len(lines) > 0.5


def _literal_arg_bytes(arg: object) -> bytes | None:
    if isinstance(arg, str):
        return arg.encode("utf-8", errors="ignore")
    if isinstance(arg, bytes):
        return arg
    return None


def _documentation_literal_spans(data: bytes) -> tuple[tuple[int, int], ...]:
    try:
        operations = list(pickletools.genops(data))
    except Exception:
        return ()

    spans: list[tuple[int, int]] = []
    for index, (opcode, arg, position) in enumerate(operations):
        if position is None or opcode.name not in _PICKLE_LITERAL_OPCODE_NAMES:
            continue
        literal = _literal_arg_bytes(arg)
        if literal is None or not _is_primarily_documentation(literal):
            continue
        next_position = operations[index + 1][2] if index + 1 < len(operations) else None
        end_position = next_position if isinstance(next_position, int) and next_position > position else len(data)
        spans.append((position, end_position))
    return tuple(spans)


def _pickle_literal_strings(data: bytes) -> tuple[str, ...]:
    try:
        operations = pickletools.genops(data)
        literals: list[str] = []
        for opcode, arg, _position in operations:
            if opcode.name not in _PICKLE_LITERAL_OPCODE_NAMES:
                continue
            if isinstance(arg, str):
                literals.append(arg)
            elif isinstance(arg, bytes):
                literals.append(arg.decode("utf-8", errors="ignore"))
        return tuple(literals)
    except Exception:
        return ()


def _contains_validated_code_call_literal(data: bytes, label: str) -> bool:
    token = f"{label}("
    for literal in _pickle_literal_strings(data):
        if len(literal) > _MAX_RAW_CODE_LITERAL_VALIDATION_CHARS or token not in literal.lower():
            continue
        is_valid, _error = validate_python_syntax(literal)
        if is_valid:
            return True
    return False


def _raw_call_token_should_report(
    data: bytes,
    lower: bytes,
    label: bytes,
    documentation_spans: tuple[tuple[int, int], ...],
) -> bool:
    if not _contains_call_token(lower, label, documentation_spans):
        return False
    exact_call = label + b"("
    if not _contains_non_documentation_token(lower, exact_call, documentation_spans):
        return True
    return _contains_validated_code_call_literal(data, label.decode("ascii"))


def _position_in_spans(position: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= position < end for start, end in spans)


def _line_looks_like_documentation(data: bytes, position: int) -> bool:
    line_start = data.rfind(b"\n", 0, position) + 1
    line_end = data.find(b"\n", position)
    if line_end < 0:
        line_end = len(data)
    stripped = data[line_start:line_end].strip()
    if stripped.startswith(_DOCUMENTATION_LINE_PREFIXES):
        return True
    return (
        len(stripped) > 1
        and stripped[:1] in {b"S", b"V", b"s", b"v"}
        and stripped[1:].lstrip().startswith(_DOCUMENTATION_LINE_PREFIXES)
    )


def _is_documentation_match(data: bytes, position: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return _position_in_spans(position, spans) or _line_looks_like_documentation(data, position)


def _contains_non_documentation_token(
    data: bytes,
    token: bytes,
    documentation_spans: tuple[tuple[int, int], ...],
) -> bool:
    start = 0
    while True:
        index = data.find(token, start)
        if index < 0:
            return False
        if not _is_documentation_match(data, index, documentation_spans):
            return True
        start = index + len(token)


def _contains_non_documentation_pattern(
    data: bytes,
    pattern: bytes,
    documentation_spans: tuple[tuple[int, int], ...],
) -> bool:
    return any(
        not _is_documentation_match(data, match.start(), documentation_spans) for match in re.finditer(pattern, data)
    )


def _contains_call_token(
    data: bytes,
    name: bytes,
    documentation_spans: tuple[tuple[int, int], ...] = (),
) -> bool:
    start = 0
    while True:
        index = data.find(name, start)
        if index < 0:
            return False
        if index > 0 and (data[index - 1 : index].isalnum() or data[index - 1] == ord("_")):
            start = index + len(name)
            continue
        if _is_documentation_match(data, index, documentation_spans):
            start = index + len(name)
            continue

        position = index + len(name)
        separator_end = min(len(data), position + _CALL_TOKEN_SEPARATOR_SCAN_LIMIT_BYTES)
        while position < separator_end:
            byte = data[position]
            if byte == ord("("):
                return True
            if byte <= 0x20 or byte == ord(";"):
                position += 1
                continue
            if byte == ord("#"):
                newline = data.find(b"\n", position + 1, separator_end)
                if newline < 0:
                    break
                position = newline + 1
                continue
            if data.startswith(b"\\\r\n", position):
                position += 3
                continue
            if data.startswith(b"\\\n", position) or data.startswith(b"\\\r", position):
                position += 2
                continue
            if data.startswith(b"/*", position):
                comment_end = data.find(b"*/", position + 2, separator_end)
                if comment_end < 0:
                    break
                position = comment_end + 2
                continue
            break

        start = index + len(name)


def _contains_module_attr(
    data: bytes,
    module: bytes,
    attr: bytes,
    documentation_spans: tuple[tuple[int, int], ...] = (),
) -> bool:
    pattern = rb"(?<![A-Za-z0-9_])" + re.escape(module) + rb"\s*\.\s*" + re.escape(attr) + rb"(?![A-Za-z0-9_])"
    return _contains_non_documentation_pattern(data, pattern, documentation_spans)


def _contains_pickle_global_reference(
    data: bytes,
    module: bytes,
    attr: bytes,
    documentation_spans: tuple[tuple[int, int], ...],
) -> bool:
    return _contains_non_documentation_token(data, b"c" + module + b"\n" + attr + b"\n", documentation_spans)


def _contains_any_seed(data: bytes, seeds: tuple[bytes, ...]) -> bool:
    return _contains_any_seed_lowered(data.lower(), seeds)


def _seed_possible_from_present_bytes(seed: bytes, present_bytes: frozenset[int] | None) -> bool:
    return present_bytes is None or all(byte in present_bytes for byte in seed)


def _contains_any_seed_lowered(
    lower_data: bytes,
    seeds: tuple[bytes, ...],
    present_bytes: frozenset[int] | None = None,
) -> bool:
    return any(_seed_possible_from_present_bytes(seed, present_bytes) and seed in lower_data for seed in seeds)


def _has_raw_text_indicator_shape(
    data: bytes,
    lower_data: bytes,
    *,
    rust_clean: bool,
    present_bytes: frozenset[int] | None = None,
) -> bool:
    if _contains_any_seed_lowered(lower_data, _RAW_TEXT_SCAN_SEEDS, present_bytes):
        return True
    if rust_clean:
        return False
    return b"R" in data and any(opcode in data for opcode in _COPYREG_EXTENSION_OPCODES)


def _has_alnum_secret_shape(
    data: bytes,
    lower_data: bytes | None = None,
    present_bytes: frozenset[int] | None = None,
) -> bool:
    lower = data.lower() if lower_data is None else lower_data
    if not _contains_any_seed_lowered(lower, _SECRET_SHAPE_KEYWORDS, present_bytes):
        return False
    return _SECRET_ASSIGNMENT_SHAPE_RE.search(data) is not None


def _has_domain_or_ip_shape(data: bytes) -> bool:
    if b"://" in data:
        return True
    if b"/" in data and _has_domain_with_path_shape(data):
        return True
    return _IPV4_DOT_DIGIT_RE.search(data) is not None and _has_ipv4_shape(data)


def _has_domain_with_path_shape(data: bytes) -> bool:
    start = 0
    while True:
        slash_index = data.find(b"/", start)
        if slash_index < 0:
            return False
        host_start = slash_index
        while host_start > 0 and _is_domain_host_byte(data[host_start - 1]):
            host_start -= 1
        if _is_plausible_domain_host(data[host_start:slash_index]):
            return True
        start = slash_index + 1


def _has_ipv4_shape(data: bytes) -> bool:
    start = 0
    while True:
        dot_index = data.find(b".", start)
        if dot_index < 0:
            return False
        candidate_start = dot_index
        while candidate_start > 0 and _is_ipv4_candidate_byte(data[candidate_start - 1]):
            candidate_start -= 1
        candidate_end = dot_index + 1
        while candidate_end < len(data) and _is_ipv4_candidate_byte(data[candidate_end]):
            candidate_end += 1
        if _is_plausible_ipv4(data[candidate_start:candidate_end]):
            return True
        start = dot_index + 1


def _is_domain_host_byte(byte: int) -> bool:
    return byte == 45 or byte == 46 or (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122)


def _is_domain_label_byte(byte: int) -> bool:
    return byte == 45 or (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122)


def _is_ascii_alpha_byte(byte: int) -> bool:
    return (65 <= byte <= 90) or (97 <= byte <= 122)


def _is_plausible_domain_host(host: bytes) -> bool:
    if not 3 <= len(host) <= 253 or b"." not in host:
        return False
    labels = host.split(b".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or label.startswith(b"-") or label.endswith(b"-"):
            return False
        if not all(_is_domain_label_byte(byte) for byte in label):
            return False
    tld = labels[-1]
    return len(tld) >= 2 and any(_is_ascii_alpha_byte(byte) for byte in tld)


def _is_ipv4_candidate_byte(byte: int) -> bool:
    return byte == 46 or (48 <= byte <= 57)


def _is_plausible_ipv4(candidate: bytes) -> bool:
    parts = candidate.split(b".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not 1 <= len(part) <= 3 or not part.isdigit():
            return False
        if int(part) > 255:
            return False
    return True


def _looks_like_portable_executable(data: bytes) -> bool:
    if not data.startswith(b"MZ"):
        return False
    if b"This program cannot be run in DOS mode" in data[:512]:
        return True
    if len(data) < 0x40:
        return False
    pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    return pe_offset > 0 and pe_offset + 4 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _stream_is_seekable(file_obj: BinaryIO) -> bool:
    try:
        return bool(file_obj.seekable())
    except (AttributeError, OSError, ValueError):
        return False


def _has_rule_for_import_reference(result: ScanResult, rule_code: str, import_reference: str) -> bool:
    return any(
        issue.rule_code == rule_code
        and issue.details.get("associated_global", issue.details.get("import_reference")) == import_reference
        for issue in result.issues
    )


def _has_issue_for_import_reference(result: ScanResult, import_reference: str) -> bool:
    return any(
        issue.details.get("associated_global", issue.details.get("import_reference")) == import_reference
        for issue in result.issues
    )


def _append_raw_indicator(
    indicators: list[tuple[str, dict[str, Any]]],
    label: str,
    associated_global: str | None = None,
) -> None:
    indicators.append((label, {"associated_global": associated_global or label}))


def _result_opcode_counts(result: ScanResult) -> dict[str, int]:
    counts = result.metadata.get("opcode_counts")
    if not isinstance(counts, dict):
        return {}

    parsed_counts: dict[str, int] = {}
    for opcode, count in counts.items():
        if isinstance(opcode, str) and isinstance(count, int):
            parsed_counts[opcode] = count
    return parsed_counts


def _result_import_references(result: ScanResult) -> list[dict[str, Any]]:
    references = result.metadata.get("import_references")
    if not isinstance(references, list):
        return []
    return [dict(reference) for reference in references if isinstance(reference, dict)]


def _result_has_rebuild_tensor_global(result: ScanResult) -> bool:
    for reference in _result_import_references(result):
        import_reference = reference.get("import_reference")
        if isinstance(import_reference, str) and "_rebuild_tensor" in import_reference:
            return True
    return False


def _pickle_has_parsed_rebuild_tensor_literal(data: bytes) -> bool:
    try:
        for opcode, arg, _position in pickletools.genops(data):
            if opcode.name in {
                "STRING",
                "UNICODE",
                "BINSTRING",
                "SHORT_BINSTRING",
                "BINUNICODE",
                "SHORT_BINUNICODE",
            } and (
                isinstance(arg, str)
                and "_rebuild_tensor" in arg
                and not _is_primarily_documentation(arg.encode("utf-8", errors="ignore"))
            ):
                return True
    except Exception:
        return False
    return False


def _pickle_has_setitem_abuse_for_entries(
    data: bytes,
    *,
    global_needles: tuple[str, ...],
    literal_needles: tuple[str, ...] = (),
) -> bool:
    stack: list[tuple[str, str | None]] = []
    memo: dict[int, tuple[str, str | None]] = {}
    mark = ("mark", None)

    def pop() -> tuple[str, str | None]:
        return stack.pop() if stack else ("unknown", None)

    def pop_to_mark() -> list[tuple[str, str | None]]:
        values: list[tuple[str, str | None]] = []
        while stack:
            value = stack.pop()
            if value == mark:
                break
            values.append(value)
        values.reverse()
        return values

    def is_interesting_entry(value: tuple[str, str | None]) -> bool:
        kind, text = value
        if kind == "interesting_result":
            return True
        if kind == "global" and isinstance(text, str):
            return any(needle in text for needle in global_needles)
        if kind == "string" and isinstance(text, str):
            return any(needle in text for needle in literal_needles) and not _is_primarily_documentation(
                text.encode("utf-8", errors="ignore")
            )
        return False

    def entry_for_global(arg: object) -> tuple[str, str | None]:
        parts = _global_parts(arg)
        if parts is None:
            return ("global", None)
        return ("global", f"{parts[0]}.{parts[1]}")

    def collapse_callable_result(callable_value: tuple[str, str | None]) -> tuple[str, str | None]:
        return ("interesting_result", None) if is_interesting_entry(callable_value) else ("object", None)

    try:
        for opcode, arg, _position in pickletools.genops(data):
            name = opcode.name
            if name == "MARK":
                stack.append(mark)
            elif name == "GLOBAL":
                stack.append(entry_for_global(arg))
            elif name == "STACK_GLOBAL":
                global_name = pop()
                module = pop()
                if module[0] == "string" and global_name[0] == "string":
                    stack.append(("global", f"{module[1]}.{global_name[1]}"))
                else:
                    stack.append(("global", None))
            elif name in {
                "STRING",
                "UNICODE",
                "BINSTRING",
                "SHORT_BINSTRING",
                "BINUNICODE",
                "SHORT_BINUNICODE",
            }:
                stack.append(("string", arg if isinstance(arg, str) else None))
            elif name == "EMPTY_DICT":
                stack.append(("dict", None))
            elif name == "DICT":
                pop_to_mark()
                stack.append(("dict", None))
            elif name in {"EMPTY_LIST", "LIST", "EMPTY_SET", "SET", "FROZENSET"}:
                if name in {"LIST", "SET", "FROZENSET"}:
                    pop_to_mark()
                stack.append(("container", None))
            elif name == "EMPTY_TUPLE":
                stack.append(("tuple", None))
            elif name == "TUPLE":
                pop_to_mark()
                stack.append(("tuple", None))
            elif name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
                arity = int(name[-1])
                for _ in range(min(arity, len(stack))):
                    pop()
                stack.append(("tuple", None))
            elif name in {"REDUCE", "NEWOBJ"}:
                pop()
                stack.append(collapse_callable_result(pop()))
            elif name == "NEWOBJ_EX":
                pop()
                pop()
                stack.append(collapse_callable_result(pop()))
            elif name == "SETITEM":
                value = pop()
                key = pop()
                target = stack[-1] if stack else ("unknown", None)
                if is_interesting_entry(target) or is_interesting_entry(key):
                    return True
                if is_interesting_entry(value) and (target[0] not in {"dict", "unknown"} or value[0] == "global"):
                    return True
            elif name == "SETITEMS":
                values = pop_to_mark()
                target = stack[-1] if stack else ("unknown", None)
                if is_interesting_entry(target):
                    return True
                for index in range(0, len(values), 2):
                    if is_interesting_entry(values[index]):
                        return True
                    if (
                        index + 1 < len(values)
                        and values[index + 1][0] == "global"
                        and is_interesting_entry(values[index + 1])
                    ):
                        return True
            elif name in {"APPEND", "APPENDS", "ADDITEMS"}:
                if name == "APPEND":
                    pop()
                else:
                    pop_to_mark()
            elif name in {"POP", "DUP"}:
                if name == "POP":
                    pop()
                elif stack:
                    stack.append(stack[-1])
            elif name in {"PUT", "BINPUT", "LONG_BINPUT"}:
                if stack:
                    memo_index = int(arg) if isinstance(arg, int) else None
                    if memo_index is not None:
                        memo[memo_index] = stack[-1]
            elif name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]
            elif name in {"GET", "BINGET", "LONG_BINGET"}:
                memo_index = int(arg) if isinstance(arg, int) else None
                stack.append(memo.get(memo_index, ("unknown", None)) if memo_index is not None else ("unknown", None))
            elif name in {
                "NONE",
                "NEWTRUE",
                "NEWFALSE",
                "INT",
                "BININT",
                "BININT1",
                "BININT2",
                "LONG",
                "LONG1",
                "LONG4",
            }:
                stack.append(("scalar", None))
    except Exception:
        return False
    return False


def _pickle_has_rebuild_tensor_setitem_abuse(data: bytes) -> bool:
    return _pickle_has_setitem_abuse_for_entries(
        data,
        global_needles=("_rebuild_tensor",),
        literal_needles=("_rebuild_tensor",),
    )


def _pickle_has_dangerous_system_setitem_abuse(data: bytes) -> bool:
    return _pickle_has_setitem_abuse_for_entries(
        data,
        global_needles=("os.system", "posix.system", "nt.system"),
    )


def _result_parse_was_incomplete(result: ScanResult) -> bool:
    if result.metadata.get("parsing_failed") is True or result.metadata.get("analysis_incomplete") is True:
        return True
    status = result.metadata.get("pickle_report_status")
    return isinstance(status, str) and status != "complete"


def _metadata_pickle_read_limit(configured_limit: Any) -> tuple[int | None, str | None]:
    try:
        read_limit = int(configured_limit)
    except (TypeError, ValueError, OverflowError):
        return None, "max_metadata_pickle_read_size must be greater than 0"

    if read_limit <= 0:
        return None, "max_metadata_pickle_read_size must be greater than 0"
    if read_limit > _MAX_METADATA_PICKLE_READ_BYTES:
        return None, f"max_metadata_pickle_read_size too large (max: {_MAX_METADATA_PICKLE_READ_BYTES})"
    return read_limit, None


def _is_dangerous_module(module: str) -> bool:
    """Return whether a module path is always dangerous."""
    normalized = module.strip()
    if _is_safe_module_policy_path(normalized):
        return False
    return normalized in ALWAYS_DANGEROUS_MODULES or any(
        normalized.startswith(f"{dangerous}.") for dangerous in ALWAYS_DANGEROUS_MODULES
    )


def _is_safe_module_policy_path(module: str) -> bool:
    return any(module == safe or module.startswith(f"{safe}.") for safe in _SAFE_MODULE_POLICY_PREFIXES)


def _suspicious_global_policy_matches(module: str, name: str) -> bool:
    if _is_safe_module_policy_path(module):
        return False

    suspicious = SUSPICIOUS_GLOBALS.get(module)
    if suspicious is None:
        top_level_module = module.split(".", 1)[0]
        suspicious = SUSPICIOUS_GLOBALS.get(top_level_module)
        if suspicious != "*":
            return False

    if suspicious == "*":
        return True
    if isinstance(suspicious, (list, tuple, set, frozenset)):
        return name in suspicious
    if isinstance(suspicious, str):
        return name == suspicious
    return False


def is_suspicious_global(module: str, name: str) -> bool:
    """Compatibility helper for checking pickle global policy."""
    normalized_module = module.strip()
    normalized_name = name.strip()
    full_name = f"{normalized_module}.{normalized_name}"
    return (
        full_name in ALWAYS_DANGEROUS_FUNCTIONS
        or (not normalized_module and normalized_name in ALWAYS_DANGEROUS_FUNCTIONS)
        or _suspicious_global_policy_matches(normalized_module, normalized_name)
    )


def _is_actually_dangerous_global(module: str, name: str, ml_context: dict[str, Any] | None = None) -> bool:
    """Compatibility helper that never lets ML context suppress dangerous symbols."""
    del ml_context
    return is_suspicious_global(module, name)


def _is_legitimate_serialization_file(path: str) -> bool:
    """Return whether a pickle-like file scans without Rust security findings."""
    path_obj = Path(path)
    if not path_obj.is_file():
        return False
    try:
        with path_obj.open("rb") as handle:
            if not _looks_like_pickle(handle.read(_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)):
                return False
        report = StandalonePickleScanner().scan_file(path_obj, enrich_call_graph=False)
    except Exception:
        return False
    return not report.has_security_findings and report.status.value != "error"


def _path_prefix_looks_like_pickle(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return _looks_like_pickle(handle.read(_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES))
    except OSError:
        return Path(path).suffix.lower() in _KNOWN_PICKLE_EXTENSIONS


def _global_parts(arg: object) -> tuple[str, str] | None:
    if isinstance(arg, str):
        parts = arg.replace("\n", " ").split()
        if len(parts) >= 2:
            return parts[0], parts[1]
    if isinstance(arg, tuple) and len(arg) >= 2 and all(isinstance(part, str) for part in arg[:2]):
        return arg[0], arg[1]
    return None


def _pickle_opcode_summary(data: bytes) -> dict[str, Any]:
    dangerous_opcodes = {
        "REDUCE",
        "INST",
        "OBJ",
        "NEWOBJ",
        "NEWOBJ_EX",
        "STACK_GLOBAL",
        "GLOBAL",
        "BUILD",
    }
    opcode_counts: dict[str, int] = {}
    stack: list[str | None] = []
    memo: dict[int, str | None] = {}
    dangerous_globals: list[str] = []
    protocol: int | None = None
    total_opcodes = 0

    def _memo_index(value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return None

    def _pop_value() -> str | None:
        return stack.pop() if stack else None

    try:
        for opcode, arg, _position in pickletools.genops(data):
            name = opcode.name
            total_opcodes += 1
            opcode_counts[name] = opcode_counts.get(name, 0) + 1
            if name == "PROTO" and isinstance(arg, int):
                protocol = arg
            if name in {"STRING", "UNICODE", "BINSTRING", "SHORT_BINSTRING", "BINUNICODE", "SHORT_BINUNICODE"}:
                stack.append(str(arg))
                continue
            if name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]
                continue
            if name in {"PUT", "BINPUT", "LONG_BINPUT"}:
                index = _memo_index(arg)
                if index is not None and stack:
                    memo[index] = stack[-1]
                continue
            if name in {"GET", "BINGET", "LONG_BINGET"}:
                index = _memo_index(arg)
                stack.append(memo.get(index) if index is not None else None)
                continue
            if name == "GLOBAL":
                parts = _global_parts(arg)
                if parts is not None:
                    module, global_name = parts
                    if is_suspicious_global(module, global_name):
                        dangerous_globals.append(f"{module}.{global_name}")
                stack.append(None)
                continue
            if name == "STACK_GLOBAL" and len(stack) >= 2:
                stack_global_name = _pop_value()
                stack_module = _pop_value()
                if (
                    stack_module is not None
                    and stack_global_name is not None
                    and is_suspicious_global(stack_module, stack_global_name)
                ):
                    dangerous_globals.append(f"{stack_module}.{stack_global_name}")
                stack.append(None)
                continue
            if name == "POP":
                _pop_value()
            elif name in {
                "EMPTY_DICT",
                "EMPTY_LIST",
                "EMPTY_SET",
                "EMPTY_TUPLE",
                "MARK",
                "NONE",
                "NEWFALSE",
                "NEWTRUE",
                "INT",
                "BININT",
                "BININT1",
                "BININT2",
                "LONG",
                "LONG1",
                "LONG4",
                "FLOAT",
                "BINFLOAT",
            }:
                stack.append(None)
    except Exception as error:
        return {"parse_error": str(error)}

    observed_dangerous_opcodes = sorted(opcode for opcode in dangerous_opcodes if opcode_counts.get(opcode, 0) > 0)
    return {
        "dangerous_opcodes": observed_dangerous_opcodes,
        "has_dangerous_opcodes": bool(observed_dangerous_opcodes),
        "opcode_counts": opcode_counts,
        "total_opcodes": total_opcodes,
        "pickle_protocol": protocol,
        "dangerous_globals": sorted(set(dangerous_globals)),
    }


def _rebuild_tensor_indicators_are_documentation_literals(data: bytes) -> bool:
    """Return True when CVE-2026-24747 text indicators appear only in doc-like literals."""
    saw_rebuild_tensor_literal = False
    stack: list[str] = []
    try:
        for opcode, arg, _position in pickletools.genops(data):
            if opcode.name == "GLOBAL":
                parts = _global_parts(arg)
                if parts is not None and "_rebuild_tensor" in f"{parts[0]}.{parts[1]}":
                    return False
                stack.clear()
                continue
            if opcode.name == "STACK_GLOBAL":
                if len(stack) >= 2:
                    global_name = stack.pop()
                    module = stack.pop()
                    if "_rebuild_tensor" in f"{module}.{global_name}":
                        return False
                continue
            if opcode.name not in {
                "STRING",
                "UNICODE",
                "BINSTRING",
                "SHORT_BINSTRING",
                "BINUNICODE",
                "SHORT_BINUNICODE",
            }:
                continue
            if isinstance(arg, str):
                stack.append(arg)
            if not isinstance(arg, str) or "_rebuild_tensor" not in arg:
                continue
            saw_rebuild_tensor_literal = True
            if not _is_primarily_documentation(arg.encode("utf-8", errors="ignore")):
                return False
    except Exception:
        return False
    return saw_rebuild_tensor_literal


def _copyreg_extension_reduce_references(data: bytes) -> list[tuple[str, int]]:
    """Find opaque copyreg extension references that are consumed by REDUCE."""
    references: list[tuple[str, int]] = []
    pending_extensions: list[tuple[str, int]] = []
    try:
        for opcode, arg, position in pickletools.genops(data):
            if opcode.name in {"EXT1", "EXT2", "EXT4"}:
                pending_extensions.append((f"__copyreg_extension__.code_{arg}", position or 0))
                continue
            if opcode.name == "REDUCE":
                references.extend(pending_extensions)
                pending_extensions.clear()
                if len(references) >= 16:
                    break
    except Exception:
        return references
    return references


class PickleScanner(BaseScanner):
    """ModelAudit scanner adapter backed exclusively by the Rust pickle scanner."""

    name = "pickle"
    description = "Scans Python pickle files for suspicious code references"
    supported_extensions: ClassVar[list[str]] = [
        ".pkl",
        ".pickle",
        ".dill",
        ".joblib",
        ".bin",
        ".pt",
        ".pth",
        ".ckpt",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._standalone_pickle_scanner = StandalonePickleScanner(options=scan_options_from_config(self.config))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if the file is a raw pickle stream."""
        suffix = Path(path).suffix.lower()
        try:
            from modelaudit.utils.file.detection import detect_file_format, validate_file_type

            file_format = detect_file_format(path)
        except Exception:
            return _path_prefix_looks_like_pickle(path)

        if file_format == "zip":
            return False
        if file_format == "pickle":
            try:
                if not validate_file_type(path):
                    logger.warning("File type validation failed for potential pickle file: %s", path)
            except Exception as validation_error:
                logger.warning("File type validation errored for potential pickle file %s: %s", path, validation_error)
            return True
        if suffix in _KNOWN_PICKLE_EXTENSIONS:
            return _path_prefix_looks_like_pickle(path)
        return False

    def _prepare_scan_context(self, source: str) -> None:
        self._path_validation_result = None
        self._start_scan_timer()
        self._initialize_context(source)
        self.current_file_path = source

    @staticmethod
    def _is_zip_backed_pytorch_container(path: str) -> bool:
        if Path(path).suffix.lower() not in _PYTORCH_CONTAINER_EXTENSIONS:
            return False
        try:
            from modelaudit.utils.file.detection import detect_file_format

            return detect_file_format(path) == "zip"
        except Exception:
            return False

    def _scan_zip_backed_pytorch_container(self, path: str) -> ScanResult | None:
        if not self._is_zip_backed_pytorch_container(path):
            return None
        try:
            from .pytorch_zip_scanner import PyTorchZipScanner
        except Exception as error:
            logger.warning("Unable to load PyTorch ZIP scanner for %s: %s", path, error)
            return None
        return PyTorchZipScanner(config=self.config).scan(path, timeout=self.timeout)

    def _check_scan_stream_size_limit(self, file_size: int | None, source: str) -> ScanResult | None:
        normalized_size = None if file_size is None else max(file_size, 0)
        if (
            normalized_size is not None
            and self.max_file_read_size
            and self.max_file_read_size > 0
            and normalized_size > self.max_file_read_size
        ):
            result = self._create_result()
            result.metadata["file_size"] = normalized_size
            result.add_check(
                name="File Size Limit",
                passed=False,
                message=f"File too large: {normalized_size} bytes (max: {self.max_file_read_size})",
                severity=IssueSeverity.INFO,
                location=source,
                details={"file_size": normalized_size, "max_file_read_size": self.max_file_read_size},
            )
            result.finish(success=False)
            return result

        return None

    def _scan_standalone_stream(self, file_obj: BinaryIO, file_size: int | None, *, source: str) -> ScanResult:
        report = self._standalone_pickle_scanner.scan_stream(file_obj, source=source, size=file_size)
        result = pickle_report_to_scan_result(report, scanner_name=self.name, scanner=self)
        result.metadata["pickle_primary_engine"] = "rust"
        return result

    def _finish_after_wrapper_analysis(self, result: ScanResult, *, base_success: bool) -> None:
        success = base_success
        if result.metadata.get("operational_error") or result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
            success = False
        result.finish(success=success)

    @staticmethod
    def _mark_operational_incomplete(result: ScanResult, reason: str) -> None:
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = reason
        mark_inconclusive_scan_result(result, reason)

    def _stream_position_error_result(self, source: str, error: Exception) -> ScanResult:
        result = self._create_result()
        reason = "stream_position_failed"
        self._mark_operational_incomplete(result, reason)
        result.add_check(
            name="Pickle Stream Position",
            passed=False,
            message=f"Error positioning pickle stream: {error!s}",
            severity=IssueSeverity.INFO,
            location=source,
            details={
                "category": reason,
                "exception": str(error),
                "exception_type": type(error).__name__,
                "operational_error": True,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.finish(success=False)
        return result

    def _record_file_read_failure(self, result: ScanResult, path: str, error: OSError) -> None:
        # Retain the existing reason identifier because consumers may already key on it.
        reason = "pickle_file_open_failed"
        self._mark_operational_incomplete(result, reason)
        result.add_check(
            name="Pickle File Read",
            passed=False,
            message=f"Unable to read pickle file for analysis: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "category": reason,
                "exception": str(error),
                "exception_type": type(error).__name__,
                "operational_error": True,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.finish(success=False)

    def _record_stream_coverage_failure(self, result: ScanResult, source: str, error: Exception) -> None:
        reason = "stream_raw_read_failed"
        self._mark_operational_incomplete(result, reason)
        result.add_check(
            name="Pickle Stream Supplemental Analysis",
            passed=False,
            message=f"Unable to read pickle stream for supplemental analysis: {error!s}",
            severity=IssueSeverity.INFO,
            location=source,
            details={
                "category": reason,
                "exception": str(error),
                "exception_type": type(error).__name__,
                "operational_error": True,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.finish(success=False)

    def _stream_read_error_result(self, source: str, error: Exception) -> ScanResult:
        result = self._create_result()
        reason = "stream_read_failed"
        self._mark_operational_incomplete(result, reason)
        result.add_check(
            name="Pickle Stream Read",
            passed=False,
            message=f"Unable to read pickle stream for analysis: {error!s}",
            severity=IssueSeverity.INFO,
            location=source,
            details={
                "category": reason,
                "exception": str(error),
                "exception_type": type(error).__name__,
                "operational_error": True,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.finish(success=False)
        return result

    def _root_raw_scan_limit(self) -> int:
        limit = self.config.get("pickle_root_raw_scan_limit_bytes", _ROOT_RAW_SCAN_LIMIT_BYTES)
        try:
            return int(limit)
        except (TypeError, ValueError, OverflowError):
            return _ROOT_RAW_SCAN_LIMIT_BYTES

    def _root_expensive_raw_scan_limit(self) -> int:
        limit = self.config.get("pickle_expensive_raw_scan_limit_bytes", _ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES)
        try:
            parsed_limit = int(limit)
        except (TypeError, ValueError, OverflowError):
            return _ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES
        return max(parsed_limit, 0)

    @staticmethod
    def _rust_scan_completed_cleanly(result: ScanResult) -> bool:
        return (
            result.metadata.get("pickle_report_status") == "complete"
            and result.metadata.get("pickle_verdict") == "clean"
            and not result.metadata.get("analysis_incomplete")
            and not result.metadata.get("operational_error")
            and not result.has_errors
            and not result.has_warnings
        )

    def _should_skip_expensive_raw_detectors(self, result: ScanResult, raw_data: bytes) -> bool:
        if not self._rust_scan_completed_cleanly(result):
            return False

        # This fast path is valid only for the current expensive raw detectors
        # (secrets, JIT code, and network indicators), whose evidence is covered
        # by the seed/shape gates below. Any future expensive raw detector with
        # non-seeded structural evidence must update this predicate and tests.
        expensive_limit = self._root_expensive_raw_scan_limit()
        if expensive_limit <= 0:
            return True
        expensive_data = raw_data[:expensive_limit]
        return not _has_domain_or_ip_shape(expensive_data) and not _contains_any_seed_lowered(
            expensive_data.lower(),
            _EXPENSIVE_RAW_SCAN_SEEDS,
        )

    def _read_root_raw_scan_window(self, path: str, file_size: int) -> bytes:
        parsed_limit = self._root_raw_scan_limit()
        if parsed_limit <= 0:
            return b""
        read_size = min(file_size, parsed_limit)
        chunks: list[bytes] = []
        remaining = read_size
        with open(path, "rb") as handle:
            while remaining > 0:
                self.check_interrupted()
                if self._check_timeout(allow_partial=True):
                    break
                chunk = handle.read(min(_RAW_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        return b"".join(chunks)

    def _read_root_raw_scan_window_from_stream(self, file_obj: BinaryIO, file_size: int | None) -> bytes:
        parsed_limit = self._root_raw_scan_limit()
        if parsed_limit <= 0:
            return b""

        read_size = parsed_limit if file_size is None else min(max(file_size, 0), parsed_limit)
        if read_size <= 0:
            return b""

        if not _stream_is_seekable(file_obj):
            return b""
        start_position = file_obj.tell()
        data = self._read_stream_bytes(file_obj, read_size)
        file_obj.seek(start_position)
        return data

    def _read_stream_bytes(self, file_obj: BinaryIO, read_size: int) -> bytes:
        remaining = max(read_size, 0)
        chunks: list[bytes] = []
        while remaining > 0:
            self.check_interrupted()
            if self._check_timeout(allow_partial=True):
                break
            chunk = file_obj.read(min(_RAW_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_stream_payload_for_root(self, file_obj: BinaryIO, file_size: int | None) -> _RootStreamPayloadRead:
        if file_size is not None:
            limit = self._standalone_pickle_scanner.options.max_known_stream_read_bytes
            if self.max_file_read_size and self.max_file_read_size > 0:
                limit = min(limit, self.max_file_read_size)
        else:
            limit = min(
                self._root_raw_scan_limit(),
                self._standalone_pickle_scanner.options.max_unbounded_stream_read_bytes,
            )
            if self.max_file_read_size and self.max_file_read_size > 0:
                limit = min(limit, self.max_file_read_size)
        if limit <= 0:
            return _RootStreamPayloadRead(payload=b"", truncated=False, read_limit=0)

        read_target = limit if file_size is None else min(file_size, limit)
        if read_target <= 0:
            return _RootStreamPayloadRead(payload=b"", truncated=False, read_limit=limit)

        payload = self._read_stream_bytes(file_obj, read_target)
        truncated = file_size is not None and file_size > read_target and len(payload) >= read_target
        if file_size is None and len(payload) >= read_target:
            truncated = True
        return _RootStreamPayloadRead(
            payload=payload,
            truncated=truncated,
            read_limit=limit,
        )

    @staticmethod
    def _raw_window_from_payload(payload: bytes, configured_limit: int) -> bytes:
        if configured_limit <= 0:
            return b""
        return payload[:configured_limit]

    def _add_stream_integrity_check(self, payload: bytes, result: ScanResult, source: str) -> None:
        sha256 = hashlib.sha256(payload).hexdigest()
        result.metadata.setdefault("file_hashes", {})["sha256"] = sha256
        result.add_check(
            name="File Integrity Check",
            passed=True,
            message="Stream SHA256 hash calculated",
            location=source,
            details={"sha256": sha256, "bytes_hashed": len(payload)},
        )

    def _add_seekable_stream_integrity_check(
        self,
        file_obj: BinaryIO,
        result: ScanResult,
        source: str,
        start_position: int,
        file_size: int | None,
    ) -> None:
        hasher = hashlib.sha256()
        bytes_hashed = 0
        remaining = file_size if file_size is not None and file_size >= 0 else None
        hash_complete = False
        try:
            file_obj.seek(start_position)
            while remaining is None or remaining > 0:
                self.check_interrupted()
                if self._check_timeout(allow_partial=True):
                    break
                read_size = _RAW_READ_CHUNK_BYTES if remaining is None else min(_RAW_READ_CHUNK_BYTES, remaining)
                chunk = file_obj.read(read_size)
                if not chunk:
                    hash_complete = True
                    break
                hasher.update(chunk)
                bytes_hashed += len(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
            if remaining == 0:
                hash_complete = True
        except (AttributeError, OSError, ValueError):
            return
        finally:
            with suppress(AttributeError, OSError, ValueError):
                file_obj.seek(start_position)

        sha256 = hasher.hexdigest()
        result.metadata.setdefault("file_hashes", {})["sha256"] = sha256
        result.add_check(
            name="File Integrity Check",
            passed=True,
            message="Stream SHA256 hash calculated",
            location=source,
            details={
                "sha256": sha256,
                "bytes_hashed": bytes_hashed,
                "hash_complete": hash_complete,
            },
        )

    def _add_stream_truncation_check(
        self,
        read_result: _RootStreamPayloadRead,
        result: ScanResult,
        source: str,
        declared_size: int | None,
    ) -> None:
        if not read_result.truncated:
            return

        result.metadata["pickle_stream_truncated_for_root_scan"] = True
        result.metadata["pickle_stream_root_scan_read_limit"] = read_result.read_limit
        result.metadata["pickle_stream_bytes_buffered"] = len(read_result.payload)
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        scan_outcome_reasons = result.metadata.setdefault("scan_outcome_reasons", [])
        if isinstance(scan_outcome_reasons, list) and "non_seekable_stream_truncated" not in scan_outcome_reasons:
            scan_outcome_reasons.append("non_seekable_stream_truncated")
        if declared_size is not None:
            result.metadata["pickle_stream_declared_size"] = declared_size
        result.add_check(
            name="Pickle Stream Read Limit",
            passed=False,
            message="Non-seekable pickle stream exceeded the bounded root scan read limit",
            severity=IssueSeverity.WARNING,
            location=source,
            details={
                "source": "pickle_stream_buffer",
                "bytes_buffered": len(read_result.payload),
                "declared_size": declared_size,
                "read_limit": read_result.read_limit,
                "analysis_incomplete": True,
            },
            rule_code="S902",
        )
        result.finish(success=False)

    def _run_root_raw_detectors(
        self,
        data: bytes,
        result: ScanResult,
        source: str,
        *,
        skip_expensive_detectors: bool = False,
        scan_binary_tail: bool = True,
    ) -> None:
        """Run non-pickle-specific ModelAudit detectors over a bounded raw window."""
        if not data:
            return

        lower_data = data.lower()
        present_bytes = frozenset(lower_data)

        self._scan_raw_text_indicators(data, result, source, lower_data=lower_data, present_bytes=present_bytes)
        self._scan_encoded_text_indicators(data, result, source)
        self._analyze_cve_patterns(data, result, source, lower_data=lower_data, present_bytes=present_bytes)
        if scan_binary_tail:
            self._scan_binary_tail_if_needed(data, result, source)
        if skip_expensive_detectors:
            result.metadata["pickle_expensive_raw_detectors_skipped"] = True
            result.metadata["pickle_expensive_raw_detector_skip_reason"] = "rust_complete_clean_no_expensive_raw_seeds"
            if self.config.get("check_network_comm", True):
                result.add_check(
                    name="Network Communication Detection",
                    passed=True,
                    message="No network communication patterns detected",
                    location=source,
                )
            return

        expensive_limit = self._root_expensive_raw_scan_limit()
        if expensive_limit <= 0:
            result.metadata["pickle_expensive_raw_detectors_skipped"] = True
            result.metadata["pickle_expensive_raw_detector_skip_reason"] = "disabled"
            return
        expensive_data = data[:expensive_limit]
        if len(expensive_data) == len(data):
            expensive_lower = lower_data
            expensive_present_bytes = present_bytes
        else:
            expensive_lower = expensive_data.lower()
            expensive_present_bytes = frozenset(expensive_lower)
        if len(expensive_data) < len(data):
            result.metadata["pickle_expensive_raw_detector_bytes_scanned"] = len(expensive_data)
            result.metadata["pickle_expensive_raw_detector_bytes_available"] = len(data)

        if _contains_any_seed_lowered(
            expensive_lower,
            _SECRET_SCAN_SEEDS,
            expensive_present_bytes,
        ) or _has_alnum_secret_shape(expensive_data, expensive_lower, expensive_present_bytes):
            self.check_for_embedded_secrets(expensive_data, result, source)
        else:
            result.metadata["pickle_secrets_raw_detector_skipped"] = True

        if _contains_any_seed_lowered(expensive_lower, _JIT_SCAN_SEEDS, expensive_present_bytes):
            self.check_for_jit_script_code(expensive_data, result, model_type="pickle", context=source)
        else:
            result.metadata["pickle_jit_raw_detector_skipped"] = True

        if _contains_any_seed_lowered(expensive_lower, _NETWORK_SCAN_SEEDS, expensive_present_bytes) or (
            _has_domain_or_ip_shape(expensive_data)
        ):
            self.check_for_network_communication(expensive_data, result, context=source)
        else:
            result.metadata["pickle_network_raw_detector_skipped"] = True

    def _scan_binary_tail_if_needed(self, data: bytes, result: ScanResult, source: str) -> None:
        if Path(source).suffix.lower() not in _PYTORCH_CONTAINER_EXTENSIONS:
            return
        tail_start = self._binary_tail_start(result)
        if tail_start is None:
            return
        tail = data[tail_start : tail_start + _BINARY_TAIL_SCAN_BYTES]
        self._scan_binary_tail_window(tail, result, source, tail_start)
        self._mark_binary_tail_window_incomplete_if_needed(
            result,
            source,
            tail_start=tail_start,
            scanned_tail_bytes=len(tail),
            total_tail_bytes=max(len(data) - tail_start, 0),
        )

    def _scan_file_binary_tail_if_needed(self, path: str, file_size: int, result: ScanResult) -> None:
        if Path(path).suffix.lower() not in _PYTORCH_CONTAINER_EXTENSIONS:
            return
        tail_start = self._binary_tail_start(result)
        if tail_start is None or tail_start >= file_size:
            return

        tail = self._read_file_binary_tail_window(path, tail_start, file_size)
        self._scan_binary_tail_window(tail, result, path, tail_start)
        self._mark_binary_tail_window_incomplete_if_needed(
            result,
            path,
            tail_start=tail_start,
            scanned_tail_bytes=len(tail),
            total_tail_bytes=file_size - tail_start,
        )

    def _scan_seekable_stream_binary_tail_if_needed(
        self,
        file_obj: BinaryIO,
        start_position: int,
        file_size: int | None,
        result: ScanResult,
        source: str,
    ) -> None:
        if Path(source).suffix.lower() not in _PYTORCH_CONTAINER_EXTENSIONS:
            return
        tail_start = self._binary_tail_start(result)
        if tail_start is None:
            return
        local_tail_start = tail_start - start_position if tail_start >= start_position else tail_start
        if file_size is not None and local_tail_start >= file_size:
            return
        remaining = (
            _BINARY_TAIL_SCAN_BYTES if file_size is None else min(_BINARY_TAIL_SCAN_BYTES, file_size - local_tail_start)
        )
        if remaining <= 0:
            return
        absolute_tail_start = start_position + local_tail_start
        chunks: list[bytes] = []
        unknown_tail_exceeds_window = False
        incomplete_reason: str | None = None
        stream_error: Exception | None = None
        rewind_error: Exception | None = None
        try:
            file_obj.seek(absolute_tail_start)
            while remaining > 0:
                self.check_interrupted()
                if self._check_timeout(allow_partial=True):
                    incomplete_reason = "pickle_binary_tail_scan_timeout"
                    break
                chunk = file_obj.read(min(_RAW_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if file_size is None and remaining == 0:
                unknown_tail_exceeds_window = True
                with suppress(AttributeError, OSError, ValueError):
                    unknown_tail_exceeds_window = bool(file_obj.read(1))
        except (AttributeError, OSError, ValueError) as error:
            stream_error = error
        finally:
            try:
                file_obj.seek(start_position)
            except (AttributeError, OSError, ValueError) as error:
                rewind_error = error
        if stream_error is not None or rewind_error is not None:
            coverage_error = stream_error if stream_error is not None else rewind_error
            assert coverage_error is not None
            self._record_stream_coverage_failure(result, source, coverage_error)
            return
        self._scan_binary_tail_window(b"".join(chunks), result, source, absolute_tail_start)
        total_tail_bytes = None if file_size is None else max(file_size - local_tail_start, 0)
        self._mark_binary_tail_window_incomplete_if_needed(
            result,
            source,
            tail_start=absolute_tail_start,
            scanned_tail_bytes=sum(len(chunk) for chunk in chunks),
            total_tail_bytes=total_tail_bytes,
            tail_window_exceeded=unknown_tail_exceeds_window,
            incomplete_reason=incomplete_reason,
        )

    @staticmethod
    def _binary_tail_start(result: ScanResult) -> int | None:
        first_pickle_end_pos = result.metadata.get("first_pickle_end_pos")
        if isinstance(first_pickle_end_pos, int) and first_pickle_end_pos > 0:
            return first_pickle_end_pos

        coverage = result.metadata.get("pickle_coverage")
        if isinstance(coverage, dict):
            bytes_scanned = coverage.get("bytes_scanned")
            if isinstance(bytes_scanned, int) and bytes_scanned > 0:
                return max(bytes_scanned - _BINARY_TAIL_SIGNATURE_BACKTRACK_BYTES, 0)
        return None

    def _read_file_binary_tail_window(self, path: str, tail_start: int, file_size: int) -> bytes:
        remaining = min(_BINARY_TAIL_SCAN_BYTES, max(file_size - tail_start, 0))
        chunks: list[bytes] = []
        with open(path, "rb") as handle:
            handle.seek(tail_start)
            while remaining > 0:
                self.check_interrupted()
                if self._check_timeout(allow_partial=True):
                    break
                chunk = handle.read(min(_RAW_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        return b"".join(chunks)

    def _mark_binary_tail_window_incomplete_if_needed(
        self,
        result: ScanResult,
        source: str,
        *,
        tail_start: int,
        scanned_tail_bytes: int,
        total_tail_bytes: int | None,
        tail_window_exceeded: bool = False,
        incomplete_reason: str | None = None,
    ) -> None:
        if (
            incomplete_reason is None
            and not tail_window_exceeded
            and (total_tail_bytes is None or total_tail_bytes <= scanned_tail_bytes)
        ):
            return

        reason = incomplete_reason or "pickle_binary_tail_scan_window_exceeded"
        message = (
            "Pickle binary-tail analysis timed out before the bounded scan window was completed"
            if reason == "pickle_binary_tail_scan_timeout"
            else (
                "Pickle binary-tail analysis exceeded the bounded scan window; "
                "bytes after the inspected window were not analyzed"
            )
        )
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name="Pickle Binary Tail Coverage",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=source,
            details={
                "tail_scan_start": tail_start,
                "tail_bytes_scanned": scanned_tail_bytes,
                "tail_bytes_total": total_tail_bytes,
                "tail_scan_limit_bytes": _BINARY_TAIL_SCAN_BYTES,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
                "timed_out": reason == "pickle_binary_tail_scan_timeout",
            },
            rule_code="S902",
        )

    def _scan_binary_tail_window(self, tail: bytes, result: ScanResult, source: str, tail_start: int) -> None:
        if not tail:
            return
        lower_tail = tail.lower()
        for signature, label, rule_code in _BINARY_TAIL_SIGNATURES:
            haystack = lower_tail if signature.isascii() else tail
            needle = signature.lower() if signature.isascii() else signature
            offset = haystack.find(needle)
            if offset < 0:
                continue
            if signature == b"MZ" and not _looks_like_portable_executable(tail[offset : offset + 1024]):
                continue
            absolute_offset = tail_start + offset
            result.add_check(
                name="Pickle Binary Tail Detection",
                passed=False,
                message=f"Suspicious binary tail after pickle stream: {label}",
                severity=IssueSeverity.CRITICAL,
                location=f"{source} (pos {absolute_offset})",
                details={
                    "source": "pickle_binary_tail",
                    "pattern": label,
                    "offset": absolute_offset,
                    "tail_scan_start": tail_start,
                },
                rule_code=rule_code,
            )

    def _add_root_legacy_metadata_detectors(self, result: ScanResult, source: str) -> None:
        references = result.metadata.get("import_references")
        if not isinstance(references, list):
            return

        for reference in references:
            if not isinstance(reference, dict):
                continue
            import_reference = reference.get("import_reference")
            if not isinstance(import_reference, str):
                continue

            location = source
            position = reference.get("position")
            if isinstance(position, int):
                location = f"{source} (pos {position})"

            module = reference.get("module")
            name = reference.get("name")
            opcode = reference.get("opcode")
            if (
                opcode == "GLOBAL"
                and name == "__dict__"
                and not bool(reference.get("is_dangerous"))
                and not _has_rule_for_import_reference(result, "S206", import_reference)
            ):
                result.add_check(
                    name="Pickle Import Reference Safety Check",
                    passed=False,
                    message=f"Suspicious import-only reference {import_reference}",
                    severity=IssueSeverity.WARNING,
                    location=location,
                    details={
                        "source": "root_legacy_pickle_metadata",
                        "associated_global": import_reference,
                        **reference,
                    },
                    rule_code="S206",
                )

            if (
                module == "__main__"
                and not bool(reference.get("is_dangerous"))
                and not _has_rule_for_import_reference(result, "S207", import_reference)
                and not _has_issue_for_import_reference(result, import_reference)
            ):
                result.add_check(
                    name="Pickle BUILD State Safety Check",
                    passed=False,
                    message=f"Detected potential __setstate__ exploitation via BUILD with {import_reference}",
                    severity=IssueSeverity.WARNING,
                    location=location,
                    details={
                        "source": "root_legacy_pickle_metadata",
                        "associated_global": import_reference,
                        **reference,
                    },
                    rule_code="S207",
                )

    def _scan_raw_text_indicators(
        self,
        data: bytes,
        result: ScanResult,
        source: str,
        *,
        lower_data: bytes | None = None,
        present_bytes: frozenset[int] | None = None,
    ) -> None:
        lower = data.lower() if lower_data is None else lower_data
        if present_bytes is None:
            present_bytes = frozenset(lower)
        if not _has_raw_text_indicator_shape(
            data,
            lower,
            rust_clean=self._rust_scan_completed_cleanly(result),
            present_bytes=present_bytes,
        ):
            result.metadata["pickle_raw_text_detector_skipped"] = True
            return
        documentation_spans = _documentation_literal_spans(data)
        indicators: list[tuple[str, dict[str, Any]]] = []
        warning_indicators: list[tuple[str, dict[str, Any]]] = []
        if _contains_non_documentation_token(lower, b"import os", documentation_spans):
            _append_raw_indicator(warning_indicators, "import os", "os")
        if _contains_non_documentation_token(lower, b"importlib.import_module", documentation_spans) or (
            _contains_non_documentation_token(lower, b"import importlib", documentation_spans)
            and _contains_non_documentation_token(lower, b"import_module", documentation_spans)
        ):
            _append_raw_indicator(indicators, "importlib.import_module")
        elif _contains_non_documentation_token(lower, b"importlib", documentation_spans):
            importlib_method_added = False
            for method in _RAW_IMPORTLIB_METHODS:
                if _contains_non_documentation_token(
                    lower,
                    method,
                    documentation_spans,
                ) and _contains_non_documentation_token(lower, b"importlib", documentation_spans):
                    label = f"importlib.{method.decode('ascii')}"
                    _append_raw_indicator(indicators, label)
                    importlib_method_added = True
                    break
            if (
                not importlib_method_added
                and _contains_non_documentation_token(lower, b"importlib", documentation_spans)
                and _contains_non_documentation_token(lower, b"import ", documentation_spans)
            ):
                _append_raw_indicator(indicators, "importlib")
        if _raw_call_token_should_report(data, lower, b"eval", documentation_spans):
            _append_raw_indicator(indicators, "eval", "builtins.eval")
        if _raw_call_token_should_report(data, lower, b"exec", documentation_spans):
            _append_raw_indicator(indicators, "exec", "builtins.exec")
        if _contains_module_attr(lower, b"webbrowser", b"open", documentation_spans):
            _append_raw_indicator(indicators, "webbrowser.open")
        elif _contains_non_documentation_token(lower, b"webbrowser", documentation_spans):
            for method in _RAW_WEBBROWSER_METHODS:
                if _contains_non_documentation_token(
                    lower,
                    method,
                    documentation_spans,
                ) and _contains_non_documentation_token(lower, b"webbrowser", documentation_spans):
                    label = f"webbrowser.{method.decode('ascii')}"
                    _append_raw_indicator(indicators, label)
                    break
        if _contains_non_documentation_token(lower, b"runpy", documentation_spans):
            runpy_global = (
                "runpy.run_module"
                if _contains_non_documentation_token(lower, b"run_module", documentation_spans)
                else "runpy"
            )
            _append_raw_indicator(indicators, runpy_global)
        if _contains_non_documentation_token(lower, b"__import__", documentation_spans):
            _append_raw_indicator(indicators, "__import__", "builtins.__import__")
        for module_token, attr_token, associated_global in _RAW_PICKLE_GLOBAL_REFERENCES:
            if _contains_pickle_global_reference(lower, module_token, attr_token, documentation_spans):
                _append_raw_indicator(indicators, associated_global)
        for module_token, attr_token, associated_global in _RAW_TEXT_MODULE_ATTR_INDICATORS:
            if _contains_module_attr(lower, module_token, attr_token, documentation_spans):
                _append_raw_indicator(indicators, associated_global)
        for pattern, label, associated_global in _RAW_TEXT_REGEX_INDICATORS:
            if _contains_non_documentation_pattern(lower, pattern, documentation_spans):
                _append_raw_indicator(indicators, label, associated_global)
        for token, label, associated_global in _RAW_TEXT_TOKEN_INDICATORS:
            if _contains_non_documentation_token(lower, token, documentation_spans):
                _append_raw_indicator(indicators, label, associated_global)

        for label, details in indicators:
            if label in {"eval", "exec"}:
                result.add_check(
                    name="Pickle Raw Content Detection",
                    passed=False,
                    message=f"Legacy dangerous pattern detected: {label}(",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={"pattern": f"{label}(", "source": "bounded_raw_pickle_window", **details},
                    rule_code="S104",
                )
                continue
            if label == "__import__":
                result.add_check(
                    name="Pickle Raw Content Detection",
                    passed=False,
                    message="Legacy dangerous pattern detected: __import__",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={"pattern": "__import__", "source": "bounded_raw_pickle_window", **details},
                    rule_code="S106",
                )
                continue
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message=f"Raw pickle content references dangerous helper: {label}",
                severity=IssueSeverity.CRITICAL,
                location=source,
                details={"pattern": label, "source": "bounded_raw_pickle_window", **details},
                rule_code="S201",
            )

        for label, details in warning_indicators:
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message=f"Legacy dangerous pattern detected: {label}",
                severity=IssueSeverity.WARNING,
                location=source,
                details={"pattern": label, "source": "bounded_raw_pickle_window", **details},
                rule_code="S101",
            )

        for symbol, position in _copyreg_extension_reduce_references(data):
            result.add_check(
                name="Pickle Extension REDUCE Detection",
                passed=False,
                message=f"Found REDUCE opcode invoking dangerous global: {symbol}",
                severity=IssueSeverity.CRITICAL,
                location=f"{source} (pos {position})",
                details={
                    "associated_global": symbol,
                    "source": "bounded_raw_pickle_window",
                    "position": position,
                },
                rule_code="S201",
            )

    def _scan_encoded_text_indicators(self, data: bytes, result: ScanResult, source: str) -> None:
        seen_tokens: set[bytes] = set()
        decoded_budget = _MAX_RAW_ENCODED_BYTES
        token_count = 0

        for match in _BASE64_TOKEN_RE.finditer(data):
            if token_count >= _MAX_RAW_ENCODED_TOKENS or decoded_budget <= 0:
                return

            token = match.group(0)
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            token_count += 1
            if len(token) > _MAX_RAW_ENCODED_TOKEN_WITHOUT_SEED_BYTES and not any(
                seed in token for seed in _BASE64_CODE_EXECUTION_SEEDS
            ):
                continue

            padded_token = token + (b"=" * ((4 - (len(token) % 4)) % 4))
            try:
                decoded = base64.b64decode(padded_token, validate=True)
            except (binascii.Error, ValueError):
                continue

            if not decoded or len(decoded) > decoded_budget:
                continue
            decoded_budget -= len(decoded)
            decoded_lower = decoded.lower()
            for pattern, label in _ENCODED_CODE_EXECUTION_PATTERNS:
                if pattern not in decoded_lower:
                    continue
                result.add_check(
                    name="Encoded Code Execution Pattern Detection",
                    passed=False,
                    message=f"Encoded pickle content decodes to dangerous code pattern: {label}",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={
                        "encoding": "base64",
                        "pattern": label,
                        "source": "bounded_raw_pickle_window",
                        "decoded_size": len(decoded),
                        "legacy_rule_aliases": ["S104"],
                    },
                    rule_code="S604",
                )
                return

        for match in _HEX_TOKEN_RE.finditer(data):
            if token_count >= _MAX_RAW_ENCODED_TOKENS or decoded_budget <= 0:
                return

            token = match.group(0)
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            token_count += 1
            if len(token) > _MAX_RAW_ENCODED_TOKEN_WITHOUT_SEED_BYTES and not _hex_token_has_execution_seed(token):
                continue

            if len(token) % 2 != 0:
                continue
            try:
                decoded = binascii.unhexlify(token)
            except (binascii.Error, ValueError):
                continue

            if not decoded or len(decoded) > decoded_budget:
                continue
            decoded_budget -= len(decoded)
            decoded_lower = decoded.lower()
            for pattern, label in _ENCODED_CODE_EXECUTION_PATTERNS:
                if pattern not in decoded_lower:
                    continue
                result.add_check(
                    name="Encoded Code Execution Pattern Detection",
                    passed=False,
                    message=f"Encoded Python code detected in pickle content: {label}",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={
                        "encoding": "hex",
                        "pattern": label,
                        "source": "bounded_raw_pickle_window",
                        "decoded_size": len(decoded),
                        "legacy_rule_aliases": ["S104"],
                    },
                    rule_code="S604",
                )
                return

    def _analyze_cve_patterns(
        self,
        data: bytes,
        result: ScanResult,
        source: str | None = None,
        *,
        lower_data: bytes | None = None,
        present_bytes: frozenset[int] | None = None,
    ) -> None:
        """Add CVE attribution checks from a bounded raw pickle scan window."""
        opcode_counts = _result_opcode_counts(result)
        has_setitem_opcode = opcode_counts.get("SETITEM", 0) > 0 or opcode_counts.get("SETITEMS", 0) > 0
        import_references = _result_import_references(result)
        has_dangerous_system_global = any(
            reference.get("import_reference") in {"os.system", "posix.system", "nt.system"}
            for reference in import_references
        )
        lower = data.lower() if lower_data is None else lower_data
        if present_bytes is None:
            present_bytes = frozenset(lower)
        if not _contains_any_seed_lowered(lower, _CVE_RAW_SCAN_SEEDS, present_bytes) and not (
            has_setitem_opcode and has_dangerous_system_global
        ):
            result.metadata["pickle_cve_raw_detector_skipped"] = True
            return

        try:
            from modelaudit.detectors.cve_patterns import analyze_cve_patterns
        except ImportError:
            return

        text = lower.decode("utf-8", errors="ignore")
        try:
            attributions = analyze_cve_patterns(text, data)
        except Exception as error:
            logger.warning("Error checking pickle CVE patterns: %s", error)
            return

        has_rebuild_tensor_setitem_abuse = (
            _pickle_has_rebuild_tensor_setitem_abuse(data) if has_setitem_opcode else False
        )
        has_rebuild_tensor_literal = _pickle_has_parsed_rebuild_tensor_literal(data) if has_setitem_opcode else False
        has_cve_2026_setitem_evidence = has_rebuild_tensor_setitem_abuse or has_rebuild_tensor_literal
        has_dangerous_system_setitem_abuse = (
            _pickle_has_dangerous_system_setitem_abuse(data)
            if has_setitem_opcode and has_dangerous_system_global
            else False
        )

        if (
            has_cve_2026_setitem_evidence
            and has_setitem_opcode
            and not any(attribution.cve_id == "CVE-2026-24747" for attribution in attributions)
        ):
            from modelaudit.detectors.cve_patterns import CVEAttribution

            attributions.append(
                CVEAttribution(
                    cve_id="CVE-2026-24747",
                    description="PyTorch weights_only restricted unpickler SETITEM abuse pattern",
                    severity="CRITICAL",
                    cvss=9.8,
                    cwe="CWE-502",
                    affected_versions="PyTorch versions before the fixed release",
                    remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                    patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
                )
            )

        pickle_parse_failed = _result_parse_was_incomplete(result)
        attributions = self._dedupe_cve_attributions(
            [
                attribution
                for attribution in attributions
                if not (
                    attribution.cve_id == "CVE-2026-24747"
                    and (
                        (not has_setitem_opcode and not pickle_parse_failed)
                        or (not has_cve_2026_setitem_evidence and not pickle_parse_failed)
                        or (
                            not has_cve_2026_setitem_evidence
                            and _rebuild_tensor_indicators_are_documentation_literals(data)
                        )
                    )
                )
            ]
        )

        emitted_cve_rule_keys: set[tuple[str, str]] = set()
        if has_setitem_opcode and has_dangerous_system_setitem_abuse:
            emitted_cve_rule_keys.add(("CVE-2026-24747", "S209"))
            result.add_check(
                name="CVE-2026-24747 SETITEM Abuse Detection",
                passed=False,
                message="CVE-2026-24747: SETITEM occurs near dangerous global os.system",
                severity=IssueSeverity.CRITICAL,
                location=source or self.current_file_path,
                details={
                    "cve_id": "CVE-2026-24747",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": "PyTorch weights_only restricted unpickler SETITEM abuse pattern",
                    "remediation": "Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                    "cve_risk_score": 9.8,
                    "pattern_type": "setitem_near_dangerous_global",
                    "associated_global": "os.system",
                    "analysis": "bounded_raw_pickle_window",
                },
                rule_code="S209",
            )

        if not attributions:
            return

        result.metadata["cve_attributions"] = [attribution.to_dict() for attribution in attributions]
        result.metadata["cve_count"] = len(attributions)
        result.metadata["primary_cve"] = max(attributions, key=lambda item: item.cvss).cve_id

        for attribution in attributions:
            rule_code = self._rule_code_for_cve_attribution(attribution.patterns_matched)
            cve_rule_key = (attribution.cve_id, rule_code)
            if cve_rule_key in emitted_cve_rule_keys:
                continue
            emitted_cve_rule_keys.add(cve_rule_key)
            severity = (
                IssueSeverity.CRITICAL
                if attribution.severity.upper() in {"CRITICAL", "HIGH"}
                else IssueSeverity.WARNING
            )
            result.add_check(
                name=f"{attribution.cve_id} Pattern Detection",
                passed=False,
                message=f"{attribution.cve_id}: {attribution.description}",
                severity=severity,
                location=source or self.current_file_path,
                details={**attribution.to_dict(), "cve_risk_score": attribution.cvss},
                rule_code=rule_code,
            )

    @staticmethod
    def _rule_code_for_cve_attribution(patterns_matched: list[str]) -> str:
        joined = " ".join(patterns_matched).lower()
        if "setitem" in joined:
            return "S209"
        if "eval" in joined or "exec" in joined:
            return "S104"
        if "compile" in joined:
            return "S105"
        if "__import__" in joined:
            return "S106"
        if "subprocess" in joined:
            return "S103"
        if "os.system" in joined or "system" in joined:
            return "S101"
        if "newobj_ex" in joined:
            return "S204"
        if "stack_global" in joined:
            return "S205"
        if "global" in joined:
            return "S206"
        if "build" in joined:
            return "S207"
        return "S115"

    def _dedupe_cve_attributions(self, attributions: list[Any]) -> list[Any]:
        deduped: list[Any] = []
        seen_rule_keys: set[tuple[str, str]] = set()
        for attribution in attributions:
            rule_code = self._rule_code_for_cve_attribution(attribution.patterns_matched)
            cve_rule_key = (attribution.cve_id, rule_code)
            if cve_rule_key in seen_rule_keys:
                continue
            seen_rule_keys.add(cve_rule_key)
            deduped.append(attribution)
        return deduped

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        metadata = super().extract_metadata(file_path)
        metadata["deserialization_skipped"] = True
        metadata["safe_loading"] = False
        metadata["reason"] = "pickle metadata is extracted without deserializing payloads"

        file_size = self.get_file_size(file_path)
        configured_limit = self.config.get("max_metadata_pickle_read_size", _NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)
        read_limit, limit_error = _metadata_pickle_read_limit(configured_limit)
        if read_limit is None:
            metadata["extraction_error"] = limit_error
            return metadata
        if file_size > read_limit:
            metadata["extraction_error"] = f"pickle metadata read limit exceeded: {file_size} > {read_limit}"
            return metadata

        try:
            with open(file_path, "rb") as handle:
                payload = handle.read(read_limit)
        except OSError as error:
            metadata["extraction_error"] = str(error)
            return metadata

        metadata["pickle_size"] = len(payload)
        opcode_summary = _pickle_opcode_summary(payload)
        metadata.update(opcode_summary)
        return metadata

    def scan_stream(self, file_obj: BinaryIO, file_size: int | None, source: str = "<stream>") -> ScanResult:
        """Scan pickle bytes from an already-open stream."""
        self._prepare_scan_context(source)
        size_check = self._check_scan_stream_size_limit(file_size, source)
        if size_check:
            return size_check
        standalone_size = file_size if file_size is not None and file_size >= 0 else None
        stream_is_seekable = _stream_is_seekable(file_obj)
        start_position: int | None = None
        if stream_is_seekable:
            try:
                start_position = file_obj.tell()
            except (AttributeError, OSError, ValueError) as error:
                return self._stream_position_error_result(source, error)
            result = self._scan_standalone_stream(file_obj, standalone_size, source=source)
            if result.metadata.get("operational_error"):
                return result
            try:
                file_obj.seek(start_position)
            except (AttributeError, OSError, ValueError) as error:
                reason = "stream_rewind_failed"
                self._mark_operational_incomplete(result, reason)
                result.add_check(
                    name="Pickle Stream Position",
                    passed=False,
                    message=f"Error rewinding pickle stream after native scan: {error!s}",
                    severity=IssueSeverity.INFO,
                    location=source,
                    details={
                        "category": reason,
                        "exception": str(error),
                        "exception_type": type(error).__name__,
                        "operational_error": True,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": reason,
                    },
                    rule_code="S902",
                )
                result.finish(success=False)
                return result
            try:
                raw_data = self._read_root_raw_scan_window_from_stream(file_obj, standalone_size)
            except (AttributeError, OSError, ValueError) as error:
                self._record_stream_coverage_failure(result, source, error)
                return result
            self._add_seekable_stream_integrity_check(file_obj, result, source, start_position, standalone_size)
            binary_tail_payload: bytes | None = None
        else:
            try:
                stream_read = self._read_stream_payload_for_root(file_obj, standalone_size)
            except (AttributeError, OSError, ValueError) as error:
                return self._stream_read_error_result(source, error)
            payload = stream_read.payload
            rust_stream_size = len(payload) if stream_read.truncated else standalone_size
            result = self._scan_standalone_stream(io.BytesIO(payload), rust_stream_size, source=source)
            result.metadata["pickle_stream_bytes_buffered"] = len(payload)
            self._add_stream_integrity_check(payload, result, source)
            self._add_stream_truncation_check(stream_read, result, source, standalone_size)
            raw_data = self._raw_window_from_payload(payload, self._root_raw_scan_limit())
            binary_tail_payload = payload
        base_success = result.success
        self._run_root_raw_detectors(
            raw_data,
            result,
            source,
            skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, raw_data),
            scan_binary_tail=False,
        )
        if stream_is_seekable and start_position is not None:
            self._scan_seekable_stream_binary_tail_if_needed(file_obj, start_position, standalone_size, result, source)
        elif binary_tail_payload is not None:
            self._scan_binary_tail_if_needed(binary_tail_payload, result, source)
        self._add_root_legacy_metadata_detectors(result, source)
        self._finish_after_wrapper_analysis(result, base_success=base_success)
        return result

    def scan(self, path: str) -> ScanResult:
        """Scan a pickle file for suspicious content."""
        self._prepare_scan_context(path)

        path_check = self._check_path(path)
        if path_check:
            return path_check

        if Path(path).is_dir():
            result = self._create_result()
            if self._path_validation_result is not None:
                result.merge(self._path_validation_result)
            result.add_check(
                name="Pickle File Open",
                passed=False,
                message="Path is a directory, not a pickle file",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "category": "pickle_file_open_failed",
                    "exception_type": "IsADirectoryError",
                    "operational_error": True,
                },
            )
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "path_is_directory"
            result.finish(success=False)
            return result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        zip_result = self._scan_zip_backed_pytorch_container(path)
        if zip_result is not None:
            return zip_result

        file_size = self.get_file_size(path)
        result = self._create_result()
        result.metadata["file_size"] = file_size
        self.add_file_integrity_check(path, result)

        try:
            with open(path, "rb") as handle:
                scan_result = self._scan_standalone_stream(handle, file_size, source=path)
            result.merge(scan_result)
            raw_data = self._read_root_raw_scan_window(path, file_size)
            self._run_root_raw_detectors(
                raw_data,
                result,
                path,
                skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, raw_data),
                scan_binary_tail=False,
            )
            self._scan_file_binary_tail_if_needed(path, file_size, result)
        except OSError as error:
            self._record_file_read_failure(result, path, error)
            return result

        self._add_root_legacy_metadata_detectors(result, path)
        try:
            self._scan_jax_checkpoint_patterns_if_needed(path, file_size, raw_data, result)
        except OSError as error:
            self._record_file_read_failure(result, path, error)
            return result
        self._finish_after_wrapper_analysis(result, base_success=scan_result.success)
        return result

    def _scan_jax_checkpoint_patterns_if_needed(
        self,
        path: str,
        file_size: int,
        raw_data: bytes,
        result: ScanResult,
    ) -> None:
        if file_size <= len(raw_data) and file_size <= self._jax_pickle_scan_limit():
            lowered_raw_data = raw_data.lower()
            if not any(indicator in lowered_raw_data for indicator in _JAX_PICKLE_CONTEXT_INDICATORS):
                return

        from .jax_checkpoint_scanner import JaxCheckpointScanner

        jax_scanner = JaxCheckpointScanner(config=self.config)
        read_limit = min(file_size, jax_scanner.max_pickle_scan_bytes)
        with open(path, "rb") as handle:
            data = handle.read(read_limit + 1)

        decoded_text = data[: jax_scanner.max_pickle_scan_bytes].decode("utf-8", errors="ignore")
        jax_result = jax_scanner.scan_pickle_pattern_text(
            path,
            decoded_text,
        )
        if len(data) > jax_scanner.max_pickle_scan_bytes:
            mark_inconclusive_scan_result(result, "jax_pickle_scan_limit_exceeded")
            jax_result.add_check(
                name="Pickle Checkpoint Prefix Scan Limit",
                passed=False,
                message=(
                    f"Only the first {jax_scanner.max_pickle_scan_bytes} bytes of the pickle checkpoint were "
                    "inspected for opcode patterns"
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "max_pickle_scan_bytes": jax_scanner.max_pickle_scan_bytes,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_pickle_scan_limit_exceeded",
                },
                rule_code="S902",
            )
        result.merge(jax_result)

    def _jax_pickle_scan_limit(self) -> int:
        raw_value = self.config.get("jax_pickle_max_scan_bytes", _DEFAULT_JAX_PICKLE_SCAN_LIMIT_BYTES)
        try:
            parsed_value = int(raw_value)
        except (TypeError, ValueError):
            parsed_value = _DEFAULT_JAX_PICKLE_SCAN_LIMIT_BYTES
        return max(parsed_value, _MIN_JAX_PICKLE_SCAN_LIMIT_BYTES)
