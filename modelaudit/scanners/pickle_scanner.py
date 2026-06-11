"""Rust-backed scanner for Python pickle serialized files."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import pickletools
import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, TextIO, cast

from modelaudit_picklescan import PickleScanner as StandalonePickleScanner

from modelaudit.detectors.network_comm import redact_url_for_finding
from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_GLOBALS
from modelaudit.utils.helpers.code_validation import validate_python_syntax

from ..scanner_results import mark_inconclusive_scan_result
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult, logger
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
_MAX_CVE_PICKLE_STREAMS = 64
_CVE_PICKLE_STREAM_PADDING = frozenset(b"\x00\t\n\x0b\x0c\r ")
_PYTORCH_LEGACY_MAGIC_NUMBER = 0x1950A86A20F9469CFC6C
_PYTORCH_LEGACY_PROTOCOL_VERSION = 1001
_PYTORCH_LEGACY_STREAM_COUNT = 5
_PYTORCH_LEGACY_MAGIC_BINARY = _PYTORCH_LEGACY_MAGIC_NUMBER.to_bytes(10, "little")
_PYTORCH_LEGACY_MAGIC_DECIMAL = str(_PYTORCH_LEGACY_MAGIC_NUMBER).encode("ascii")
_PYTORCH_LEGACY_SYS_INFO_KEYS = frozenset({"protocol_version", "little_endian", "type_sizes"})
_PYTORCH_LEGACY_MAX_CONTROL_BYTES = 10 * 1024 * 1024
_PYTORCH_LEGACY_MAX_STORAGE_KEYS = 10_000
_PYTORCH_LEGACY_MAX_TRACKED_MEMO_ENTRIES = 100_000
_PYTORCH_LEGACY_MAX_STACK_DEPTH = 1024
_PYTORCH_LEGACY_MAX_CONTROL_OPCODES = 100_000
_PYTORCH_LEGACY_STORAGE_ELEMENT_SIZES = {
    "BFloat16Storage": 2,
    "BoolStorage": 1,
    "ByteStorage": 1,
    "CharStorage": 1,
    "ComplexDoubleStorage": 16,
    "ComplexFloatStorage": 8,
    "DoubleStorage": 8,
    "FloatStorage": 4,
    "HalfStorage": 2,
    "IntStorage": 4,
    "LongStorage": 8,
    "QInt32Storage": 4,
    "QInt8Storage": 1,
    "QUInt8Storage": 1,
    "QUInt4x2Storage": 1,
    "QUInt2x4Storage": 1,
    "ShortStorage": 2,
    "UntypedStorage": 1,
}
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
_PICKLE_LITERAL_URL_RE = re.compile(
    rb"(?i)https?://(?:[A-Za-z0-9\-._~:/?#[\]@!$&()*+,;=%-]|"
    rb"'(?=[A-Za-z0-9\-._~:/?#[\]@!$&*+,=%-]))+"
)
_PICKLE_LITERAL_URL_NETWORK_FUNCTION_TOKENS: tuple[bytes, ...] = (
    b"dns.resolver",
    b"ftp.connect",
    b"getaddrinfo",
    b"gethostbyaddr",
    b"gethostbyname",
    b"http.request",
    b"imap.login",
    b"mongo.connect",
    b"redis.connect",
    b"requests.delete",
    b"requests.get",
    b"requests.post",
    b"requests.put",
    b"smtp.connect",
    b"socket.connect",
    b"socket.create_connection",
    b"ssh.connect",
    b"telnet.open",
    b"urlopen",
    b"urlretrieve",
)
_EXECUTABLE_NETWORK_LITERAL_SEEDS: tuple[bytes, ...] = (
    b"__import__",
    b"cloudpickle.load",
    b"dill.load",
    b"download_file(",
    b"download_url_to_file",
    b"eval(",
    b"exec(",
    b"gethostbyname",
    b"getaddrinfo",
    b"hf_hub_download(",
    b"http.request",
    b"httpx.",
    b"aiohttp.",
    b"joblib.load",
    b"load_state_dict_from_url",
    b"os.popen",
    b"os.system",
    b"pickle.load",
    b"requests.",
    b"shell=true",
    b"socket.",
    b"snapshot_download(",
    b"subprocess",
    b"torch.hub.download_url_to_file",
    b"torch.hub.load",
    b"urllib.",
    b"urlopen",
    b"urlretrieve",
    b"yaml.load",
)
_EXECUTABLE_NETWORK_LITERAL_COMMAND_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9_./-])(?:bash|curl|nc|netcat|pwsh|powershell|sh|wget)(?:\.exe)?(?=$|[\s;&|'\")])"
)
_PYTHON_IDENTIFIER_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
_NETWORK_IMPORT_ALIAS_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9_.])import\s+"
    rb"(?P<module>requests|httpx|aiohttp|socket|urllib(?:\.request)?|http\.client)\s+as\s+"
    rb"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)"
)
_NETWORK_FROM_IMPORT_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9_.])from\s+"
    rb"(?P<module>requests|httpx|aiohttp|socket|urllib\.request|http\.client)\s+import\s+"
    rb"(?P<imports>[^;\r\n]+)"
)
_NETWORK_IMPORTABLE_MODULE_CALLS: dict[bytes, tuple[bytes, ...]] = {
    b"aiohttp": (b"delete", b"get", b"head", b"options", b"patch", b"post", b"put", b"request"),
    b"http.client": (b"connect", b"request", b"send"),
    b"httpx": (b"delete", b"get", b"head", b"options", b"patch", b"post", b"put", b"request", b"stream"),
    b"requests": (b"delete", b"get", b"head", b"options", b"patch", b"post", b"put", b"request", b"session"),
    b"socket": (b"connect", b"create_connection", b"getaddrinfo", b"gethostbyaddr", b"gethostbyname", b"socket"),
    b"urllib": (b"urlopen", b"urlretrieve"),
    b"urllib.request": (b"urlopen", b"urlretrieve"),
}
_EXECUTABLE_PICKLE_GLOBAL_FULL_NAMES = frozenset(
    {
        "huggingface_hub.hf_hub_download",
        "huggingface_hub.snapshot_download",
        "torch.hub.download_url_to_file",
        "torch.hub.load",
        "torch.hub.load_state_dict_from_url",
        "torch.utils.model_zoo.load_url",
    }
)
_EXECUTABLE_PICKLE_GLOBAL_MODULE_PREFIXES = (
    "aiohttp",
    "httpx",
    "urllib",
)
_EXECUTABLE_PICKLE_GLOBAL_NAMES = frozenset(
    {
        "download_file",
        "download_url_to_file",
        "hf_hub_download",
        "load_state_dict_from_url",
        "load_url",
        "snapshot_download",
        "urlopen",
        "urlretrieve",
    }
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
_PICKLE_LITERAL_RECORD_MAX_OPCODES = 250_000
_PICKLE_STRING_OPCODE_NAMES = frozenset(
    {
        "STRING",
        "UNICODE",
        "BINSTRING",
        "SHORT_BINSTRING",
        "BINUNICODE",
        "SHORT_BINUNICODE",
        "BINUNICODE8",
    }
)
_PYTORCH_LEGACY_SYS_INFO_OPCODES = frozenset(
    {
        "PROTO",
        "FRAME",
        "MARK",
        "STOP",
        "EMPTY_DICT",
        "DICT",
        "SETITEM",
        "SETITEMS",
        "PUT",
        "BINPUT",
        "LONG_BINPUT",
        "MEMOIZE",
        "INT",
        "BININT",
        "BININT1",
        "BININT2",
        "LONG",
        "LONG1",
        "LONG4",
        "NEWTRUE",
        "NEWFALSE",
        *_PICKLE_STRING_OPCODE_NAMES,
    }
)
_PYTORCH_LEGACY_STORAGE_KEY_OPCODES = frozenset(
    {
        "PROTO",
        "FRAME",
        "MARK",
        "STOP",
        "EMPTY_LIST",
        "LIST",
        "APPEND",
        "APPENDS",
        "PUT",
        "BINPUT",
        "LONG_BINPUT",
        "MEMOIZE",
        *_PICKLE_STRING_OPCODE_NAMES,
    }
)
_PICKLE_OPCODE_PREFIX_BYTES = frozenset(ord(opcode.code) for opcode in pickletools.opcodes)
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
_CVE_2026_24747_SYSTEM_RAW_SEEDS: tuple[bytes, ...] = (
    b"os.system",
    b"posix.system",
    b"nt.system",
    b"cos\nsystem\n",
    b"cposix\nsystem\n",
    b"cnt\nsystem\n",
)
_COPYREG_EXTENSION_OPCODES = (b"\x82", b"\x83", b"\x84")


@dataclass(frozen=True)
class _RootStreamPayloadRead:
    payload: bytes
    truncated: bool
    read_limit: int


@dataclass(frozen=True)
class _PickleCveStream:
    payload: bytes
    offset: int
    parse_incomplete: bool


@dataclass(frozen=True)
class _PickleLiteralRecord:
    start: int
    end: int
    literal: bytes
    executable_consumer: bool = False


@dataclass
class _PickleLiteralRecordBuilder:
    start: int
    end: int
    literal: bytes
    executable_consumer: bool = False


@dataclass(frozen=True)
class _PickleStackValue:
    text: str | None = None
    record_indexes: tuple[int, ...] = ()
    global_module: str | None = None
    global_name: str | None = None
    opaque_extension: bool = False


@dataclass(frozen=True)
class _LegacyPyTorchStorageRecord:
    key: str
    element_count: int
    element_size: int


@dataclass(frozen=True)
class _LegacyPickleGlobalRef:
    module: str
    name: str


@dataclass(frozen=True)
class _LegacyPyTorchStreamLayout:
    boundaries: tuple[tuple[int, int], ...]
    storage_keys: tuple[str, ...]
    storage_records: tuple[_LegacyPyTorchStorageRecord, ...] | None
    storage_end: int | None = None

    @property
    def pickle_end(self) -> int:
        return self.boundaries[-1][1]

    @property
    def storage_key_count(self) -> int:
        return len(self.storage_keys)


class _PositionedBytesIO(io.BytesIO):
    def __init__(self, payload: bytes, position_offset: int) -> None:
        super().__init__(payload)
        self._position_offset = max(position_offset, 0)

    def tell(self) -> int:
        return self._position_offset + super().tell()

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            offset -= self._position_offset
        return self._position_offset + super().seek(offset, whence)


class _NullTextWriter:
    def write(self, value: str) -> int:
        return len(value)


@dataclass(frozen=True)
class _PickleSetitemAnalysis:
    saw_setitem: bool
    confirmed_dangerous_target: bool
    suspicious_entry_on_unknown_target: bool
    parse_incomplete: bool

    @property
    def has_abuse(self) -> bool:
        return self.confirmed_dangerous_target or (self.parse_incomplete and self.suspicious_entry_on_unknown_target)


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
        return data[1] in {0, 1, 2, 3, 4, 5}

    # Pickles without an explicit PROTO may start with a scalar, string, global,
    # or container constructor. This is intentionally a sniff, not validation.
    return first in {
        ord("("),
        ord(")"),
        ord("B"),
        ord("C"),
        ord("F"),
        ord("G"),
        ord("I"),
        ord("J"),
        ord("K"),
        ord("L"),
        ord("M"),
        ord("N"),
        ord("S"),
        ord("T"),
        ord("U"),
        ord("V"),
        ord("X"),
        ord("]"),
        ord("c"),
        ord("d"),
        ord("i"),
        ord("l"),
        ord("t"),
        ord("}"),
        0x88,  # NEWTRUE
        0x89,  # NEWFALSE
        0x8A,  # LONG1
        0x8B,  # LONG4
        0x8C,  # SHORT_BINUNICODE
        0x8D,  # BINUNICODE8
        0x8E,  # BINBYTES8
        0x8F,  # EMPTY_SET
        0x91,  # FROZENSET
        0x96,  # BYTEARRAY8
    }


def _probe_pickle_stream(
    stream: io.BytesIO,
    offset: int = 0,
    *,
    max_opcodes: int | None = None,
) -> tuple[int | None, int, bool]:
    stream.seek(offset)
    parsed_opcode = False
    try:
        for opcode_index, (opcode, _arg, position) in enumerate(pickletools.genops(stream), start=1):
            if max_opcodes is not None and opcode_index > max_opcodes:
                return None, max(1, stream.tell() - offset), True
            parsed_opcode = True
            if opcode.name == "STOP":
                extent = None if position is None else position + 1 - offset
                return extent, max(1, stream.tell() - offset), parsed_opcode
    except Exception:
        pass
    return None, max(1, stream.tell() - offset), parsed_opcode


def _pickle_scalar_integer(data: bytes) -> int | None:
    value: int | None = None
    value_opcodes = frozenset({"INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4"})
    try:
        for opcode, arg, _position in pickletools.genops(data):
            if opcode.name in {"PROTO", "FRAME", "STOP"}:
                continue
            if (
                opcode.name not in value_opcodes
                or isinstance(arg, bool)
                or not isinstance(arg, int)
                or value is not None
            ):
                return None
            value = arg
    except Exception:
        return None
    return value


def _pickle_stack_is_valid(data: bytes) -> bool:
    try:
        pickletools.dis(data, out=cast(TextIO, _NullTextWriter()), annotate=0)
    except Exception:
        return False
    return True


def _matches_legacy_pytorch_sys_info(data: bytes) -> bool:
    keys: set[str] = set()
    try:
        for opcode_index, (opcode, arg, _position) in enumerate(pickletools.genops(data), start=1):
            if opcode_index > _PYTORCH_LEGACY_MAX_CONTROL_OPCODES:
                return False
            if opcode.name not in _PYTORCH_LEGACY_SYS_INFO_OPCODES:
                return False
            if opcode.name in _PICKLE_STRING_OPCODE_NAMES and isinstance(arg, str):
                keys.add(arg)
    except Exception:
        return False
    return keys >= _PYTORCH_LEGACY_SYS_INFO_KEYS and _pickle_stack_is_valid(data)


def _legacy_pytorch_storage_keys(data: bytes) -> tuple[str, ...] | None:
    marker = object()
    stack: list[object] = []
    try:
        for opcode_index, (opcode, arg, _position) in enumerate(pickletools.genops(data), start=1):
            if opcode_index > _PYTORCH_LEGACY_MAX_CONTROL_OPCODES:
                return None
            if opcode.name not in _PYTORCH_LEGACY_STORAGE_KEY_OPCODES:
                return None
            if opcode.name in {"PROTO", "FRAME", "PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"}:
                continue
            if opcode.name == "MARK":
                stack.append(marker)
            elif opcode.name == "EMPTY_LIST":
                stack.append([])
            elif opcode.name == "LIST":
                list_items: list[str] = []
                while stack and stack[-1] is not marker:
                    item = stack.pop()
                    if not isinstance(item, str):
                        return None
                    list_items.append(item)
                if not stack:
                    return None
                stack.pop()
                stack.append(list(reversed(list_items)))
            elif opcode.name in _PICKLE_STRING_OPCODE_NAMES:
                if not isinstance(arg, str):
                    return None
                stack.append(arg)
            elif opcode.name == "APPEND":
                if len(stack) < 2 or not isinstance(stack[-2], list) or not isinstance(stack[-1], str):
                    return None
                appended_value = cast(str, stack.pop())
                append_target = cast(list[object], stack[-1])
                append_target.append(appended_value)
            elif opcode.name == "APPENDS":
                appended_items: list[str] = []
                while stack and stack[-1] is not marker:
                    item = stack.pop()
                    if not isinstance(item, str):
                        return None
                    appended_items.append(item)
                if len(stack) < 2 or stack[-1] is not marker or not isinstance(stack[-2], list):
                    return None
                stack.pop()
                appends_target = cast(list[object], stack[-1])
                appends_target.extend(reversed(appended_items))
            elif opcode.name == "STOP":
                break
            if len(stack) > _PYTORCH_LEGACY_MAX_STORAGE_KEYS + 2:
                return None
    except Exception:
        return None

    if len(stack) != 1 or not isinstance(stack[0], list):
        return None
    keys = stack[0]
    if (
        len(keys) > _PYTORCH_LEGACY_MAX_STORAGE_KEYS
        or any(not isinstance(key, str) or not key.isascii() or not key.isdecimal() or len(key) > 128 for key in keys)
        or keys != sorted(set(keys))
    ):
        return None
    return tuple(keys) if _pickle_stack_is_valid(data) else None


def _legacy_pytorch_storage_records(
    data: bytes,
    storage_keys: tuple[str, ...],
) -> tuple[_LegacyPyTorchStorageRecord, ...] | None:
    marker = object()
    unknown = object()
    memo: dict[int, object] = {}
    stack: list[object] = []
    records: dict[str, _LegacyPyTorchStorageRecord] = {}
    expected_keys = set(storage_keys)

    def pop_marked_tuple() -> tuple[object, ...] | None:
        items: list[object] = []
        while stack:
            item = stack.pop()
            if item is marker:
                return tuple(reversed(items)) if len(items) <= 16 else None
            items.append(item)
        return None

    def memo_key(value: object) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            key = value
        elif isinstance(value, str):
            try:
                key = int(value)
            except ValueError:
                return None
        else:
            return None
        return key if key >= 0 else None

    def storage_record_from_pid(pid: object) -> tuple[bool, _LegacyPyTorchStorageRecord | None]:
        if not isinstance(pid, tuple) or not pid or pid[0] != "storage":
            return False, None
        if len(pid) != 6:
            return True, None
        storage_type = pid[1]
        key = pid[2]
        location = pid[3]
        element_count = pid[4]
        view_metadata = pid[5]
        valid_view_metadata = view_metadata is None or (
            isinstance(view_metadata, tuple)
            and len(view_metadata) == 3
            and isinstance(view_metadata[0], str)
            and view_metadata[0].isascii()
            and view_metadata[0].isdecimal()
            and len(view_metadata[0]) <= 128
            and not isinstance(view_metadata[1], bool)
            and isinstance(view_metadata[1], int)
            and view_metadata[1] >= 0
            and not isinstance(view_metadata[2], bool)
            and isinstance(view_metadata[2], int)
            and view_metadata[2] >= 0
        )
        if (
            not isinstance(storage_type, _LegacyPickleGlobalRef)
            or storage_type.module not in {"torch", "torch.storage"}
            or storage_type.name not in _PYTORCH_LEGACY_STORAGE_ELEMENT_SIZES
            or not isinstance(key, str)
            or key not in expected_keys
            or not key.isascii()
            or not key.isdecimal()
            or not isinstance(location, str)
            or not location
            or isinstance(element_count, bool)
            or not isinstance(element_count, int)
            or not 0 <= element_count <= (1 << 63) - 1
            or not valid_view_metadata
            or (
                isinstance(view_metadata, tuple)
                and (
                    not isinstance(element_count, int)
                    or view_metadata[1] > element_count
                    or view_metadata[2] > element_count - view_metadata[1]
                )
            )
        ):
            return True, None
        return (
            True,
            _LegacyPyTorchStorageRecord(
                key=key,
                element_count=element_count,
                element_size=_PYTORCH_LEGACY_STORAGE_ELEMENT_SIZES[storage_type.name],
            ),
        )

    try:
        for opcode_index, (opcode, arg, _position) in enumerate(pickletools.genops(data), start=1):
            if opcode_index > _PYTORCH_LEGACY_MAX_CONTROL_OPCODES:
                return None
            opcode_name = opcode.name
            if opcode_name in {"PROTO", "FRAME", "STOP"}:
                continue
            if opcode_name == "MARK":
                stack.append(marker)
            elif opcode_name in _PICKLE_STRING_OPCODE_NAMES:
                stack.append(arg if isinstance(arg, str) else unknown)
            elif opcode_name == "GLOBAL":
                if not isinstance(arg, str):
                    stack.append(unknown)
                else:
                    parts = arg.split()
                    stack.append(_LegacyPickleGlobalRef(parts[0], parts[1]) if len(parts) == 2 else unknown)
            elif opcode_name == "STACK_GLOBAL":
                if len(stack) < 2:
                    stack.clear()
                    continue
                name = stack.pop()
                module = stack.pop()
                stack.append(
                    _LegacyPickleGlobalRef(module, name)
                    if isinstance(module, str) and isinstance(name, str)
                    else unknown
                )
            elif opcode_name == "EMPTY_TUPLE":
                stack.append(())
            elif opcode_name == "TUPLE":
                tuple_value = pop_marked_tuple()
                if tuple_value is None:
                    stack.clear()
                else:
                    stack.append(tuple_value)
            elif opcode_name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
                tuple_size = int(opcode_name[-1])
                if len(stack) < tuple_size:
                    stack.clear()
                    continue
                items = stack[-tuple_size:]
                del stack[-tuple_size:]
                stack.append(tuple(items))
            elif opcode_name in {"BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "INT"}:
                stack.append(arg if isinstance(arg, int) and not isinstance(arg, bool) else unknown)
            elif opcode_name == "NONE":
                stack.append(None)
            elif opcode_name == "NEWTRUE":
                stack.append(True)
            elif opcode_name == "NEWFALSE":
                stack.append(False)
            elif opcode_name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                key = memo_key(arg)
                if key is not None:
                    if len(memo) >= _PYTORCH_LEGACY_MAX_TRACKED_MEMO_ENTRIES and key not in memo:
                        return None
                    memo[key] = stack[-1] if stack else unknown
            elif opcode_name == "MEMOIZE":
                if len(memo) >= _PYTORCH_LEGACY_MAX_TRACKED_MEMO_ENTRIES:
                    return None
                memo[len(memo)] = stack[-1] if stack else unknown
            elif opcode_name in {"BINGET", "LONG_BINGET", "GET"}:
                key = memo_key(arg)
                stack.append(memo.get(key, unknown) if key is not None else unknown)
            elif opcode_name == "POP":
                if stack:
                    stack.pop()
            elif opcode_name == "POP_MARK":
                pop_marked_tuple()
            elif opcode_name == "DUP":
                if stack:
                    stack.append(stack[-1])
            elif opcode_name == "PERSID":
                return None
            elif opcode_name == "BINPERSID":
                pid = stack.pop() if stack else unknown
                is_storage, record = storage_record_from_pid(pid)
                if not is_storage:
                    return None
                if is_storage:
                    if record is None or (record.key in records and records[record.key] != record):
                        return None
                    records[record.key] = record
                stack.append(unknown)
            else:
                stack.clear()

            if len(stack) > _PYTORCH_LEGACY_MAX_STACK_DEPTH:
                return None
    except Exception:
        return None

    if set(records) != expected_keys:
        return None
    if not _pickle_stack_is_valid(data):
        return None
    return tuple(records[key] for key in storage_keys)


def _might_be_legacy_pytorch(data: bytes) -> bool:
    prefix = data[:64]
    return _PYTORCH_LEGACY_MAGIC_BINARY in prefix or _PYTORCH_LEGACY_MAGIC_DECIMAL in prefix


def _matches_legacy_pytorch_preamble(data: bytes) -> bool:
    if not _might_be_legacy_pytorch(data):
        return False
    probe = io.BytesIO(data)
    offset = 0
    expected_values = (_PYTORCH_LEGACY_MAGIC_NUMBER, _PYTORCH_LEGACY_PROTOCOL_VERSION)
    for expected_value in expected_values:
        extent, _consumed, _parsed_opcode = _probe_pickle_stream(
            probe,
            offset,
            max_opcodes=_PYTORCH_LEGACY_MAX_CONTROL_OPCODES,
        )
        if extent is None:
            return False
        end = offset + extent
        if _pickle_scalar_integer(data[offset:end]) != expected_value:
            return False
        offset = end
    return True


def _legacy_pytorch_stream_layout(data: bytes) -> _LegacyPyTorchStreamLayout | None:
    if not _matches_legacy_pytorch_preamble(data):
        return None

    probe_data = data[:_PYTORCH_LEGACY_MAX_CONTROL_BYTES]
    probe = io.BytesIO(probe_data)
    boundaries: list[tuple[int, int]] = []
    offset = 0
    for _stream_index in range(_PYTORCH_LEGACY_STREAM_COUNT):
        extent, _consumed, _parsed_opcode = _probe_pickle_stream(
            probe,
            offset,
            max_opcodes=_PYTORCH_LEGACY_MAX_CONTROL_OPCODES,
        )
        if extent is None:
            return None
        end = offset + extent
        boundaries.append((offset, end))
        offset = end

        if len(boundaries) == 1 and _pickle_scalar_integer(probe_data[:end]) != _PYTORCH_LEGACY_MAGIC_NUMBER:
            return None
        if len(boundaries) == 2:
            start, _end = boundaries[-1]
            if _pickle_scalar_integer(probe_data[start:end]) != _PYTORCH_LEGACY_PROTOCOL_VERSION:
                return None

    sys_info_start, sys_info_end = boundaries[2]
    if not _matches_legacy_pytorch_sys_info(probe_data[sys_info_start:sys_info_end]):
        return None

    storage_keys_start, storage_keys_end = boundaries[4]
    storage_keys = _legacy_pytorch_storage_keys(probe_data[storage_keys_start:storage_keys_end])
    if storage_keys is None:
        return None

    object_start, object_end = boundaries[3]
    storage_records = _legacy_pytorch_storage_records(probe_data[object_start:object_end], storage_keys)
    return _LegacyPyTorchStreamLayout(tuple(boundaries), storage_keys, storage_records)


def _legacy_pytorch_storage_end(
    data: bytes,
    layout: _LegacyPyTorchStreamLayout,
    *,
    total_size: int | None,
    read_at: Callable[[int, int], bytes] | None,
) -> int | None:
    if layout.storage_records is None:
        return None

    def read_range(offset: int, size: int) -> bytes:
        end = offset + size
        if 0 <= offset <= end <= len(data):
            return data[offset:end]
        if read_at is None:
            return b""
        try:
            return read_at(offset, size)
        except (AttributeError, OSError, OverflowError, ValueError):
            return b""

    cursor = layout.pickle_end
    for record in layout.storage_records:
        header = read_range(cursor, 8)
        if len(header) != 8:
            return None
        expected_little = record.element_count.to_bytes(8, "little")
        expected_big = record.element_count.to_bytes(8, "big")
        if header not in {expected_little, expected_big}:
            return None
        cursor += 8 + (record.element_count * record.element_size)
        if total_size is not None and cursor > total_size:
            return None

    if total_size is None and layout.storage_records and (cursor <= 0 or len(read_range(cursor - 1, 1)) != 1):
        return None
    return cursor


def _legacy_pytorch_suffix_pickle_offset(data: bytes) -> int | None:
    offset = 0
    while offset < len(data) and data[offset] in _CVE_PICKLE_STREAM_PADDING:
        offset += 1
    if offset >= len(data) or not _looks_like_pickle(data[offset:]):
        return None
    return offset


def _pickle_cve_streams(
    data: bytes,
    *,
    first_stream_extent: int | None = None,
    position_offset: int = 0,
) -> tuple[tuple[_PickleCveStream, ...], bool]:
    streams: list[_PickleCveStream] = []
    probe = io.BytesIO(data)
    offset = 0
    while offset < len(data):
        while offset < len(data) and (
            data[offset] in _CVE_PICKLE_STREAM_PADDING or data[offset] not in _PICKLE_OPCODE_PREFIX_BYTES
        ):
            offset += 1
        if offset >= len(data):
            break

        if len(streams) >= _MAX_CVE_PICKLE_STREAMS:
            return tuple(streams), True
        extent: int | None
        consumed: int
        parsed_opcode: bool
        if offset == 0 and isinstance(first_stream_extent, int) and 0 < first_stream_extent <= len(data):
            extent = first_stream_extent
            consumed = first_stream_extent
            parsed_opcode = True
        else:
            extent, consumed, parsed_opcode = _probe_pickle_stream(probe, offset)
        if extent is None:
            end = min(len(data), offset + consumed)
            streams.append(_PickleCveStream(data[offset:end], position_offset + offset, True))
            offset = end if parsed_opcode else offset + 1
            continue

        streams.append(_PickleCveStream(data[offset : offset + extent], position_offset + offset, False))
        offset += extent

    if not streams and data:
        streams.append(_PickleCveStream(data, position_offset, True))
    return tuple(streams), False


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


def _literal_arg_text(arg: object) -> str | None:
    if isinstance(arg, str):
        return arg
    if isinstance(arg, bytes):
        return arg.decode("utf-8", errors="ignore")
    return None


def _pickle_literal_memo_index(arg: object) -> int | None:
    if isinstance(arg, bool):
        return None
    if isinstance(arg, int):
        return arg if arg >= 0 else None
    if isinstance(arg, str):
        try:
            index = int(arg)
        except ValueError:
            return None
        return index if index >= 0 else None
    return None


def _pickle_literal_record_value(*values: _PickleStackValue) -> _PickleStackValue:
    seen: set[int] = set()
    indexes: list[int] = []
    for value in values:
        for index in value.record_indexes:
            if index in seen:
                continue
            seen.add(index)
            indexes.append(index)
    return _PickleStackValue(record_indexes=tuple(indexes))


def _pickle_stack_value_is_executable_network_consumer(value: _PickleStackValue) -> bool:
    if value.opaque_extension:
        return True
    if value.global_module is None or value.global_name is None:
        return False

    module = value.global_module.strip()
    name = value.global_name.strip()
    lowered_module = module.lower()
    lowered_name = name.lower()
    lowered_full_name = f"{lowered_module}.{lowered_name}"

    if is_suspicious_global(module, name):
        return True
    if lowered_full_name in _EXECUTABLE_PICKLE_GLOBAL_FULL_NAMES:
        return True
    if any(
        lowered_module == prefix or lowered_module.startswith(f"{prefix}.")
        for prefix in _EXECUTABLE_PICKLE_GLOBAL_MODULE_PREFIXES
    ):
        return True
    return lowered_name in _EXECUTABLE_PICKLE_GLOBAL_NAMES


def _documentation_literal_spans(data: bytes) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    for record in _pickle_literal_records(data):
        if not _is_primarily_documentation(record.literal):
            continue
        spans.append((record.start, record.end))
    return tuple(spans)


def _pickle_literal_records(data: bytes) -> tuple[_PickleLiteralRecord, ...]:
    marker = object()
    unknown = _PickleStackValue()
    stack: list[_PickleStackValue | object] = []
    memo: dict[int, _PickleStackValue] = {}
    builders: list[_PickleLiteralRecordBuilder] = []
    last_literal_index: int | None = None

    def finish_previous_literal(position: int | None) -> None:
        nonlocal last_literal_index
        if last_literal_index is None or not isinstance(position, int):
            return
        previous = builders[last_literal_index]
        if position > previous.start:
            previous.end = position
        last_literal_index = None

    def pop_value() -> _PickleStackValue:
        while stack:
            value = stack.pop()
            if isinstance(value, _PickleStackValue):
                return value
            return unknown
        return unknown

    def pop_to_mark() -> tuple[_PickleStackValue, ...]:
        values: list[_PickleStackValue] = []
        while stack:
            value = stack.pop()
            if value is marker:
                values.reverse()
                return tuple(values)
            if isinstance(value, _PickleStackValue):
                values.append(value)
        return tuple(reversed(values))

    def push(value: _PickleStackValue) -> None:
        stack.append(value)

    def push_container(values: tuple[_PickleStackValue, ...]) -> None:
        push(_pickle_literal_record_value(*values))

    def mark_executable_consumer(value: _PickleStackValue) -> None:
        for index in value.record_indexes:
            if 0 <= index < len(builders):
                builders[index].executable_consumer = True

    def mark_literal_result_consumers(*values: _PickleStackValue) -> None:
        mark_executable_consumer(_pickle_literal_record_value(*values))

    def mark_unresolved_records_executable_consumers() -> None:
        stack_values = tuple(value for value in stack if isinstance(value, _PickleStackValue))
        mark_literal_result_consumers(*stack_values, *memo.values())

    def build_records() -> tuple[_PickleLiteralRecord, ...]:
        return tuple(
            _PickleLiteralRecord(
                builder.start,
                builder.end,
                builder.literal,
                executable_consumer=builder.executable_consumer,
            )
            for builder in builders
        )

    opcode_count = 0
    parsed_streams = 0
    stream = io.BytesIO(data)
    offset = 0
    while offset < len(data):
        while offset < len(data) and (
            data[offset] in _CVE_PICKLE_STREAM_PADDING or data[offset] not in _PICKLE_OPCODE_PREFIX_BYTES
        ):
            offset += 1
        if offset >= len(data):
            break

        stack = []
        memo = {}
        stream_builder_start = len(builders)
        stream_complete = False
        saw_opcode = False
        stream.seek(offset)
        try:
            for opcode, arg, position in pickletools.genops(stream):
                opcode_count += 1
                if opcode_count > _PICKLE_LITERAL_RECORD_MAX_OPCODES:
                    finish_previous_literal(position)
                    mark_unresolved_records_executable_consumers()
                    return build_records()

                saw_opcode = True
                finish_previous_literal(position)
                opcode_name = opcode.name

                if opcode_name == "MARK":
                    stack.append(marker)
                    continue

                if opcode_name in _PICKLE_LITERAL_OPCODE_NAMES:
                    literal = _literal_arg_bytes(arg)
                    if literal is None or not isinstance(position, int):
                        push(unknown)
                        continue
                    index = len(builders)
                    builders.append(_PickleLiteralRecordBuilder(position, len(data), literal))
                    last_literal_index = index
                    push(_PickleStackValue(text=_literal_arg_text(arg), record_indexes=(index,)))
                    continue

                if opcode_name == "GLOBAL":
                    parts = _global_parts(arg)
                    if parts is None:
                        push(unknown)
                    else:
                        module, name = parts
                        push(_PickleStackValue(text=f"{module}.{name}", global_module=module, global_name=name))
                    continue

                if opcode_name == "STACK_GLOBAL":
                    name_value = pop_value()
                    module_value = pop_value()
                    if module_value.text is None or name_value.text is None:
                        push(unknown)
                    else:
                        push(
                            _PickleStackValue(
                                text=f"{module_value.text}.{name_value.text}",
                                global_module=module_value.text,
                                global_name=name_value.text,
                            )
                        )
                    continue

                if opcode_name in {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}:
                    if stack and isinstance(stack[-1], _PickleStackValue):
                        memo_index = len(memo) if opcode_name == "MEMOIZE" else _pickle_literal_memo_index(arg)
                        if memo_index is not None and len(memo) < _PYTORCH_LEGACY_MAX_TRACKED_MEMO_ENTRIES:
                            memo[memo_index] = stack[-1]
                    continue

                if opcode_name in {"GET", "BINGET", "LONG_BINGET"}:
                    lookup_index = _pickle_literal_memo_index(arg)
                    push(memo.get(lookup_index, unknown) if lookup_index is not None else unknown)
                    continue

                if opcode_name == "POP":
                    pop_value()
                    continue

                if opcode_name == "POP_MARK":
                    pop_to_mark()
                    continue

                if opcode_name == "DUP":
                    push(stack[-1] if stack and isinstance(stack[-1], _PickleStackValue) else unknown)
                    continue

                if opcode_name in {"EMPTY_TUPLE", "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET"}:
                    push(unknown)
                    continue

                if opcode_name in {"TUPLE", "LIST", "DICT", "SET", "FROZENSET"}:
                    push_container(pop_to_mark())
                    continue

                if opcode_name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
                    arity = int(opcode_name[-1])
                    if len(stack) < arity:
                        push(unknown)
                        continue
                    tuple_values = [pop_value() for _ in range(arity)]
                    tuple_values.reverse()
                    push_container(tuple(tuple_values))
                    continue

                if opcode_name == "APPEND":
                    item = pop_value()
                    target = pop_value()
                    push_container((target, item))
                    continue

                if opcode_name == "SETITEM":
                    value = pop_value()
                    key = pop_value()
                    target = pop_value()
                    push_container((target, key, value))
                    continue

                if opcode_name in {"APPENDS", "SETITEMS", "ADDITEMS"}:
                    marked_values = pop_to_mark()
                    target = pop_value() if stack and isinstance(stack[-1], _PickleStackValue) else unknown
                    push_container((target, *marked_values))
                    continue

                if opcode_name == "REDUCE":
                    args = pop_value()
                    callable_value = pop_value()
                    if _pickle_stack_value_is_executable_network_consumer(callable_value):
                        mark_literal_result_consumers(args)
                    push(unknown)
                    continue

                if opcode_name == "NEWOBJ":
                    args = pop_value()
                    callable_value = pop_value()
                    if _pickle_stack_value_is_executable_network_consumer(callable_value):
                        mark_literal_result_consumers(args)
                    push(unknown)
                    continue

                if opcode_name == "NEWOBJ_EX":
                    kwargs = pop_value()
                    args = pop_value()
                    callable_value = pop_value()
                    if _pickle_stack_value_is_executable_network_consumer(callable_value):
                        mark_literal_result_consumers(args, kwargs)
                    push(unknown)
                    continue

                if opcode_name == "OBJ":
                    obj_values = pop_to_mark()
                    if obj_values and _pickle_stack_value_is_executable_network_consumer(obj_values[0]):
                        mark_literal_result_consumers(*obj_values[1:])
                    push(unknown)
                    continue

                if opcode_name == "INST":
                    inst_values = pop_to_mark()
                    inst_global = unknown
                    parts = _global_parts(arg)
                    if parts is not None:
                        module, name = parts
                        inst_global = _PickleStackValue(global_module=module, global_name=name)
                    if _pickle_stack_value_is_executable_network_consumer(inst_global):
                        mark_literal_result_consumers(*inst_values)
                    push(unknown)
                    continue

                if opcode_name == "BINPERSID":
                    mark_literal_result_consumers(pop_value())
                    push(unknown)
                    continue

                if opcode_name == "PERSID":
                    push(unknown)
                    continue

                if opcode_name == "BUILD":
                    mark_literal_result_consumers(pop_value())
                    continue

                if opcode_name in {"EXT1", "EXT2", "EXT4"}:
                    push(_PickleStackValue(opaque_extension=True))
                    continue

                if opcode_name in {
                    "BINBYTES",
                    "BINBYTES8",
                    "BINFLOAT",
                    "BININT",
                    "BININT1",
                    "BININT2",
                    "BYTEARRAY8",
                    "FLOAT",
                    "INT",
                    "LONG",
                    "LONG1",
                    "LONG4",
                    "NEWFALSE",
                    "NEWTRUE",
                    "NEXT_BUFFER",
                    "NONE",
                    "READONLY_BUFFER",
                    "SHORT_BINBYTES",
                }:
                    push(unknown)
                    continue

                if opcode_name == "STOP":
                    stream_complete = True
                    break

        except Exception:
            if parsed_streams == 0:
                return ()
            del builders[stream_builder_start:]
            last_literal_index = None
            break

        if not saw_opcode:
            offset += 1
            continue
        parsed_streams += 1
        if not stream_complete:
            break
        offset = max(offset + 1, stream.tell())

    return build_records()


def _pickle_network_from_import_aliases(context: bytes) -> set[bytes]:
    aliases: set[bytes] = set()
    for match in _NETWORK_FROM_IMPORT_RE.finditer(context):
        module = match.group("module").lower()
        call_names = _NETWORK_IMPORTABLE_MODULE_CALLS.get(module, ())
        for raw_import in match.group("imports").split(b","):
            words = raw_import.strip().split()
            if not words:
                continue
            imported_name = words[0].strip(b"()").lower()
            if imported_name == b"*":
                aliases.update(call_names)
                continue
            if imported_name not in call_names:
                continue
            alias = imported_name
            if len(words) >= 3 and words[1].lower() == b"as":
                alias = words[2].strip(b"()").lower()
            if _PYTHON_IDENTIFIER_RE.fullmatch(alias):
                aliases.add(alias)
    return aliases


def _pickle_network_module_import_aliases(context: bytes) -> dict[bytes, tuple[bytes, ...]]:
    aliases: dict[bytes, tuple[bytes, ...]] = {}
    for match in _NETWORK_IMPORT_ALIAS_RE.finditer(context):
        module = match.group("module").lower()
        alias = match.group("alias").lower()
        call_names = _NETWORK_IMPORTABLE_MODULE_CALLS.get(module)
        if call_names is None or _PYTHON_IDENTIFIER_RE.fullmatch(alias) is None:
            continue
        aliases[alias] = call_names
    return aliases


def _pickle_literal_contains_imported_network_alias_call(context: bytes) -> bool:
    for alias in _pickle_network_from_import_aliases(context):
        if re.search(rb"(?<![A-Za-z0-9_])" + re.escape(alias) + rb"\s*\(", context):
            return True

    for alias, call_names in _pickle_network_module_import_aliases(context).items():
        escaped_calls = b"|".join(re.escape(call_name) for call_name in call_names)
        if re.search(
            rb"(?<![A-Za-z0-9_])" + re.escape(alias) + rb"\s*\.\s*(?:" + escaped_calls + rb")\s*\(",
            context,
        ):
            return True
    return False


def _pickle_literal_has_executable_network_context(literal: bytes) -> bool:
    context = _PICKLE_LITERAL_URL_RE.sub(b" ", literal)
    lowered = context.lower()
    compact = re.sub(rb"\s+", b"", lowered)
    if any(seed in lowered or seed in compact for seed in _EXECUTABLE_NETWORK_LITERAL_SEEDS):
        return True
    if _pickle_literal_contains_imported_network_alias_call(lowered):
        return True
    return _EXECUTABLE_NETWORK_LITERAL_COMMAND_RE.search(context) is not None


def _position_is_within_pickle_literal_url_span(data: bytes, record: _PickleLiteralRecord, position: int) -> bool:
    return any(
        match.start() <= position < match.end()
        for match in _PICKLE_LITERAL_URL_RE.finditer(data, record.start, record.end)
    )


def _network_finding_is_inert_pickle_literal_network_evidence(
    finding: dict[str, Any],
    literal_records: tuple[_PickleLiteralRecord, ...],
    data: bytes,
) -> bool:
    finding_type = finding.get("type")
    if finding_type == "explicit_network_pattern":
        if finding.get("pattern_type") != "url":
            return False
    elif finding_type == "url_detected":
        pass
    elif finding_type not in {"network_function", "network_library"}:
        return False
    position = finding.get("position")
    if not isinstance(position, int):
        return False
    for record in literal_records:
        if record.start <= position < record.end:
            if record.executable_consumer:
                return False
            if _pickle_literal_has_executable_network_context(record.literal):
                return False
            if finding_type in {"network_function", "network_library"}:
                return _position_is_within_pickle_literal_url_span(data, record, position)
            return _position_is_within_pickle_literal_url_span(data, record, position)
    return False


def executable_pickle_literal_network_findings(
    data: bytes,
    *,
    context: str,
    position_offset: int = 0,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for record in _pickle_literal_records(data):
        if not record.executable_consumer:
            continue
        for match in _PICKLE_LITERAL_URL_RE.finditer(data, record.start, record.end):
            absolute_position = position_offset + match.start()
            raw_url = match.group().decode("utf-8", errors="ignore")
            if not raw_url:
                continue
            matched_text = redact_url_for_finding(raw_url)
            key = (absolute_position, matched_text)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "type": "explicit_network_pattern",
                    "severity": "CRITICAL",
                    "confidence": 0.95,
                    "message": f"Executable pickle call argument contains URL: {matched_text[:100]}",
                    "pattern_type": "url",
                    "matched_text": matched_text[:200],
                    "position": absolute_position,
                    "context": context,
                    "source": "pickle_executable_literal_consumer",
                }
            )
    return findings


def filter_inert_pickle_literal_network_findings(
    findings: list[dict[str, Any]],
    data: bytes,
) -> list[dict[str, Any]]:
    """Drop URL-only critical network findings for inert pickle literals."""
    if not findings:
        return findings
    literal_records = _pickle_literal_records(data)
    if not literal_records:
        return findings
    return [
        finding
        for finding in findings
        if not _network_finding_is_inert_pickle_literal_network_evidence(finding, literal_records, data)
    ]


def _literal_url_contains_network_function_text(url: bytes) -> bool:
    lowered = url.lower()
    return any(token in lowered for token in _PICKLE_LITERAL_URL_NETWORK_FUNCTION_TOKENS)


def _pickle_literal_url_stripped_scan_view(data: bytes, *, network_functions_only: bool = False) -> bytes:
    literal_records = _pickle_literal_records(data)
    if not literal_records:
        return data
    stripped: bytearray | None = None
    for record in literal_records:
        if record.executable_consumer:
            continue
        if _pickle_literal_has_executable_network_context(record.literal):
            continue
        for match in _PICKLE_LITERAL_URL_RE.finditer(data, record.start, record.end):
            if network_functions_only and not _literal_url_contains_network_function_text(match.group()):
                continue
            if stripped is None:
                stripped = bytearray(data)
            stripped[match.start() : match.end()] = b" " * (match.end() - match.start())
    return data if stripped is None else bytes(stripped)


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
            if opcode.name in _PICKLE_LITERAL_OPCODE_NAMES and (
                isinstance(arg, str)
                and "_rebuild_tensor" in arg
                and not _is_primarily_documentation(arg.encode("utf-8", errors="ignore"))
            ):
                return True
    except Exception:
        return False
    return False


def _analyze_pickle_setitem_entries(
    data: bytes,
    *,
    global_needles: tuple[str, ...],
    literal_needles: tuple[str, ...] = (),
) -> _PickleSetitemAnalysis:
    stack: list[tuple[str, str | None]] = []
    memo: dict[int, tuple[str, str | None]] = {}
    mark = ("mark", None)
    saw_setitem = False
    confirmed_dangerous_target = False
    suspicious_entry_on_unknown_target = False
    parse_incomplete = False

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
            global_name = text.rsplit(".", 1)[-1]
            return any(
                text == needle or (needle == "_rebuild_tensor" and global_name.startswith(needle))
                for needle in global_needles
            )
        if kind == "string" and isinstance(text, str):
            return any(needle in text for needle in literal_needles) and not _is_primarily_documentation(
                text.encode("utf-8", errors="ignore")
            )
        return False

    def is_confirmed_dangerous_target(value: tuple[str, str | None]) -> bool:
        return value[0] == "interesting_result"

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
            elif name in _PICKLE_LITERAL_OPCODE_NAMES:
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
            elif name == "BUILD":
                pop()
            elif name == "INST":
                pop_to_mark()
                stack.append(collapse_callable_result(entry_for_global(arg)))
            elif name == "OBJ":
                values = pop_to_mark()
                callable_value = values[0] if values else ("unknown", None)
                stack.append(collapse_callable_result(callable_value))
            elif name == "SETITEM":
                saw_setitem = True
                value = pop()
                key = pop()
                target = stack[-1] if stack else ("unknown", None)
                if is_confirmed_dangerous_target(target):
                    confirmed_dangerous_target = True
                if target[0] == "unknown" and (is_interesting_entry(key) or is_interesting_entry(value)):
                    suspicious_entry_on_unknown_target = True
            elif name == "SETITEMS":
                saw_setitem = True
                values = pop_to_mark()
                target = stack[-1] if stack else ("unknown", None)
                if is_confirmed_dangerous_target(target):
                    confirmed_dangerous_target = True
                if target[0] == "unknown" and any(is_interesting_entry(value) for value in values):
                    suspicious_entry_on_unknown_target = True
            elif name in {"APPEND", "APPENDS", "ADDITEMS"}:
                if name == "APPEND":
                    pop()
                else:
                    pop_to_mark()
            elif name in {"POP", "POP_MARK", "DUP"}:
                if name == "POP":
                    pop()
                elif name == "POP_MARK":
                    pop_to_mark()
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
                "FLOAT",
                "BINFLOAT",
            }:
                stack.append(("scalar", None))
            elif name in {"EXT1", "EXT2", "EXT4", "NEXT_BUFFER", "PERSID"}:
                stack.append(("object", None))
            elif name == "BINPERSID":
                pop()
                stack.append(("object", None))
    except Exception:
        parse_incomplete = True
    return _PickleSetitemAnalysis(
        saw_setitem=saw_setitem,
        confirmed_dangerous_target=confirmed_dangerous_target,
        suspicious_entry_on_unknown_target=suspicious_entry_on_unknown_target,
        parse_incomplete=parse_incomplete,
    )


def _pickle_has_setitem_abuse_for_entries(
    data: bytes,
    *,
    global_needles: tuple[str, ...],
    literal_needles: tuple[str, ...] = (),
) -> bool:
    return _analyze_pickle_setitem_entries(
        data,
        global_needles=global_needles,
        literal_needles=literal_needles,
    ).has_abuse


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
    parse_error: str | None = None

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
            if name in _PICKLE_LITERAL_OPCODE_NAMES:
                stack.append(arg if isinstance(arg, str) else None)
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
        parse_error = str(error)

    observed_dangerous_opcodes = sorted(opcode for opcode in dangerous_opcodes if opcode_counts.get(opcode, 0) > 0)
    summary = {
        "dangerous_opcodes": observed_dangerous_opcodes,
        "has_dangerous_opcodes": bool(observed_dangerous_opcodes),
        "opcode_counts": opcode_counts,
        "total_opcodes": total_opcodes,
        "pickle_protocol": protocol,
        "dangerous_globals": sorted(set(dangerous_globals)),
    }
    if parse_error is not None:
        summary["parse_error"] = parse_error
    return summary


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
            if opcode.name not in _PICKLE_LITERAL_OPCODE_NAMES:
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

    def _scan_standalone_bytes(self, payload: bytes, *, source: str, position_offset: int = 0) -> ScanResult:
        if position_offset:
            report = self._standalone_pickle_scanner.scan_stream(
                _PositionedBytesIO(payload, position_offset),
                source=source,
                size=len(payload),
            )
        else:
            report = self._standalone_pickle_scanner.scan_bytes(payload, source=source)
        result = pickle_report_to_scan_result(report, scanner_name=self.name, scanner=self)
        result.metadata["pickle_primary_engine"] = "rust"
        return result

    @staticmethod
    def _merge_standalone_pickle_segment(
        result: ScanResult,
        segment_result: ScanResult,
        *,
        segment_start: int,
    ) -> None:
        first_pickle_end_pos = result.metadata.get("first_pickle_end_pos")
        control_coverage_value = result.metadata.get("pickle_coverage")
        segment_coverage_value = segment_result.metadata.get("pickle_coverage")
        control_coverage = dict(control_coverage_value) if isinstance(control_coverage_value, dict) else None
        segment_coverage = dict(segment_coverage_value) if isinstance(segment_coverage_value, dict) else None
        control_globals_count = result.metadata.get("globals_count")
        segment_globals_count = segment_result.metadata.get("globals_count")
        segment_pickle_end_pos = segment_result.metadata.get("last_pickle_end_pos")
        if not isinstance(segment_pickle_end_pos, int):
            segment_pickle_end_pos = segment_result.metadata.get("first_pickle_end_pos")
        control_status = result.metadata.get("pickle_report_status")
        segment_status = segment_result.metadata.get("pickle_report_status")
        if segment_status == "complete" and isinstance(segment_coverage, dict):
            segment_bytes_scanned = segment_coverage.get("bytes_scanned")
            if isinstance(segment_bytes_scanned, int) and segment_bytes_scanned >= 0:
                segment_pickle_end_pos = segment_start + segment_bytes_scanned
        incomplete_flags = {
            key: result.metadata.get(key) is True or segment_result.metadata.get(key) is True
            for key in (
                "analysis_incomplete",
                "import_references_truncated",
                "callable_invocations_truncated",
                "non_allowlisted_global_imports_truncated",
            )
        }
        combined_lists: dict[str, list[Any]] = {}
        for key in ("import_references", "callable_invocations", "protocols"):
            control_values = result.metadata.get(key)
            segment_values = segment_result.metadata.get(key)
            combined_lists[key] = [
                *(control_values if isinstance(control_values, list) else []),
                *(segment_values if isinstance(segment_values, list) else []),
            ]
        combined_lists["protocols"] = list(dict.fromkeys(combined_lists["protocols"]))
        combined_opcode_count_maps: dict[str, dict[str, int]] = {}
        for count_key in ("opcode_counts", "nested_opcode_counts", "follow_on_opcode_counts"):
            combined_counts: dict[str, int] = {}
            for metadata in (result.metadata, segment_result.metadata):
                opcode_counts = metadata.get(count_key)
                if not isinstance(opcode_counts, dict):
                    continue
                for opcode, count in opcode_counts.items():
                    if isinstance(opcode, str) and isinstance(count, int):
                        combined_counts[opcode] = combined_counts.get(opcode, 0) + count
            combined_opcode_count_maps[count_key] = combined_counts
        combined_opcode_counts = combined_opcode_count_maps["opcode_counts"]
        control_verdict = result.metadata.get("pickle_verdict")
        segment_verdict = segment_result.metadata.get("pickle_verdict")

        result.merge(segment_result)
        result.metadata.update(combined_lists)
        result.metadata.update(combined_opcode_count_maps)
        result.metadata["opcode_count"] = sum(combined_opcode_counts.values())
        result.metadata["globals_count"] = sum(
            value
            for value in (
                control_globals_count,
                segment_globals_count,
            )
            if isinstance(value, int)
        )
        result.metadata.update(incomplete_flags)
        if isinstance(first_pickle_end_pos, int):
            result.metadata["first_pickle_end_pos"] = first_pickle_end_pos
        if isinstance(segment_pickle_end_pos, int):
            result.metadata["last_pickle_end_pos"] = segment_pickle_end_pos
            result.metadata["legacy_pytorch_suffix_pickle_end_pos"] = segment_pickle_end_pos
        if isinstance(control_coverage, dict) and isinstance(segment_coverage, dict):
            result.metadata["pickle_coverage"] = {
                "bytes_scanned": sum(
                    value
                    for value in (control_coverage.get("bytes_scanned"), segment_coverage.get("bytes_scanned"))
                    if isinstance(value, int)
                ),
                "bytes_total": sum(
                    value
                    for value in (control_coverage.get("bytes_total"), segment_coverage.get("bytes_total"))
                    if isinstance(value, int)
                ),
                "opcode_count": sum(combined_opcode_counts.values()),
                "raw_scan_complete": control_coverage.get("raw_scan_complete") is True
                and segment_coverage.get("raw_scan_complete") is True,
                "opcode_scan_complete": control_coverage.get("opcode_scan_complete") is True
                and segment_coverage.get("opcode_scan_complete") is True,
            }
            result.metadata["legacy_pytorch_suffix_pickle_coverage"] = segment_coverage
        status_rank = {"complete": 0, "inconclusive": 1, "error": 2}
        statuses = [status for status in (control_status, segment_status) if isinstance(status, str)]
        if statuses:
            result.metadata["pickle_report_status"] = max(statuses, key=lambda value: status_rank.get(value, 2))
        verdict_rank = {"clean": 0, "suspicious": 1, "unknown": 2, "malicious": 3}
        if isinstance(control_verdict, str) and isinstance(segment_verdict, str):
            result.metadata["pickle_verdict"] = max(
                (control_verdict, segment_verdict),
                key=lambda value: verdict_rank.get(value, 3),
            )

    def _legacy_pytorch_layout_for_scan(
        self,
        data: bytes,
        *,
        total_size: int | None,
        read_at: Callable[[int, int], bytes] | None = None,
    ) -> tuple[_LegacyPyTorchStreamLayout | None, bool]:
        layout = _legacy_pytorch_stream_layout(data)
        if layout is None or layout.pickle_end > self._standalone_pickle_scanner.options.max_known_stream_read_bytes:
            return None, False
        storage_end = _legacy_pytorch_storage_end(
            data,
            layout,
            total_size=total_size,
            read_at=read_at,
        )
        if storage_end is None:
            return layout, False
        return (
            _LegacyPyTorchStreamLayout(
                boundaries=layout.boundaries,
                storage_keys=layout.storage_keys,
                storage_records=layout.storage_records,
                storage_end=storage_end,
            ),
            True,
        )

    @staticmethod
    def _legacy_pytorch_control_scan_complete(result: ScanResult) -> bool:
        return (
            result.metadata.get("pickle_report_status") == "complete"
            and not result.metadata.get("analysis_incomplete")
            and not result.metadata.get("operational_error")
        )

    @staticmethod
    def _annotate_legacy_pytorch_layout(
        result: ScanResult,
        layout: _LegacyPyTorchStreamLayout,
        *,
        position_offset: int = 0,
    ) -> None:
        assert layout.storage_end is not None
        boundaries = [
            {"start": position_offset + start, "end": position_offset + end} for start, end in layout.boundaries
        ]
        result.metadata["legacy_pytorch_container"] = True
        result.metadata["legacy_pytorch_pickle_stream_count"] = len(boundaries)
        result.metadata["legacy_pytorch_pickle_stream_boundaries"] = boundaries
        result.metadata["legacy_pytorch_storage_key_count"] = layout.storage_key_count
        result.metadata["legacy_pytorch_storage_start"] = position_offset + layout.pickle_end
        result.metadata["legacy_pytorch_storage_end"] = position_offset + layout.storage_end
        result.metadata["last_pickle_end_pos"] = position_offset + layout.pickle_end
        if layout.storage_key_count > 0:
            result.metadata["legacy_pytorch_storage_payload_skipped"] = True

    @staticmethod
    def _is_legacy_pytorch_storage_persistent_id_record(
        details: dict[str, Any],
        trusted_storage_keys: set[str],
    ) -> bool:
        storage_key = details.get("pytorch_storage_key")
        return (
            details.get("pickle_rule_code") == "PERSISTENT_ID"
            and details.get("opcode") == "BINPERSID"
            and details.get("pytorch_storage_persistent_id") is True
            and isinstance(storage_key, str)
            and storage_key in trusted_storage_keys
        )

    @classmethod
    def _downgrade_legacy_pytorch_storage_persistent_ids(
        cls,
        result: ScanResult,
        layout: _LegacyPyTorchStreamLayout,
    ) -> None:
        """Treat canonical storage BINPERSID records as informational in validated legacy PyTorch streams."""
        trusted_storage_keys = set(layout.storage_keys)
        downgraded_count = 0
        for check in result.checks:
            if not cls._is_legacy_pytorch_storage_persistent_id_record(check.details, trusted_storage_keys):
                continue
            check.status = CheckStatus.PASSED
            check.severity = IssueSeverity.INFO
            check.message = "PyTorch storage persistent ID found in validated legacy PyTorch stream"
            check.details["trusted_legacy_pytorch_context"] = True
            downgraded_count += 1

        result.issues = [
            issue
            for issue in result.issues
            if not cls._is_legacy_pytorch_storage_persistent_id_record(issue.details, trusted_storage_keys)
        ]
        if downgraded_count:
            result.metadata["legacy_pytorch_trusted_storage_persistent_id_count"] = downgraded_count
            if (
                not result.has_errors
                and not result.has_warnings
                and result.metadata.get("pickle_verdict") == "suspicious"
            ):
                result.metadata["pickle_verdict"] = "clean"

    @staticmethod
    def _mark_legacy_pytorch_storage_layout_incomplete(
        result: ScanResult,
        layout: _LegacyPyTorchStreamLayout,
        source: str,
        *,
        position_offset: int = 0,
    ) -> None:
        reason = "legacy_pytorch_storage_layout_incomplete"
        mark_inconclusive_scan_result(result, reason)
        result.metadata["legacy_pytorch_control_streams"] = True
        result.metadata["legacy_pytorch_pickle_stream_count"] = len(layout.boundaries)
        result.metadata["legacy_pytorch_pickle_stream_boundaries"] = [
            {"start": position_offset + start, "end": position_offset + end} for start, end in layout.boundaries
        ]
        result.metadata["legacy_pytorch_storage_key_count"] = layout.storage_key_count
        result.metadata["legacy_pytorch_storage_start"] = position_offset + layout.pickle_end
        result.add_check(
            name="Legacy PyTorch Storage Layout",
            passed=False,
            message="Legacy PyTorch storage records could not be validated completely",
            severity=IssueSeverity.WARNING,
            location=source,
            details={
                "storage_key_count": layout.storage_key_count,
                "storage_start": position_offset + layout.pickle_end,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.finish(success=False)

    @staticmethod
    def _mark_legacy_pytorch_control_layout_incomplete(
        result: ScanResult,
        source: str,
        *,
        position_offset: int = 0,
    ) -> None:
        reason = "legacy_pytorch_control_layout_incomplete"
        mark_inconclusive_scan_result(result, reason)
        result.metadata["legacy_pytorch_control_streams"] = True
        result.add_check(
            name="Legacy PyTorch Control Layout",
            passed=False,
            message="Legacy PyTorch control streams could not be validated completely",
            severity=IssueSeverity.WARNING,
            location=source,
            details={
                "control_start": position_offset,
                "control_scan_limit_bytes": _PYTORCH_LEGACY_MAX_CONTROL_BYTES,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.finish(success=False)

    def _scan_legacy_pytorch_suffix_bytes(
        self,
        result: ScanResult,
        suffix: bytes,
        source: str,
        *,
        position_offset: int,
    ) -> None:
        pickle_offset = _legacy_pytorch_suffix_pickle_offset(suffix)
        if pickle_offset is None:
            return
        suffix_result = self._scan_standalone_bytes(
            suffix[pickle_offset:],
            source=source,
            position_offset=position_offset + pickle_offset,
        )
        self._merge_standalone_pickle_segment(
            result,
            suffix_result,
            segment_start=position_offset + pickle_offset,
        )

    def _scan_legacy_pytorch_file_suffix(
        self,
        result: ScanResult,
        path: str,
        file_size: int,
        storage_end: int,
        *,
        raw_limit: int,
    ) -> bytes:
        suffix_size = max(file_size - storage_end, 0)
        if suffix_size == 0:
            return b""
        probe_size = min(suffix_size, max(raw_limit, _BINARY_TAIL_SCAN_BYTES))
        with open(path, "rb") as handle:
            handle.seek(storage_end)
            probe = self._read_stream_bytes(handle, probe_size)
        pickle_offset = _legacy_pytorch_suffix_pickle_offset(probe)
        if pickle_offset is not None:
            with open(path, "rb") as handle:
                handle.seek(storage_end + pickle_offset)
                suffix_result = self._scan_standalone_stream(
                    handle,
                    suffix_size - pickle_offset,
                    source=path,
                )
            self._merge_standalone_pickle_segment(
                result,
                suffix_result,
                segment_start=storage_end + pickle_offset,
            )
        return probe[:raw_limit]

    def _scan_legacy_pytorch_seekable_suffix(
        self,
        result: ScanResult,
        file_obj: BinaryIO,
        start_position: int,
        file_size: int | None,
        storage_end: int,
        source: str,
        *,
        raw_limit: int,
    ) -> bytes:
        suffix_size = None if file_size is None else max(file_size - storage_end, 0)
        if suffix_size == 0:
            return b""
        probe_size = max(raw_limit, _BINARY_TAIL_SCAN_BYTES)
        if suffix_size is not None:
            probe_size = min(probe_size, suffix_size)
        try:
            file_obj.seek(start_position + storage_end)
            probe = self._read_stream_bytes(file_obj, probe_size)
            pickle_offset = _legacy_pytorch_suffix_pickle_offset(probe)
            if pickle_offset is not None:
                file_obj.seek(start_position + storage_end + pickle_offset)
                segment_size = None if suffix_size is None else suffix_size - pickle_offset
                suffix_result = self._scan_standalone_stream(file_obj, segment_size, source=source)
                self._merge_standalone_pickle_segment(
                    result,
                    suffix_result,
                    segment_start=start_position + storage_end + pickle_offset,
                )
            return probe[:raw_limit]
        finally:
            file_obj.seek(start_position)

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

    def _legacy_pytorch_control_probe_size(self, total_size: int | None) -> int:
        probe_limit = min(
            _PYTORCH_LEGACY_MAX_CONTROL_BYTES,
            self._standalone_pickle_scanner.options.max_known_stream_read_bytes,
        )
        return probe_limit if total_size is None else min(max(total_size, 0), probe_limit)

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

    def _add_stream_integrity_check(
        self,
        payload: bytes,
        result: ScanResult,
        source: str,
        *,
        hash_complete: bool = True,
    ) -> None:
        sha256 = hashlib.sha256(payload).hexdigest()
        result.metadata.setdefault("file_hashes", {})["sha256"] = sha256
        result.add_check(
            name="File Integrity Check",
            passed=True,
            message="Stream SHA256 hash calculated",
            location=source,
            details={"sha256": sha256, "bytes_hashed": len(payload), "hash_complete": hash_complete},
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
        position_offset: int = 0,
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
        self._analyze_cve_patterns(
            data,
            result,
            source,
            lower_data=lower_data,
            present_bytes=present_bytes,
            position_offset=position_offset,
        )
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
            network_scan_data = _pickle_literal_url_stripped_scan_view(expensive_data, network_functions_only=True)
            network_findings = self.collect_network_communication_findings(
                network_scan_data,
                context=source,
                result=result,
            )
            network_findings = filter_inert_pickle_literal_network_findings(network_findings, expensive_data)
            network_findings.extend(
                executable_pickle_literal_network_findings(
                    expensive_data,
                    context=source,
                    position_offset=position_offset,
                )
            )
            self.add_network_communication_findings(network_findings, result, context=source)
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
        if result.metadata.get("legacy_pytorch_container") is True:
            storage_end = result.metadata.get("legacy_pytorch_storage_end")
            if not isinstance(storage_end, int) or storage_end <= 0:
                return None
            suffix_pickle_end = result.metadata.get("legacy_pytorch_suffix_pickle_end_pos")
            if isinstance(suffix_pickle_end, int) and suffix_pickle_end > storage_end:
                return suffix_pickle_end
            return storage_end

        last_pickle_end_pos = result.metadata.get("last_pickle_end_pos")
        if isinstance(last_pickle_end_pos, int) and last_pickle_end_pos > 0:
            return last_pickle_end_pos

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
        scan_data = _pickle_literal_url_stripped_scan_view(data)
        if scan_data is data:
            lower = data.lower() if lower_data is None else lower_data
        else:
            lower = scan_data.lower()
            present_bytes = None
        if present_bytes is None:
            present_bytes = frozenset(lower)
        if not _has_raw_text_indicator_shape(
            scan_data,
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
        if _raw_call_token_should_report(scan_data, lower, b"eval", documentation_spans):
            _append_raw_indicator(indicators, "eval", "builtins.eval")
        if _raw_call_token_should_report(scan_data, lower, b"exec", documentation_spans):
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
        position_offset: int = 0,
    ) -> None:
        """Add CVE attribution checks from a bounded raw pickle scan window."""
        first_pickle_end_pos = result.metadata.get("first_pickle_end_pos")
        first_stream_extent = (
            first_pickle_end_pos - position_offset
            if isinstance(first_pickle_end_pos, int)
            and position_offset < first_pickle_end_pos <= position_offset + len(data)
            else None
        )
        streams, stream_limit_exceeded = _pickle_cve_streams(
            data,
            first_stream_extent=first_stream_extent,
            position_offset=position_offset,
        )
        previous_stream_count = result.metadata.get("pickle_cve_streams_analyzed", 0)
        if not isinstance(previous_stream_count, int):
            previous_stream_count = 0
        result.metadata["pickle_cve_streams_analyzed"] = previous_stream_count + len(streams)
        if stream_limit_exceeded:
            reason = "pickle_cve_stream_limit_exceeded"
            mark_inconclusive_scan_result(result, reason)
            result.metadata[reason] = True
            result.add_check(
                name="Pickle CVE Stream Coverage",
                passed=False,
                message=f"Pickle CVE analysis stopped after {_MAX_CVE_PICKLE_STREAMS} streams",
                severity=IssueSeverity.INFO,
                location=source or self.current_file_path,
                details={
                    "streams_analyzed": len(streams),
                    "max_streams": _MAX_CVE_PICKLE_STREAMS,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                },
                rule_code="S902",
            )
            result.finish(success=False)

        opcode_counts = _result_opcode_counts(result)
        has_setitem_opcode = opcode_counts.get("SETITEM", 0) > 0 or opcode_counts.get("SETITEMS", 0) > 0
        import_references = _result_import_references(result)
        has_dangerous_system_global = any(
            reference.get("import_reference") in {"os.system", "posix.system", "nt.system"}
            for reference in import_references
        )
        has_rebuild_tensor_global = _result_has_rebuild_tensor_global(result)
        lower = data.lower() if lower_data is None else lower_data
        if present_bytes is None:
            present_bytes = frozenset(lower)
        has_raw_cve_seed = _contains_any_seed_lowered(lower, _CVE_RAW_SCAN_SEEDS, present_bytes)
        has_raw_setitem_opcode = ord("s") in present_bytes or ord("u") in present_bytes
        has_setitem_candidate = has_setitem_opcode or has_raw_setitem_opcode
        has_rebuild_tensor_candidate = has_rebuild_tensor_global or b"_rebuild_tensor" in lower
        has_system_candidate = has_dangerous_system_global or any(
            seed in lower for seed in _CVE_2026_24747_SYSTEM_RAW_SEEDS
        )
        has_stack_global_candidate = opcode_counts.get("STACK_GLOBAL", 0) > 0 or b"\x93" in data
        if has_stack_global_candidate and b"system" in lower:
            has_system_candidate = has_system_candidate or b"os" in lower or b"posix" in lower or b"nt" in lower
        has_escaped_string_operand = b"S'\\" in data or b'S"\\' in data or b"V\\" in data
        if has_stack_global_candidate and has_escaped_string_operand:
            has_system_candidate = True
            has_rebuild_tensor_candidate = True
        should_analyze_setitems = has_setitem_candidate and (has_rebuild_tensor_candidate or has_system_candidate)
        if (
            not has_raw_cve_seed
            and not (has_setitem_opcode and has_dangerous_system_global)
            and not should_analyze_setitems
        ):
            result.metadata["pickle_cve_raw_detector_skipped"] = True
            return

        no_setitem_abuse = _PickleSetitemAnalysis(
            saw_setitem=False,
            confirmed_dangerous_target=False,
            suspicious_entry_on_unknown_target=False,
            parse_incomplete=False,
        )
        stream_setitem_analyses: list[tuple[_PickleSetitemAnalysis, _PickleSetitemAnalysis]] = []
        for stream in streams:
            if not should_analyze_setitems:
                stream_setitem_analyses.append((no_setitem_abuse, no_setitem_abuse))
                continue
            candidate_analysis = _analyze_pickle_setitem_entries(
                stream.payload,
                global_needles=("_rebuild_tensor", "os.system", "posix.system", "nt.system"),
                literal_needles=("_rebuild_tensor",),
            )
            if not candidate_analysis.has_abuse:
                stream_setitem_analyses.append((candidate_analysis, candidate_analysis))
                continue
            stream_setitem_analyses.append(
                (
                    _analyze_pickle_setitem_entries(
                        stream.payload,
                        global_needles=("_rebuild_tensor",),
                        literal_needles=("_rebuild_tensor",),
                    ),
                    _analyze_pickle_setitem_entries(
                        stream.payload,
                        global_needles=("os.system", "posix.system", "nt.system"),
                    ),
                )
            )
        has_stream_setitem_evidence = any(
            rebuild_analysis.has_abuse or dangerous_system_analysis.has_abuse
            for rebuild_analysis, dangerous_system_analysis in stream_setitem_analyses
        )
        if (
            not has_raw_cve_seed
            and not (has_setitem_opcode and has_dangerous_system_global)
            and not (has_stream_setitem_evidence)
        ):
            result.metadata["pickle_cve_raw_detector_skipped"] = True
            return

        try:
            from modelaudit.detectors.cve_patterns import CVEAttribution, analyze_cve_patterns
        except ImportError:
            return

        try:
            attributions = analyze_cve_patterns(lower.decode("utf-8", errors="ignore"), data)
        except Exception as error:
            logger.warning("Error checking pickle CVE patterns: %s", error)
            return

        # Other CVEs intentionally retain whole-window matching. CVE-2026-24747
        # remains fail-closed for wholly unparseable inputs, but once a complete
        # stream exists its target-sensitive SETITEM evidence is stream-scoped.
        has_complete_stream = any(not stream.parse_incomplete for stream in streams)
        all_attributions = [
            attribution
            for attribution in attributions
            if attribution.cve_id != "CVE-2026-24747" or not has_complete_stream
        ]
        attribution_context: dict[tuple[str, str], tuple[int, int, bool]] = {}
        dangerous_system_context: tuple[int, int, bool] | None = None
        for stream_index, (stream, setitem_analyses) in enumerate(zip(streams, stream_setitem_analyses, strict=True)):
            if len(streams) == 1 and stream.offset == position_offset and stream.payload == data:
                stream_attributions = attributions
            else:
                try:
                    stream_attributions = analyze_cve_patterns(
                        stream.payload.decode("utf-8", errors="ignore"),
                        stream.payload,
                    )
                except Exception as error:
                    logger.warning("Error checking pickle stream CVE patterns: %s", error)
                    stream_attributions = []
            for attribution in stream_attributions:
                if attribution.cve_id != "CVE-2026-24747" or any(
                    "setitem" in pattern.lower() for pattern in attribution.patterns_matched
                ):
                    continue
                all_attributions.append(attribution)
                rule_code = self._rule_code_for_cve_attribution(attribution.patterns_matched)
                attribution_context.setdefault(
                    (attribution.cve_id, rule_code),
                    (stream_index, stream.offset, stream.parse_incomplete),
                )

            rebuild_analysis, dangerous_system_analysis = setitem_analyses
            if rebuild_analysis.has_abuse:
                attribution = CVEAttribution(
                    cve_id="CVE-2026-24747",
                    description="PyTorch weights_only restricted unpickler SETITEM abuse pattern",
                    severity="CRITICAL",
                    cvss=9.8,
                    cwe="CWE-502",
                    affected_versions="PyTorch versions before the fixed release",
                    remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                    patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
                )
                all_attributions.append(attribution)
                rule_code = self._rule_code_for_cve_attribution(attribution.patterns_matched)
                attribution_context.setdefault(
                    (attribution.cve_id, rule_code),
                    (stream_index, stream.offset, stream.parse_incomplete or rebuild_analysis.parse_incomplete),
                )
            if dangerous_system_analysis.has_abuse and dangerous_system_context is None:
                dangerous_system_context = (
                    stream_index,
                    stream.offset,
                    stream.parse_incomplete or dangerous_system_analysis.parse_incomplete,
                )

        attributions = self._dedupe_cve_attributions(all_attributions)
        emitted_cve_rule_keys: set[tuple[str, str]] = set()
        if dangerous_system_context is not None:
            stream_index, stream_offset, stream_parse_incomplete = dangerous_system_context
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
                    "pickle_stream_index": stream_index,
                    "pickle_stream_offset": stream_offset,
                    "pickle_stream_parse_incomplete": stream_parse_incomplete,
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
            details = {**attribution.to_dict(), "cve_risk_score": attribution.cvss}
            stream_context = attribution_context.get(cve_rule_key)
            if stream_context is not None:
                stream_index, stream_offset, stream_parse_incomplete = stream_context
                details.update(
                    {
                        "pickle_stream_index": stream_index,
                        "pickle_stream_offset": stream_offset,
                        "pickle_stream_parse_incomplete": stream_parse_incomplete,
                    }
                )
            result.add_check(
                name=f"{attribution.cve_id} Pattern Detection",
                passed=False,
                message=f"{attribution.cve_id}: {attribution.description}",
                severity=severity,
                location=source or self.current_file_path,
                details=details,
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
        legacy_layout: _LegacyPyTorchStreamLayout | None = None
        legacy_storage_valid = False
        suffix_raw_data = b""
        suffix_position_offset = 0
        allow_binary_tail_scan = True
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

            control_probe_size = self._legacy_pytorch_control_probe_size(standalone_size)
            if len(raw_data) >= control_probe_size:
                control_probe = raw_data[:control_probe_size]
            else:
                try:
                    file_obj.seek(start_position)
                    control_probe = self._read_stream_bytes(file_obj, control_probe_size)
                except (AttributeError, OSError, ValueError) as error:
                    self._record_stream_coverage_failure(result, source, error)
                    return result

            def read_at(local_offset: int, size: int) -> bytes:
                file_obj.seek(start_position + local_offset)
                return self._read_stream_bytes(file_obj, size)

            legacy_layout, legacy_storage_valid = self._legacy_pytorch_layout_for_scan(
                control_probe,
                total_size=standalone_size,
                read_at=read_at,
            )
            try:
                file_obj.seek(start_position)
            except (AttributeError, OSError, ValueError) as error:
                self._record_stream_coverage_failure(result, source, error)
                return result
            if legacy_layout is not None:
                result = self._scan_standalone_bytes(
                    control_probe[: legacy_layout.pickle_end],
                    source=source,
                    position_offset=start_position,
                )
                legacy_storage_valid = legacy_storage_valid and self._legacy_pytorch_control_scan_complete(result)
                raw_data = raw_data[: legacy_layout.pickle_end]
                if legacy_storage_valid:
                    assert legacy_layout.storage_end is not None
                    self._annotate_legacy_pytorch_layout(result, legacy_layout, position_offset=start_position)
                    self._downgrade_legacy_pytorch_storage_persistent_ids(result, legacy_layout)
                    suffix_raw_limit = max(self._root_raw_scan_limit() - len(raw_data), 0)
                    try:
                        suffix_raw_data = self._scan_legacy_pytorch_seekable_suffix(
                            result,
                            file_obj,
                            start_position,
                            standalone_size,
                            legacy_layout.storage_end,
                            source,
                            raw_limit=suffix_raw_limit,
                        )
                    except (AttributeError, OSError, ValueError) as error:
                        self._record_stream_coverage_failure(result, source, error)
                        return result
                    suffix_position_offset = start_position + legacy_layout.storage_end
                else:
                    self._mark_legacy_pytorch_storage_layout_incomplete(
                        result,
                        legacy_layout,
                        source,
                        position_offset=start_position,
                    )
                    allow_binary_tail_scan = False
            elif _matches_legacy_pytorch_preamble(control_probe):
                result = self._scan_standalone_bytes(
                    control_probe,
                    source=source,
                    position_offset=start_position,
                )
                self._mark_legacy_pytorch_control_layout_incomplete(
                    result,
                    source,
                    position_offset=start_position,
                )
                allow_binary_tail_scan = False
            self._add_seekable_stream_integrity_check(file_obj, result, source, start_position, standalone_size)
            binary_tail_payload: bytes | None = None
            raw_position_offset = start_position
        else:
            try:
                stream_read = self._read_stream_payload_for_root(file_obj, standalone_size)
            except (AttributeError, OSError, ValueError) as error:
                return self._stream_read_error_result(source, error)
            payload = stream_read.payload
            legacy_layout, legacy_storage_valid = self._legacy_pytorch_layout_for_scan(
                payload,
                total_size=standalone_size,
            )
            if legacy_layout is not None:
                result = self._scan_standalone_bytes(payload[: legacy_layout.pickle_end], source=source)
                legacy_storage_valid = legacy_storage_valid and self._legacy_pytorch_control_scan_complete(result)
                if legacy_storage_valid:
                    assert legacy_layout.storage_end is not None
                    self._annotate_legacy_pytorch_layout(result, legacy_layout)
                    self._downgrade_legacy_pytorch_storage_persistent_ids(result, legacy_layout)
                    suffix = payload[legacy_layout.storage_end :]
                    self._scan_legacy_pytorch_suffix_bytes(
                        result,
                        suffix,
                        source,
                        position_offset=legacy_layout.storage_end,
                    )
                else:
                    self._mark_legacy_pytorch_storage_layout_incomplete(result, legacy_layout, source)
                    allow_binary_tail_scan = False
            else:
                rust_stream_size = len(payload) if stream_read.truncated else standalone_size
                result = self._scan_standalone_stream(io.BytesIO(payload), rust_stream_size, source=source)
                if _matches_legacy_pytorch_preamble(payload):
                    self._mark_legacy_pytorch_control_layout_incomplete(result, source)
                    allow_binary_tail_scan = False
            result.metadata["pickle_stream_bytes_buffered"] = len(payload)
            self._add_stream_integrity_check(
                payload,
                result,
                source,
                hash_complete=not stream_read.truncated,
            )
            storage_only_omitted = (
                legacy_layout is not None
                and legacy_storage_valid
                and legacy_layout.storage_end is not None
                and stream_read.truncated
                and standalone_size is not None
                and legacy_layout.storage_end == standalone_size
            )
            if storage_only_omitted:
                assert legacy_layout is not None and legacy_layout.storage_end is not None
                result.metadata["legacy_pytorch_storage_scan_bounded"] = True
                result.metadata["legacy_pytorch_storage_bytes_buffered"] = max(
                    min(len(payload), legacy_layout.storage_end) - legacy_layout.pickle_end,
                    0,
                )
            else:
                self._add_stream_truncation_check(stream_read, result, source, standalone_size)
            raw_limit = self._root_raw_scan_limit()
            if legacy_layout is not None:
                raw_data = payload[: min(legacy_layout.pickle_end, raw_limit)]
                if legacy_storage_valid and legacy_layout.storage_end is not None:
                    suffix_raw_limit = max(raw_limit - len(raw_data), 0)
                    suffix_raw_data = payload[legacy_layout.storage_end : legacy_layout.storage_end + suffix_raw_limit]
                    suffix_position_offset = legacy_layout.storage_end
            else:
                raw_data = self._raw_window_from_payload(payload, raw_limit)
            binary_tail_payload = payload
            raw_position_offset = 0
        base_success = result.success
        self._run_root_raw_detectors(
            raw_data,
            result,
            source,
            position_offset=raw_position_offset,
            skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, raw_data),
            scan_binary_tail=False,
        )
        if suffix_raw_data:
            self._run_root_raw_detectors(
                suffix_raw_data,
                result,
                source,
                position_offset=suffix_position_offset,
                skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, suffix_raw_data),
                scan_binary_tail=False,
            )
        if allow_binary_tail_scan and stream_is_seekable and start_position is not None:
            self._scan_seekable_stream_binary_tail_if_needed(file_obj, start_position, standalone_size, result, source)
        elif allow_binary_tail_scan and binary_tail_payload is not None:
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
        legacy_layout: _LegacyPyTorchStreamLayout | None = None
        legacy_storage_valid = False
        legacy_control_incomplete = False
        suffix_raw_data = b""

        try:
            raw_data = self._read_root_raw_scan_window(path, file_size)
            with open(path, "rb") as layout_handle:
                control_probe = self._read_stream_bytes(
                    layout_handle,
                    self._legacy_pytorch_control_probe_size(file_size),
                )

                def read_at(local_offset: int, size: int) -> bytes:
                    layout_handle.seek(local_offset)
                    return self._read_stream_bytes(layout_handle, size)

                legacy_layout, legacy_storage_valid = self._legacy_pytorch_layout_for_scan(
                    control_probe,
                    total_size=file_size,
                    read_at=read_at,
                )
            if legacy_layout is not None:
                scan_result = self._scan_standalone_bytes(control_probe[: legacy_layout.pickle_end], source=path)
                legacy_storage_valid = legacy_storage_valid and self._legacy_pytorch_control_scan_complete(scan_result)
                detector_data = raw_data[: legacy_layout.pickle_end]
                if legacy_storage_valid:
                    assert legacy_layout.storage_end is not None
                    self._annotate_legacy_pytorch_layout(scan_result, legacy_layout)
                    self._downgrade_legacy_pytorch_storage_persistent_ids(scan_result, legacy_layout)
                    suffix_raw_limit = max(self._root_raw_scan_limit() - len(detector_data), 0)
                    suffix_raw_data = self._scan_legacy_pytorch_file_suffix(
                        scan_result,
                        path,
                        file_size,
                        legacy_layout.storage_end,
                        raw_limit=suffix_raw_limit,
                    )
                else:
                    self._mark_legacy_pytorch_storage_layout_incomplete(scan_result, legacy_layout, path)
            else:
                with open(path, "rb") as handle:
                    scan_result = self._scan_standalone_stream(handle, file_size, source=path)
                if _matches_legacy_pytorch_preamble(control_probe):
                    self._mark_legacy_pytorch_control_layout_incomplete(scan_result, path)
                    legacy_control_incomplete = True
                detector_data = raw_data
            result.merge(scan_result)
            self._run_root_raw_detectors(
                detector_data,
                result,
                path,
                skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, detector_data),
                scan_binary_tail=False,
            )
            if suffix_raw_data and legacy_layout is not None and legacy_layout.storage_end is not None:
                self._run_root_raw_detectors(
                    suffix_raw_data,
                    result,
                    path,
                    position_offset=legacy_layout.storage_end,
                    skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, suffix_raw_data),
                    scan_binary_tail=False,
                )
            if (legacy_layout is None and not legacy_control_incomplete) or legacy_storage_valid:
                self._scan_file_binary_tail_if_needed(path, file_size, result)
        except OSError as error:
            self._record_file_read_failure(result, path, error)
            return result

        self._add_root_legacy_metadata_detectors(result, path)
        if legacy_layout is None and not legacy_control_incomplete:
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
