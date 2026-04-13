"""Rust-backed scanner for Python pickle serialized files."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import pickletools
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, ClassVar

from modelaudit_picklescan import PickleScanner as StandalonePickleScanner

from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_GLOBALS

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult, logger
from .picklescan_adapter import pickle_report_to_scan_result, scan_options_from_config

_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES = 64 * 1024
_ROOT_RAW_SCAN_LIMIT_BYTES = 8 * 1024 * 1024
_ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
_KNOWN_PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".dill", ".joblib"})
_PYTORCH_CONTAINER_EXTENSIONS = frozenset({".bin", ".pt", ".pth", ".ckpt", ".pkl"})
_BASE64_TOKEN_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
_MAX_RAW_ENCODED_TOKENS = 64
_MAX_RAW_ENCODED_BYTES = 1024 * 1024
_MAX_RAW_ENCODED_TOKEN_WITHOUT_SEED_BYTES = 4096
_BASE64_CODE_EXECUTION_SEEDS: tuple[bytes, ...] = (
    b"ZXZhbCg",  # eval(
    b"ZXhlYyg",  # exec(
    b"b3Muc3lzdGVt",  # os.system
    b"c3VicHJvY2Vzcw",  # subprocess
    b"X19pbXBvcnRfXw",  # __import__
)
_ENCODED_CODE_EXECUTION_PATTERNS: tuple[tuple[bytes, str], ...] = (
    (b"eval(", "eval"),
    (b"exec(", "exec"),
    (b"os.system", "os.system"),
    (b"subprocess", "subprocess"),
    (b"__import__", "__import__"),
)
_RAW_READ_CHUNK_BYTES = 1024 * 1024
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
_SECRET_SCAN_SEEDS: tuple[bytes, ...] = (
    b"://",
    b"-----begin ",
    b"akia",
    b"api",
    b"auth",
    b"aws_",
    b"az",
    b"bearer",
    b"client_secret",
    b"credential",
    b"eyj",
    b"gcp_api_key",
    b"github_pat_",
    b"ghp_",
    b"ghs_",
    b"glpat-",
    b"hooks.slack.com",
    b"key",
    b"mailgun",
    b"mongodb+srv://",
    b"npm_",
    b"openai_api_key",
    b"passwd",
    b"password",
    b"pwd",
    b"rg_",
    b"secret",
    b"seed phrase",
    b"sendgrid",
    b"sk-",
    b"sk_live_",
    b"slack://",
    b"sq0",
    b"stripe_live_",
    b"token",
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
    b"class ",
    b"compile",
    b"def ",
    b"eval",
    b"exec",
    b"lambda",
    b"os.",
    b"requests.",
    b"socket.",
    b"subprocess.",
    b"tf.",
    b"torch",
    b"torchscript",
    b"urllib.",
)
_EXPENSIVE_RAW_SCAN_SEEDS = tuple(dict.fromkeys(_SECRET_SCAN_SEEDS + _NETWORK_SCAN_SEEDS + _JIT_SCAN_SEEDS))


@dataclass(frozen=True)
class _RootStreamPayloadRead:
    payload: bytes
    truncated: bool
    read_limit: int


# Kept as small compatibility exports for callers/tests that inspect the policy.
# The scanner itself no longer uses Python opcode analysis; Rust owns detection.
ALWAYS_DANGEROUS_FUNCTIONS: frozenset[str] = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "execfile",
        "getattr",
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
        "pickle.load",
        "pickle.loads",
        "posix.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
)
ALWAYS_DANGEROUS_MODULES: frozenset[str] = frozenset(
    {
        "__builtin__",
        "__builtins__",
        "builtins",
        "ctypes",
        "marshal",
        "nt",
        "os",
        "posix",
        "runpy",
        "subprocess",
        "sys",
    }
)
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
        return data[1] in {2, 3, 4, 5}

    # Protocol 0 pickles often start directly with GLOBAL/INST/list/dict/tuple
    # structural opcodes. This is intentionally a sniff, not validation.
    return first in {ord("("), ord("]"), ord("}"), ord("c"), ord("i"), ord("l"), ord("d"), ord("t")}


def _contains_non_comment_token(
    data: bytes,
    token: bytes,
    documentation_spans: tuple[tuple[int, int], ...] = (),
) -> bool:
    start = 0
    while True:
        index = data.find(token, start)
        if index < 0:
            return False
        if _is_documentation_match(data, index, documentation_spans):
            start = index + len(token)
            continue

        after = index + len(token)
        while after < len(data) and data[after] in b" \t":
            after += 1
        if after >= len(data) or data[after] != ord("#"):
            return True

        start = index + len(token)


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
    pattern = rb"(?<![A-Za-z0-9_])" + re.escape(name) + rb"(?:\s|#[^\n]*\n)*\("
    return _contains_non_documentation_pattern(data, pattern, documentation_spans)


def _contains_module_attr(
    data: bytes,
    module: bytes,
    attr: bytes,
    documentation_spans: tuple[tuple[int, int], ...] = (),
) -> bool:
    pattern = rb"(?<![A-Za-z0-9_])" + re.escape(module) + rb"\s*\.\s*" + re.escape(attr) + rb"(?![A-Za-z0-9_])"
    return _contains_non_documentation_pattern(data, pattern, documentation_spans)


def _contains_any_seed(data: bytes, seeds: tuple[bytes, ...]) -> bool:
    lower = data.lower()
    return any(seed in lower for seed in seeds)


def _has_alnum_secret_shape(data: bytes) -> bool:
    has_digit = False
    has_alpha = False
    for byte in data[:_ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES]:
        if 48 <= byte <= 57:
            has_digit = True
        elif (65 <= byte <= 90) or (97 <= byte <= 122):
            has_alpha = True
        if has_digit and has_alpha:
            return True
    return False


def _has_domain_or_ip_shape(data: bytes) -> bool:
    if b"." not in data:
        return False
    has_digit = False
    has_alpha = False
    for byte in data[:_ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES]:
        if 48 <= byte <= 57:
            has_digit = True
        elif (65 <= byte <= 90) or (97 <= byte <= 122):
            has_alpha = True
        if has_digit and has_alpha:
            return True
    return has_digit


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


def _is_dangerous_module(module: str) -> bool:
    """Return whether a module path is always dangerous."""
    normalized = module.strip()
    return normalized in ALWAYS_DANGEROUS_MODULES or any(
        normalized.startswith(f"{dangerous}.") for dangerous in ALWAYS_DANGEROUS_MODULES
    )


def is_suspicious_global(module: str, name: str) -> bool:
    """Compatibility helper for checking pickle global policy."""
    normalized_module = module.strip()
    normalized_name = name.strip()
    full_name = f"{normalized_module}.{normalized_name}"
    if (
        full_name in ALWAYS_DANGEROUS_FUNCTIONS
        or normalized_name in ALWAYS_DANGEROUS_FUNCTIONS
        or _is_dangerous_module(normalized_module)
    ):
        safe_builtin = normalized_module in {"builtins", "__builtin__", "__builtins__"} and normalized_name in {
            "abs",
            "dict",
            "float",
            "int",
            "len",
            "list",
            "max",
            "min",
            "print",
            "set",
            "str",
            "tuple",
        }
        return not safe_builtin

    suspicious = SUSPICIOUS_GLOBALS.get(normalized_module)
    if isinstance(suspicious, (list, tuple, set, frozenset)):
        return normalized_name in suspicious
    if isinstance(suspicious, str):
        return normalized_name == suspicious
    return False


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
        report = StandalonePickleScanner().scan_file(path_obj)
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
    stack: list[str] = []
    dangerous_globals: list[str] = []
    protocol: int | None = None
    total_opcodes = 0

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
            if name == "GLOBAL":
                parts = _global_parts(arg)
                if parts is not None:
                    module, global_name = parts
                    if is_suspicious_global(module, global_name):
                        dangerous_globals.append(f"{module}.{global_name}")
                continue
            if name == "STACK_GLOBAL" and len(stack) >= 2:
                global_name = stack.pop()
                module = stack.pop()
                if is_suspicious_global(module, global_name):
                    dangerous_globals.append(f"{module}.{global_name}")
                continue
            if name not in {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}:
                stack.clear()
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
        if result.has_errors:
            return True
        if not self._rust_scan_completed_cleanly(result):
            return False

        expensive_limit = self._root_expensive_raw_scan_limit()
        if expensive_limit <= 0:
            return True
        return not _contains_any_seed(raw_data[:expensive_limit], _EXPENSIVE_RAW_SCAN_SEEDS)

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

        try:
            if not _stream_is_seekable(file_obj):
                return b""
            start_position = file_obj.tell()
            data = file_obj.read(read_size)
            file_obj.seek(start_position)
        except (AttributeError, OSError, ValueError):
            return b""
        return bytes(data)

    def _read_stream_payload_for_root(self, file_obj: BinaryIO, file_size: int | None) -> _RootStreamPayloadRead:
        limit = (
            self.max_file_read_size
            if self.max_file_read_size and self.max_file_read_size > 0
            else self._root_raw_scan_limit()
        )
        if limit <= 0:
            return _RootStreamPayloadRead(payload=b"", truncated=False, read_limit=0)

        read_target = limit if file_size is None else min(file_size, limit)
        if read_target <= 0:
            return _RootStreamPayloadRead(payload=b"", truncated=False, read_limit=limit)

        remaining = read_target
        chunks: list[bytes] = []
        bytes_read = 0
        while remaining > 0:
            self.check_interrupted()
            if self._check_timeout(allow_partial=True):
                break
            read_size = min(_RAW_READ_CHUNK_BYTES, remaining)
            chunk = file_obj.read(read_size)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            remaining -= len(chunk)
        return _RootStreamPayloadRead(
            payload=b"".join(chunks),
            truncated=file_size is not None and file_size > read_target and bytes_read >= read_target,
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
    ) -> None:
        """Run non-pickle-specific ModelAudit detectors over a bounded raw window."""
        if not data:
            return

        self._scan_raw_text_indicators(data, result, source)
        self._scan_encoded_text_indicators(data, result, source)
        self._analyze_cve_patterns(data, result, source)
        self._scan_binary_tail_if_needed(data, result, source)
        if skip_expensive_detectors:
            result.metadata["pickle_expensive_raw_detectors_skipped"] = True
            result.metadata["pickle_expensive_raw_detector_skip_reason"] = (
                "prior_critical_findings" if result.has_errors else "rust_complete_clean_no_expensive_raw_seeds"
            )
            return

        expensive_limit = self._root_expensive_raw_scan_limit()
        if expensive_limit <= 0:
            result.metadata["pickle_expensive_raw_detectors_skipped"] = True
            result.metadata["pickle_expensive_raw_detector_skip_reason"] = "disabled"
            return
        expensive_data = data[:expensive_limit]
        if len(expensive_data) < len(data):
            result.metadata["pickle_expensive_raw_detector_bytes_scanned"] = len(expensive_data)
            result.metadata["pickle_expensive_raw_detector_bytes_available"] = len(data)

        if _contains_any_seed(expensive_data, _SECRET_SCAN_SEEDS) or _has_alnum_secret_shape(expensive_data):
            self.check_for_embedded_secrets(expensive_data, result, source)
        else:
            result.metadata["pickle_secrets_raw_detector_skipped"] = True

        if _contains_any_seed(expensive_data, _JIT_SCAN_SEEDS):
            self.check_for_jit_script_code(expensive_data, result, model_type="pickle", context=source)
        else:
            result.metadata["pickle_jit_raw_detector_skipped"] = True

        if _contains_any_seed(expensive_data, _NETWORK_SCAN_SEEDS) or _has_domain_or_ip_shape(expensive_data):
            self.check_for_network_communication(expensive_data, result, context=source)
        else:
            result.metadata["pickle_network_raw_detector_skipped"] = True

    def _scan_binary_tail_if_needed(self, data: bytes, result: ScanResult, source: str) -> None:
        if Path(source).suffix.lower() not in _PYTORCH_CONTAINER_EXTENSIONS:
            return
        first_pickle_end_pos = result.metadata.get("first_pickle_end_pos")
        if not isinstance(first_pickle_end_pos, int) or first_pickle_end_pos <= 0 or first_pickle_end_pos >= len(data):
            return
        tail = data[first_pickle_end_pos:]
        lower_tail = tail.lower()
        for signature, label, rule_code in _BINARY_TAIL_SIGNATURES:
            haystack = lower_tail if signature.isascii() else tail
            needle = signature.lower() if signature.isascii() else signature
            offset = haystack.find(needle)
            if offset < 0:
                continue
            if signature == b"MZ" and not _looks_like_portable_executable(tail[offset : offset + 1024]):
                continue
            absolute_offset = first_pickle_end_pos + offset
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
                    "first_pickle_end_pos": first_pickle_end_pos,
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

    def _scan_raw_text_indicators(self, data: bytes, result: ScanResult, source: str) -> None:
        lower = data.lower()
        documentation_spans = _documentation_literal_spans(data)
        indicators: list[tuple[str, bytes, dict[str, Any]]] = []
        warning_indicators: list[tuple[str, bytes, dict[str, Any]]] = []
        if _contains_non_documentation_token(lower, b"import os", documentation_spans):
            warning_indicators.append(("import os", b"import os", {"associated_global": "os"}))
        if _contains_non_documentation_token(lower, b"importlib.import_module", documentation_spans) or (
            _contains_non_documentation_token(lower, b"import importlib", documentation_spans)
            and _contains_non_documentation_token(lower, b"import_module", documentation_spans)
        ):
            indicators.append(
                ("importlib.import_module", b"importlib", {"associated_global": "importlib.import_module"})
            )
        elif _contains_non_documentation_token(lower, b"importlib", documentation_spans):
            importlib_method_added = False
            for method in (b"import_module", b"reload", b"find_loader", b"load_module"):
                if _contains_non_documentation_token(
                    lower,
                    method,
                    documentation_spans,
                ) and _contains_non_comment_token(lower, b"importlib", documentation_spans):
                    label = f"importlib.{method.decode('ascii')}"
                    indicators.append((label, b"importlib", {"associated_global": label}))
                    importlib_method_added = True
                    break
            if (
                not importlib_method_added
                and _contains_non_comment_token(lower, b"importlib", documentation_spans)
                and _contains_non_documentation_token(lower, b"import ", documentation_spans)
            ):
                indicators.append(("importlib", b"importlib", {"associated_global": "importlib"}))
        if _contains_call_token(lower, b"eval", documentation_spans):
            indicators.append(("eval", b"eval", {"associated_global": "builtins.eval"}))
        if _contains_call_token(lower, b"exec", documentation_spans):
            indicators.append(("exec", b"exec", {"associated_global": "builtins.exec"}))
        if _contains_module_attr(lower, b"webbrowser", b"open", documentation_spans):
            indicators.append(("webbrowser.open", b"webbrowser", {"associated_global": "webbrowser.open"}))
        elif _contains_non_documentation_token(lower, b"webbrowser", documentation_spans):
            for method in (b"open", b"open_new", b"open_new_tab"):
                if _contains_non_documentation_token(
                    lower,
                    method,
                    documentation_spans,
                ) and _contains_non_comment_token(lower, b"webbrowser", documentation_spans):
                    label = f"webbrowser.{method.decode('ascii')}"
                    indicators.append((label, b"webbrowser", {"associated_global": label}))
                    break
        if _contains_non_documentation_token(lower, b"runpy", documentation_spans):
            runpy_global = (
                "runpy.run_module"
                if _contains_non_documentation_token(lower, b"run_module", documentation_spans)
                else "runpy"
            )
            indicators.append((runpy_global, b"runpy", {"associated_global": runpy_global}))
        if _contains_non_documentation_token(lower, b"__import__", documentation_spans):
            indicators.append(("__import__", b"__import__", {"associated_global": "builtins.__import__"}))
        for module_token, associated_global in (
            (b"cos\nsystem\n", "os.system"),
            (b"cposix\nsystem\n", "posix.system"),
            (b"cnt\nsystem\n", "nt.system"),
        ):
            if _contains_non_documentation_token(lower, module_token, documentation_spans):
                indicators.append((associated_global, module_token, {"associated_global": associated_global}))
        if _contains_module_attr(lower, b"os", b"system", documentation_spans):
            indicators.append(("os.system", b"os.system", {"associated_global": "os.system"}))
        if _contains_module_attr(lower, b"posix", b"system", documentation_spans):
            indicators.append(("posix.system", b"posix.system", {"associated_global": "posix.system"}))
        if _contains_module_attr(lower, b"nt", b"system", documentation_spans):
            indicators.append(("nt.system", b"nt.system", {"associated_global": "nt.system"}))
        if _contains_module_attr(lower, b"os", b"popen", documentation_spans):
            indicators.append(("os.popen", b"os.popen", {"associated_global": "os.popen"}))
        if _contains_non_documentation_pattern(
            lower,
            rb"(?<![A-Za-z0-9_])os\s*\.\s*spawn",
            documentation_spans,
        ):
            indicators.append(("os.spawn", b"os.spawn", {"associated_global": "os.spawn"}))
        for commands_api in (b"commands.getoutput", b"commands.getstatusoutput"):
            if _contains_non_documentation_token(lower, commands_api, documentation_spans):
                label = commands_api.decode("ascii")
                indicators.append((label, commands_api, {"associated_global": label}))
        for subprocess_api in (b"subprocess.call", b"subprocess.run", b"subprocess.popen"):
            if _contains_non_documentation_token(lower, subprocess_api, documentation_spans):
                label = subprocess_api.decode("ascii")
                indicators.append((label, subprocess_api, {"associated_global": label}))

        for label, _token, details in indicators:
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message=f"Raw pickle content references dangerous helper: {label}",
                severity=IssueSeverity.CRITICAL,
                location=source,
                details={"pattern": label, "source": "bounded_raw_pickle_window", **details},
                rule_code="S201",
            )
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

        if _contains_non_documentation_token(lower, b"__import__", documentation_spans):
            result.add_check(
                name="Pickle Raw Content Detection",
                passed=False,
                message="Legacy dangerous pattern detected: __import__",
                severity=IssueSeverity.CRITICAL,
                location=source,
                details={
                    "pattern": "__import__",
                    "source": "bounded_raw_pickle_window",
                    "associated_global": "builtins.__import__",
                },
                rule_code="S104",
            )

        for label, token, details in warning_indicators:
            if not _contains_non_documentation_token(lower, token, documentation_spans):
                continue
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
                    },
                    rule_code="S604",
                )
                result.add_check(
                    name="Encoded Code Execution Pattern Detection",
                    passed=False,
                    message=f"Legacy encoded dangerous pattern detected: {label}",
                    severity=IssueSeverity.CRITICAL,
                    location=source,
                    details={
                        "encoding": "base64",
                        "pattern": label,
                        "source": "bounded_raw_pickle_window",
                        "decoded_size": len(decoded),
                        "legacy_rule_alias": True,
                    },
                    rule_code="S104",
                )
                return

    def _analyze_cve_patterns(self, data: bytes, result: ScanResult, source: str | None = None) -> None:
        """Add CVE attribution checks from a bounded raw pickle scan window."""
        try:
            from modelaudit.detectors.cve_patterns import analyze_cve_patterns
        except ImportError:
            return

        text = data.decode("utf-8", errors="ignore")
        try:
            attributions = analyze_cve_patterns(text, data)
        except Exception as error:
            logger.warning("Error checking pickle CVE patterns: %s", error)
            return

        opcode_summary = _pickle_opcode_summary(data)
        opcode_counts = opcode_summary.get("opcode_counts", {})
        has_setitem_opcode = isinstance(opcode_counts, dict) and (
            opcode_counts.get("SETITEM", 0) > 0 or opcode_counts.get("SETITEMS", 0) > 0
        )

        if (
            b"_rebuild_tensor" in data
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

        pickle_parse_failed = "parse_error" in opcode_summary
        attributions = [
            attribution
            for attribution in attributions
            if not (
                attribution.cve_id == "CVE-2026-24747"
                and (
                    (not has_setitem_opcode and not pickle_parse_failed)
                    or _rebuild_tensor_indicators_are_documentation_literals(data)
                )
            )
        ]

        dangerous_globals = opcode_summary.get("dangerous_globals", [])
        has_dangerous_system_global = isinstance(dangerous_globals, list) and any(
            global_ref in {"os.system", "posix.system", "nt.system"} for global_ref in dangerous_globals
        )
        emitted_cve_rule_keys: set[tuple[str, str]] = set()
        if has_setitem_opcode and has_dangerous_system_global:
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

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        metadata = super().extract_metadata(file_path)
        metadata["deserialization_skipped"] = True
        metadata["safe_loading"] = False
        metadata["reason"] = "pickle metadata is extracted without deserializing payloads"

        file_size = self.get_file_size(file_path)
        configured_limit = self.config.get("max_metadata_pickle_read_size", _NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)
        try:
            read_limit = int(configured_limit)
        except (TypeError, ValueError, OverflowError):
            metadata["extraction_error"] = "max_metadata_pickle_read_size must be greater than 0"
            return metadata

        max_limit = 10 * 1024 * 1024
        if read_limit <= 0:
            metadata["extraction_error"] = "max_metadata_pickle_read_size must be greater than 0"
            return metadata
        if read_limit > max_limit:
            metadata["extraction_error"] = f"max_metadata_pickle_read_size too large (max: {max_limit})"
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
        if _stream_is_seekable(file_obj):
            start_position = file_obj.tell()
            result = self._scan_standalone_stream(file_obj, standalone_size, source=source)
            file_obj.seek(start_position)
            raw_data = self._read_root_raw_scan_window_from_stream(file_obj, standalone_size)
            if standalone_size is not None and len(raw_data) == standalone_size:
                self._add_stream_integrity_check(raw_data, result, source)
        else:
            stream_read = self._read_stream_payload_for_root(file_obj, standalone_size)
            payload = stream_read.payload
            rust_stream_size = len(payload) if stream_read.truncated else standalone_size
            result = self._scan_standalone_stream(io.BytesIO(payload), rust_stream_size, source=source)
            self._add_stream_integrity_check(payload, result, source)
            self._add_stream_truncation_check(stream_read, result, source, standalone_size)
            raw_data = self._raw_window_from_payload(payload, self._root_raw_scan_limit())
        self._run_root_raw_detectors(
            raw_data,
            result,
            source,
            skip_expensive_detectors=self._should_skip_expensive_raw_detectors(result, raw_data),
        )
        self._add_root_legacy_metadata_detectors(result, source)
        return result

    def scan(self, path: str) -> ScanResult:
        """Scan a pickle file for suspicious content."""
        self._prepare_scan_context(path)

        path_check = self._check_path(path)
        if path_check:
            return path_check

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
            )
        except OSError as error:
            result.add_check(
                name="Pickle File Open",
                passed=False,
                message=f"Error opening pickle file: {error!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "category": "pickle_file_open_failed",
                    "exception": str(error),
                    "exception_type": type(error).__name__,
                },
            )
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "pickle_file_open_failed"
            result.finish(success=False)
            return result

        self._add_root_legacy_metadata_detectors(result, path)
        result.finish(success=scan_result.success)
        return result
