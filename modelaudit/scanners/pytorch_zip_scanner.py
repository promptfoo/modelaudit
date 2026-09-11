"""Scanner for PyTorch zip-archived model files (.pt, .pth)."""

import ast
import base64
import binascii
import codecs
import hashlib
import importlib.machinery
import io
import json
import logging
import os
import pickletools
import posixpath
import re
import stat
import struct
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import suppress
from copy import copy, deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from ..detectors.suspicious_symbols import CVE_COMBINED_PATTERNS, SUSPICIOUS_STRING_PATTERNS
from ..scanner_results import (
    ACTIONABLE_FAILED_CHECKS_METADATA_KEY,
    INCONCLUSIVE_SCAN_OUTCOME,
    MEMBER_FILE_HASHES_METADATA_KEY,
    MEMBER_FILE_HASHES_OMITTED_METADATA_KEY,
    MEMBER_FILE_HASHES_TOTAL_METADATA_KEY,
    MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY,
    RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY,
    RAW_DETECTOR_FAILURES_METADATA_KEY,
    mark_inconclusive_scan_result,
)
from ..scanner_selection import add_scanner_selection_skip_check, embedded_pickle_scanner
from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.file.detection import (
    PROTO0_1_IGNORABLE_TRAILING_BYTES,
    PROTO0_1_MAX_PROBE_BYTES,
    PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES,
    PROTO0_1_START_BYTES,
    PROTO0_1_TRIVIAL_LEADING_OPCODES,
    _looks_like_proto0_or_1_pickle,
)
from ..utils.repository_context import (
    RepositoryFileInventory,
    repository_file_inventory_context_from_config,
    repository_has_safetensors_sibling,
    safetensors_alternative_filenames_for_member,
)
from ._archive_config import get_archive_depth
from ._archive_locations import rewrite_extracted_member_location
from ._evidence_redaction import redact_evidence_string, redact_untrusted_error_message
from .archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY, scan_nested_file
from .archive_member_security import (
    executable_archive_member_content_rule_code_from_bytes,
    executable_archive_member_name_rule_code,
    probe_executable_archive_member_signature,
)
from .base import BaseScanner, Check, CheckStatus, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner, _pickle_literal_url_stripped_scan_view
from .picklescan_adapter import apply_pickle_member_context
from .pytorch_zip_support import (
    RelaxedZipCrcTracker,
    find_zip_entry,
    get_zip_member_name,
    get_zip_member_names,
    read_member_bytes,
    read_member_prefix,
    read_member_to_spooled_file,
    read_zip_header,
)
from .zip_scanner import ZipPreflightRejected

logger = logging.getLogger(__name__)
_INSTALLED_PYTORCH_VERSION_UNSET = object()
_TORCHSCRIPT_DEBUG_PAYLOAD_MARKER = b"FORMAT_WITH_STRING_TABLE"
_TORCHSCRIPT_DEBUG_PREFIX_BYTES = 256
_TORCHSCRIPT_SOURCE_MAX_BYTES = 1024 * 1024
_TORCHSCRIPT_GENERATED_CLASS_PATTERN = re.compile(r"(?m)^class\s+[A-Za-z_][A-Za-z0-9_]*\(Module\):\s*$")
_TORCHSCRIPT_GENERATED_METHOD_PATTERN = re.compile(r"(?m)^\s+def\s+\w+\(self:\s+__torch__\.")
_EXECUTABLE_MEMBER_PROBE_BYTES = 1024
_TORCHSCRIPT_FORBIDDEN_SOURCE_PATTERN = re.compile(
    r"(?im)(?:^\s*(?:import|from)\s+|\b(?:__import__|eval|exec|compile|open)\s*\(|\b(?:os|subprocess|socket|requests)\s*\.)"
)
_PICKLE_CODE_EXECUTION_OPCODE_RISKS = (
    ("REDUCE", "__reduce__ method exploitation"),
    ("INST", "Class instantiation code execution"),
    ("OBJ", "Object creation code execution"),
    ("NEWOBJ", "New-style object creation"),
    ("NEWOBJ_EX", "Extended new-style object creation"),
    ("STACK_GLOBAL", "Dynamic import and attribute access"),
    ("GLOBAL", "Module import and attribute access"),
    ("BUILD", "__setstate__ method exploitation"),
)
_PICKLE_NESTED_EXECUTION_OPCODES = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})
_PICKLE_MEMBER_SEVERITY_RANK = {
    "debug": 0,
    "info": 1,
    "warning": 2,
    "critical": 3,
}
_PICKLE_MEMBER_VERDICT_RANK = {
    "clean": 0,
    "suspicious": 2,
    "malicious": 3,
}
_PICKLE_SECURITY_RELEVANT_OPCODES = frozenset(
    {
        "BINPERSID",
        "BUILD",
        "EXT1",
        "EXT2",
        "EXT4",
        "GLOBAL",
        "INST",
        "NEWOBJ",
        "NEWOBJ_EX",
        "OBJ",
        "PERSID",
        "REDUCE",
        "STACK_GLOBAL",
    }
)
_PICKLE_OPCODE_BYTES = frozenset(ord(opcode.code) for opcode in pickletools.opcodes)
_PROTO0_1_LITERAL_OPCODES = frozenset(
    {
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "UNICODE",
        "BINUNICODE",
        "BINUNICODE8",
        "SHORT_BINUNICODE",
    }
)
_PICKLE_BINARY_BYTE_LITERAL_OPCODES = frozenset({"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"})
_PICKLE_LITERAL_OPCODES = _PROTO0_1_LITERAL_OPCODES | _PICKLE_BINARY_BYTE_LITERAL_OPCODES
_BASE64_NESTED_LITERAL_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/_-][A-Za-z0-9+/_\-\s\r\n\t]{7,}={0,2}")
_HEX_NESTED_LITERAL_TOKEN_RE = re.compile(rb"[0-9A-Fa-f][0-9A-Fa-f\s\r\n\t]{15,}")
_RAW_NESTED_TEXT_SECURITY_PICKLE_START_BYTES = b"\x80(cioRbP\x82\x83\x84"
_RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES = b"\x8c\x8d\x95"
_RAW_NESTED_SECURITY_PICKLE_START_BYTES = (
    _RAW_NESTED_TEXT_SECURITY_PICKLE_START_BYTES + _RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES
)
_BINARY_EXTENSION_SECURITY_OPCODE_BYTES = b"\x82\x83\x84"
_BINARY_EXTENSION_OPCODE_OPERAND_BYTES = {0x82: 1, 0x83: 2, 0x84: 4}
_BINARY_EXTENSION_OPCODE_FOLLOWER_BYTES = b".)Rq\x85\x86\x87\x94\x95"
_BINARY_SECURITY_OPCODE_REQUIRING_EXISTING_STACK_BYTES = b"\x81\x92\x93"
_MAX_RAW_NESTED_PICKLE_CANDIDATES = 64
_MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES = 8 * 1024
_PROTO0_GLOBAL_OR_INST_PREFIX_WITHOUT_NEWLINE_RE = re.compile(rb"[ci][A-Za-z_][A-Za-z0-9_.]*")
_REPEATED_PROTO0_INT_STREAM_RE = re.compile(rb"(?:I[+-]?\d+\n\.)+")
_PROTO0_GLOBAL_NAME_START_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_PROTO0_GLOBAL_NAME_BYTES = _PROTO0_GLOBAL_NAME_START_BYTES | frozenset(b"0123456789.")
_RAW_NESTED_SECURITY_PICKLE_TEXT_MARKERS = (
    b"builtins\neval\n",
    b"builtins\nexec\n",
    b"__builtin__\neval\n",
    b"__builtin__\nexec\n",
    b"os\npopen\n",
    b"os\nsystem\n",
    b"nt\npopen\n",
    b"nt\nsystem\n",
    b"posix\npopen\n",
    b"posix\nsystem\n",
    b"subprocess\nPopen\n",
    b"subprocess\ncall\n",
    b"subprocess\ncheck_call\n",
    b"subprocess\ncheck_output\n",
    b"subprocess\ngetoutput\n",
    b"subprocess\ngetstatusoutput\n",
    b"subprocess\nrun\n",
    b"commands\ngetoutput\n",
    b"commands\ngetstatusoutput\n",
)
_PICKLE_ENGINE_MAGIC_METHOD_LITERAL_PATTERN = r"(?<!\w)__(?:call|code|getattribute)__(?!\w)"
_SUSPICIOUS_LITERAL_TEXT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (*SUSPICIOUS_STRING_PATTERNS, _PICKLE_ENGINE_MAGIC_METHOD_LITERAL_PATTERN)
)
_STORAGE_LITERAL_TEXT_ROUTE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        r"\b(?:compile|eval|exec)\s*(?:\\\r?\n\s*)*\(",
        r"__import__\s*(?:\\\r?\n\s*)*\(",
        r"\bimportlib\s*(?:\\\r?\n\s*)*\.\s*(?:import_module|__import__)\s*\(",
        r"\bos\s*(?:\\\r?\n\s*)*\.\s*(?:\\\r?\n\s*)*(?:system|popen|spawn[a-z]*)\s*(?:\.__call__)?\s*\(",
        r"\bsubprocess\s*(?:\\\r?\n\s*)*\.\s*(?:Popen|call|check_output|run|check_call)\s*\(",
        r"\bbase64\s*(?:\\\r?\n\s*)*\.\s*(?:b64decode|decode)\s*\(",
        r"\b(?:pickle|cloudpickle|joblib)\s*(?:\\\r?\n\s*)*\.\s*(?:_pickle_load|load|loads)\s*\(",
        r"\bcopyreg\s*(?:\\\r?\n\s*)*\.\s*(?:add_extension|remove_extension)\s*\(",
        r"getattr\s*\(\s*\w+\s*,\s*['\"](?:system|popen|spawn|exec|eval|call|run|Popen)['\"]",
    )
)
_BASE64_LITERAL_TEXT_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/_-][A-Za-z0-9+/_\-\s\r\n\t]{7,}={0,2}")
_HEX_LITERAL_TEXT_TOKEN_RE = re.compile(rb"(?:[0-9A-Fa-f]{2}[\s\r\n\t]*){4,}")
_MAX_STORAGE_LITERAL_TEXT_CANDIDATES = 64
_MAX_STORAGE_LITERAL_DECODED_TEXT_BYTES = 64 * 1024
_STORAGE_LITERAL_DECODED_TEXT_WINDOW_OVERLAP_BYTES = 1024
_MAX_STORAGE_LITERAL_DECODED_TEXT_WINDOWS = 16
_MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES = ((_MAX_STORAGE_LITERAL_DECODED_TEXT_BYTES + 2) // 3) * 4
_STORAGE_LITERAL_BASE64_DECODE_INPUT_OVERLAP_BYTES = ((_STORAGE_LITERAL_DECODED_TEXT_WINDOW_OVERLAP_BYTES + 2) // 3) * 4
_STORAGE_LITERAL_BASE64_DECODE_INPUT_STRIDE_BYTES = (
    _MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES - _STORAGE_LITERAL_BASE64_DECODE_INPUT_OVERLAP_BYTES
)


@dataclass(frozen=True)
class _PickleGlobalRef:
    module: str
    name: str


@dataclass(frozen=True)
class _PytorchStorageRef:
    module: str
    name: str
    location: str
    element_count: int
    item_size: int | None


@dataclass(frozen=True)
class _PytorchStorageReferenceParse:
    referenced_keys: set[str]
    storage_refs_by_key: dict[str, _PytorchStorageRef]
    parse_complete: bool
    all_persistent_ids_are_pytorch_storage: bool


@dataclass(frozen=True)
class _ValidatedPytorchStorageDataPklMembers:
    storage_keys_by_data_pkl: dict[str, set[str]]
    storage_probe_keys_by_data_pkl: dict[str, set[str]]
    persistent_id_downgrade_keys_by_data_pkl: dict[str, set[str]]
    storage_member_sizes_by_data_pkl: dict[str, dict[str, int]]


_TORCHSCRIPT_FORBIDDEN_AST_NAMES: frozenset[str] = frozenset(
    {
        "__builtins__",
        "__class__",
        "__dict__",
        "__getattribute__",
        "__globals__",
        "__import__",
        "__mro__",
        "__subclasses__",
        "breakpoint",
        "compile",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "globals",
        "input",
        "locals",
        "load_library",
        "open",
        "print",
        "setattr",
        "vars",
    }
)
_TORCHSCRIPT_UNSAFE_DEFINITION_EXPR_NODES: tuple[type[ast.AST], ...] = (
    ast.Await,
    ast.Call,
    ast.DictComp,
    ast.GeneratorExp,
    ast.Lambda,
    ast.ListComp,
    ast.NamedExpr,
    ast.SetComp,
    ast.Yield,
    ast.YieldFrom,
)
_TORCHSCRIPT_UNSAFE_BODY_NODES: tuple[type[ast.AST], ...] = (
    ast.AsyncFor,
    ast.AsyncFunctionDef,
    ast.AsyncWith,
    ast.Await,
    ast.Delete,
    ast.Global,
    ast.Import,
    ast.ImportFrom,
    ast.Lambda,
    ast.Nonlocal,
    ast.Raise,
    ast.Try,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)
_PICKLE_BINARY_PROTOCOL_PREFIXES: tuple[bytes, ...] = (
    b"\x80\x01",
    b"\x80\x02",
    b"\x80\x03",
    b"\x80\x04",
    b"\x80\x05",
)
_PICKLE_DISCOVERY_SHORT_PROBE_BYTES = 16
_TRUSTED_STORAGE_PICKLE_PROBE_BYTES = 4 * 1024
_PICKLE_FRAME_OPCODE = b"\x95"
_PICKLE_FRAME_OPCODE_BYTES = 9
_PROTO0_1_TEXT_WHITESPACE_BYTES = b" \t\r\n"
_PICKLE_DISCOVERY_PADDING_PROBE_BYTES = 256 * 1024
_PICKLE_DISCOVERY_NUL_PADDING_VERIFY_CHUNK_BYTES = 64 * 1024
_PICKLE_DISCOVERY_PADDING_PROBE_BUDGET_BYTES = 4 * 1024 * 1024
_PICKLE_DISCOVERY_NUL_PADDING_VERIFY_BUDGET_BYTES = 64 * 1024 * 1024
_PICKLE_INCOMPLETE_FRAME_MIN_PAYLOAD_OPCODES = 4
_PYTORCH_STORAGE_TRUST_MAX_OPCODES = 100_000
_PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH = 1024
_PYTORCH_STORAGE_TRUST_MAX_MEMO_ENTRIES = 100_000
_PYTORCH_STORAGE_TRUST_MAX_TUPLE_WIDTH = 64
_PYTORCH_STORAGE_TRUST_MAX_REFERENCED_KEYS = 10_000
_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX = 2**63 - 1
_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT = str(_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX)
_JIT_SCAN_MEMBER_MAX_BYTES = 32 * 1024 * 1024
_PYTORCH_ZIP_INTEGRITY_PREFIX_BYTES = 8 * 1024 * 1024
_PYTORCH_ZIP_HASH_CHUNK_BYTES = 1024 * 1024
_PICKLE_DISCOVERY_LONG_PROBE_BYTES = PROTO0_1_MAX_PROBE_BYTES
_NESTED_ZIP_HEADER_PROBE_BYTES = 4
_PYTORCH_STORAGE_GLOBAL_NAMES = frozenset(
    {
        "BFloat16Storage",
        "BoolStorage",
        "ByteStorage",
        "CharStorage",
        "ComplexDoubleStorage",
        "ComplexFloatStorage",
        "DoubleStorage",
        "FloatStorage",
        "HalfStorage",
        "IntStorage",
        "LongStorage",
        "QInt32Storage",
        "QInt8Storage",
        "QUInt8Storage",
        "QUInt4x2Storage",
        "QUInt2x4Storage",
        "ShortStorage",
        "UntypedStorage",
    }
)
_PYTORCH_STORAGE_GLOBALS = frozenset(
    (module, name) for module in ("torch", "torch.storage") for name in _PYTORCH_STORAGE_GLOBAL_NAMES
)
_PYTORCH_STORAGE_ITEM_SIZES = {
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
    "ShortStorage": 2,
    "UntypedStorage": 1,
}
_PYTORCH_STORAGE_REDACTED_BINPERSID_PREVIEW = re.compile(
    r"^tuple\(str_span\(len=7\), global:(?P<module>[A-Za-z_][A-Za-z0-9_.]*)\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r", str_span\(len=(?P<key_len>[0-9]+)\), str_span\(len=(?P<device_len>[0-9]+)\), int:(?P<size>[0-9]+)\)$"
)
_ZIP_LOCAL_FILE_SIGNATURES: tuple[bytes, ...] = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
CRITICAL_SYSTEM_PATHS: tuple[str, ...] = (
    "/etc",
    "/bin",
    "/usr",
    "/var",
    "/lib",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/sbin",
    "C:\\Windows",
)
_WINDOWS_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{index}" for index in range(1, 10)} | {f"LPT{index}" for index in range(1, 10)}
)
_WINDOWS_DEVICE_SUPERSCRIPT_DIGITS = str.maketrans({"\u00b9": "1", "\u00b2": "2", "\u00b3": "3"})
_UNIX_MODE_ZIP_CREATOR_SYSTEMS: frozenset[int] = frozenset({3, 19})


def _targets_windows_reserved_device(target: str) -> bool:
    """Return whether any target component names a reserved Windows device."""
    for component in target.replace("\\", "/").split("/"):
        if not component or component in {".", ".."}:
            continue
        basename = component.split(":", 1)[0].split(".", 1)[0].rstrip(" ").upper()
        if basename.translate(_WINDOWS_DEVICE_SUPERSCRIPT_DIGITS) in _WINDOWS_RESERVED_DEVICE_NAMES:
            return True
    return False


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    """Return whether the entry uses Unix mode metadata to declare a symlink."""
    return info.create_system in _UNIX_MODE_ZIP_CREATOR_SYSTEMS and stat.S_ISLNK(info.external_attr >> 16)


@dataclass(frozen=True)
class _PyTorchVersionCveMetadata:
    """Metadata for PyTorch version-gated CVE checks."""

    cve_id: str
    check_name: str
    fix_version: str
    fix_version_parts: tuple[int, int, int]
    vulnerable_message_suffix: str
    description: str
    remediation: str
    cvss: float
    cwe: str
    why: str


def _build_pytorch_version_cve_metadata(
    *,
    cve_id: str,
    check_name: str,
    fix_version: str,
    fix_version_parts: tuple[int, int, int],
    vulnerable_message_suffix: str,
    why: str,
) -> _PyTorchVersionCveMetadata:
    """Build PyTorch version-check metadata from the canonical CVE registry."""
    cve_info = CVE_COMBINED_PATTERNS[cve_id]
    cvss = cve_info.get("cvss", 0.0)
    return _PyTorchVersionCveMetadata(
        cve_id=cve_id,
        check_name=check_name,
        fix_version=fix_version,
        fix_version_parts=fix_version_parts,
        vulnerable_message_suffix=vulnerable_message_suffix,
        description=str(cve_info["description"]),
        remediation=str(cve_info["remediation"]),
        cvss=float(cvss) if isinstance(cvss, int | float) else 0.0,
        cwe=str(cve_info["cwe"]),
        why=why,
    )


class PyTorchZipScanner(BaseScanner):
    """Scanner for PyTorch ZIP-based model files (.pt, .pth, .ckpt, .pkl, .bin)."""

    name = "pytorch_zip"
    description = "Scans PyTorch model files for suspicious code in embedded pickles"
    # Include .pkl and .ckpt since torch.save() commonly uses ZIP containers for both.
    supported_extensions: ClassVar[list[str]] = [".pt", ".pth", ".ckpt", ".pkl", ".bin"]

    # CVE-2025-32434 constants
    CVE_2025_32434_ID: ClassVar[str] = "CVE-2025-32434"
    CVE_2025_32434_FIX_VERSION: ClassVar[str] = "2.6.0"
    CVE_2025_32434_FIX_VERSION_PARTS: ClassVar[tuple[int, int, int]] = (2, 6, 0)
    CVE_2025_32434_DESCRIPTION: ClassVar[str] = "RCE when loading models with torch.load(weights_only=True)"

    # CVE-2026-24747 constants
    CVE_2026_24747_ID: ClassVar[str] = "CVE-2026-24747"
    CVE_2026_24747_FIX_VERSION: ClassVar[str] = "2.10.0"
    CVE_2026_24747_FIX_VERSION_PARTS: ClassVar[tuple[int, int, int]] = (2, 10, 0)
    CVE_2026_24747_DESCRIPTION: ClassVar[str] = (
        "weights_only=True bypass via SETITEM abuse and tensor metadata mismatch"
    )

    # CVE-2022-45907 constants
    CVE_2022_45907_ID: ClassVar[str] = "CVE-2022-45907"
    CVE_2022_45907_FIX_VERSION: ClassVar[str] = "1.13.1"

    # CVE-2024-5480 constants
    CVE_2024_5480_ID: ClassVar[str] = "CVE-2024-5480"
    CVE_2024_5480_FIX_VERSION: ClassVar[str] = "2.2.3"

    # CVE-2024-48063 constants
    CVE_2024_48063_ID: ClassVar[str] = "CVE-2024-48063"
    CVE_2024_48063_FIX_VERSION: ClassVar[str] = "2.5.0"

    _PYTORCH_VERSION_CVE_METADATA: ClassVar[dict[str, _PyTorchVersionCveMetadata]] = {
        CVE_2022_45907_ID: _build_pytorch_version_cve_metadata(
            cve_id=CVE_2022_45907_ID,
            check_name="CVE-2022-45907 PyTorch Version Check",
            fix_version=CVE_2022_45907_FIX_VERSION,
            fix_version_parts=(1, 13, 1),
            vulnerable_message_suffix="(unsafe eval() in torch.jit.annotations.parse_type_line)",
            why=(
                "CVE-2022-45907 (CVSS 9.8) allows arbitrary code execution via crafted type "
                "annotations processed by torch.jit.annotations.parse_type_line, which passes "
                "user-controlled strings to Python's eval()."
            ),
        ),
        CVE_2024_5480_ID: _build_pytorch_version_cve_metadata(
            cve_id=CVE_2024_5480_ID,
            check_name="CVE-2024-5480 PyTorch Version Check",
            fix_version=CVE_2024_5480_FIX_VERSION,
            fix_version_parts=(2, 2, 3),
            vulnerable_message_suffix="(RPC framework arbitrary function execution via PythonUDF)",
            why=(
                "CVE-2024-5480 (CVSS 10.0) allows remote code execution because "
                "torch.distributed.rpc does not validate function calls, enabling an "
                "attacker to send eval/exec as PythonUDF payloads."
            ),
        ),
        CVE_2024_48063_ID: _build_pytorch_version_cve_metadata(
            cve_id=CVE_2024_48063_ID,
            check_name="CVE-2024-48063 PyTorch Version Check",
            fix_version=CVE_2024_48063_FIX_VERSION,
            fix_version_parts=(2, 5, 0),
            vulnerable_message_suffix="(RemoteModule deserialization RCE via pickle)",
            why=(
                "CVE-2024-48063 (CVSS 9.8) allows RCE through deserialization of "
                "torch.distributed.rpc.RemoteModule objects, which use pickle internally. "
                "Disputed as 'intended behavior' but still poses a critical risk."
            ),
        ),
    }

    # Security limits for archive manipulation protection
    MAX_COMPRESSION_RATIO: ClassVar[int] = 100  # 100:1 compression ratio threshold
    MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE: ClassVar[int] = 1024 * 1024
    MAX_ARCHIVE_ENTRIES: ClassVar[int] = 10000  # Maximum number of entries in archive
    MAX_SYMLINK_TARGET_BYTES: ClassVar[int] = 64 * 1024
    MAX_SYMLINK_TARGET_COMPRESSED_BYTES: ClassVar[int] = 128 * 1024
    MAX_VERSION_METADATA_BYTES: ClassVar[int] = 4096
    MAX_VERSION_JSON_BYTES: ClassVar[int] = 10 * 1024 * 1024
    MAX_SAFETENSORS_HEADER_BYTES: ClassVar[int] = 10 * 1024 * 1024
    DEFAULT_VERSION_PICKLE_PROBE_BYTES: ClassVar[int] = 1024 * 1024
    DEFAULT_MAX_NESTED_ZIP_DEPTH: ClassVar[int] = 5
    DEFAULT_MAX_BLACKLIST_SCAN_BYTES: ClassVar[int] = 100 * 1024 * 1024
    MAX_STORAGE_REFERENCE_DATA_PICKLE_BYTES: ClassVar[int] = 10 * 1024 * 1024
    MAX_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES: ClassVar[int] = 64 * 1024 * 1024
    BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_zip_blacklist_member_size_limit"
    BLACKLIST_READ_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_zip_blacklist_member_read_failed"
    ENTRY_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_zip_entry_limit"
    LOCAL_ENTRY_LIMIT_METADATA_KEY: ClassVar[str] = "pytorch_zip_local_entry_limit_exceeded"
    VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_zip_version_metadata_size_limit"
    VERSION_METADATA_READ_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_zip_version_metadata_read_failed"
    STORAGE_REFERENCE_VALIDATION_INCONCLUSIVE_REASON: ClassVar[str] = (
        "pytorch_zip_storage_reference_validation_incomplete"
    )
    STORAGE_REFERENCE_MISSING_MEMBERS_INCONCLUSIVE_REASON: ClassVar[str] = (
        "pytorch_zip_storage_reference_missing_members"
    )
    RUNTIME_VERSION_UNKNOWN_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_runtime_version_unknown"
    SCAN_INCONCLUSIVE_REASON: ClassVar[str] = "pytorch_zip_scan_incomplete"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        pickle_scanner, self.scanner_selection = embedded_pickle_scanner(self.config, PickleScanner)
        self.pickle_scanner: PickleScanner | None = pickle_scanner
        self.current_file_path = ""  # Will be set when scanning files
        self._relaxed_crc_tracker = RelaxedZipCrcTracker()
        self._repository_inventory_context: RepositoryFileInventory = repository_file_inventory_context_from_config(
            self.config
        )
        self._installed_pytorch_version_cache: object = _INSTALLED_PYTORCH_VERSION_UNSET
        self._installed_pytorch_metadata_path: str | None = None
        # Configurable limits (can override class defaults via config)
        self.max_compression_ratio = self.config.get("max_compression_ratio", self.MAX_COMPRESSION_RATIO)
        self.min_compression_bomb_uncompressed_size = self._normalize_positive_int_config(
            self.config.get("min_compression_bomb_uncompressed_size"),
            self.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE,
        )
        self.max_archive_entries = self._normalize_positive_int_config(
            self.config.get("max_archive_entries"),
            self.MAX_ARCHIVE_ENTRIES,
        )
        self.max_version_probe_bytes = self._normalize_positive_int_config(
            self.config.get("version_probe_bytes"),
            self.DEFAULT_VERSION_PICKLE_PROBE_BYTES,
        )
        # ``max_jit_scan_member_bytes`` caps per-member reads during the JIT /
        # network pattern pass to avoid unbounded memory blowup. Non-positive
        # or non-integer values fall back to the default; there is *no*
        # "0 = unlimited" escape hatch here (unlike ``ZipScanner.max_entry_size``)
        # because this pass cannot afford to run without a bound.
        self.max_jit_scan_member_bytes = self._normalize_positive_int_config(
            self.config.get("max_jit_scan_member_bytes"),
            _JIT_SCAN_MEMBER_MAX_BYTES,
        )
        self.max_nested_zip_member_bytes = self._normalize_positive_int_config(
            self.config.get("max_nested_zip_member_bytes"),
            self.default_max_file_read_size,
        )
        self.max_nested_zip_depth = self._normalize_positive_int_config(
            self.config.get("max_zip_depth"),
            self.DEFAULT_MAX_NESTED_ZIP_DEPTH,
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        try:
            from modelaudit.utils.file.detection import is_pytorch_zip_archive
        except Exception:
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return is_pytorch_zip_archive(path)

        # For .bin, .pkl, and .ckpt files, only handle ZIP-backed containers.
        # torch.save() uses ZIP format by default since PyTorch 1.6 (_use_new_zipfile_serialization=True)
        if ext in [".bin", ".pkl", ".ckpt"]:
            return is_pytorch_zip_archive(path)

        # For .pt and .pth, always try to handle.
        return True

    def scan(self, path: str, timeout: int | None = None) -> ScanResult:
        """Scan a PyTorch model file for suspicious code"""
        # Override timeout if provided
        if timeout is not None:
            self.timeout = timeout

        # Start timeout tracking
        self._start_scan_timer()
        self._relaxed_crc_tracker.reset()
        result: ScanResult | None = None

        try:
            # Initial validation and setup
            result = self._initialize_scan(path)
            if result.success is False:  # Early return for validation failures
                return result

            # Store the file path for use in issue locations
            self.current_file_path = path

            from .zip_scanner import open_preflighted_zip

            with open_preflighted_zip(path, self.config) as zip_file:
                # Validate ZIP entries and check for path traversal
                safe_entries = self._validate_zip_entries(zip_file, result, path)
                self._check_timeout()  # Check timeout after entry validation

                validated_storage_data_pkl_members = self._validated_pytorch_storage_data_pkl_members_from_data_pickle(
                    zip_file,
                    safe_entries,
                    result,
                )

                # Discover pickle files in the archive
                pickle_files = self._discover_pickle_files(
                    zip_file,
                    safe_entries,
                    result,
                    validated_pytorch_storage_data_pkl_members=validated_storage_data_pkl_members,
                )

                # Extract version info and check for CVE vulnerabilities
                self._check_pytorch_vulnerabilities(zip_file, safe_entries, result, path)

                # Scan all discovered pickle files
                bytes_scanned, clean_pickle_entry_ids = self._scan_pickle_files(
                    zip_file,
                    pickle_files,
                    result,
                    path,
                    trusted_pytorch_storage_persistent_id_data_pkl_members=(
                        validated_storage_data_pkl_members.persistent_id_downgrade_keys_by_data_pkl
                    ),
                    pytorch_data_pickle_storage_sizes_by_data_pkl=(
                        validated_storage_data_pkl_members.storage_member_sizes_by_data_pkl
                    ),
                )
                self._scan_nested_zip_members(zip_file, safe_entries, result, path)
                self._check_timeout()  # Check timeout after pickle scanning

                # Validate tensor metadata consistency (CVE-2026-24747)
                self._validate_tensor_metadata_consistency(zip_file, safe_entries, pickle_files, result, path)

                # Check for JIT/Script code execution risks
                bytes_scanned += self._scan_for_jit_patterns(
                    zip_file,
                    safe_entries,
                    result,
                    path,
                    clean_pickle_entry_ids=clean_pickle_entry_ids,
                )

                # Detect suspicious non-pickle files
                self._detect_suspicious_files(
                    zip_file,
                    safe_entries,
                    result,
                    path,
                    non_executable_pytorch_storage_data_pkl_members=(
                        validated_storage_data_pkl_members.persistent_id_downgrade_keys_by_data_pkl
                    ),
                )

                # Validate PyTorch model structure
                self._validate_pytorch_structure(pickle_files, result)

                # Check for blacklisted patterns across all files
                self._check_blacklist_patterns(zip_file, safe_entries, result)

                result.bytes_scanned += bytes_scanned

        except TimeoutError as e:
            # Handle timeout gracefully
            if result is None:
                result = self._create_result()
            mark_inconclusive_scan_result(result, "pytorch_zip_scan_timeout")
            result.add_check(
                name="Scan Timeout",
                passed=False,
                message=f"Scan timed out: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"timeout_seconds": self.timeout, "analysis_incomplete": True},
            )
            result.finish(success=False)
            return result
        except ZipPreflightRejected as exc:
            return exc.result
        except zipfile.BadZipFile:
            return self._handle_bad_zip_error(path)
        except Exception as e:
            return self._handle_scan_error(path, e, result)

        assert result is not None
        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors
        )
        return result

    @staticmethod
    def _get_zip_member_name(name: str | zipfile.ZipInfo) -> str:
        """Return the archive member name for a string or ZipInfo."""
        return get_zip_member_name(name)

    @classmethod
    def _get_zip_member_names(cls, entries: list[zipfile.ZipInfo]) -> list[str]:
        """Return archive member names while preserving duplicate entries."""
        return get_zip_member_names(entries)

    @staticmethod
    def _torchscript_debug_member_name(name: str, member_names: set[str]) -> str | None:
        """Return the sibling TorchScript debug member name for a generated-source path."""
        normalized = name.replace("\\", "/").lstrip("/")
        parts = tuple(part for part in normalized.split("/") if part)
        if not parts or not parts[-1].endswith(".py"):
            return None

        try:
            code_index = parts.index("code")
        except ValueError:
            return None

        # TorchScript writes generated Python directly under the archive root
        # (optionally behind a single top-level archive prefix like "archive/").
        if code_index > 1:
            return None

        torchscript_parts = parts[code_index + 1 :]
        is_generated_path = torchscript_parts == ("__torch__.py",) or (
            len(torchscript_parts) > 1 and torchscript_parts[0] == "__torch__"
        )
        debug_name = f"{normalized}.debug_pkl"
        if not is_generated_path or debug_name not in member_names:
            return None
        return debug_name

    @staticmethod
    def _looks_like_torchscript_generated_source(source: bytes) -> bool:
        """Return true when source text has TorchScript-generated structure and no Python escape hatches."""
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError:
            return False

        if _TORCHSCRIPT_FORBIDDEN_SOURCE_PATTERN.search(text):
            return False
        return (
            _TORCHSCRIPT_GENERATED_CLASS_PATTERN.search(text) is not None
            and _TORCHSCRIPT_GENERATED_METHOD_PATTERN.search(text) is not None
            and PyTorchZipScanner._has_torchscript_generated_ast_shape(text)
        )

    @staticmethod
    def _has_torchscript_generated_ast_shape(text: str) -> bool:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return False

        if not tree.body or any(not isinstance(node, ast.ClassDef) for node in tree.body):
            return False

        for node in ast.walk(tree):
            if PyTorchZipScanner._is_torchscript_forbidden_ast_symbol(node):
                return False

            if isinstance(node, ast.ClassDef):
                if node.decorator_list:
                    return False
                if not PyTorchZipScanner._is_torchscript_class_header_safe(node):
                    return False
                if not any(isinstance(item, ast.FunctionDef) for item in node.body):
                    return False
                generated_marker_assignments: set[str] = set()
                for item in node.body:
                    if isinstance(item, ast.Pass):
                        continue
                    if isinstance(item, ast.Assign):
                        generated_marker_assignments.update(
                            PyTorchZipScanner._torchscript_assignment_target_names(item.targets)
                        )
                        if not PyTorchZipScanner._is_torchscript_definition_time_expression_safe(item.value):
                            return False
                        continue
                    if isinstance(item, ast.AnnAssign):
                        generated_marker_assignments.update(
                            PyTorchZipScanner._torchscript_assignment_target_names([item.target])
                        )
                        if not PyTorchZipScanner._is_torchscript_definition_time_expression_safe(item.annotation):
                            return False
                        if (
                            item.value is not None
                            and not PyTorchZipScanner._is_torchscript_definition_time_expression_safe(item.value)
                        ):
                            return False
                        continue
                    if isinstance(item, ast.FunctionDef):
                        if not PyTorchZipScanner._is_torchscript_function_definition_safe(item):
                            return False
                        continue
                    return False
                if not {"__parameters__", "__buffers__"}.issubset(generated_marker_assignments):
                    return False

        return True

    @staticmethod
    def _torchscript_assignment_target_names(targets: list[ast.expr]) -> set[str]:
        return {target.id for target in targets if isinstance(target, ast.Name)}

    @staticmethod
    def _is_torchscript_definition_time_expression_safe(expression: ast.expr) -> bool:
        return not any(isinstance(node, _TORCHSCRIPT_UNSAFE_DEFINITION_EXPR_NODES) for node in ast.walk(expression))

    @staticmethod
    def _is_torchscript_forbidden_ast_symbol(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in _TORCHSCRIPT_FORBIDDEN_AST_NAMES
        if isinstance(node, ast.Attribute):
            return node.attr in _TORCHSCRIPT_FORBIDDEN_AST_NAMES
        return (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _TORCHSCRIPT_FORBIDDEN_AST_NAMES
        )

    @staticmethod
    def _is_torchscript_class_header_safe(node: ast.ClassDef) -> bool:
        if node.keywords or len(node.bases) != 1:
            return False
        base = node.bases[0]
        return isinstance(base, ast.Name) and base.id == "Module"

    @staticmethod
    def _is_torchscript_function_definition_safe(node: ast.FunctionDef) -> bool:
        if node.decorator_list:
            return False
        definition_expressions: list[ast.expr] = [
            *node.args.defaults,
            *(default for default in node.args.kw_defaults if default is not None),
        ]
        if node.returns is not None:
            definition_expressions.append(node.returns)
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if arg.annotation is not None:
                definition_expressions.append(arg.annotation)

        return all(
            PyTorchZipScanner._is_torchscript_definition_time_expression_safe(expression)
            for expression in definition_expressions
        ) and PyTorchZipScanner._is_torchscript_function_body_safe(node.body)

    @staticmethod
    def _is_torchscript_function_body_safe(statements: list[ast.stmt]) -> bool:
        for statement in statements:
            for node in ast.walk(statement):
                if isinstance(node, _TORCHSCRIPT_UNSAFE_BODY_NODES):
                    return False
                if PyTorchZipScanner._is_torchscript_forbidden_ast_symbol(node):
                    return False
        return True

    def _is_torchscript_generated_python(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        debug_entry: zipfile.ZipInfo,
        result: ScanResult,
    ) -> bool:
        """Return true for validated TorchScript-generated Python source members."""
        try:
            debug_prefix = self._read_member_prefix(
                zip_file,
                debug_entry,
                _TORCHSCRIPT_DEBUG_PREFIX_BYTES,
                phase="torchscript generated source validation",
                result=result,
            )
            if _TORCHSCRIPT_DEBUG_PAYLOAD_MARKER not in debug_prefix:
                return False

            source = self._read_member_bytes(
                zip_file,
                entry,
                phase="torchscript generated source validation",
                result=result,
                max_bytes=_TORCHSCRIPT_SOURCE_MAX_BYTES,
            )
        except Exception as exc:
            logger.debug("Unable to validate TorchScript generated source member %s: %s", entry.filename, exc)
            return False

        return self._looks_like_torchscript_generated_source(source)

    @staticmethod
    def _find_zip_entry(entries: list[zipfile.ZipInfo], member_name: str) -> zipfile.ZipInfo | None:
        """Return the first matching ZipInfo entry for a member name, or None."""
        return find_zip_entry(entries, member_name)

    def _read_member_prefix(
        self,
        zip_file: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        limit: int,
        *,
        phase: str,
        result: ScanResult,
    ) -> bytes:
        """Read up to ``limit`` bytes from a ZIP member with guarded CRC fallback."""
        return read_member_prefix(
            zip_file,
            name,
            limit,
            phase=phase,
            result=result,
            archive_path=self.current_file_path or self._get_zip_member_name(name),
            crc_tracker=self._relaxed_crc_tracker,
        )

    def _read_member_bytes(
        self,
        zip_file: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *,
        phase: str,
        result: ScanResult,
        max_bytes: int | None = None,
    ) -> bytes:
        """Read an entire ZIP member with optional bounded size and guarded CRC fallback."""
        return read_member_bytes(
            zip_file,
            name,
            phase=phase,
            result=result,
            archive_path=self.current_file_path or self._get_zip_member_name(name),
            crc_tracker=self._relaxed_crc_tracker,
            max_bytes=max_bytes,
        )

    def _read_symlink_target(
        self, zip_file: zipfile.ZipFile, info: zipfile.ZipInfo, result: ScanResult
    ) -> tuple[str, bool]:
        """Read a bounded ZIP symlink target and report whether it was complete."""
        bounded_info = copy(info)
        bounded_info.file_size = self.MAX_SYMLINK_TARGET_BYTES + 1
        target = self._read_member_prefix(
            zip_file,
            bounded_info,
            self.MAX_SYMLINK_TARGET_BYTES + 1,
            phase="symlink_target_validation",
            result=result,
        )
        target_complete = len(target) <= self.MAX_SYMLINK_TARGET_BYTES
        bounded_target = target[: self.MAX_SYMLINK_TARGET_BYTES]
        return bounded_target.decode("utf-8", errors="surrogateescape"), target_complete

    @staticmethod
    def _symlink_payload_bounds_match(zip_file: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
        """Return whether local ZIP metadata bounds the same payload as the central entry."""
        archive = zip_file.fp
        end_offset = getattr(info, "_end_offset", None)
        if archive is None or not isinstance(end_offset, int):
            return False

        original_position = archive.tell()
        try:
            archive.seek(info.header_offset)
            header = archive.read(30)
            if len(header) != 30 or header[:4] != b"PK\x03\x04":
                return False

            local_flags, local_compress_type = struct.unpack_from("<HH", header, 6)
            local_crc, local_compressed_size, local_file_size = struct.unpack_from("<III", header, 14)
            filename_length, extra_length = struct.unpack_from("<HH", header, 26)
            data_offset = info.header_offset + 30 + filename_length + extra_length
            if data_offset > end_offset or local_flags != info.flag_bits or local_compress_type != info.compress_type:
                return False

            if not (local_flags & 0x08):
                local_sizes_match = local_compressed_size in {info.compress_size, 0xFFFFFFFF} and local_file_size in {
                    info.file_size,
                    0xFFFFFFFF,
                }
                return local_crc == info.CRC and local_sizes_match and data_offset + info.compress_size == end_offset

            descriptor_offset = data_offset + info.compress_size
            if descriptor_offset > end_offset:
                return False
            descriptor_length = end_offset - descriptor_offset
            if descriptor_length not in {12, 16, 20, 24}:
                return False
            archive.seek(descriptor_offset)
            descriptor = archive.read(descriptor_length)
            if descriptor.startswith(b"PK\x07\x08"):
                descriptor = descriptor[4:]
            if len(descriptor) == 12:
                crc, compressed_size, file_size = struct.unpack("<III", descriptor)
            elif len(descriptor) == 20:
                crc, compressed_size, file_size = struct.unpack("<IQQ", descriptor)
            else:
                return False
            return (crc, compressed_size, file_size) == (info.CRC, info.compress_size, info.file_size)
        finally:
            archive.seek(original_position)

    @staticmethod
    def _resolve_symlink_target(
        target: str,
        *,
        resolved_name: str,
        extraction_root: str,
    ) -> tuple[str, bool]:
        """Resolve a relative symlink target while enforcing the archive extraction root."""
        if is_absolute_archive_path(target):
            return target, False

        normalized_target = target.replace("\\", os.sep).replace("/", os.sep)
        target_base = os.path.dirname(resolved_name)
        target_resolved = os.path.normpath(os.path.join(target_base, normalized_target))
        try:
            target_from_root = os.path.relpath(target_resolved, extraction_root)
        except ValueError:
            return target_resolved, False
        return sanitize_archive_path(target_from_root, extraction_root)

    def _read_member_to_spooled_file(
        self,
        zip_file: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *,
        phase: str,
        result: ScanResult,
        max_size: int,
        max_bytes: int | None = None,
    ) -> tuple[Any, int]:
        """Copy a ZIP member into a spooled temp file with guarded CRC fallback."""
        return read_member_to_spooled_file(
            zip_file,
            name,
            phase=phase,
            result=result,
            archive_path=self.current_file_path or self._get_zip_member_name(name),
            crc_tracker=self._relaxed_crc_tracker,
            max_size=max_size,
            max_bytes=max_bytes,
        )

    def _add_pytorch_zip_integrity_check(self, path: str, result: ScanResult, file_size: int) -> None:
        if not (self.max_file_read_size and self.max_file_read_size > 0 and file_size > self.max_file_read_size):
            self.add_file_integrity_check(path, result)
            return

        prefix_size = min(file_size, self.max_file_read_size, _PYTORCH_ZIP_INTEGRITY_PREFIX_BYTES)
        hasher = hashlib.sha256()
        bytes_hashed = 0
        with open(path, "rb") as handle:
            remaining = prefix_size
            while remaining > 0:
                self.check_interrupted()
                if self._check_timeout(allow_partial=True):
                    break
                chunk = handle.read(min(_PYTORCH_ZIP_HASH_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                hasher.update(chunk)
                bytes_hashed += len(chunk)
                remaining -= len(chunk)

        sha256_prefix = hasher.hexdigest()
        result.add_check(
            name="File Integrity Hash",
            passed=True,
            message="File SHA256 prefix hash calculated",
            location=path,
            details={
                "sha256_prefix": sha256_prefix,
                "bytes_hashed": bytes_hashed,
                "file_size": file_size,
                "hash_complete": False,
            },
        )
        result.metadata["file_hashes"] = {"sha256_prefix": sha256_prefix}
        result.metadata["file_size"] = file_size

    def _initialize_scan(self, path: str) -> ScanResult:
        """Initialize scan with basic validation and setup"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance without unbounded reads on
        # multi-GB PyTorch archives that are analyzed through bounded members.
        self._add_pytorch_zip_integrity_check(path, result, file_size)

        # Validate ZIP format
        header = read_zip_header(path)
        if not header.startswith(b"PK") and not zipfile.is_zipfile(path):
            result.add_check(
                name="ZIP Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S902",
            )
            result.finish(success=False)
            return result
        else:
            result.add_check(
                name="ZIP Format Validation",
                passed=True,
                message="Valid ZIP format detected",
                location=path,
                rule_code=None,
            )

        return result

    @classmethod
    def _entry_limit_exceeded(cls, result: ScanResult) -> bool:
        reasons = result.metadata.get("scan_outcome_reasons")
        return isinstance(reasons, list) and cls.ENTRY_LIMIT_INCONCLUSIVE_REASON in reasons

    @classmethod
    def _local_entry_limit_exceeded(cls, result: ScanResult) -> bool:
        return result.metadata.get(cls.LOCAL_ENTRY_LIMIT_METADATA_KEY) is True

    def _validate_zip_entries(
        self,
        zip_file: zipfile.ZipFile,
        result: ScanResult,
        path: str,
    ) -> list[zipfile.ZipInfo]:
        """Validate ZIP entries and check for path traversal, symlinks, and archive manipulation attacks"""
        archive_entries = zip_file.infolist()
        safe_entries: list[zipfile.ZipInfo] = []
        seen_entries: dict[str, zipfile.ZipInfo] = {}
        path_traversal_found = False
        symlink_issues_found = False
        compression_issues_found = False
        duplicate_entry_collisions_found = False
        temp_base = os.path.join(tempfile.gettempdir(), "extract")

        # Check entry count limit (decompression bomb indicator)
        entry_count = len(archive_entries)
        entry_limit_exceeded = entry_count > self.max_archive_entries
        entries_to_process = archive_entries
        entry_summary_details: dict[str, int | bool] = {"entries_checked": entry_count}
        entry_scope = "archive entries"
        if entry_count > self.max_archive_entries:
            entries_to_process = archive_entries[: self.max_archive_entries]
            dropped_entry_count = entry_count - len(entries_to_process)
            mark_inconclusive_scan_result(result, self.ENTRY_LIMIT_INCONCLUSIVE_REASON)
            result.metadata[self.LOCAL_ENTRY_LIMIT_METADATA_KEY] = True
            entry_summary_details = {
                "entries_checked": len(entries_to_process),
                "total_entries": entry_count,
                "analysis_incomplete": True,
            }
            entry_scope = "processed archive entries"
            result.add_check(
                name="Archive Entry Limit",
                passed=False,
                message=(
                    f"Archive contains {entry_count} entries (max processed: {self.max_archive_entries}); "
                    f"{dropped_entry_count} entries were skipped and scan coverage is incomplete"
                ),
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "entry_count": entry_count,
                    "max_entries": self.max_archive_entries,
                    "processed_entries": len(entries_to_process),
                    "dropped_entry_count": dropped_entry_count,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self.ENTRY_LIMIT_INCONCLUSIVE_REASON,
                    "risk": "Excessive entries may indicate a decompression bomb attack",
                },
                why=(
                    "Archives with excessive entries can exhaust system resources during extraction; "
                    "entries beyond the processing cap are not inspected."
                ),
            )
        else:
            result.add_check(
                name="Archive Entry Limit",
                passed=True,
                message=f"Archive entry count ({entry_count}) is within limits",
                location=path,
                details={"entry_count": entry_count, "max_entries": self.max_archive_entries},
            )

        for info in entries_to_process:
            self._check_timeout()
            name = info.filename
            previous_info = seen_entries.get(name)
            if previous_info is None:
                seen_entries[name] = info
            else:
                previous_signature = (
                    previous_info.CRC,
                    previous_info.file_size,
                    (previous_info.external_attr >> 16) & 0o170000,
                )
                current_signature = (
                    info.CRC,
                    info.file_size,
                    (info.external_attr >> 16) & 0o170000,
                )
                if current_signature != previous_signature:
                    coverage_message = (
                        "all processed copies will be scanned explicitly; later archive entries remain uninspected"
                        if entry_limit_exceeded
                        else "all copies will be scanned explicitly"
                    )
                    result.add_check(
                        name="Duplicate ZIP Entry Collision",
                        passed=False,
                        message=(f"Duplicate archive entry {name} has conflicting metadata; {coverage_message}"),
                        severity=IssueSeverity.INFO,
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "first_header_offset": previous_info.header_offset,
                            "duplicate_header_offset": info.header_offset,
                            "first_crc": previous_info.CRC,
                            "duplicate_crc": info.CRC,
                            "first_file_size": previous_info.file_size,
                            "duplicate_file_size": info.file_size,
                        },
                        why=(
                            "Duplicate ZIP members with the same path can shadow earlier payloads "
                            "when readers resolve by filename. The scanner now preserves every ZipInfo "
                            "entry and scans all copies explicitly, so divergent duplicates are reported "
                            "for visibility without turning benign-but-conflicting archives into warning-level "
                            "findings by themselves."
                        ),
                    )
                    duplicate_entry_collisions_found = True

            # Check for path traversal
            resolved_name, is_safe = sanitize_archive_path(name, temp_base)
            if not is_safe:
                result.add_check(
                    name="Path Traversal Protection",
                    passed=False,
                    message=f"Archive entry {name} attempted path traversal outside the archive",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path}:{name}",
                    details={"entry": name},
                )
                path_traversal_found = True
                continue

            # Check for symlinks (ZIP slip variant attack)
            is_symlink = _is_zip_symlink(info)
            if is_symlink:
                scan_symlink_content = True
                if info.file_size > self.MAX_SYMLINK_TARGET_BYTES:
                    result.add_check(
                        name="Symlink Safety Validation",
                        passed=False,
                        message=f"Symlink {name} has an invalid target that exceeds the maximum length",
                        severity=IssueSeverity.CRITICAL,
                        rule_code="S406",
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "target": "<oversized>",
                            "target_class": "invalid",
                            "target_size": info.file_size,
                            "max_target_size": self.MAX_SYMLINK_TARGET_BYTES,
                        },
                    )
                    scan_symlink_content = False
                elif info.compress_size > self.MAX_SYMLINK_TARGET_COMPRESSED_BYTES:
                    result.add_check(
                        name="Symlink Safety Validation",
                        passed=False,
                        message=f"Symlink {name} has an invalid target with excessive compressed input",
                        severity=IssueSeverity.CRITICAL,
                        rule_code="S406",
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "target": "<compressed-input-too-large>",
                            "target_class": "invalid",
                            "compressed_size": info.compress_size,
                            "max_compressed_size": self.MAX_SYMLINK_TARGET_COMPRESSED_BYTES,
                        },
                    )
                    scan_symlink_content = False
                elif not self._symlink_payload_bounds_match(zip_file, info):
                    result.add_check(
                        name="Symlink Safety Validation",
                        passed=False,
                        message=f"Symlink {name} has inconsistent ZIP payload bounds",
                        severity=IssueSeverity.CRITICAL,
                        rule_code="S406",
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "target": "<inconsistent-zip-metadata>",
                            "target_class": "invalid",
                        },
                    )
                    scan_symlink_content = False
                else:
                    try:
                        target, target_complete = self._read_symlink_target(zip_file, info, result)
                    except Exception as exc:
                        safe_error = redact_untrusted_error_message(exc)
                        reason = "pytorch_zip_symlink_target_read_incomplete"
                        mark_inconclusive_scan_result(result, reason)
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=f"Unable to read symlink target for {name}: {safe_error}",
                            severity=IssueSeverity.INFO,
                            rule_code="S902",
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "exception": safe_error,
                                "exception_type": type(exc).__name__,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": reason,
                            },
                        )
                        scan_symlink_content = False
                    else:
                        safe_target = redact_evidence_string(target, max_chars=1024)
                        if not target_complete:
                            result.add_check(
                                name="Symlink Safety Validation",
                                passed=False,
                                message=f"Symlink {name} has an invalid target that exceeds the maximum length",
                                severity=IssueSeverity.CRITICAL,
                                rule_code="S406",
                                location=f"{path}:{name}",
                                details={"entry": name, "target": safe_target, "target_class": "invalid"},
                            )
                            scan_symlink_content = False
                        elif not target or "\x00" in target:
                            invalid_reason = "empty" if not target else "contains a NUL byte"
                            result.add_check(
                                name="Symlink Safety Validation",
                                passed=False,
                                message=f"Symlink {name} has an invalid target that {invalid_reason}",
                                severity=IssueSeverity.CRITICAL,
                                rule_code="S406",
                                location=f"{path}:{name}",
                                details={"entry": name, "target": safe_target, "target_class": "invalid"},
                            )
                        elif _targets_windows_reserved_device(target):
                            result.add_check(
                                name="Symlink Safety Validation",
                                passed=False,
                                message=f"Symlink {name} targets a reserved Windows device name",
                                severity=IssueSeverity.CRITICAL,
                                rule_code="S406",
                                location=f"{path}:{name}",
                                details={"entry": name, "target": safe_target, "target_class": "invalid"},
                            )
                        else:
                            _target_resolved, target_safe = self._resolve_symlink_target(
                                target,
                                resolved_name=resolved_name,
                                extraction_root=temp_base,
                            )
                            normalized_absolute_target = posixpath.normpath(target.replace("\\", "/"))
                            targets_critical_system_path = is_absolute_archive_path(target) and is_critical_system_path(
                                normalized_absolute_target,
                                CRITICAL_SYSTEM_PATHS,
                            )
                            if not target_safe:
                                if targets_critical_system_path:
                                    message = f"Symlink {name} points to critical system path: {safe_target}"
                                    target_class = "critical_system_path"
                                    rule_code = "S408"
                                else:
                                    message = f"Symlink {name} resolves outside extraction directory"
                                    target_class = "external"
                                    rule_code = "S406"
                                result.add_check(
                                    name="Symlink Safety Validation",
                                    passed=False,
                                    message=message,
                                    severity=IssueSeverity.CRITICAL,
                                    rule_code=rule_code,
                                    location=f"{path}:{name}",
                                    details={"entry": name, "target": safe_target, "target_class": target_class},
                                )
                            else:
                                result.add_check(
                                    name="Symlink Safety Validation",
                                    passed=True,
                                    message=f"Symlink {name} is safe",
                                    location=f"{path}:{name}",
                                    rule_code=None,
                                    details={"entry": name, "target": safe_target, "target_class": "safe"},
                                )

                symlink_issues_found = True
                if not scan_symlink_content:
                    continue

            # Skip directories for content checks
            if name.endswith("/"):
                safe_entries.append(info)
                continue

            # Check compression ratio (decompression bomb detection)
            # Entries with compress_size == 0 (e.g., empty files or stored entries
            # where the size field is zero) are skipped since ratio is undefined.
            if info.compress_size > 0:
                compression_ratio = info.file_size / info.compress_size
                if (
                    compression_ratio > self.max_compression_ratio
                    and info.file_size >= self.min_compression_bomb_uncompressed_size
                ):
                    result.add_check(
                        name="Compression Ratio Check",
                        passed=False,
                        message=(
                            f"Suspicious compression ratio ({compression_ratio:.1f}x) and "
                            f"uncompressed size ({info.file_size} bytes) in entry: {name}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "compressed_size": info.compress_size,
                            "uncompressed_size": info.file_size,
                            "ratio": compression_ratio,
                            "threshold": self.max_compression_ratio,
                            "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                            "risk": "High compression ratio may indicate a decompression bomb",
                            "analysis_incomplete": True,
                        },
                        why="Decompression bombs use high compression ratios to exhaust system resources",
                    )
                    mark_inconclusive_scan_result(result, "pytorch_zip_compression_ratio_unscanned")
                    compression_issues_found = True
                    continue

            safe_entries.append(info)

        # Summary checks for clean archives
        if not path_traversal_found and archive_entries:
            result.add_check(
                name="Path Traversal Protection",
                passed=True,
                message=f"All {entry_scope} have safe paths",
                location=path,
                details=dict(entry_summary_details),
            )

        if not symlink_issues_found and archive_entries:
            result.add_check(
                name="Symlink Safety Validation",
                passed=True,
                message=f"No symlinks detected in {entry_scope}",
                location=path,
                details=dict(entry_summary_details) if entry_limit_exceeded else {},
            )

        if not compression_issues_found and archive_entries:
            result.add_check(
                name="Compression Ratio Check",
                passed=True,
                message=f"All {entry_scope} have safe compression ratios",
                location=path,
                details={
                    **entry_summary_details,
                    "threshold": self.max_compression_ratio,
                    "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                },
            )

        if not duplicate_entry_collisions_found and archive_entries:
            result.add_check(
                name="Duplicate ZIP Entry Collision",
                passed=True,
                message=f"No conflicting duplicate ZIP entries found in {entry_scope}",
                location=path,
                details=dict(entry_summary_details),
            )

        return safe_entries

    def _discover_pickle_files(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
        *,
        validated_pytorch_storage_data_pkl_members: _ValidatedPytorchStorageDataPklMembers | None = None,
    ) -> list[zipfile.ZipInfo]:
        """Discover pickle files in the ZIP archive"""
        pickle_files: list[zipfile.ZipInfo] = []
        # Identity-based dedup: the same ``ZipInfo`` instance can be considered
        # by both the filename pass and the sniff pass, and since both iterate
        # the same ``safe_entries`` list the ``id()`` of each entry is stable
        # for the duration of this discovery. If a future refactor ever feeds
        # these passes from separate ``infolist()`` walks or from reconstructed
        # ``ZipInfo`` objects, fall back to a ``(name, header_offset)`` key.
        seen_entries: set[int] = set()

        def add_pickle_entry(entry: zipfile.ZipInfo) -> None:
            entry_key = id(entry)
            if entry_key in seen_entries:
                return
            pickle_files.append(entry)
            seen_entries.add(entry_key)

        # First pass: Look for common pickle file patterns
        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            if name.endswith(".pkl") or name == "data.pkl" or name.endswith("/data.pkl"):
                add_pickle_entry(entry)

        if validated_pytorch_storage_data_pkl_members is None:
            validated_pytorch_storage_data_pkl_members = (
                self._validated_pytorch_storage_data_pkl_members_from_data_pickle(zip_file, safe_entries, result)
            )
        trusted_storage_blob_members = self._storage_blob_members_from_data_pkl_members(
            validated_pytorch_storage_data_pkl_members.storage_keys_by_data_pkl
        )
        storage_probe_blob_members = self._storage_blob_members_from_data_pkl_members(
            validated_pytorch_storage_data_pkl_members.storage_probe_keys_by_data_pkl
        )

        # Second pass: always sniff unselected members. A benign data.pkl must not
        # hide an extensionless pickle payload or one placed under data/<n>.
        # Aggregate probe failures into a single summary check so an
        # adversarial archive with many unreadable members does not flood the
        # checks list with one INFO finding apiece.
        probe_failures: list[dict[str, Any]] = []
        padding_probe_bytes_remaining = [_PICKLE_DISCOVERY_PADDING_PROBE_BUDGET_BYTES]
        nul_padding_verify_bytes_remaining = [_PICKLE_DISCOVERY_NUL_PADDING_VERIFY_BUDGET_BYTES]
        deferred_padding_probe_entries: list[zipfile.ZipInfo] = []
        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            if id(entry) in seen_entries or entry.is_dir():
                continue
            try:
                needs_deferred_padding_probe = [False]
                if name in trusted_storage_blob_members:
                    looks_like_pickle = self._trusted_storage_entry_looks_like_pickle(
                        zip_file,
                        entry,
                        result,
                        padding_probe_bytes_remaining=padding_probe_bytes_remaining,
                        nul_padding_verify_bytes_remaining=nul_padding_verify_bytes_remaining,
                        defer_padding_probe=needs_deferred_padding_probe,
                    )
                elif name in storage_probe_blob_members:
                    looks_like_pickle = self._trusted_storage_entry_looks_like_pickle(
                        zip_file,
                        entry,
                        result,
                        max_probe_bytes=_PICKLE_DISCOVERY_LONG_PROBE_BYTES,
                        padding_probe_bytes_remaining=padding_probe_bytes_remaining,
                        nul_padding_verify_bytes_remaining=nul_padding_verify_bytes_remaining,
                        defer_padding_probe=needs_deferred_padding_probe,
                    )
                else:
                    looks_like_pickle = self._entry_looks_like_pickle(zip_file, entry, result)
                if looks_like_pickle:
                    add_pickle_entry(entry)
                elif needs_deferred_padding_probe[0]:
                    deferred_padding_probe_entries.append(entry)
            except Exception as exc:
                logger.debug("Unable to inspect ZIP member %s as a pickle: %s", entry.filename, exc)
                probe_failures.append(
                    {
                        "zip_entry": entry.filename,
                        "exception": str(exc),
                        "exception_type": type(exc).__name__,
                        "location": f"{self.current_file_path}:{entry.filename}",
                    }
                )

        for entry in deferred_padding_probe_entries:
            if id(entry) in seen_entries or entry.is_dir():
                continue
            try:
                if self._trusted_storage_entry_looks_like_pickle(
                    zip_file,
                    entry,
                    result,
                    max_probe_bytes=_PICKLE_DISCOVERY_LONG_PROBE_BYTES,
                    padding_probe_bytes_remaining=padding_probe_bytes_remaining,
                    nul_padding_verify_bytes_remaining=nul_padding_verify_bytes_remaining,
                ):
                    add_pickle_entry(entry)
            except Exception as exc:
                logger.debug("Unable to inspect ZIP member %s as a pickle: %s", entry.filename, exc)
                probe_failures.append(
                    {
                        "zip_entry": entry.filename,
                        "exception": str(exc),
                        "exception_type": type(exc).__name__,
                        "location": f"{self.current_file_path}:{entry.filename}",
                    }
                )

        if probe_failures:
            mark_inconclusive_scan_result(result, "pytorch_zip_pickle_discovery_incomplete")
            count = len(probe_failures)
            noun = "member" if count == 1 else "members"
            result.add_check(
                name="Pickle Discovery",
                passed=False,
                message=f"{count} PyTorch ZIP {noun} could not be inspected for hidden pickle payloads",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "zip_entries": [failure["zip_entry"] for failure in probe_failures],
                    "entries": probe_failures,
                    "failed_count": count,
                    "analysis_incomplete": True,
                },
            )

        result.metadata["pickle_files"] = self._get_zip_member_names(pickle_files)
        return pickle_files

    def _scan_nested_zip_members(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
    ) -> None:
        """Recursively route embedded ZIP members, including ZIPs named like pickle files."""
        current_depth = get_archive_depth(self.config)
        probe_failures: list[dict[str, str]] = []
        size_limited_entries: list[dict[str, Any]] = []
        depth_limited_entries: list[dict[str, Any]] = []
        scan_failures: list[dict[str, str]] = []

        for entry in safe_entries:
            self._check_timeout()
            if entry.is_dir():
                continue

            try:
                header = self._read_member_prefix(
                    zip_file,
                    entry,
                    _NESTED_ZIP_HEADER_PROBE_BYTES,
                    phase="nested_zip_probe",
                    result=result,
                )
            except Exception as exc:
                logger.debug("Unable to inspect ZIP member %s for nested archives: %s", entry.filename, exc)
                probe_failures.append(
                    {
                        "zip_entry": entry.filename,
                        "exception": str(exc),
                        "exception_type": type(exc).__name__,
                    }
                )
                continue

            if not any(header.startswith(signature) for signature in _ZIP_LOCAL_FILE_SIGNATURES):
                continue

            entry_name = self._get_zip_member_name(entry)
            if current_depth >= self.max_nested_zip_depth:
                depth_limited_entries.append(
                    {
                        "zip_entry": entry_name,
                        "depth": current_depth,
                        "max_depth": self.max_nested_zip_depth,
                    }
                )
                continue

            if entry.file_size > self.max_nested_zip_member_bytes:
                size_limited_entries.append(
                    {
                        "zip_entry": entry_name,
                        "file_size": entry.file_size,
                        "max_member_bytes": self.max_nested_zip_member_bytes,
                    }
                )
                continue

            temp_path: str | None = None
            try:
                temp_path = self._copy_nested_zip_member_to_tempfile(zip_file, entry)

                nested_config = dict(self.config)
                nested_config["_archive_depth"] = current_depth + 1
                nested_scan_callback = self.config.get(NESTED_SCAN_CALLBACK_CONFIG_KEY)
                if callable(nested_scan_callback):
                    nested_result = nested_scan_callback(temp_path, nested_config)
                else:
                    nested_result = scan_nested_file(temp_path, nested_config)

                self._rewrite_nested_result_context(nested_result, temp_path, path, self._get_zip_member_name(entry))
                self._merge_nested_zip_result(result, nested_result, entry_name)
                self._check_timeout()
            except TimeoutError:
                raise
            except ValueError as exc:
                size_limited_entries.append(
                    {
                        "zip_entry": entry_name,
                        "file_size": entry.file_size,
                        "max_member_bytes": self.max_nested_zip_member_bytes,
                        "exception": str(exc),
                        "exception_type": type(exc).__name__,
                    }
                )
            except Exception as exc:
                logger.debug("Unable to scan nested ZIP member %s: %s", entry.filename, exc)
                scan_failures.append(
                    {
                        "zip_entry": entry.filename,
                        "exception": str(exc),
                        "exception_type": type(exc).__name__,
                    }
                )
            finally:
                if temp_path is not None:
                    with suppress(FileNotFoundError):
                        os.unlink(temp_path)

        if probe_failures:
            self._record_nested_zip_incomplete(
                result,
                failures=probe_failures,
                reason="pytorch_zip_nested_archive_probe_incomplete",
                check_name="Nested ZIP Discovery",
                message="PyTorch ZIP members could not be inspected for nested ZIP payloads",
            )

        if depth_limited_entries:
            mark_inconclusive_scan_result(result, "pytorch_zip_nested_archive_depth_limit")
            result.add_check(
                name="Nested ZIP Depth Limit",
                passed=False,
                message=(
                    f"{len(depth_limited_entries)} nested ZIP "
                    f"{'member exceeds' if len(depth_limited_entries) == 1 else 'members exceed'} "
                    f"the recursion depth limit ({self.max_nested_zip_depth})"
                ),
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "zip_entries": [entry["zip_entry"] for entry in depth_limited_entries],
                    "entries": depth_limited_entries,
                    "failed_count": len(depth_limited_entries),
                    "max_depth": self.max_nested_zip_depth,
                    "analysis_incomplete": True,
                },
            )

        if size_limited_entries:
            mark_inconclusive_scan_result(result, "pytorch_zip_nested_archive_size_limit")
            result.add_check(
                name="Nested ZIP Size Limit",
                passed=False,
                message=(
                    f"{len(size_limited_entries)} nested ZIP "
                    f"{'member exceeds' if len(size_limited_entries) == 1 else 'members exceed'} "
                    f"the bounded copy limit ({self.max_nested_zip_member_bytes} bytes)"
                ),
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "zip_entries": [entry["zip_entry"] for entry in size_limited_entries],
                    "entries": size_limited_entries,
                    "failed_count": len(size_limited_entries),
                    "max_member_bytes": self.max_nested_zip_member_bytes,
                    "analysis_incomplete": True,
                },
            )

        if scan_failures:
            self._record_nested_zip_incomplete(
                result,
                failures=scan_failures,
                reason="pytorch_zip_nested_archive_scan_incomplete",
                check_name="Nested ZIP Scan",
                message="Nested ZIP members could not be scanned completely",
            )

    def _copy_nested_zip_member_to_tempfile(self, zip_file: zipfile.ZipFile, entry: zipfile.ZipInfo) -> str:
        """Copy a nested ZIP member into a bounded temporary file for rescanning."""
        copied_bytes = 0
        temp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                temp_path = temp_file.name
                with zip_file.open(entry) as source:
                    while chunk := source.read(1024 * 1024):
                        copied_bytes += len(chunk)
                        if copied_bytes > self.max_nested_zip_member_bytes:
                            raise ValueError(
                                f"Nested ZIP member {entry.filename} exceeds bounded copy limit "
                                f"({self.max_nested_zip_member_bytes} bytes)"
                            )
                        temp_file.write(chunk)
            return temp_path
        except Exception:
            if temp_path is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temp_path)
            raise

    def _record_nested_zip_incomplete(
        self,
        result: ScanResult,
        *,
        failures: list[dict[str, str]],
        reason: str,
        check_name: str,
        message: str,
    ) -> None:
        """Record aggregated nested ZIP probe/scan failures without flooding checks."""
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name=check_name,
            passed=False,
            message=f"{len(failures)} {message}",
            severity=IssueSeverity.INFO,
            location=self.current_file_path,
            details={
                "zip_entries": [failure["zip_entry"] for failure in failures],
                "entries": failures,
                "failed_count": len(failures),
                "analysis_incomplete": True,
            },
        )

    @staticmethod
    def _merge_nested_zip_result(result: ScanResult, nested_result: ScanResult, member_name: str) -> None:
        """Merge nested findings while preserving the parent archive metadata."""
        parent_metadata = dict(result.metadata)
        for key in ("file_hashes", "file_size", "file_hashes_complete", "file_hashes_bytes_hashed"):
            if key in parent_metadata:
                parent_metadata[key] = deepcopy(parent_metadata[key])
        result.merge_member_result(nested_result, member_name)
        raw_detector_failures = result.metadata.get(RAW_DETECTOR_FAILURES_METADATA_KEY)
        raw_detector_failed_detectors = result.metadata.get(RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY)
        member_file_hashes = result.metadata.get(MEMBER_FILE_HASHES_METADATA_KEY)
        member_file_hash_summary = {
            key: result.metadata[key]
            for key in (
                MEMBER_FILE_HASHES_TOTAL_METADATA_KEY,
                MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY,
                MEMBER_FILE_HASHES_OMITTED_METADATA_KEY,
            )
            if key in result.metadata
        }
        result.metadata = parent_metadata
        if isinstance(member_file_hashes, dict) and member_file_hashes:
            result.metadata[MEMBER_FILE_HASHES_METADATA_KEY] = member_file_hashes
        result.metadata.update(member_file_hash_summary)
        if isinstance(raw_detector_failures, list):
            result.metadata[RAW_DETECTOR_FAILURES_METADATA_KEY] = list(raw_detector_failures)
        if isinstance(raw_detector_failed_detectors, list):
            result.metadata[RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY] = list(raw_detector_failed_detectors)
        if nested_result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
            nested_reasons = nested_result.metadata.get("scan_outcome_reasons")
            if isinstance(nested_reasons, list) and nested_reasons:
                for reason in nested_reasons:
                    if isinstance(reason, str) and reason:
                        mark_inconclusive_scan_result(result, reason)
            else:
                mark_inconclusive_scan_result(result, "pytorch_zip_nested_archive_scan_incomplete")
        nested_scans = result.metadata.setdefault("nested_zip_scans", [])
        if isinstance(nested_scans, list):
            nested_metadata = {
                key: value
                for key, value in nested_result.metadata.items()
                if key
                not in {
                    MEMBER_FILE_HASHES_METADATA_KEY,
                    MEMBER_FILE_HASHES_TOTAL_METADATA_KEY,
                    MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY,
                    MEMBER_FILE_HASHES_OMITTED_METADATA_KEY,
                }
            }
            nested_scans.append(
                {
                    "zip_entry": member_name,
                    "scanner_name": nested_result.scanner_name,
                    "success": nested_result.success,
                    "metadata": nested_metadata,
                }
            )
        result.remove_failed_raw_detector_clean_checks()

    @staticmethod
    def _rewrite_nested_result_context(
        nested_result: ScanResult,
        temp_path: str,
        archive_path: str,
        member_name: str,
    ) -> None:
        """Rewrite extracted nested ZIP paths back to archive provenance."""
        archive_location = f"{archive_path}:{member_name}"

        for issue in nested_result.issues:
            issue.location = rewrite_extracted_member_location(
                issue.location,
                temp_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )
            existing_entry = issue.details.get("zip_entry")
            issue.details["zip_entry"] = (
                f"{member_name}:{existing_entry}" if isinstance(existing_entry, str) and existing_entry else member_name
            )

        for check in nested_result.checks:
            check.location = rewrite_extracted_member_location(
                check.location,
                temp_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )
            existing_entry = check.details.get("zip_entry")
            check.details["zip_entry"] = (
                f"{member_name}:{existing_entry}" if isinstance(existing_entry, str) and existing_entry else member_name
            )

    def _entry_looks_like_pickle(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        result: ScanResult,
    ) -> bool:
        """Return True when a bounded ZIP member prefix structurally resembles pickle."""
        data_start = self._read_member_prefix(
            zip_file,
            entry,
            _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
            phase="pickle_discovery",
            result=result,
        )
        if not data_start:
            return False

        if any(data_start.startswith(magic) for magic in _PICKLE_BINARY_PROTOCOL_PREFIXES):
            sample = self._read_member_prefix(
                zip_file,
                entry,
                _PICKLE_DISCOVERY_LONG_PROBE_BYTES,
                phase="pickle_discovery",
                result=result,
            )
            return self._looks_like_binary_pickle_prefix(sample, sample_is_prefix=entry.file_size > len(sample))

        if data_start[0] not in PROTO0_1_START_BYTES:
            return False

        sample = data_start
        if entry.file_size > len(data_start):
            sample = self._read_member_prefix(
                zip_file,
                entry,
                PROTO0_1_MAX_PROBE_BYTES,
                phase="pickle_discovery",
                result=result,
            )
        return _looks_like_proto0_or_1_pickle(
            sample,
            sample_is_prefix=entry.file_size > len(sample),
        )

    def _trusted_storage_entry_looks_like_pickle(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        result: ScanResult,
        *,
        max_probe_bytes: int = _TRUSTED_STORAGE_PICKLE_PROBE_BYTES,
        padding_probe_bytes_remaining: list[int] | None = None,
        nul_padding_verify_bytes_remaining: list[int] | None = None,
        defer_padding_probe: list[bool] | None = None,
    ) -> bool:
        """Return True only for parse-confirmed pickle payloads in referenced tensor storage."""
        data_start = self._read_member_prefix(
            zip_file,
            entry,
            _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
            phase="pickle_discovery",
            result=result,
        )
        if not data_start:
            return False
        is_binary_pickle_candidate = data_start.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES)
        is_frame_first_candidate = data_start.startswith(_PICKLE_FRAME_OPCODE)
        if (
            not is_binary_pickle_candidate
            and not is_frame_first_candidate
            and data_start[0] not in PROTO0_1_START_BYTES
        ):
            return False

        sample = data_start
        detection_probe_budget_charge_bytes = 0
        charge_deferred_probe_budget_on_skip = False

        def charge_detection_probe_budget() -> None:
            nonlocal detection_probe_budget_charge_bytes
            if not detection_probe_budget_charge_bytes:
                return
            if (
                padding_probe_bytes_remaining is not None
                and padding_probe_bytes_remaining[0] < detection_probe_budget_charge_bytes
            ):
                padding_probe_bytes_remaining[0] = 0
                detection_probe_budget_charge_bytes = 0
                return
            PyTorchZipScanner._charge_padding_probe_budget(
                padding_probe_bytes_remaining,
                detection_probe_budget_charge_bytes,
            )
            detection_probe_budget_charge_bytes = 0

        def charge_deferred_probe_budget_before_skip() -> None:
            nonlocal charge_deferred_probe_budget_on_skip, detection_probe_budget_charge_bytes
            if not charge_deferred_probe_budget_on_skip or not detection_probe_budget_charge_bytes:
                return
            PyTorchZipScanner._charge_padding_probe_budget(
                padding_probe_bytes_remaining,
                detection_probe_budget_charge_bytes,
            )
            charge_deferred_probe_budget_on_skip = False
            detection_probe_budget_charge_bytes = 0

        if entry.file_size > len(data_start):
            probe_bytes = max_probe_bytes
            probe_budget_charge_bytes = 0
            if max_probe_bytes > _TRUSTED_STORAGE_PICKLE_PROBE_BYTES:
                if entry.file_size <= max_probe_bytes:
                    if padding_probe_bytes_remaining is None or entry.file_size <= padding_probe_bytes_remaining[0]:
                        probe_budget_charge_bytes = entry.file_size
                    else:
                        charge_deferred_probe_budget_on_skip = True
                        detection_probe_budget_charge_bytes = entry.file_size
                elif (
                    PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(data_start)
                    and defer_padding_probe is None
                ):
                    padding_probe_bytes = min(entry.file_size, _PICKLE_DISCOVERY_PADDING_PROBE_BYTES)
                    if padding_probe_bytes_remaining is None or padding_probe_bytes <= padding_probe_bytes_remaining[0]:
                        probe_bytes = padding_probe_bytes
                        probe_budget_charge_bytes = padding_probe_bytes
                    else:
                        detection_probe_budget_charge_bytes = min(entry.file_size, probe_bytes)
                else:
                    detection_probe_budget_charge_bytes = min(entry.file_size, probe_bytes)
            if probe_budget_charge_bytes:
                PyTorchZipScanner._charge_padding_probe_budget(
                    padding_probe_bytes_remaining,
                    probe_budget_charge_bytes,
                )
            sample = self._read_member_prefix(
                zip_file,
                entry,
                probe_bytes,
                phase="pickle_discovery",
                result=result,
            )
        if is_binary_pickle_candidate:
            should_scan = (
                self._binary_pickle_probe_should_scan(sample, sample_is_prefix=entry.file_size > len(sample))
                or PyTorchZipScanner._expanded_probe_preserves_trusted_scan(
                    entry,
                    sample,
                    max_probe_bytes,
                    PyTorchZipScanner._binary_pickle_probe_should_scan,
                )
                or (
                    max_probe_bytes > _TRUSTED_STORAGE_PICKLE_PROBE_BYTES
                    and PyTorchZipScanner._looks_like_binary_pickle_prefix(
                        sample,
                        sample_is_prefix=entry.file_size > len(sample),
                    )
                )
            )
            if should_scan:
                charge_detection_probe_budget()
                return True
            charge_deferred_probe_budget_before_skip()
            return False
        if is_frame_first_candidate:
            if self._frame_first_trusted_storage_probe_should_scan(sample) or (
                max_probe_bytes > _TRUSTED_STORAGE_PICKLE_PROBE_BYTES
                and PyTorchZipScanner._frame_first_trusted_storage_probe_should_scan(
                    sample[:_TRUSTED_STORAGE_PICKLE_PROBE_BYTES]
                )
            ):
                charge_detection_probe_budget()
                return True
        elif self._proto0_or_1_trusted_storage_probe_should_scan(
            sample,
            sample_is_prefix=entry.file_size > len(sample),
        ):
            charge_detection_probe_budget()
            return True
        if (
            max_probe_bytes == _TRUSTED_STORAGE_PICKLE_PROBE_BYTES
            and entry.file_size > len(sample)
            and PyTorchZipScanner._proto0_or_1_trusted_storage_probe_needs_expanded_sample(
                sample,
                entry_size=entry.file_size,
            )
        ):
            if (
                PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample)
                and defer_padding_probe is not None
            ):
                defer_padding_probe[0] = True
                charge_deferred_probe_budget_before_skip()
                return False
            expanded_probe_bytes = min(entry.file_size, _PICKLE_DISCOVERY_LONG_PROBE_BYTES)
            PyTorchZipScanner._charge_padding_probe_budget(
                padding_probe_bytes_remaining,
                max(0, expanded_probe_bytes - len(sample)),
            )
            expanded_sample = self._read_member_prefix(
                zip_file,
                entry,
                expanded_probe_bytes,
                phase="pickle_discovery",
                result=result,
            )
            if is_frame_first_candidate and self._frame_first_trusted_storage_probe_should_scan(expanded_sample):
                return True
            if not is_frame_first_candidate and self._proto0_or_1_trusted_storage_probe_should_scan(
                expanded_sample,
                sample_is_prefix=entry.file_size > len(expanded_sample),
            ):
                return True
            if not is_frame_first_candidate and PyTorchZipScanner._expanded_probe_preserves_trusted_scan(
                entry,
                expanded_sample,
                expanded_probe_bytes,
                PyTorchZipScanner._proto0_or_1_trusted_storage_probe_should_scan,
            ):
                return True
            sample = expanded_sample
        if (
            entry.file_size > len(sample)
            and len(sample) >= _PICKLE_DISCOVERY_LONG_PROBE_BYTES
            and PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample)
        ):
            if defer_padding_probe is not None:
                defer_padding_probe[0] = True
                charge_deferred_probe_budget_before_skip()
                return False
            padding_probe_bytes = min(entry.file_size, _PICKLE_DISCOVERY_PADDING_PROBE_BYTES)
            if padding_probe_bytes > len(sample):
                PyTorchZipScanner._charge_padding_probe_budget(
                    padding_probe_bytes_remaining,
                    padding_probe_bytes - len(sample),
                )
                padding_sample = self._read_member_prefix(
                    zip_file,
                    entry,
                    padding_probe_bytes,
                    phase="pickle_discovery",
                    result=result,
                )
                if is_frame_first_candidate and self._frame_first_trusted_storage_probe_should_scan(padding_sample):
                    return True
                if not is_frame_first_candidate and self._proto0_or_1_trusted_storage_probe_should_scan(
                    padding_sample,
                    sample_is_prefix=entry.file_size > len(padding_sample),
                ):
                    return True
                sample = padding_sample
            if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample):
                if entry.file_size > len(sample):
                    if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_nul_padding(sample):
                        return self._verified_nul_padding_storage_probe_should_scan(
                            zip_file,
                            entry,
                            sample,
                            result,
                            padding_probe_bytes_remaining,
                            nul_padding_verify_bytes_remaining,
                            is_frame_first_candidate=is_frame_first_candidate,
                        )
                    raise ValueError("trusted PyTorch storage padding probe limit reached")
                charge_deferred_probe_budget_before_skip()
                return False
        if (
            entry.file_size > len(sample)
            and len(sample) >= _PICKLE_DISCOVERY_LONG_PROBE_BYTES
            and PyTorchZipScanner._proto0_or_1_trusted_storage_probe_needs_expanded_sample(
                sample,
                entry_size=entry.file_size,
            )
        ):
            if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample):
                if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_nul_padding(sample):
                    return self._verified_nul_padding_storage_probe_should_scan(
                        zip_file,
                        entry,
                        sample,
                        result,
                        padding_probe_bytes_remaining,
                        nul_padding_verify_bytes_remaining,
                        is_frame_first_candidate=is_frame_first_candidate,
                    )
                raise ValueError("trusted PyTorch storage padding probe limit reached")
            raise ValueError("trusted PyTorch storage prefix exceeds pickle discovery probe")
        charge_deferred_probe_budget_before_skip()
        return False

    def _verified_nul_padding_storage_probe_should_scan(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        sample: bytes,
        result: ScanResult,
        padding_probe_bytes_remaining: list[int] | None,
        nul_padding_verify_bytes_remaining: list[int] | None,
        *,
        is_frame_first_candidate: bool,
    ) -> bool:
        if entry.file_size > len(sample):
            sample = self._verified_nul_padding_storage_probe_sample(
                zip_file,
                entry,
                sample,
                verified_prefix_bytes=len(sample),
                result=result,
                padding_probe_bytes_remaining=padding_probe_bytes_remaining,
                nul_padding_verify_bytes_remaining=nul_padding_verify_bytes_remaining,
            )
        if is_frame_first_candidate and self._frame_first_trusted_storage_probe_should_scan(sample):
            return True
        if not is_frame_first_candidate and self._proto0_or_1_trusted_storage_probe_should_scan(
            sample,
            sample_is_prefix=False,
        ):
            return True
        if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample):
            return False
        raise ValueError("trusted PyTorch storage padding probe limit reached")

    def _verified_nul_padding_storage_probe_sample(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        sample: bytes,
        *,
        verified_prefix_bytes: int,
        result: ScanResult,
        padding_probe_bytes_remaining: list[int] | None,
        nul_padding_verify_bytes_remaining: list[int] | None,
    ) -> bytes:
        remaining_bytes = max(entry.file_size - verified_prefix_bytes, 0)
        PyTorchZipScanner._charge_padding_probe_budget(
            nul_padding_verify_bytes_remaining,
            remaining_bytes,
        )
        if remaining_bytes == 0:
            return sample

        member_name = self._get_zip_member_name(entry)
        archive_path = self.current_file_path or member_name

        def read_verified_tail(*, relaxed_crc: bool, record_relaxed_usage: bool) -> bytes:
            if relaxed_crc and record_relaxed_usage:
                self._relaxed_crc_tracker.record_usage(
                    member_name,
                    "trusted_storage_padding_probe",
                    result,
                    archive_path=archive_path,
                )
            with zip_file.open(entry, "r") as member:
                if relaxed_crc and hasattr(member, "_expected_crc"):
                    member._expected_crc = None

                prefix_bytes_left = verified_prefix_bytes
                while prefix_bytes_left > 0:
                    chunk = member.read(min(_PICKLE_DISCOVERY_NUL_PADDING_VERIFY_CHUNK_BYTES, prefix_bytes_left))
                    if not chunk:
                        raise ValueError("trusted PyTorch storage padding probe limit reached")
                    prefix_bytes_left -= len(chunk)

                retained_chunks: list[bytes] = []
                verified_nul_tail_bytes = 0
                bytes_left = remaining_bytes
                while bytes_left > 0:
                    chunk = member.read(min(_PICKLE_DISCOVERY_NUL_PADDING_VERIFY_CHUNK_BYTES, bytes_left))
                    if not chunk:
                        raise ValueError("trusted PyTorch storage padding probe limit reached")
                    if retained_chunks:
                        retained_chunks.append(chunk)
                    elif chunk.rstrip(b"\x00"):
                        PyTorchZipScanner._charge_padding_probe_budget(
                            padding_probe_bytes_remaining,
                            remaining_bytes,
                        )
                        if verified_nul_tail_bytes:
                            retained_chunks.append(b"\x00" * verified_nul_tail_bytes)
                            verified_nul_tail_bytes = 0
                        retained_chunks.append(chunk)
                    else:
                        verified_nul_tail_bytes += len(chunk)
                    bytes_left -= len(chunk)
            if retained_chunks:
                return sample + b"".join(retained_chunks)
            return sample

        relaxed_crc = self._relaxed_crc_tracker.has_member(member_name)
        try:
            return read_verified_tail(relaxed_crc=relaxed_crc, record_relaxed_usage=True)
        except zipfile.BadZipFile as exc:
            if relaxed_crc or "Bad CRC-32" not in str(exc):
                raise ValueError("trusted PyTorch storage padding probe limit reached") from exc
            self._relaxed_crc_tracker.record_usage(
                member_name,
                "trusted_storage_padding_probe",
                result,
                archive_path=archive_path,
                error=exc,
            )
            try:
                return read_verified_tail(relaxed_crc=True, record_relaxed_usage=False)
            except Exception as retry_exc:
                raise ValueError("trusted PyTorch storage padding probe limit reached") from retry_exc
        except Exception as exc:
            raise ValueError("trusted PyTorch storage padding probe limit reached") from exc

    @staticmethod
    def _expanded_probe_preserves_trusted_scan(
        entry: zipfile.ZipInfo,
        sample: bytes,
        max_probe_bytes: int,
        predicate: Callable[..., bool],
    ) -> bool:
        if max_probe_bytes <= _TRUSTED_STORAGE_PICKLE_PROBE_BYTES:
            return False
        short_sample = sample[:_TRUSTED_STORAGE_PICKLE_PROBE_BYTES]
        return predicate(short_sample, sample_is_prefix=entry.file_size > len(short_sample))

    @staticmethod
    def _charge_padding_probe_budget(padding_probe_bytes_remaining: list[int] | None, probe_bytes: int) -> None:
        if padding_probe_bytes_remaining is None:
            return
        if probe_bytes <= 0:
            return
        if padding_probe_bytes_remaining[0] < probe_bytes:
            raise ValueError("trusted PyTorch storage padding probe budget exceeded")
        padding_probe_bytes_remaining[0] -= probe_bytes

    @staticmethod
    def _binary_pickle_probe_should_scan(sample: bytes, *, sample_is_prefix: bool) -> bool:
        opcode_count = 0
        try:
            for opcode, _arg, _pos in pickletools.genops(sample):
                opcode_count += 1
                if opcode.name == "STOP":
                    return opcode_count >= 2
        except Exception:
            return sample_is_prefix and (
                opcode_count >= 2 or PyTorchZipScanner._has_known_binary_pickle_second_opcode(sample)
            )
        return sample_is_prefix and opcode_count >= 2

    @staticmethod
    def _has_known_binary_pickle_second_opcode(sample: bytes) -> bool:
        return len(sample) >= 3 and sample[2] in _PICKLE_OPCODE_BYTES

    @staticmethod
    def _proto0_or_1_trusted_storage_probe_should_scan(sample: bytes, *, sample_is_prefix: bool) -> bool:
        if PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(sample):
            return True
        if PyTorchZipScanner._has_security_relevant_opcode_in_incomplete_frame(sample):
            return True
        if PyTorchZipScanner._trivial_complete_pickle_prefix_trailing_should_scan(
            sample,
            sample_is_prefix=sample_is_prefix,
        ):
            return True
        if PyTorchZipScanner._complete_trivial_literal_pickle_has_nested_security_pickle(sample):
            return True
        if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample):
            return False
        if not sample_is_prefix:
            return False
        if PyTorchZipScanner._contains_pickle_frame_opcode(sample):
            return False
        return _looks_like_proto0_or_1_pickle(sample, sample_is_prefix=True)

    @staticmethod
    def _proto0_or_1_trusted_storage_probe_needs_expanded_sample(
        sample: bytes,
        *,
        entry_size: int | None = None,
    ) -> bool:
        if (
            entry_size is None or entry_size > len(sample)
        ) and PyTorchZipScanner._trailing_pickle_candidate_needs_more_bytes(
            sample.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
        ):
            return True
        if PyTorchZipScanner._trivial_complete_pickle_prefix_needs_more_bytes(sample):
            return entry_size is None or entry_size > len(sample)
        if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_text_padding(sample):
            return True
        if PyTorchZipScanner._trivial_complete_pickle_prefix_has_only_padding(sample):
            return entry_size is not None and entry_size > len(sample)
        if (
            entry_size is not None
            and entry_size > len(sample)
            and PyTorchZipScanner._trivial_complete_pickle_prefix_has_mixed_nonpickle_trailing(sample)
        ):
            return True
        return PyTorchZipScanner._trivial_complete_pickle_prefix_has_ambiguous_trivial_trailing(sample)

    @staticmethod
    def _frame_first_trusted_storage_probe_should_scan(sample: bytes) -> bool:
        if not sample.startswith(_PICKLE_FRAME_OPCODE):
            return False
        if PyTorchZipScanner._complete_trivial_literal_pickle_has_nested_security_pickle(sample):
            return True
        return PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(
            sample
        ) or PyTorchZipScanner._has_structural_pickle_evidence_in_incomplete_frame(sample)

    @staticmethod
    def _has_structural_pickle_evidence_in_incomplete_frame(sample: bytes) -> bool:
        frame_end: int | None = None
        payload_opcode_count = 0
        try:
            for opcode, arg, pos in pickletools.genops(sample):
                if pos is None:
                    continue
                if opcode.name == "FRAME":
                    if frame_end is not None or not isinstance(arg, int):
                        return False
                    frame_end = pos + _PICKLE_FRAME_OPCODE_BYTES + arg
                    if frame_end <= len(sample):
                        return False
                    continue
                if frame_end is None or pos >= frame_end:
                    return False
                payload_opcode_count += 1
        except Exception as exc:
            message = str(exc).lower()
            return (
                frame_end is not None
                and frame_end > len(sample)
                and payload_opcode_count >= _PICKLE_INCOMPLETE_FRAME_MIN_PAYLOAD_OPCODES
                and (
                    "exhausted before seeing stop" in message
                    or "no newline found when trying to read" in message
                    or "not enough data" in message
                    or "expected" in message
                )
            )
        return frame_end is not None and payload_opcode_count >= _PICKLE_INCOMPLETE_FRAME_MIN_PAYLOAD_OPCODES

    @staticmethod
    def _has_security_relevant_opcode_in_incomplete_frame(sample: bytes) -> bool:
        incomplete_frame_seen = False
        security_relevant_opcode_seen = False
        try:
            for opcode, arg, pos in pickletools.genops(sample):
                if opcode.name == "FRAME" and isinstance(arg, int) and pos is not None:
                    incomplete_frame_seen = pos + _PICKLE_FRAME_OPCODE_BYTES + arg > len(sample)
                elif opcode.name in _PICKLE_SECURITY_RELEVANT_OPCODES:
                    security_relevant_opcode_seen = True
                if incomplete_frame_seen and security_relevant_opcode_seen:
                    return True
        except Exception:
            return incomplete_frame_seen and security_relevant_opcode_seen
        return False

    @staticmethod
    def _has_security_relevant_pickle_opcode(sample: bytes) -> bool:
        stream = io.BytesIO(sample)
        offset = 0
        sample_length = len(sample)
        while offset < sample_length:
            if (
                offset + 1 < sample_length
                and sample[offset : offset + 1] == b"#"
                and sample[offset + 1] in PROTO0_1_START_BYTES
            ):
                offset += 1
            trivial_offset = PyTorchZipScanner._repeated_trivial_stream_offset(sample, offset)
            if trivial_offset != offset:
                if (
                    trivial_offset < sample_length
                    and sample[trivial_offset] in _BINARY_SECURITY_OPCODE_REQUIRING_EXISTING_STACK_BYTES
                ):
                    return False
                offset = trivial_offset
                continue
            stream.seek(offset)
            try:
                for opcode, _arg, pos in pickletools.genops(stream):
                    if opcode.name in _PICKLE_SECURITY_RELEVANT_OPCODES:
                        return True
                    if opcode.name == "STOP" and pos is not None:
                        offset = pos + 1
                        while offset < sample_length and sample[offset] in PROTO0_1_IGNORABLE_TRAILING_BYTES:
                            offset += 1
                        break
                else:
                    return False
            except Exception:
                return False
        return False

    @staticmethod
    def _trailing_pickle_probe_should_scan(trailing: bytes, *, sample_is_prefix: bool) -> bool:
        candidate = trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
        if not candidate:
            return False
        candidate = PyTorchZipScanner._strip_optional_proto0_comment_prefix(candidate)
        if (
            not PyTorchZipScanner._candidate_starts_with_binary_security_opcode_requiring_existing_stack(candidate)
            and PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate)
            and (
                PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate)
                or _looks_like_proto0_or_1_pickle(
                    candidate,
                    sample_is_prefix=False,
                )
                or PyTorchZipScanner._looks_like_binary_pickle_prefix(candidate, sample_is_prefix=False)
                or PyTorchZipScanner._frame_first_trusted_storage_probe_should_scan(candidate)
            )
        ):
            return True
        if PyTorchZipScanner._trailing_candidate_has_raw_nested_security_pickle(
            candidate,
            sample_is_prefix=sample_is_prefix,
        ):
            return True
        if PyTorchZipScanner._malformed_separator_proto0_string_literal_has_nested_security_pickle(candidate):
            return True
        if not sample_is_prefix:
            return False
        if candidate.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES):
            return PyTorchZipScanner._binary_pickle_probe_should_scan(
                candidate,
                sample_is_prefix=True,
            ) or PyTorchZipScanner._looks_like_binary_pickle_prefix(candidate, sample_is_prefix=True)
        if candidate.startswith(_PICKLE_FRAME_OPCODE):
            return PyTorchZipScanner._frame_first_trusted_storage_probe_should_scan(candidate)
        return candidate[0] in PROTO0_1_START_BYTES and (
            _looks_like_proto0_or_1_pickle(candidate, sample_is_prefix=True)
        )

    @staticmethod
    def _looks_like_truncated_proto0_or_1_operand_prefix(candidate: bytes) -> bool:
        if candidate.startswith(b"S"):
            if len(candidate) == 1:
                return True
            if candidate.startswith((b"S'", b'S"')):
                return b"\n" not in candidate[2:]
            return False
        if candidate.startswith(b"P"):
            return b"\n" not in candidate[1:]
        if candidate.startswith((b"c", b"i")):
            if len(candidate) == 1:
                return True
            if b"\n" in candidate:
                return candidate.count(b"\n") < 2
            return (
                len(candidate) <= _TRUSTED_STORAGE_PICKLE_PROBE_BYTES
                and _PROTO0_GLOBAL_OR_INST_PREFIX_WITHOUT_NEWLINE_RE.fullmatch(candidate) is not None
            )
        if candidate.startswith((b"F", b"I", b"L")):
            return b"\n" not in candidate[1:]
        if candidate.startswith(b"V"):
            return b"\n" not in candidate[1:]
        if candidate.startswith((b"T", b"X")):
            if len(candidate) < 5:
                return True
            declared_size = int.from_bytes(candidate[1:5], "little")
            return len(candidate) - 5 < declared_size
        if candidate.startswith(b"U"):
            if len(candidate) < 2:
                return True
            declared_size = candidate[1]
            return len(candidate) - 2 < declared_size
        return False

    @staticmethod
    def _candidate_starts_with_binary_security_opcode_requiring_existing_stack(candidate: bytes) -> bool:
        return bool(candidate) and candidate[0] in _BINARY_SECURITY_OPCODE_REQUIRING_EXISTING_STACK_BYTES

    @staticmethod
    def _looks_like_truncated_binary_pickle_operand_prefix(candidate: bytes) -> bool:
        if candidate.startswith((b"B", b"T", b"X", b"\x8b")):
            if len(candidate) < 5:
                return True
            declared_size = int.from_bytes(candidate[1:5], "little")
            return len(candidate) - 5 < declared_size
        if candidate.startswith((b"C", b"U", b"\x8a", b"\x8c")):
            if len(candidate) < 2:
                return True
            declared_size = candidate[1]
            return len(candidate) - 2 < declared_size
        if candidate.startswith((b"\x8d", b"\x8e", b"\x96")):
            if len(candidate) < 9:
                return True
            declared_size = int.from_bytes(candidate[1:9], "little")
            return len(candidate) - 9 < declared_size
        return False

    @staticmethod
    def _looks_like_truncated_fixed_width_pickle_operand_prefix(candidate: bytes) -> bool:
        if candidate.startswith((b"K", b"h", b"q", b"\x82")):
            return len(candidate) < 2
        if candidate.startswith((b"M", b"\x83")):
            return len(candidate) < 3
        if candidate.startswith((b"J", b"j", b"r", b"\x84")):
            return len(candidate) < 5
        if candidate.startswith(b"G"):
            return len(candidate) < 9
        return False

    @staticmethod
    def _looks_like_truncated_security_opcode_prefix(candidate: bytes) -> bool:
        if candidate.startswith(b"\x82"):
            return len(candidate) < 2
        if candidate.startswith(b"\x83"):
            return len(candidate) < 3
        if candidate.startswith(b"\x84"):
            return len(candidate) < 5
        return False

    @staticmethod
    def _trivial_complete_pickle_prefix_trailing_should_scan(sample: bytes, *, sample_is_prefix: bool) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        return trailing is not None and PyTorchZipScanner._trailing_pickle_probe_should_scan(
            trailing,
            sample_is_prefix=sample_is_prefix,
        )

    @staticmethod
    def _trivial_complete_pickle_prefix_has_ambiguous_trivial_trailing(sample: bytes) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        if trailing is None:
            return False
        candidate = trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
        if not candidate:
            return True
        if PyTorchZipScanner._looks_like_truncated_proto0_or_1_operand_prefix(candidate):
            return True
        while candidate:
            active_frame_end = 0
            opcode_count = 0
            saw_opcode = False
            try:
                for opcode, arg, pos in pickletools.genops(candidate):
                    saw_opcode = True
                    opcode_count += 1
                    if pos is None:
                        continue
                    if opcode.name == "FRAME":
                        if not isinstance(arg, int):
                            return False
                        active_frame_end = max(active_frame_end, pos + _PICKLE_FRAME_OPCODE_BYTES + arg)
                    elif opcode.name == "STOP":
                        if opcode_count < 2 or active_frame_end > len(candidate):
                            return False
                        candidate = candidate[pos + 1 :].lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
                        break
                    elif opcode.name not in PROTO0_1_TRIVIAL_LEADING_OPCODES:
                        return False
                else:
                    return saw_opcode
            except ValueError as exc:
                exc_message = str(exc)
                return saw_opcode and any(
                    exc_message.startswith(error_prefix) for error_prefix in PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES
                )
            except Exception:
                return False
        return True

    @staticmethod
    def _trivial_complete_pickle_prefix_needs_more_bytes(sample: bytes) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        if trailing is None:
            return False
        candidate = trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
        return PyTorchZipScanner._trailing_pickle_candidate_needs_more_bytes(candidate)

    @staticmethod
    def _trailing_pickle_candidate_needs_more_bytes(candidate: bytes) -> bool:
        while candidate:
            if candidate == b"#":
                return True
            if len(candidate) == 1 and candidate[0] not in PROTO0_1_START_BYTES:
                return True
            stripped_comment_candidate = PyTorchZipScanner._strip_optional_proto0_comment_prefix(candidate)
            if stripped_comment_candidate != candidate:
                candidate = stripped_comment_candidate
                continue
            trivial_trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(candidate)
            if trivial_trailing is not None and len(trivial_trailing) < len(candidate):
                candidate = trivial_trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
                continue
            repeated_none_trailing = PyTorchZipScanner._repeated_none_stream_trailing(candidate)
            if repeated_none_trailing is not None and len(repeated_none_trailing) < len(candidate):
                candidate = repeated_none_trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
                continue
            if PyTorchZipScanner._looks_like_malformed_separator_run_prefix(candidate):
                return True
            if candidate.startswith(_PICKLE_FRAME_OPCODE):
                if len(candidate) < _PICKLE_FRAME_OPCODE_BYTES:
                    return True
                frame_payload_size = int.from_bytes(candidate[1:_PICKLE_FRAME_OPCODE_BYTES], "little")
                frame_end = _PICKLE_FRAME_OPCODE_BYTES + frame_payload_size
                if len(candidate) <= frame_end:
                    return True
                candidate = candidate[frame_end:].lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
                continue
            if PyTorchZipScanner._looks_like_truncated_proto0_or_1_operand_prefix(candidate):
                return True
            if PyTorchZipScanner._looks_like_truncated_binary_pickle_operand_prefix(candidate):
                return True
            if PyTorchZipScanner._looks_like_truncated_fixed_width_pickle_operand_prefix(candidate):
                return True
            if PyTorchZipScanner._looks_like_truncated_security_opcode_prefix(candidate):
                return True
            if PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate):
                return not PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate)
            return any(
                magic.startswith(candidate) or (candidate.startswith(magic) and len(candidate) < 3)
                for magic in _PICKLE_BINARY_PROTOCOL_PREFIXES
            )
        return False

    @staticmethod
    def _strip_optional_proto0_comment_prefix(candidate: bytes) -> bytes:
        if len(candidate) >= 2 and candidate[0:1] == b"#" and candidate[1] in PROTO0_1_START_BYTES:
            return candidate[1:]
        return candidate

    @staticmethod
    def _trivial_complete_pickle_prefix_has_only_padding(sample: bytes) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        return trailing is not None and not trailing.strip(PROTO0_1_IGNORABLE_TRAILING_BYTES)

    @staticmethod
    def _trivial_complete_pickle_prefix_has_only_nul_padding(sample: bytes) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        return trailing is not None and bool(trailing) and not trailing.strip(b"\x00")

    @staticmethod
    def _trivial_complete_pickle_prefix_has_only_text_padding(sample: bytes) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        return trailing is not None and bool(trailing) and not trailing.strip(_PROTO0_1_TEXT_WHITESPACE_BYTES)

    @staticmethod
    def _trivial_complete_pickle_prefix_has_mixed_nonpickle_trailing(sample: bytes) -> bool:
        trailing = PyTorchZipScanner._trivial_complete_pickle_prefix_trailing(sample)
        if trailing is None:
            return False
        candidate = trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
        if len(candidate) < 2 or candidate[0] in PROTO0_1_START_BYTES:
            return False
        first_byte = candidate[0]
        return any(byte != first_byte and byte not in PROTO0_1_IGNORABLE_TRAILING_BYTES for byte in candidate[1:])

    @staticmethod
    def _malformed_separator_proto0_string_literal_has_nested_security_pickle(candidate: bytes) -> bool:
        if not candidate or candidate[0] in PROTO0_1_START_BYTES:
            return False
        offset = 0
        limit = len(candidate)
        while offset < limit and candidate[offset] not in PROTO0_1_START_BYTES:
            offset += 1
        if offset >= limit or candidate[offset : offset + 1] != b"S":
            return False
        return PyTorchZipScanner._complete_proto0_string_literal_has_nested_security_pickle(
            candidate[offset:].lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
        )

    @staticmethod
    def _looks_like_malformed_separator_run_prefix(candidate: bytes) -> bool:
        if not candidate or candidate[0] in PROTO0_1_START_BYTES or candidate[0] in PROTO0_1_IGNORABLE_TRAILING_BYTES:
            return False
        return len(candidate) <= _TRUSTED_STORAGE_PICKLE_PROBE_BYTES and not candidate.strip(bytes([candidate[0]]))

    @staticmethod
    def _trivial_complete_pickle_prefix_trailing(sample: bytes) -> bytes | None:
        active_frame_end = 0
        opcode_count = 0
        has_non_trivial_opcode = False
        try:
            for opcode, arg, pos in pickletools.genops(sample):
                opcode_count += 1
                if pos is None:
                    continue
                if opcode.name == "FRAME":
                    if not isinstance(arg, int):
                        return None
                    active_frame_end = max(active_frame_end, pos + _PICKLE_FRAME_OPCODE_BYTES + arg)
                elif opcode.name == "STOP":
                    if opcode_count < 2 or active_frame_end > len(sample) or has_non_trivial_opcode:
                        return None
                    return sample[pos + 1 :]
                elif opcode.name not in PROTO0_1_TRIVIAL_LEADING_OPCODES:
                    has_non_trivial_opcode = True
        except Exception:
            return None
        return None

    @staticmethod
    def _complete_trivial_literal_pickle_has_nested_security_pickle(sample: bytes) -> bool:
        cursor = 0
        stream = io.BytesIO(sample)
        while cursor < len(sample):
            if (
                cursor + 1 < len(sample)
                and sample[cursor : cursor + 1] == b"#"
                and sample[cursor + 1] in PROTO0_1_START_BYTES
            ):
                cursor += 1
                continue
            active_frame_end = 0
            opcode_count = 0
            literal_values: list[bytes] = []
            try:
                stream.seek(cursor)
                for opcode, arg, pos in pickletools.genops(stream):
                    opcode_count += 1
                    if pos is None:
                        continue
                    if opcode.name == "FRAME":
                        if not isinstance(arg, int):
                            return False
                        active_frame_end = max(active_frame_end, pos + _PICKLE_FRAME_OPCODE_BYTES + arg)
                    elif opcode.name == "STOP":
                        if opcode_count < 2 or active_frame_end > len(sample):
                            return False
                        if any(
                            PyTorchZipScanner._literal_value_has_storage_scan_signal(value) for value in literal_values
                        ):
                            return True
                        cursor = pos + 1
                        while cursor < len(sample) and sample[cursor] in PROTO0_1_IGNORABLE_TRAILING_BYTES:
                            cursor += 1
                        if cursor >= len(sample):
                            return False
                        break
                    elif opcode.name in _PICKLE_LITERAL_OPCODES:
                        literal_value = PyTorchZipScanner._literal_arg_bytes(opcode.name, arg)
                        if literal_value is not None:
                            literal_values.append(literal_value)
                else:
                    return False
            except Exception:
                return PyTorchZipScanner._complete_proto0_string_literal_has_nested_security_pickle(sample[cursor:])
        return False

    @staticmethod
    def _complete_proto0_string_literal_has_nested_security_pickle(sample: bytes) -> bool:
        if not sample.startswith(b"S"):
            return False
        line_end = sample.find(b"\n", 1)
        if line_end < 0:
            return False
        literal = sample[1:line_end]
        if len(literal) < 2 or literal[:1] not in {b"'", b'"'} or literal[-1:] != literal[:1]:
            return False
        trailing = sample[line_end + 1 :]
        if not trailing.startswith(b".") or trailing[1:].strip(PROTO0_1_IGNORABLE_TRAILING_BYTES):
            return False
        try:
            escape_decode: Any = codecs.escape_decode
            decoded_literal = escape_decode(literal[1:-1])[0]
        except Exception:
            return False
        literal_value = (
            decoded_literal
            if isinstance(decoded_literal, bytes)
            else PyTorchZipScanner._literal_str_to_scan_bytes(decoded_literal)
        )
        return PyTorchZipScanner._literal_value_has_storage_scan_signal(literal_value)

    @staticmethod
    def _literal_arg_bytes(opcode_name: str, value: Any) -> bytes | None:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str) and opcode_name in _PROTO0_1_LITERAL_OPCODES:
            return PyTorchZipScanner._literal_str_to_scan_bytes(value)
        return None

    @staticmethod
    def _literal_str_to_scan_bytes(value: str) -> bytes:
        output = bytearray()
        text_segment: list[str] = []
        for char in value:
            code_point = ord(char)
            if code_point <= 0xFF:
                if text_segment:
                    output.extend("".join(text_segment).encode("utf-8", errors="surrogatepass"))
                    text_segment.clear()
                output.append(code_point)
            else:
                text_segment.append(char)
        if text_segment:
            output.extend("".join(text_segment).encode("utf-8", errors="surrogatepass"))
        return bytes(output)

    @staticmethod
    def _literal_value_has_nested_security_pickle(value: bytes) -> bool:
        return PyTorchZipScanner._literal_value_has_raw_nested_security_pickle(
            value
        ) or PyTorchZipScanner._literal_value_has_encoded_nested_security_pickle(value)

    @staticmethod
    def _literal_value_has_storage_scan_signal(value: bytes) -> bool:
        return PyTorchZipScanner._literal_value_has_nested_security_pickle(
            value
        ) or PyTorchZipScanner._literal_value_has_suspicious_text(value)

    @staticmethod
    def _literal_value_has_suspicious_text(value: bytes) -> bool:
        text = value.decode("utf-8", errors="ignore")
        if not text:
            text = value.decode("latin-1", errors="ignore")
        return PyTorchZipScanner._literal_text_has_storage_route_signal(
            text
        ) or PyTorchZipScanner._literal_value_has_encoded_suspicious_text(value)

    @staticmethod
    def _literal_text_has_storage_route_signal(text: str) -> bool:
        return any(pattern.search(text) for pattern in _SUSPICIOUS_LITERAL_TEXT_PATTERNS) or any(
            pattern.search(text) for pattern in _STORAGE_LITERAL_TEXT_ROUTE_PATTERNS
        )

    @staticmethod
    def _literal_value_has_encoded_suspicious_text(value: bytes) -> bool:
        return PyTorchZipScanner._base64_literal_value_has_suspicious_text(
            value
        ) or PyTorchZipScanner._hex_literal_value_has_suspicious_text(value)

    @staticmethod
    def _decoded_literal_text_has_storage_route_signal(decoded: bytes) -> bool:
        start = 0
        window_count = 0
        step = _MAX_STORAGE_LITERAL_DECODED_TEXT_BYTES - _STORAGE_LITERAL_DECODED_TEXT_WINDOW_OVERLAP_BYTES
        while start < len(decoded):
            window_count += 1
            if window_count > _MAX_STORAGE_LITERAL_DECODED_TEXT_WINDOWS:
                return True
            window = decoded[start : start + _MAX_STORAGE_LITERAL_DECODED_TEXT_BYTES]
            for encoding in ("utf-8", "latin-1"):
                text = window.decode(encoding, errors="ignore")
                if text and PyTorchZipScanner._literal_text_has_storage_route_signal(text):
                    return True
            if start + _MAX_STORAGE_LITERAL_DECODED_TEXT_BYTES >= len(decoded):
                break
            start += step
        return False

    @staticmethod
    def _base64_literal_value_has_suspicious_text(value: bytes) -> bool:
        candidate_count = 0
        for match in _BASE64_LITERAL_TEXT_TOKEN_RE.finditer(value):
            compact = re.sub(rb"\s+", b"", match.group(0)).translate(bytes.maketrans(b"-_", b"+/"))
            if len(compact) < 8:
                continue
            candidate_count += 1
            if candidate_count > _MAX_STORAGE_LITERAL_TEXT_CANDIDATES:
                return True
            for shift in range(min(16, len(compact))):
                token = compact[shift:]
                if len(token) < 8:
                    continue
                if PyTorchZipScanner._base64_token_has_storage_route_signal(token):
                    return True
        return False

    @staticmethod
    def _base64_token_has_storage_route_signal(token: bytes) -> bool:
        start = 0
        window_count = 0
        while start < len(token):
            window_count += 1
            if window_count > _MAX_STORAGE_LITERAL_DECODED_TEXT_WINDOWS:
                return True
            window = token[start : start + _MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES]
            window += b"=" * (-len(window) % 4)
            try:
                decoded = base64.b64decode(window, validate=True)
            except (binascii.Error, ValueError):
                return False
            if decoded and PyTorchZipScanner._decoded_literal_text_has_storage_route_signal(decoded):
                return True
            if start + _MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES >= len(token):
                break
            start += _STORAGE_LITERAL_BASE64_DECODE_INPUT_STRIDE_BYTES
        return False

    @staticmethod
    def _hex_literal_value_has_suspicious_text(value: bytes) -> bool:
        candidate_count = 0
        for match in _HEX_LITERAL_TEXT_TOKEN_RE.finditer(value):
            compact = re.sub(rb"\s+", b"", match.group(0))
            if len(compact) < 8:
                continue
            candidate_count += 1
            if candidate_count > _MAX_STORAGE_LITERAL_TEXT_CANDIDATES:
                return True
            try:
                decoded = binascii.unhexlify(compact)
            except (binascii.Error, ValueError):
                continue
            if decoded and PyTorchZipScanner._decoded_literal_text_has_storage_route_signal(decoded):
                return True
        return False

    @staticmethod
    def _literal_value_has_raw_nested_security_pickle(
        value: bytes, *, fail_closed_on_candidate_budget: bool = True
    ) -> bool:
        candidate_count = 0
        for offset, marker in enumerate(value):
            if marker not in _RAW_NESTED_SECURITY_PICKLE_START_BYTES:
                continue
            candidate_count += 1
            if candidate_count > _MAX_RAW_NESTED_PICKLE_CANDIDATES:
                if not fail_closed_on_candidate_budget:
                    return PyTorchZipScanner._encoded_raw_nested_security_pickle_candidate_budget_exhausted_needs_scan(
                        value[offset:]
                    )
                return PyTorchZipScanner._raw_nested_security_pickle_candidate_budget_exhausted_needs_scan(
                    value[offset:]
                )
            candidate = value[offset : offset + _MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES]
            candidate_is_prefix = offset + len(candidate) < len(value)
            if marker == 0x80 and PyTorchZipScanner._looks_like_binary_pickle_prefix(
                candidate, sample_is_prefix=candidate_is_prefix
            ):
                if PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate):
                    return True
                if candidate_is_prefix:
                    return True
                continue
            if (
                marker in _RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES
                and PyTorchZipScanner._raw_nested_binary_candidate_should_scan(
                    candidate,
                    candidate_is_prefix=candidate_is_prefix,
                )
            ):
                return True
            if (
                marker in _BINARY_EXTENSION_SECURITY_OPCODE_BYTES
                and PyTorchZipScanner._raw_nested_extension_opcode_candidate_has_structural_signal(candidate)
            ):
                return True
            if (
                marker in PROTO0_1_START_BYTES
                and PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate)
                and (
                    PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate)
                    or _looks_like_proto0_or_1_pickle(candidate, sample_is_prefix=candidate_is_prefix)
                )
            ):
                return True
        return False

    @staticmethod
    def _trailing_candidate_has_raw_nested_security_pickle(value: bytes, *, sample_is_prefix: bool) -> bool:
        parse_attempt_count = 0
        for offset, marker in enumerate(value):
            if marker not in _RAW_NESTED_SECURITY_PICKLE_START_BYTES:
                continue
            candidate = value[offset : offset + _MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES]
            candidate_is_prefix = offset + len(candidate) < len(value) or sample_is_prefix
            parse_attempt_count += 1
            if parse_attempt_count > _MAX_RAW_NESTED_PICKLE_CANDIDATES:
                return PyTorchZipScanner._raw_nested_security_pickle_candidate_budget_exhausted_needs_scan(
                    value[offset:]
                )
            if marker == 0x80 and PyTorchZipScanner._looks_like_binary_pickle_prefix(
                candidate, sample_is_prefix=candidate_is_prefix
            ):
                if PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate) or candidate_is_prefix:
                    return True
                continue
            if (
                marker in _RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES
                and PyTorchZipScanner._raw_nested_binary_candidate_should_scan(
                    candidate,
                    candidate_is_prefix=candidate_is_prefix,
                )
            ):
                return True
            if (
                marker in PROTO0_1_START_BYTES
                and PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate)
                and (
                    PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate)
                    or _looks_like_proto0_or_1_pickle(candidate, sample_is_prefix=candidate_is_prefix)
                )
            ):
                return True
        return False

    @staticmethod
    def _raw_nested_security_pickle_candidate_budget_exhausted_needs_scan(value: bytes) -> bool:
        if PyTorchZipScanner._raw_nested_security_pickle_text_marker_seen(value):
            return True
        return PyTorchZipScanner._raw_nested_security_pickle_candidate_has_structural_signal(value)

    @staticmethod
    def _encoded_raw_nested_security_pickle_candidate_budget_exhausted_needs_scan(value: bytes) -> bool:
        if PyTorchZipScanner._raw_nested_security_pickle_text_marker_seen(value):
            return True
        value = value.lstrip(b"c \t\r\n\x00")
        candidate = value[:_MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES]
        candidate_is_prefix = len(value) > len(candidate)
        if not candidate:
            return False
        marker = candidate[0]
        if marker in _BINARY_EXTENSION_SECURITY_OPCODE_BYTES:
            return True
        if marker == 0x80 and PyTorchZipScanner._looks_like_binary_pickle_prefix(
            candidate,
            sample_is_prefix=candidate_is_prefix,
        ):
            return PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate) or candidate_is_prefix
        if (
            marker in _RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES
            and PyTorchZipScanner._raw_nested_binary_candidate_should_scan(
                candidate,
                candidate_is_prefix=candidate_is_prefix,
            )
        ):
            return True
        has_candidate_signal = (
            marker in PROTO0_1_START_BYTES
            and PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate)
            and (
                PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate)
                or _looks_like_proto0_or_1_pickle(candidate, sample_is_prefix=candidate_is_prefix)
            )
        )
        if has_candidate_signal:
            return True
        return PyTorchZipScanner._raw_nested_security_pickle_candidate_has_structural_signal(value)

    @staticmethod
    def _raw_nested_security_pickle_candidate_has_structural_signal(value: bytes) -> bool:
        parse_budget_remaining = [_MAX_RAW_NESTED_PICKLE_CANDIDATES]
        if PyTorchZipScanner._raw_nested_proto0_global_ref_seen(value):
            return True
        if PyTorchZipScanner._raw_nested_binary_protocol_candidate_has_structural_signal(
            value,
            parse_budget_remaining,
        ):
            return True
        if PyTorchZipScanner._raw_nested_extension_opcode_candidate_has_structural_signal(value):
            return True
        if PyTorchZipScanner._raw_nested_binary_opcode_candidate_has_structural_signal(
            value,
            parse_budget_remaining,
        ):
            return True
        stripped = value.lstrip(b" \t\r\n\x00")
        candidate = stripped[:_MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES]
        candidate_is_prefix = len(stripped) > len(candidate)
        if not candidate:
            return False
        marker = candidate[0]
        if marker in _BINARY_EXTENSION_SECURITY_OPCODE_BYTES:
            return True
        if not PyTorchZipScanner._consume_raw_nested_structural_parse_budget(parse_budget_remaining):
            return True
        if marker == 0x80 and PyTorchZipScanner._looks_like_binary_pickle_prefix(
            candidate,
            sample_is_prefix=candidate_is_prefix,
        ):
            return PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate) or candidate_is_prefix
        if (
            marker in _RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES
            and PyTorchZipScanner._raw_nested_binary_candidate_should_scan(
                candidate,
                candidate_is_prefix=candidate_is_prefix,
            )
        ):
            return True
        if marker == ord("c"):
            return False
        return (
            marker in PROTO0_1_START_BYTES
            and PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate)
            and (
                PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate)
                or _looks_like_proto0_or_1_pickle(candidate, sample_is_prefix=candidate_is_prefix)
            )
        )

    @staticmethod
    def _consume_raw_nested_structural_parse_budget(parse_budget_remaining: list[int]) -> bool:
        if parse_budget_remaining[0] <= 0:
            return False
        parse_budget_remaining[0] -= 1
        return True

    @staticmethod
    def _raw_nested_proto0_global_ref_seen(value: bytes) -> bool:
        search_limit = min(len(value), _PICKLE_DISCOVERY_LONG_PROBE_BYTES)
        search_start = 0
        while search_start < search_limit:
            offset = value.find(b"c", search_start, search_limit)
            if offset < 0:
                return False
            module_start = offset + 1
            if module_start >= search_limit:
                return False
            if value[module_start] not in _PROTO0_GLOBAL_NAME_START_BYTES:
                search_start = module_start
                continue
            module_end = module_start
            while module_end < search_limit and value[module_end] in _PROTO0_GLOBAL_NAME_BYTES:
                module_end += 1
            if module_end >= search_limit:
                return False
            if value[module_end] != 0x0A:
                search_start = module_end + 1
                continue
            name_start = module_end + 1
            if name_start >= search_limit:
                return False
            if value[name_start] not in _PROTO0_GLOBAL_NAME_START_BYTES:
                search_start = name_start + 1
                continue
            name_end = name_start
            while name_end < search_limit and value[name_end] in _PROTO0_GLOBAL_NAME_BYTES:
                name_end += 1
            if name_end < search_limit and value[name_end] == 0x0A:
                return True
            search_start = name_end + 1
        return False

    @staticmethod
    def _raw_nested_binary_protocol_candidate_has_structural_signal(
        value: bytes,
        parse_budget_remaining: list[int],
    ) -> bool:
        search_limit = min(len(value), _PICKLE_DISCOVERY_LONG_PROBE_BYTES)
        search_start = 0
        while search_start < search_limit:
            offset = min(
                (
                    found
                    for prefix in _PICKLE_BINARY_PROTOCOL_PREFIXES
                    if (found := value.find(prefix, search_start, search_limit)) >= 0
                ),
                default=-1,
            )
            if offset < 0:
                return False
            if not PyTorchZipScanner._consume_raw_nested_structural_parse_budget(parse_budget_remaining):
                return True
            candidate = value[offset : offset + _MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES]
            candidate_is_prefix = offset + len(candidate) < len(value)
            if PyTorchZipScanner._looks_like_binary_pickle_prefix(
                candidate,
                sample_is_prefix=candidate_is_prefix,
            ) and (PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate) or candidate_is_prefix):
                return True
            search_start = offset + 1
        return False

    @staticmethod
    def _raw_nested_extension_opcode_candidate_has_structural_signal(value: bytes) -> bool:
        search_limit = min(len(value), _PICKLE_DISCOVERY_LONG_PROBE_BYTES)
        search_start = 0
        while search_start < search_limit:
            offset = min(
                (
                    found
                    for marker in _BINARY_EXTENSION_SECURITY_OPCODE_BYTES
                    if (found := value.find(bytes([marker]), search_start, search_limit)) >= 0
                ),
                default=-1,
            )
            if offset < 0:
                return False
            operand_len = _BINARY_EXTENSION_OPCODE_OPERAND_BYTES[value[offset]]
            follower_offset = offset + 1 + operand_len
            if (
                follower_offset < search_limit
                and follower_offset < len(value)
                and value[follower_offset] in _BINARY_EXTENSION_OPCODE_FOLLOWER_BYTES
            ):
                return True
            search_start = offset + 1
        return False

    @staticmethod
    def _raw_nested_binary_opcode_candidate_has_structural_signal(
        value: bytes,
        parse_budget_remaining: list[int],
    ) -> bool:
        search_limit = min(len(value), _PICKLE_DISCOVERY_LONG_PROBE_BYTES)
        search_start = 0
        while search_start < search_limit:
            offset = min(
                (
                    found
                    for marker in _RAW_NESTED_BINARY_SECURITY_PICKLE_START_BYTES
                    if (found := value.find(bytes([marker]), search_start, search_limit)) >= 0
                ),
                default=-1,
            )
            if offset < 0:
                return False
            if not PyTorchZipScanner._consume_raw_nested_structural_parse_budget(parse_budget_remaining):
                return True
            candidate = value[offset : offset + _MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES]
            candidate_is_prefix = offset + len(candidate) < len(value)
            if PyTorchZipScanner._raw_nested_binary_candidate_should_scan(
                candidate,
                candidate_is_prefix=candidate_is_prefix,
            ):
                return True
            search_start = offset + 1
        return False

    @staticmethod
    def _raw_nested_binary_candidate_should_scan(candidate: bytes, *, candidate_is_prefix: bool) -> bool:
        if not PyTorchZipScanner._has_security_relevant_pickle_opcode(candidate):
            return False
        if PyTorchZipScanner._has_complete_pickle_stream_without_frame_stop_overrun(candidate):
            return True
        if PyTorchZipScanner._frame_first_trusted_storage_probe_should_scan(candidate):
            return True
        return candidate_is_prefix and PyTorchZipScanner._has_security_relevant_opcode_in_incomplete_frame(candidate)

    @staticmethod
    def _raw_nested_security_pickle_text_marker_seen(value: bytes) -> bool:
        return any(marker in value for marker in _RAW_NESTED_SECURITY_PICKLE_TEXT_MARKERS)

    @staticmethod
    def _literal_value_has_encoded_nested_security_pickle(value: bytes) -> bool:
        for match in _BASE64_NESTED_LITERAL_TOKEN_RE.finditer(value):
            token = re.sub(rb"\s+", b"", match.group(0)).translate(bytes.maketrans(b"-_", b"+/"))
            for shift in range(min(4, len(token))):
                shifted_token = token[shift:]
                shifted_token += b"=" * (-len(shifted_token) % 4)
                try:
                    decoded = base64.b64decode(shifted_token, validate=True)
                except (binascii.Error, ValueError):
                    continue
                if decoded and PyTorchZipScanner._literal_value_has_raw_nested_security_pickle(
                    decoded, fail_closed_on_candidate_budget=False
                ):
                    return True
        for match in _HEX_NESTED_LITERAL_TOKEN_RE.finditer(value):
            compact = re.sub(rb"\s+", b"", match.group(0))
            for shift in range(min(2, len(compact))):
                shifted_token = compact[shift:]
                shifted_token = shifted_token[: len(shifted_token) - (len(shifted_token) % 2)]
                if len(shifted_token) < 16:
                    continue
                try:
                    decoded = binascii.unhexlify(shifted_token)
                except (binascii.Error, ValueError):
                    continue
                if decoded and PyTorchZipScanner._literal_value_has_raw_nested_security_pickle(
                    decoded, fail_closed_on_candidate_budget=False
                ):
                    return True
        return False

    @staticmethod
    def _contains_pickle_frame_opcode(sample: bytes) -> bool:
        try:
            return any(opcode.name == "FRAME" for opcode, _arg, _pos in pickletools.genops(sample))
        except Exception:
            return False

    @staticmethod
    def _has_complete_pickle_stream_without_frame_stop_overrun(sample: bytes) -> bool:
        stream = io.BytesIO(sample)
        offset = 0
        skipped_trivial_prefix = False
        sample_length = len(sample)
        while offset < sample_length:
            if (
                offset + 1 < sample_length
                and sample[offset : offset + 1] == b"#"
                and sample[offset + 1] in PROTO0_1_START_BYTES
            ):
                offset += 1
            trivial_offset = PyTorchZipScanner._repeated_trivial_stream_offset(sample, offset)
            if trivial_offset != offset:
                if trivial_offset >= sample_length:
                    return False
                if sample[trivial_offset] in _BINARY_SECURITY_OPCODE_REQUIRING_EXISTING_STACK_BYTES:
                    return False
                offset = trivial_offset
                skipped_trivial_prefix = True
                continue
            stream.seek(offset)
            active_frame_end = 0
            opcode_count = 0
            has_non_trivial_opcode = False
            has_security_relevant_opcode = False
            try:
                for opcode, arg, pos in pickletools.genops(stream):
                    opcode_count += 1
                    if pos is None:
                        continue
                    if opcode.name == "FRAME":
                        if not isinstance(arg, int):
                            return False
                        active_frame_end = max(active_frame_end, pos + _PICKLE_FRAME_OPCODE_BYTES + arg)
                    elif opcode.name == "STOP":
                        if opcode_count < 2 or active_frame_end > sample_length:
                            return False
                        if has_non_trivial_opcode:
                            return has_security_relevant_opcode or not skipped_trivial_prefix
                        offset = pos + 1
                        while offset < sample_length and sample[offset] in PROTO0_1_IGNORABLE_TRAILING_BYTES:
                            offset += 1
                        if offset >= sample_length:
                            return False
                        skipped_trivial_prefix = True
                        break
                    elif opcode.name not in PROTO0_1_TRIVIAL_LEADING_OPCODES:
                        has_non_trivial_opcode = True
                        if opcode.name in _PICKLE_SECURITY_RELEVANT_OPCODES:
                            has_security_relevant_opcode = True
                else:
                    return False
            except Exception:
                return False
        return False

    @staticmethod
    def _repeated_trivial_stream_offset(sample: bytes, offset: int) -> int:
        original_offset = offset
        sample_length = len(sample)
        while offset < sample_length:
            if offset + 2 <= sample_length and sample[offset : offset + 2] == b"N.":
                offset += 2
            elif offset < sample_length and sample[offset : offset + 1] == b"I":
                match = _REPEATED_PROTO0_INT_STREAM_RE.match(sample, offset)
                if match is None:
                    break
                offset = match.end()
            else:
                break
            while offset < sample_length and sample[offset] in PROTO0_1_IGNORABLE_TRAILING_BYTES:
                offset += 1
        return offset if offset != original_offset else original_offset

    @staticmethod
    def _repeated_none_stream_trailing(sample: bytes) -> bytes | None:
        offset = 0
        saw_stream = False
        sample_length = len(sample)
        while offset + 2 <= sample_length and sample[offset : offset + 2] == b"N.":
            saw_stream = True
            offset += 2
            while offset < sample_length and sample[offset] in PROTO0_1_IGNORABLE_TRAILING_BYTES:
                offset += 1
        if not saw_stream:
            return None
        return sample[offset:] if offset < sample_length else b""

    @staticmethod
    def _looks_like_binary_pickle_prefix(sample: bytes, *, sample_is_prefix: bool) -> bool:
        """Validate binary pickle-looking bytes enough to avoid random tensor false positives."""
        if not any(sample.startswith(magic) for magic in _PICKLE_BINARY_PROTOCOL_PREFIXES):
            return False

        # Thresholds tuned for the discovery probe:
        # * ``>= 4`` on a clean parse — a ``PROTO`` byte plus three additional
        #   opcodes is unlikely to appear coincidentally in tensor storage noise
        #   that just happens to start with ``\x80\x0?``, but any real pickle
        #   (even trivial ones) will clear it quickly.
        # * ``>= 2`` when ``genops`` either ran out of bytes mid-stream (prefix
        #   sample) or raised a truncation-style ``ValueError``. Two valid
        #   opcodes before the cliff is enough structural evidence to route to
        #   the full pickle scanner, where the authoritative parse happens.
        op_count = 0
        try:
            for opcode, _arg, _pos in pickletools.genops(sample):
                op_count += 1
                if opcode.name == "STOP":
                    return True
                if op_count >= 4:
                    return True
        except ValueError as exc:
            message = str(exc).lower()
            return (
                sample_is_prefix
                and op_count >= 2
                and ("exhausted before seeing stop" in message or "not enough data" in message or "expected" in message)
            )

        return sample_is_prefix and op_count >= 2

    def _check_pytorch_vulnerabilities(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
    ) -> None:
        """Extract PyTorch version info and check for CVE vulnerabilities"""
        pytorch_version_info = self._extract_pytorch_version_info(zip_file, safe_entries, result)
        result.metadata.update(pytorch_version_info)
        self._add_pytorch_version_provenance_check(pytorch_version_info, result, path)
        self._check_cve_2025_32434_vulnerability(pytorch_version_info, result, path)
        self._check_cve_2026_24747_vulnerability(pytorch_version_info, result, path)
        self._check_cve_2022_45907_vulnerability(pytorch_version_info, result, path)
        self._check_cve_2024_5480_vulnerability(pytorch_version_info, result, path)
        self._check_cve_2024_48063_vulnerability(pytorch_version_info, result, path)

    def _scan_pickle_files(
        self,
        zip_file: zipfile.ZipFile,
        pickle_files: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
        *,
        trusted_pytorch_storage_persistent_id_data_pkl_members: dict[str, set[str]],
        pytorch_data_pickle_storage_sizes_by_data_pkl: dict[str, dict[str, int]],
    ) -> tuple[int, set[int]]:
        """Scan all discovered pickle files for malicious content"""
        bytes_scanned = 0
        clean_pickle_entry_ids: set[int] = set()

        # Get the original ZIP file size for proper density calculations
        # This is crucial for CVE-2025-32434 detection to avoid false positives
        original_file_size = int(result.metadata.get("file_size") or 0)
        if original_file_size <= 0:
            try:
                original_file_size = os.path.getsize(path)
            except OSError:
                original_file_size = 1  # Avoid divide-by-zero in density calculations

        fallback_storage_trust_opcodes_remaining = [_PYTORCH_STORAGE_TRUST_MAX_OPCODES]
        for info in pickle_files:
            self._check_timeout()
            name = self._get_zip_member_name(info)
            pickle_data_size = info.file_size
            pickle_source = f"{path}:{name}"
            pytorch_data_pickle_storage_sizes = pytorch_data_pickle_storage_sizes_by_data_pkl.get(name)

            if self.pickle_scanner is None:
                bytes_scanned += pickle_data_size
                trusted_storage_keys = trusted_pytorch_storage_persistent_id_data_pkl_members.get(name)
                if trusted_storage_keys is not None:
                    self._record_trusted_storage_persistent_ids_without_pickle_scanner(
                        zip_file,
                        info,
                        result,
                        path,
                        name,
                        trusted_storage_keys,
                        opcode_budget_remaining=fallback_storage_trust_opcodes_remaining,
                    )
                add_scanner_selection_skip_check(
                    result,
                    pickle_source,
                    "pickle",
                    self.scanner_selection,
                    context="embedded PyTorch pickle analysis",
                )
                self._record_pickle_member_outcome(
                    result,
                    name,
                    None,
                    analysis_state="skipped",
                    location=pickle_source,
                )
                continue

            # Choose scanning approach based on file size with spooling for seekability
            cfg = self.config or {}
            max_in_mem = int(cfg.get("pickle_max_memory_read", 32 * 1024 * 1024))  # 32MB default
            if pickle_data_size <= max_in_mem:
                data = self._read_member_bytes(
                    zip_file,
                    info,
                    phase="pickle_scan",
                    result=result,
                )
                bytes_scanned += len(data)
                with io.BytesIO(data) as file_like:
                    sub_result = self.pickle_scanner.scan_stream(
                        file_like,
                        len(data),
                        source=pickle_source,
                        _pytorch_zip_storage_member_sizes=pytorch_data_pickle_storage_sizes,
                    )
            else:
                # Stream to a spooled temp file to avoid OOM and provide seek()
                with self._read_member_to_spooled_file(
                    zip_file,
                    info,
                    phase="pickle_scan",
                    result=result,
                    max_size=max_in_mem,
                )[0] as spool:
                    spool.seek(0, io.SEEK_END)
                    member_size = spool.tell()
                    bytes_scanned += member_size
                    spool.seek(0)
                    sub_result = self.pickle_scanner.scan_stream(
                        spool,  # type: ignore[arg-type]
                        member_size,
                        source=pickle_source,
                        _pytorch_zip_storage_member_sizes=pytorch_data_pickle_storage_sizes,
                    )
            sub_result.metadata.setdefault("archive_file_size", original_file_size)
            apply_pickle_member_context(sub_result, archive_path=path, member_name=name)
            trusted_storage_keys = trusted_pytorch_storage_persistent_id_data_pkl_members.get(name)
            if trusted_storage_keys is not None:
                self._downgrade_trusted_storage_persistent_ids(sub_result, trusted_storage_keys)
            if (
                sub_result.success is True
                and self.pickle_scanner._rust_scan_completed_cleanly(sub_result)
                and not self.pickle_scanner._has_warning_or_critical_findings(sub_result)
                and not sub_result._private_metadata.get(ACTIONABLE_FAILED_CHECKS_METADATA_KEY)
            ):
                clean_pickle_entry_ids.add(id(info))

            # Add CVE-2025-32434 specific warnings
            self._add_weights_only_safety_warnings(sub_result, result, path, name)
            result.merge_member_result(sub_result, name)
            self._record_pickle_member_outcome(result, name, sub_result, location=pickle_source)

        return bytes_scanned, clean_pickle_entry_ids

    @staticmethod
    def _pickle_member_max_severity(member_result: ScanResult) -> str | None:
        severities = [issue.severity.value for issue in member_result.issues if issue.severity is not None]
        severities.extend(
            check.severity.value
            for check in member_result.checks
            if check.status == CheckStatus.FAILED and check.severity is not None
        )
        if not severities:
            return None
        return max(severities, key=lambda severity: _PICKLE_MEMBER_SEVERITY_RANK.get(severity, -1))

    @staticmethod
    def _pickle_member_outcome_rank(record: dict[str, Any]) -> int:
        rank = _PICKLE_MEMBER_SEVERITY_RANK.get(str(record.get("max_severity")), -1)
        verdict = record.get("pickle_verdict")
        if isinstance(verdict, str):
            rank = max(rank, _PICKLE_MEMBER_VERDICT_RANK.get(verdict, -1))
        if record.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
            rank = max(rank, 2)
        if record.get("analysis_state") == "skipped":
            rank = max(rank, 1)
        return rank

    @classmethod
    def _record_pickle_member_outcome(
        cls,
        result: ScanResult,
        pickle_name: str,
        member_result: ScanResult | None,
        *,
        analysis_state: str = "scanned",
        location: str,
    ) -> None:
        normalized_name = pickle_name.replace("\\", "/").lstrip("/")
        record: dict[str, Any] = {
            "pickle_filename": normalized_name,
            "location": location,
            "analysis_state": analysis_state,
        }
        if member_result is not None:
            max_severity = cls._pickle_member_max_severity(member_result)
            record.update(
                {
                    "success": member_result.success,
                    "pickle_report_status": member_result.metadata.get("pickle_report_status"),
                    "pickle_verdict": member_result.metadata.get("pickle_verdict"),
                    "scan_outcome": member_result.metadata.get("scan_outcome", "complete"),
                    "max_severity": max_severity,
                    "issue_count": len(member_result.issues),
                    "failed_check_count": sum(
                        1 for check in member_result.checks if check.status == CheckStatus.FAILED
                    ),
                }
            )

        outcomes = result.metadata.setdefault("pickle_member_outcomes", [])
        if isinstance(outcomes, list):
            outcomes.append(record)

        worst_outcome = result.metadata.get("pickle_member_worst_outcome")
        if not isinstance(worst_outcome, dict) or cls._pickle_member_outcome_rank(
            record
        ) > cls._pickle_member_outcome_rank(worst_outcome):
            result.metadata["pickle_member_worst_outcome"] = dict(record)

    @classmethod
    def _trusted_pytorch_storage_data_pkl_members(cls, safe_entries: list[zipfile.ZipInfo]) -> dict[str, set[str]]:
        """Return data.pkl members with PyTorch ZIP storage keys under the same prefix."""
        members = [
            (cls._get_zip_member_name(entry), entry)
            for entry in safe_entries
            if not entry.is_dir() and cls._is_canonical_pytorch_zip_member_name(cls._get_zip_member_name(entry))
        ]
        entries_by_name: dict[str, list[zipfile.ZipInfo]] = {}
        for name, entry in members:
            entries_by_name.setdefault(name, []).append(entry)
        trusted_members: dict[str, set[str]] = {}
        for name, data_pkl_entries in entries_by_name.items():
            if name.rsplit("/", 1)[-1] != "data.pkl":
                continue
            if len(data_pkl_entries) != 1:
                continue
            prefix = name[: -len("data.pkl")]
            if f"{prefix}version" not in entries_by_name:
                continue
            data_prefix = f"{prefix}data/"
            storage_keys = {
                candidate[len(data_prefix) :]
                for candidate, candidate_entries in entries_by_name.items()
                if candidate.startswith(data_prefix)
                and cls._is_ascii_decimal_digits(candidate[len(data_prefix) :])
                and len(candidate_entries) == 1
            }
            if storage_keys:
                trusted_members[name] = storage_keys
        return trusted_members

    @classmethod
    def _pytorch_storage_layout_blob_members(cls, safe_entries: list[zipfile.ZipInfo]) -> set[str]:
        """Return numeric blob members in structurally valid PyTorch storage layouts."""
        storage_keys_by_data_pkl = cls._trusted_pytorch_storage_data_pkl_members(safe_entries)
        return {
            f"{data_pkl_member[: -len('data.pkl')]}data/{storage_key}"
            for data_pkl_member, storage_keys in storage_keys_by_data_pkl.items()
            for storage_key in storage_keys
        }

    @classmethod
    def _trusted_pytorch_storage_blob_members(
        cls,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> set[str]:
        """Return only storage blobs referenced by a validated ``data.pkl`` persistent ID."""
        storage_keys_by_data_pkl = cls._trusted_pytorch_storage_data_pkl_members(safe_entries)
        trusted_blobs: set[str] = set()
        referenced_keys_by_data_pkl: dict[str, set[str]] = {}
        for check in result.checks:
            details = check.details
            if details.get("trusted_pytorch_archive_context") is not True:
                continue
            data_pkl_member = details.get("pickle_filename")
            storage_key = details.get("pytorch_storage_key")
            if isinstance(data_pkl_member, str) and isinstance(storage_key, str):
                referenced_keys_by_data_pkl.setdefault(data_pkl_member, set()).add(storage_key)

        for data_pkl_member, storage_keys in storage_keys_by_data_pkl.items():
            prefix = data_pkl_member[: -len("data.pkl")]
            referenced_keys = referenced_keys_by_data_pkl.get(data_pkl_member, set())
            trusted_blobs.update(f"{prefix}data/{storage_key}" for storage_key in storage_keys & referenced_keys)
        return trusted_blobs

    @staticmethod
    def _storage_blob_members_from_data_pkl_members(storage_keys_by_data_pkl: dict[str, set[str]]) -> set[str]:
        return {
            f"{data_pkl_member[: -len('data.pkl')]}data/{storage_key}"
            for data_pkl_member, storage_keys in storage_keys_by_data_pkl.items()
            for storage_key in storage_keys
        }

    def _trusted_pytorch_storage_blob_members_from_data_pickle(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> set[str]:
        """Return tensor storage blobs referenced by same-prefix ``data.pkl`` before pickle discovery."""
        return self._storage_blob_members_from_data_pkl_members(
            self._validated_pytorch_storage_data_pkl_members_from_data_pickle(
                zip_file,
                safe_entries,
                result,
            ).storage_keys_by_data_pkl
        )

    def _validated_pytorch_storage_data_pkl_members_from_data_pickle(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> _ValidatedPytorchStorageDataPklMembers:
        """Return validated same-prefix PyTorch storage keys referenced by each data.pkl."""
        members = [
            (self._get_zip_member_name(entry), entry)
            for entry in safe_entries
            if not entry.is_dir() and self._is_canonical_pytorch_zip_member_name(self._get_zip_member_name(entry))
        ]
        entries_by_name: dict[str, list[zipfile.ZipInfo]] = {}
        for name, entry in members:
            entries_by_name.setdefault(name, []).append(entry)

        trusted_members: dict[str, set[str]] = {}
        storage_probe_members: dict[str, set[str]] = {}
        persistent_id_downgrade_members: dict[str, set[str]] = {}
        storage_member_sizes_by_data_pkl: dict[str, dict[str, int]] = {}
        storage_reference_bytes_read = 0
        storage_reference_opcodes_remaining = [_PYTORCH_STORAGE_TRUST_MAX_OPCODES]
        for data_pkl_member, data_pkl_entries in entries_by_name.items():
            self._check_timeout()
            if data_pkl_member.rsplit("/", 1)[-1] != "data.pkl":
                continue
            prefix = data_pkl_member[: -len("data.pkl")]
            if f"{prefix}version" not in entries_by_name or len(data_pkl_entries) != 1:
                continue

            data_prefix = f"{prefix}data/"
            storage_entries_by_key: dict[str, zipfile.ZipInfo] = {}
            for candidate_name, candidate_entries in entries_by_name.items():
                if not candidate_name.startswith(data_prefix) or len(candidate_entries) != 1:
                    continue
                storage_key = candidate_name[len(data_prefix) :]
                if self._is_ascii_decimal_digits(storage_key):
                    storage_entries_by_key[storage_key] = candidate_entries[0]
            if not storage_entries_by_key:
                continue

            data_pkl_entry = data_pkl_entries[0]
            if data_pkl_entry.file_size > self.MAX_STORAGE_REFERENCE_DATA_PICKLE_BYTES:
                self._record_storage_reference_validation_incomplete(
                    result,
                    data_pkl_member=data_pkl_member,
                    message=(
                        f"PyTorch storage reference validation skipped oversized data.pkl member {data_pkl_member}"
                    ),
                    reason=self.STORAGE_REFERENCE_VALIDATION_INCONCLUSIVE_REASON,
                    details={
                        "member_size": data_pkl_entry.file_size,
                        "max_member_size": self.MAX_STORAGE_REFERENCE_DATA_PICKLE_BYTES,
                    },
                )
                continue

            try:
                if (
                    storage_reference_bytes_read + data_pkl_entry.file_size
                    > self.MAX_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES
                ):
                    self._record_storage_reference_validation_incomplete(
                        result,
                        data_pkl_member=data_pkl_member,
                        message=(
                            "PyTorch storage reference validation skipped data.pkl members after "
                            f"{self.MAX_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES} bytes"
                        ),
                        reason=self.STORAGE_REFERENCE_VALIDATION_INCONCLUSIVE_REASON,
                        details={
                            "member_size": data_pkl_entry.file_size,
                            "bytes_read": storage_reference_bytes_read,
                            "max_total_bytes": self.MAX_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES,
                        },
                    )
                    continue
                pickle_data = self._read_member_bytes(
                    zip_file,
                    data_pkl_entry,
                    phase="pytorch_storage_pickle_discovery",
                    result=result,
                )
                storage_reference_bytes_read += len(pickle_data)
            except Exception as exc:
                self._record_storage_reference_validation_incomplete(
                    result,
                    data_pkl_member=data_pkl_member,
                    message=f"Could not inspect PyTorch storage references in {data_pkl_member}: {exc!s}",
                    reason=self.STORAGE_REFERENCE_VALIDATION_INCONCLUSIVE_REASON,
                    details={"exception_type": type(exc).__name__},
                )
                continue

            reference_parse = self._trusted_storage_keys_from_pickle_bytes(
                pickle_data,
                opcode_budget_remaining=storage_reference_opcodes_remaining,
            )
            if not reference_parse.parse_complete:
                self._record_storage_reference_validation_incomplete(
                    result,
                    data_pkl_member=data_pkl_member,
                    message=f"Could not parse PyTorch storage references in {data_pkl_member}",
                    reason=self.STORAGE_REFERENCE_VALIDATION_INCONCLUSIVE_REASON,
                    details={},
                )
                continue

            referenced_keys = reference_parse.referenced_keys
            existing_storage_keys = set(storage_entries_by_key)
            missing_storage_keys = referenced_keys - existing_storage_keys
            if missing_storage_keys:
                self._record_storage_reference_validation_incomplete(
                    result,
                    data_pkl_member=data_pkl_member,
                    message=f"PyTorch data.pkl references missing tensor storage members in {data_pkl_member}",
                    reason=self.STORAGE_REFERENCE_MISSING_MEMBERS_INCONCLUSIVE_REASON,
                    details={
                        "missing_storage_keys": sorted(missing_storage_keys)[:10],
                        "missing_storage_key_count": len(missing_storage_keys),
                    },
                )

            trusted_storage_keys = referenced_keys & existing_storage_keys
            storage_size_mismatch_keys = {
                key
                for key in trusted_storage_keys
                if self._pytorch_storage_size_mismatches(
                    storage_entries_by_key[key].file_size,
                    reference_parse.storage_refs_by_key.get(key),
                )
            }
            validated_storage_keys = trusted_storage_keys - storage_size_mismatch_keys
            exact_trusted_storage_keys = (
                validated_storage_keys if reference_parse.all_persistent_ids_are_pytorch_storage else set()
            )
            storage_probe_keys = trusted_storage_keys - exact_trusted_storage_keys
            if exact_trusted_storage_keys:
                trusted_members[data_pkl_member] = exact_trusted_storage_keys
            if storage_probe_keys:
                storage_probe_members[data_pkl_member] = storage_probe_keys
            if exact_trusted_storage_keys and not missing_storage_keys:
                persistent_id_downgrade_members[data_pkl_member] = exact_trusted_storage_keys
                storage_member_sizes_by_data_pkl[data_pkl_member] = {
                    storage_key: storage_entries_by_key[storage_key].file_size
                    for storage_key in exact_trusted_storage_keys
                }

        return _ValidatedPytorchStorageDataPklMembers(
            storage_keys_by_data_pkl=trusted_members,
            storage_probe_keys_by_data_pkl=storage_probe_members,
            persistent_id_downgrade_keys_by_data_pkl=persistent_id_downgrade_members,
            storage_member_sizes_by_data_pkl=storage_member_sizes_by_data_pkl,
        )

    @staticmethod
    def _pytorch_storage_size_mismatches(
        storage_size_bytes: int,
        storage_ref: _PytorchStorageRef | None,
    ) -> bool:
        if storage_ref is None or storage_ref.item_size is None:
            return True
        return storage_size_bytes != storage_ref.element_count * storage_ref.item_size

    def _record_storage_reference_validation_incomplete(
        self,
        result: ScanResult,
        *,
        data_pkl_member: str,
        message: str,
        reason: str,
        details: dict[str, Any],
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name="PyTorch Storage Reference Validation",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=f"{self.current_file_path}:{data_pkl_member}",
            details={
                "data_pkl_member": data_pkl_member,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
                **details,
            },
        )

    @staticmethod
    def _coerce_pickle_string_arg(value: Any) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None

    @staticmethod
    def _split_protocol0_persid_fields(text: str) -> list[str] | None:
        if not text.startswith("(") or not text.endswith(")"):
            return None
        fields: list[str] = []
        start = 1
        in_quote: str | None = None
        escaped = False
        for index, char in enumerate(text[1:-1], start=1):
            if escaped:
                escaped = False
                continue
            if in_quote is not None:
                if char == "\\":
                    escaped = True
                elif char == in_quote:
                    in_quote = None
                continue
            if char in {"'", '"'}:
                in_quote = char
            elif char == ",":
                fields.append(text[start:index].strip())
                start = index + 1
        if in_quote is not None:
            return None
        fields.append(text[start:-1].strip())
        return fields

    @staticmethod
    def _quoted_protocol0_field_value(field: str) -> str | None:
        if len(field) < 2 or field[0] not in {"'", '"'} or field[-1] != field[0]:
            return None
        value = field[1:-1]
        return None if "\\" in value else value

    @staticmethod
    def _parse_pytorch_storage_element_count_text(storage_size: str) -> int | None:
        if not storage_size.isascii() or not storage_size.isdecimal():
            return None
        normalized = storage_size.lstrip("0") or "0"
        if len(normalized) > len(_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT):
            return None
        if (
            len(normalized) == len(_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT)
            and normalized > _PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT
        ):
            return None
        return int(normalized)

    @classmethod
    def _storage_ref_from_protocol0_persid_text(
        cls,
        pid_text: Any,
        trusted_storage_keys: set[str] | None = None,
    ) -> tuple[str, _PytorchStorageRef] | None:
        text = cls._coerce_pickle_string_arg(pid_text)
        if text is None:
            return None
        fields = cls._split_protocol0_persid_fields(text)
        if fields is None or len(fields) != 5:
            return None
        if cls._quoted_protocol0_field_value(fields[0]) != "storage":
            return None
        storage_type_field = fields[1]
        if not storage_type_field.startswith("<class '") or not storage_type_field.endswith("'>"):
            return None
        module, separator, name = storage_type_field[len("<class '") : -len("'>")].rpartition(".")
        if not separator or (module, name) not in _PYTORCH_STORAGE_GLOBALS:
            return None
        storage_key = cls._quoted_protocol0_field_value(fields[2])
        if storage_key is None or not cls._is_ascii_decimal_digits(storage_key):
            return None
        if trusted_storage_keys is not None and storage_key not in trusted_storage_keys:
            return None
        if cls._quoted_protocol0_field_value(fields[3]) is None:
            return None
        element_count = cls._parse_pytorch_storage_element_count_text(fields[4])
        if element_count is None:
            return None
        return (
            storage_key,
            _PytorchStorageRef(
                module=module,
                name=name,
                location=cls._quoted_protocol0_field_value(fields[3]) or "",
                element_count=element_count,
                item_size=_PYTORCH_STORAGE_ITEM_SIZES.get(name),
            ),
        )

    @classmethod
    def _structural_storage_key_from_protocol0_persid_text(
        cls,
        pid_text: Any,
        trusted_storage_keys: set[str] | None = None,
    ) -> str | None:
        text = cls._coerce_pickle_string_arg(pid_text)
        if text is None:
            return None
        fields = cls._split_protocol0_persid_fields(text)
        if fields is None or len(fields) < 4:
            return None
        if cls._quoted_protocol0_field_value(fields[0]) != "storage":
            return None
        storage_type_field = fields[1]
        if not storage_type_field.startswith("<class '") or not storage_type_field.endswith("'>"):
            return None
        module, separator, name = storage_type_field[len("<class '") : -len("'>")].rpartition(".")
        if not separator or (module, name) not in _PYTORCH_STORAGE_GLOBALS:
            return None
        storage_key = cls._quoted_protocol0_field_value(fields[2])
        if storage_key is None or not cls._is_ascii_decimal_digits(storage_key):
            return None
        if trusted_storage_keys is not None and storage_key not in trusted_storage_keys:
            return None
        if cls._quoted_protocol0_field_value(fields[3]) is None:
            return None
        return storage_key

    @classmethod
    def _storage_key_from_protocol0_persid_text(
        cls,
        pid_text: Any,
        trusted_storage_keys: set[str] | None = None,
    ) -> str | None:
        storage_ref = cls._storage_ref_from_protocol0_persid_text(pid_text, trusted_storage_keys)
        return storage_ref[0] if storage_ref is not None else None

    @staticmethod
    def _is_canonical_pytorch_zip_member_name(name: str) -> bool:
        if not name or "\\" in name or name.startswith("/"):
            return False
        parts = name.split("/")
        return all(part and part not in {".", ".."} for part in parts)

    @classmethod
    def _trusted_storage_keys_from_pickle_bytes(
        cls,
        pickle_data: bytes,
        trusted_storage_keys: set[str] | None = None,
        opcode_budget_remaining: list[int] | None = None,
    ) -> _PytorchStorageReferenceParse:
        """Extract validated PyTorch storage keys without running the embedded pickle scanner."""
        marker = object()
        memo: dict[int, Any] = {}
        stack: list[Any] = []
        referenced_keys: set[str] = set()
        storage_refs_by_key: dict[str, _PytorchStorageRef] = {}
        all_persistent_ids_are_pytorch_storage = True

        def pop_marked_tuple() -> tuple[Any, ...] | None:
            items: list[Any] = []
            while stack:
                item = stack.pop()
                if item is marker:
                    return tuple(reversed(items))
                items.append(item)
                if len(items) > _PYTORCH_STORAGE_TRUST_MAX_TUPLE_WIDTH:
                    raise ValueError("PyTorch storage persistent ID tuple exceeded trust parser width")
            return None

        def within_limits() -> bool:
            return (
                len(stack) <= _PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH
                and len(memo) <= _PYTORCH_STORAGE_TRUST_MAX_MEMO_ENTRIES
                and len(referenced_keys) <= _PYTORCH_STORAGE_TRUST_MAX_REFERENCED_KEYS
            )

        def memo_key(value: Any) -> int | None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        def storage_ref_from_pid(pid: Any) -> tuple[str, _PytorchStorageRef] | None:
            if not isinstance(pid, tuple) or len(pid) != 5:
                return None
            if pid[0] != "storage":
                return None
            storage_type = pid[1]
            if not (
                isinstance(storage_type, _PickleGlobalRef)
                and (storage_type.module, storage_type.name) in _PYTORCH_STORAGE_GLOBALS
            ):
                return None
            storage_key = cls._coerce_pickle_string_arg(pid[2])
            if storage_key is None or not cls._is_ascii_decimal_digits(storage_key):
                return None
            if trusted_storage_keys is not None and storage_key not in trusted_storage_keys:
                return None
            if cls._coerce_pickle_string_arg(pid[3]) is None:
                return None
            storage_size = pid[4]
            if (
                not isinstance(storage_size, int)
                or isinstance(storage_size, bool)
                or storage_size < 0
                or storage_size > _PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX
            ):
                return None
            return (
                storage_key,
                _PytorchStorageRef(
                    module=storage_type.module,
                    name=storage_type.name,
                    location=cls._coerce_pickle_string_arg(pid[3]) or "",
                    element_count=storage_size,
                    item_size=_PYTORCH_STORAGE_ITEM_SIZES.get(storage_type.name),
                ),
            )

        def structural_storage_key_from_pid(pid: Any) -> str | None:
            if not isinstance(pid, tuple) or len(pid) < 4:
                return None
            if pid[0] != "storage":
                return None
            storage_type = pid[1]
            if not (
                isinstance(storage_type, _PickleGlobalRef)
                and (storage_type.module, storage_type.name) in _PYTORCH_STORAGE_GLOBALS
            ):
                return None
            storage_key = cls._coerce_pickle_string_arg(pid[2])
            if storage_key is None or not cls._is_ascii_decimal_digits(storage_key):
                return None
            if trusted_storage_keys is not None and storage_key not in trusted_storage_keys:
                return None
            return storage_key if cls._coerce_pickle_string_arg(pid[3]) is not None else None

        try:
            for opcode_count, (opcode, arg, _pos) in enumerate(pickletools.genops(pickle_data), start=1):
                if opcode_budget_remaining is not None:
                    if opcode_budget_remaining[0] <= 0:
                        return _PytorchStorageReferenceParse(set(), {}, False, False)
                    opcode_budget_remaining[0] -= 1
                if opcode_count > _PYTORCH_STORAGE_TRUST_MAX_OPCODES:
                    return _PytorchStorageReferenceParse(set(), {}, False, False)
                opcode_name = opcode.name
                if opcode_name in {"PROTO", "FRAME", "STOP"}:
                    continue
                if opcode_name == "MARK":
                    stack.append(marker)
                elif opcode_name in {
                    "BINSTRING",
                    "SHORT_BINSTRING",
                    "BINUNICODE",
                    "SHORT_BINUNICODE",
                    "UNICODE",
                    "BINBYTES",
                    "SHORT_BINBYTES",
                }:
                    stack.append(cls._coerce_pickle_string_arg(arg))
                elif opcode_name == "GLOBAL":
                    global_name = cls._coerce_pickle_string_arg(arg)
                    if global_name is None:
                        stack.append(None)
                    else:
                        parts = global_name.split()
                        stack.append(_PickleGlobalRef(parts[0], parts[1]) if len(parts) == 2 else None)
                elif opcode_name == "STACK_GLOBAL":
                    if len(stack) < 2:
                        stack.clear()
                        continue
                    name = cls._coerce_pickle_string_arg(stack.pop())
                    module = cls._coerce_pickle_string_arg(stack.pop())
                    stack.append(_PickleGlobalRef(module, name) if module is not None and name is not None else None)
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
                    stack.append(arg)
                elif opcode_name == "NONE":
                    stack.append(None)
                elif opcode_name == "NEWTRUE":
                    stack.append(True)
                elif opcode_name == "NEWFALSE":
                    stack.append(False)
                elif opcode_name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                    key = memo_key(arg)
                    if key is not None and stack:
                        memo[key] = stack[-1]
                elif opcode_name == "MEMOIZE":
                    if stack:
                        memo[len(memo)] = stack[-1]
                elif opcode_name in {"BINGET", "LONG_BINGET", "GET"}:
                    key = memo_key(arg)
                    stack.append(memo.get(key) if key is not None else None)
                elif opcode_name == "POP":
                    if stack:
                        stack.pop()
                elif opcode_name == "POP_MARK":
                    pop_marked_tuple()
                elif opcode_name == "DUP":
                    if stack:
                        stack.append(stack[-1])
                elif opcode_name == "BINPERSID":
                    pid = stack.pop() if stack else None
                    storage_ref = storage_ref_from_pid(pid)
                    if storage_ref is not None:
                        storage_key, ref = storage_ref
                        referenced_keys.add(storage_key)
                        existing_ref = storage_refs_by_key.get(storage_key)
                        if existing_ref is not None and existing_ref != ref:
                            all_persistent_ids_are_pytorch_storage = False
                        storage_refs_by_key[storage_key] = ref
                    else:
                        structural_key = structural_storage_key_from_pid(pid)
                        if structural_key is not None:
                            referenced_keys.add(structural_key)
                        all_persistent_ids_are_pytorch_storage = False
                    stack.append(None)
                elif opcode_name == "PERSID":
                    storage_ref = cls._storage_ref_from_protocol0_persid_text(arg, trusted_storage_keys)
                    if storage_ref is not None:
                        storage_key, ref = storage_ref
                        referenced_keys.add(storage_key)
                        existing_ref = storage_refs_by_key.get(storage_key)
                        if existing_ref is not None and existing_ref != ref:
                            all_persistent_ids_are_pytorch_storage = False
                        storage_refs_by_key[storage_key] = ref
                    else:
                        structural_key = cls._structural_storage_key_from_protocol0_persid_text(
                            arg,
                            trusted_storage_keys,
                        )
                        if structural_key is not None:
                            referenced_keys.add(structural_key)
                        all_persistent_ids_are_pytorch_storage = False
                    stack.append(None)
                else:
                    stack.clear()
                if not within_limits():
                    return _PytorchStorageReferenceParse(set(), {}, False, False)
        except Exception:
            return _PytorchStorageReferenceParse(set(), {}, False, False)
        return _PytorchStorageReferenceParse(
            referenced_keys=referenced_keys,
            storage_refs_by_key=storage_refs_by_key,
            parse_complete=True,
            all_persistent_ids_are_pytorch_storage=all_persistent_ids_are_pytorch_storage,
        )

    def _record_trusted_storage_persistent_ids_without_pickle_scanner(
        self,
        zip_file: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        result: ScanResult,
        path: str,
        pickle_name: str,
        trusted_storage_keys: set[str],
        *,
        opcode_budget_remaining: list[int] | None = None,
    ) -> None:
        max_trust_parse_bytes = 10 * 1024 * 1024
        try:
            if info.file_size > max_trust_parse_bytes:
                pickle_data = self._read_member_prefix(
                    zip_file,
                    info,
                    max_trust_parse_bytes,
                    phase="pytorch_storage_trust_metadata",
                    result=result,
                )
            else:
                pickle_data = self._read_member_bytes(
                    zip_file,
                    info,
                    phase="pytorch_storage_trust_metadata",
                    result=result,
                )
        except Exception as exc:
            logger.debug("Unable to inspect PyTorch storage persistent IDs for %s: %s", pickle_name, exc)
            return

        reference_parse = self._trusted_storage_keys_from_pickle_bytes(
            pickle_data,
            trusted_storage_keys,
            opcode_budget_remaining=opcode_budget_remaining,
        )
        if not reference_parse.parse_complete or not reference_parse.all_persistent_ids_are_pytorch_storage:
            return
        for storage_key in sorted(reference_parse.referenced_keys):
            result.add_check(
                name="PyTorch Storage Persistent ID Trust",
                passed=True,
                message="PyTorch storage persistent ID found in validated PyTorch archive",
                severity=IssueSeverity.INFO,
                location=f"{path}:{pickle_name}",
                details={
                    "pickle_rule_code": "PERSISTENT_ID",
                    "opcode": "BINPERSID",
                    "pickle_filename": pickle_name,
                    "pytorch_storage_key": storage_key,
                    "pytorch_storage_persistent_id": True,
                    "trusted_pytorch_archive_context": True,
                },
            )

    @staticmethod
    def _is_ascii_decimal_digits(value: str) -> bool:
        return value.isascii() and value.isdecimal()

    @staticmethod
    def _protocol0_persid_text_from_preview(preview: Any) -> str | None:
        if not isinstance(preview, str) or not preview.startswith("str:") or len(preview) > 4096:
            return None
        try:
            value = ast.literal_eval(preview[len("str:") :])
        except (SyntaxError, TypeError, ValueError):
            return None
        return value if isinstance(value, str) else None

    @classmethod
    def _storage_key_from_redacted_binary_persid_preview(
        cls,
        preview: Any,
        trusted_storage_keys: set[str],
    ) -> str | None:
        if not isinstance(preview, str) or len(preview) > 4096:
            return None
        match = _PYTORCH_STORAGE_REDACTED_BINPERSID_PREVIEW.fullmatch(preview)
        if match is None:
            return None
        if (match.group("module"), match.group("name")) not in _PYTORCH_STORAGE_GLOBALS:
            return None
        key_len = int(match.group("key_len"))
        device_len = int(match.group("device_len"))
        if key_len <= 0 or device_len <= 0:
            return None
        matching_keys = [
            key
            for key in trusted_storage_keys
            if cls._is_ascii_decimal_digits(key) and len(key.encode("utf-8")) == key_len
        ]
        if len(matching_keys) != 1:
            return None
        return matching_keys[0]

    @classmethod
    def _is_pytorch_storage_persistent_id_record(cls, details: dict[str, Any], trusted_storage_keys: set[str]) -> bool:
        if details.get("pickle_rule_code") != "PERSISTENT_ID":
            return False
        storage_key = details.get("pytorch_storage_key")
        if (
            details.get("opcode") == "BINPERSID"
            and details.get("pytorch_storage_persistent_id") is True
            and isinstance(storage_key, str)
        ):
            return storage_key in trusted_storage_keys

        if details.get("opcode") == "BINPERSID":
            storage_key = cls._storage_key_from_redacted_binary_persid_preview(
                details.get("persistent_id_preview"),
                trusted_storage_keys,
            )
            if storage_key is None:
                return False
            details["pytorch_storage_persistent_id"] = True
            details["pytorch_storage_key"] = storage_key
            return True

        if details.get("opcode") != "PERSID":
            return False
        if details.get("pytorch_storage_persistent_id") is True and isinstance(storage_key, str):
            return storage_key in trusted_storage_keys

        persid_text = cls._protocol0_persid_text_from_preview(details.get("persistent_id_preview"))
        storage_key = cls._storage_key_from_protocol0_persid_text(persid_text, trusted_storage_keys)
        if storage_key is None:
            return False
        details["pytorch_storage_persistent_id"] = True
        details["pytorch_storage_key"] = storage_key
        return True

    @classmethod
    def _downgrade_trusted_storage_persistent_ids(cls, result: ScanResult, trusted_storage_keys: set[str]) -> None:
        """Treat PyTorch storage persistent IDs as informational inside validated PyTorch ZIP data.pkl."""
        downgraded_count = 0
        downgraded_private_entries: list[dict[str, str]] = []
        for check in result.checks:
            if not cls._is_pytorch_storage_persistent_id_record(check.details, trusted_storage_keys):
                continue
            if check.rule_code is not None:
                downgraded_private_entries.append({"name": check.name, "rule_code": check.rule_code})
            check.status = CheckStatus.PASSED
            check.severity = IssueSeverity.INFO
            check.message = "PyTorch storage persistent ID found in validated PyTorch archive"
            check.details["trusted_pytorch_archive_context"] = True
            downgraded_count += 1

        result.issues = [
            issue
            for issue in result.issues
            if not cls._is_pytorch_storage_persistent_id_record(issue.details, trusted_storage_keys)
        ]
        clean_trusted_storage_downgrade = (
            downgraded_count
            and not result.has_errors
            and not result.has_warnings
            and not result.metadata.get("analysis_incomplete")
            and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
            and result.metadata.get("pickle_verdict") == "suspicious"
        )
        if clean_trusted_storage_downgrade:
            cls._remove_private_actionable_failed_check_entries(result, downgraded_private_entries)
            result.metadata["pickle_verdict"] = "clean"

    @staticmethod
    def _remove_private_actionable_failed_check_entries(
        result: ScanResult,
        entries_to_remove: list[dict[str, str]],
    ) -> None:
        private_failed_checks = result._private_metadata.get(ACTIONABLE_FAILED_CHECKS_METADATA_KEY)
        if not entries_to_remove or not isinstance(private_failed_checks, list):
            return

        unmatched_entries = list(entries_to_remove)
        filtered_entries: list[Any] = []
        for entry in private_failed_checks:
            if isinstance(entry, dict):
                matched_index = next(
                    (
                        index
                        for index, candidate in enumerate(unmatched_entries)
                        if entry.get("name") == candidate["name"] and entry.get("rule_code") == candidate["rule_code"]
                    ),
                    None,
                )
                if matched_index is not None:
                    del unmatched_entries[matched_index]
                    continue
            filtered_entries.append(entry)

        if filtered_entries:
            result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY] = filtered_entries
        else:
            result._private_metadata.pop(ACTIONABLE_FAILED_CHECKS_METADATA_KEY, None)

    def _scan_for_jit_patterns(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
        *,
        clean_pickle_entry_ids: set[int],
    ) -> int:
        """Check for JIT/Script code execution risks and network communication patterns"""
        bytes_scanned = 0
        all_jit_findings = []
        all_network_findings = []
        check_jit = self._get_bool_config("check_jit_script", True)
        check_net = self._get_bool_config("check_network_comm", True)
        if safe_entries:
            if not check_jit:
                result.metadata.setdefault("disabled_checks", []).append("JIT/Script Code Execution Detection")
            if not check_net:
                result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")
        if not check_jit and not check_net:
            return 0

        # Aggregate oversize and read-failure events so adversarial archives
        # with many unreachable members produce one summary check apiece
        # instead of one INFO finding per entry in the checks list.
        size_limited_entries: list[dict[str, Any]] = []
        read_failed_entries: list[dict[str, Any]] = []
        trusted_storage_blob_members = self._pytorch_storage_layout_blob_members(safe_entries)

        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            normalized_name = name.replace("\\", "/").lstrip("/")
            try:
                if entry.is_dir() or normalized_name.endswith("/"):
                    continue
                # Skip numeric tensor data files to support different versions of PyTorch ZIP files
                # These are binary weight files that cause performance issues when scanned
                if name in trusted_storage_blob_members:
                    continue
                if entry.file_size > self.max_jit_scan_member_bytes:
                    safe_name = redact_evidence_string(name, max_chars=500)
                    size_limited_entries.append(
                        {
                            "zip_entry": safe_name,
                            "file_size": entry.file_size,
                            "location": redact_evidence_string(f"{path}:{name}", max_chars=500),
                        }
                    )
                    continue

                file_data = self._read_member_bytes(
                    zip_file,
                    entry,
                    phase="jit_script_scan",
                    result=result,
                    max_bytes=self.max_jit_scan_member_bytes,
                )
                bytes_scanned += len(file_data)

                # Collect findings for this file without creating individual checks
                if file_data:  # Only process if we have data
                    if check_jit:
                        jit_findings = self.collect_jit_script_findings(
                            file_data,
                            model_type="pytorch",
                            context=f"{path}:{name}",
                            result=result,
                        )
                        all_jit_findings.extend(jit_findings)
                    if check_net:
                        network_file_data = _pickle_literal_url_stripped_scan_view(
                            file_data,
                            allow_filtering=id(entry) in clean_pickle_entry_ids,
                        )
                        network_findings = self.collect_network_communication_findings(
                            network_file_data,
                            context=f"{path}:{name}",
                            result=result,
                        )
                        all_network_findings.extend(network_findings)

            except Exception as e:
                safe_name = redact_evidence_string(name, max_chars=500)
                safe_error = redact_untrusted_error_message(e)
                logger.debug("Exception reading %s: %s", safe_name, safe_error)
                read_failed_entries.append(
                    {
                        "zip_entry": safe_name,
                        "exception": safe_error,
                        "exception_type": type(e).__name__,
                        "location": redact_evidence_string(f"{path}:{name}", max_chars=500),
                    }
                )

        if size_limited_entries:
            mark_inconclusive_scan_result(result, "pytorch_zip_jit_member_size_limit")
            count = len(size_limited_entries)
            noun = "member" if count == 1 else "members"
            result.add_check(
                name="JIT/Network Scan Size Limit",
                passed=False,
                message=(
                    f"{count} PyTorch ZIP {noun} skipped by JIT/network scanning because "
                    f"{'it exceeds' if count == 1 else 'they exceed'} the bounded read limit "
                    f"({self.max_jit_scan_member_bytes} bytes)"
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "zip_entries": [entry["zip_entry"] for entry in size_limited_entries],
                    "entries": size_limited_entries,
                    "max_scan_bytes": self.max_jit_scan_member_bytes,
                    "skipped_count": count,
                    "analysis_incomplete": True,
                },
            )

        if read_failed_entries:
            mark_inconclusive_scan_result(result, "pytorch_zip_jit_member_read_failed")
            count = len(read_failed_entries)
            noun = "member" if count == 1 else "members"
            result.add_check(
                name="JIT/Network Scan Read Failure",
                passed=False,
                message=(f"{count} PyTorch ZIP {noun} could not be analyzed for JIT/network patterns"),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "zip_entries": [entry["zip_entry"] for entry in read_failed_entries],
                    "entries": read_failed_entries,
                    "failed_count": count,
                    "analysis_incomplete": True,
                },
            )

        # Emit explicit checks for the entire ZIP file
        if safe_entries:  # Only create checks if we processed files
            entry_limit_exceeded = self._entry_limit_exceeded(result)
            raw_member_coverage_incomplete = bool(size_limited_entries or read_failed_entries)
            if check_jit and (all_jit_findings or (not entry_limit_exceeded and not raw_member_coverage_incomplete)):
                self.add_jit_script_findings(
                    all_jit_findings,
                    result,
                    model_type="pytorch",
                    context=path,
                )

            if check_net and (
                all_network_findings or (not entry_limit_exceeded and not raw_member_coverage_incomplete)
            ):
                self.add_network_communication_findings(
                    all_network_findings,
                    result,
                    context=path,
                )

        return bytes_scanned

    def _detect_suspicious_files(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
        *,
        non_executable_pytorch_storage_data_pkl_members: dict[str, set[str]] | None = None,
    ) -> None:
        """Detect suspicious non-pickle files in the archive"""
        python_files_found = False
        executable_files_found = False
        executable_probe_failures: list[dict[str, str]] = []
        member_names = {self._get_zip_member_name(entry).replace("\\", "/").lstrip("/") for entry in safe_entries}
        if non_executable_pytorch_storage_data_pkl_members is None:
            trusted_storage_blob_members = self._trusted_pytorch_storage_blob_members(safe_entries, result)
        else:
            trusted_storage_blob_members = self._storage_blob_members_from_data_pkl_members(
                non_executable_pytorch_storage_data_pkl_members
            )
        entries_by_normalized_name = {
            self._get_zip_member_name(entry).replace("\\", "/").lstrip("/"): entry for entry in safe_entries
        }

        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            normalized_name = name.replace("\\", "/").lstrip("/")
            if entry.is_dir() or normalized_name.endswith("/"):
                continue
            normalized_name_lower = normalized_name.lower()
            # Check for Python code files independently of native-content detection.
            if normalized_name_lower.endswith(".py"):
                debug_member_name = self._torchscript_debug_member_name(name, member_names)
                debug_entry = entries_by_normalized_name.get(debug_member_name or "")
                is_generated_torchscript_source = debug_entry is not None and self._is_torchscript_generated_python(
                    zip_file,
                    entry,
                    debug_entry,
                    result,
                )
                if not is_generated_torchscript_source:
                    result.add_check(
                        name="Python Code File Detection",
                        passed=False,
                        message=f"Python code file found in PyTorch model: {name}",
                        severity=IssueSeverity.WARNING,
                        location=f"{path}:{name}",
                        details={"file": name},
                    )
                    python_files_found = True

            executable_rule_code = executable_archive_member_name_rule_code(normalized_name_lower)
            # A referenced raw tensor storage member is arbitrary bytes rather
            # than a loadable sidecar, so signature bytes are not evidence of
            # an executable. Unreferenced lookalikes must still be inspected.
            if executable_rule_code is None and name not in trusted_storage_blob_members:
                try:
                    executable_rule_code, probe_failure = self._executable_member_content_rule_code(
                        zip_file,
                        entry,
                        result,
                    )
                except Exception as exc:
                    executable_probe_failures.append(
                        {
                            "zip_entry": name,
                            "exception": str(exc),
                            "exception_type": type(exc).__name__,
                        }
                    )
                else:
                    if probe_failure is not None:
                        executable_probe_failures.append(probe_failure)

            if executable_rule_code is not None:
                result.add_check(
                    name="Executable File Detection",
                    passed=False,
                    message=f"Executable file found in PyTorch model: {name}",
                    severity=IssueSeverity.CRITICAL,
                    rule_code=executable_rule_code,
                    location=f"{path}:{name}",
                    details={"file": name},
                )
                executable_files_found = True

        if executable_probe_failures:
            mark_inconclusive_scan_result(result, "pytorch_zip_executable_member_probe_failed")
            result.add_check(
                name="Executable Content Probe",
                passed=False,
                message=(
                    f"{len(executable_probe_failures)} PyTorch ZIP member(s) could not be analyzed "
                    "for hidden executable content"
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "entries": executable_probe_failures,
                    "failed_count": len(executable_probe_failures),
                    "analysis_incomplete": True,
                },
            )

        # Add positive checks if no suspicious files found
        entry_limit_exceeded = self._entry_limit_exceeded(result)
        if not python_files_found and safe_entries and not entry_limit_exceeded:
            result.add_check(
                name="Python Code File Detection",
                passed=True,
                message="No unexpected Python code files found in model",
                location=path,
            )

        if not executable_files_found and safe_entries and not executable_probe_failures and not entry_limit_exceeded:
            result.add_check(
                name="Executable File Detection",
                passed=True,
                message="No executable files found in model",
                location=path,
            )

    def _executable_member_content_rule_code(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        result: ScanResult,
    ) -> tuple[str | None, dict[str, str] | None]:
        """Return a content-derived executable rule code or an incomplete-probe reason."""
        prefix_cache = b""

        def read_prefix(limit: int) -> bytes:
            nonlocal prefix_cache
            if (
                limit <= len(prefix_cache)
                or len(prefix_cache) >= entry.file_size
                or (prefix_cache and not prefix_cache.startswith(b"MZ"))
            ):
                return prefix_cache[:limit]
            expanded_prefix = self._read_member_prefix(
                zip_file,
                entry,
                limit,
                phase="executable member content probe",
                result=result,
            )
            if len(expanded_prefix) > len(prefix_cache):
                prefix_cache = expanded_prefix
            return prefix_cache[:limit]

        prefix = read_prefix(_EXECUTABLE_MEMBER_PROBE_BYTES)
        rule_code = executable_archive_member_content_rule_code_from_bytes(prefix)
        if rule_code is not None:
            return rule_code, None
        if not prefix.startswith(b"MZ"):
            return None, None

        probe_outcome = probe_executable_archive_member_signature(read_prefix)
        if probe_outcome == "detected":
            return "S501", None
        if probe_outcome == "incomplete":
            return None, {
                "zip_entry": self._get_zip_member_name(entry),
                "exception": "PE header pointer exceeds bounded executable-content probe budget",
                "exception_type": "BoundedProbeIncomplete",
            }
        return None, None

    def _validate_pytorch_structure(self, pickle_files: list[zipfile.ZipInfo], result: ScanResult) -> None:
        """Validate that the PyTorch model has expected structure"""
        pickle_names = self._get_zip_member_names(pickle_files)
        if not pickle_files or "data.pkl" not in [os.path.basename(f) for f in pickle_names]:
            if self._local_entry_limit_exceeded(result):
                result.add_check(
                    name="PyTorch Structure Validation",
                    passed=False,
                    message=(
                        "PyTorch model structure could not be confirmed because archive entries beyond "
                        "the processing limit were not inspected."
                    ),
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self.ENTRY_LIMIT_INCONCLUSIVE_REASON,
                    },
                )
                return
            result.add_check(
                name="PyTorch Structure Validation",
                passed=False,
                message="PyTorch model is missing 'data.pkl', which is unusual for standard PyTorch models.",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"missing_file": "data.pkl"},
            )
        else:
            result.add_check(
                name="PyTorch Structure Validation",
                passed=True,
                message="PyTorch model has expected structure with data.pkl",
                location=self.current_file_path,
                details={"pickle_files": pickle_names},
            )

    def _check_blacklist_patterns(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> None:
        """Check for blacklisted patterns in all files"""
        blacklist_patterns = self.config.get("blacklist_patterns") if self.config else None

        if blacklist_patterns:
            self._scan_blacklist_patterns(zip_file, safe_entries, blacklist_patterns, result)
        else:
            # No blacklist patterns configured
            if safe_entries:
                result.add_check(
                    name="Blacklist Pattern Check",
                    passed=True,
                    message="No blacklist patterns configured for scanning",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"reason": "no_blacklist_configured", "entries_available": len(safe_entries)},
                )

    def _scan_blacklist_patterns(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        blacklist_patterns: list[str],
        result: ScanResult,
    ) -> None:
        """Scan files for blacklisted patterns"""
        max_blacklist_scan_size = self._normalize_positive_int_config(
            self.config.get("max_blacklist_scan_size"),
            self.DEFAULT_MAX_BLACKLIST_SCAN_BYTES,
        )

        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            try:
                info = entry

                # Skip files that are too large
                if info.file_size > max_blacklist_scan_size:
                    mark_inconclusive_scan_result(result, self.BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON)
                    result.add_check(
                        name="Blacklist Pattern Check",
                        passed=False,
                        message=(
                            f"Skipped configured blacklist scanning for oversized file {name} "
                            f"(size: {info.file_size}, limit: {max_blacklist_scan_size})"
                        ),
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path} ({name})",
                        details={
                            "file_size": info.file_size,
                            "scan_limit": max_blacklist_scan_size,
                            "zip_entry": name,
                            "reason": "size_limit_exceeded",
                            "analysis_incomplete": True,
                            "scan_outcome_reason": self.BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON,
                        },
                    )
                    continue

                # Choose scanning method based on file size
                if info.file_size > 10 * 1024 * 1024:  # 10MB threshold for streaming
                    self._scan_large_file_for_patterns(zip_file, entry, blacklist_patterns, result)
                else:
                    self._scan_small_file_for_patterns(zip_file, entry, blacklist_patterns, result)

            except Exception as e:
                self._handle_blacklist_scan_error(name, e, result)

    def _scan_large_file_for_patterns(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        blacklist_patterns: list[str],
        result: ScanResult,
    ) -> None:
        """Stream large files and check patterns in chunks"""
        name = self._get_zip_member_name(entry)
        found_patterns = []
        with self._read_member_to_spooled_file(
            zip_file,
            entry,
            phase="blacklist_check",
            result=result,
            max_size=8 * 1024 * 1024,
        )[0] as zf:
            chunk_size = 1024 * 1024  # 1MB chunks
            overlap_buffer = b""
            max_pattern_len = max(len(p.encode("utf-8")) for p in blacklist_patterns) if blacklist_patterns else 0

            while True:
                chunk = zf.read(chunk_size)
                if not chunk:
                    break

                # Combine with overlap buffer to catch patterns across chunk boundaries
                search_data = overlap_buffer + chunk

                # Check for patterns in this chunk
                if name.endswith(".pkl"):
                    # Binary search for pickled files
                    for pattern in blacklist_patterns:
                        pattern_bytes = pattern.encode("utf-8")
                        if pattern_bytes in search_data and pattern not in found_patterns:
                            found_patterns.append(pattern)
                else:
                    # Text search for other files
                    try:
                        text_data = search_data.decode("utf-8", errors="ignore")
                        for pattern in blacklist_patterns:
                            if pattern in text_data and pattern not in found_patterns:
                                found_patterns.append(pattern)
                    except UnicodeDecodeError:
                        # Fall back to binary search if text decode fails
                        for pattern in blacklist_patterns:
                            pattern_bytes = pattern.encode("utf-8")
                            if pattern_bytes in search_data and pattern not in found_patterns:
                                found_patterns.append(pattern)

                # Keep overlap buffer for pattern matching across chunks
                overlap_buffer = search_data[-max_pattern_len:] if len(search_data) >= max_pattern_len else search_data

        # Report found patterns
        for pattern in found_patterns:
            result.add_check(
                name="Blacklist Pattern Check",
                passed=False,
                message=f"Blacklisted pattern '{pattern}' found in file {name}",
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} ({name})",
                details={
                    "pattern": pattern,
                    "file": name,
                    "file_type": "pickle" if name.endswith(".pkl") else "text",
                    "scan_method": "streaming",
                },
            )

    def _scan_small_file_for_patterns(
        self,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        blacklist_patterns: list[str],
        result: ScanResult,
    ) -> None:
        """Scan small files for blacklisted patterns"""
        name = self._get_zip_member_name(entry)
        file_data = self._read_member_bytes(
            zip_file,
            entry,
            phase="blacklist_check",
            result=result,
        )

        # For pickled files, check for patterns in the binary data
        if name.endswith(".pkl"):
            for pattern in blacklist_patterns:
                pattern_bytes = pattern.encode("utf-8")
                if pattern_bytes in file_data:
                    result.add_check(
                        name="Blacklist Pattern Check",
                        passed=False,
                        message=f"Blacklisted pattern '{pattern}' found in pickled file {name}",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{self.current_file_path} ({name})",
                        details={
                            "pattern": pattern,
                            "file": name,
                            "file_type": "pickle",
                            "scan_method": "direct",
                        },
                    )
        else:
            # For text files, decode and search as text
            try:
                content = file_data.decode("utf-8")
                for pattern in blacklist_patterns:
                    if pattern in content:
                        result.add_check(
                            name="Blacklist Pattern Check",
                            passed=False,
                            message=f"Blacklisted pattern '{pattern}' found in file {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} ({name})",
                            details={
                                "pattern": pattern,
                                "file": name,
                                "file_type": "text",
                                "scan_method": "direct",
                            },
                        )
            except UnicodeDecodeError:
                # Fall back to binary search for files that can't be decoded as text
                for pattern in blacklist_patterns:
                    pattern_bytes = pattern.encode("utf-8")
                    if pattern_bytes in file_data:
                        result.add_check(
                            name="Blacklist Pattern Check",
                            passed=False,
                            message=f"Blacklisted pattern '{pattern}' found in binary file {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} ({name})",
                            details={
                                "pattern": pattern,
                                "file": name,
                                "file_type": "binary",
                                "scan_method": "direct",
                            },
                        )

    def _handle_blacklist_scan_error(self, name: str, error: Exception, result: ScanResult) -> None:
        """Handle errors during blacklist pattern scanning"""
        mark_inconclusive_scan_result(result, self.BLACKLIST_READ_INCONCLUSIVE_REASON)

        result.add_check(
            name="ZIP Entry Read",
            passed=False,
            message=f"Error reading file {name}: {error!s}",
            severity=IssueSeverity.INFO,
            location=f"{self.current_file_path} ({name})",
            details={
                "zip_entry": name,
                "exception": str(error),
                "exception_type": type(error).__name__,
                "scan_phase": "blacklist_check",
                "analysis_incomplete": True,
                "scan_outcome_reason": self.BLACKLIST_READ_INCONCLUSIVE_REASON,
            },
        )

    def _handle_bad_zip_error(self, path: str) -> ScanResult:
        """Handle BadZipFile errors"""
        result = self._create_result()
        result.add_check(
            name="PyTorch ZIP Format Validation",
            passed=False,
            message=f"Not a valid zip file: {path}",
            severity=IssueSeverity.CRITICAL,
            location=path,
            details={"path": path},
            rule_code="S902",
        )
        result.finish(success=False)
        return result

    def _handle_scan_error(self, path: str, error: Exception, result: ScanResult | None = None) -> ScanResult:
        """Report incomplete analysis without discarding findings recovered before a failure."""
        if result is None:
            result = self._create_result()
        mark_inconclusive_scan_result(result, self.SCAN_INCONCLUSIVE_REASON)
        result.add_check(
            name="PyTorch ZIP Scan",
            passed=False,
            message=f"PyTorch ZIP analysis could not be completed: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": self.SCAN_INCONCLUSIVE_REASON,
            },
        )
        result.finish(success=False)
        return result

    def _read_bounded_version_metadata(
        self,
        zipfile_obj: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        result: ScanResult,
        *,
        max_bytes: int,
    ) -> bytes | None:
        """Read version metadata without allowing optional probes to allocate unbounded memory."""
        name = self._get_zip_member_name(entry)
        try:
            return self._read_member_bytes(
                zipfile_obj,
                entry,
                phase="version_probe",
                result=result,
                max_bytes=max_bytes,
            )
        except ValueError as exc:
            mark_inconclusive_scan_result(result, self.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON)
            result.add_check(
                name="PyTorch Version Metadata Limit",
                passed=False,
                message=(
                    f"Skipped version metadata in {name} because it exceeds the bounded read limit "
                    f"({entry.file_size} > {max_bytes} bytes)"
                ),
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{name}",
                details={
                    "zip_entry": name,
                    "file_size": entry.file_size,
                    "max_read_bytes": max_bytes,
                    "exception": str(exc),
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON,
                },
            )
            return None
        except Exception as exc:
            mark_inconclusive_scan_result(result, self.VERSION_METADATA_READ_INCONCLUSIVE_REASON)
            result.add_check(
                name="PyTorch Version Metadata Read",
                passed=False,
                message=f"Could not read version metadata in {name}: {exc!s}",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{name}",
                details={
                    "zip_entry": name,
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self.VERSION_METADATA_READ_INCONCLUSIVE_REASON,
                },
            )
            return None

    @classmethod
    def _version_metadata_analysis_incomplete(cls, result: ScanResult) -> bool:
        reasons = result.metadata.get("scan_outcome_reasons")
        return isinstance(reasons, list) and any(
            reason in reasons
            for reason in (
                cls.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON,
                cls.VERSION_METADATA_READ_INCONCLUSIVE_REASON,
            )
        )

    def _extract_pytorch_version_info(
        self,
        zipfile_obj: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> dict[str, Any]:
        """Extract PyTorch version information from model archive for CVE-2025-32434 detection"""
        version_info: dict[str, Any] = {
            "pytorch_archive_version": None,
            "pytorch_framework_version": None,
            "pytorch_version_source": None,
        }

        try:
            # Check for PyTorch archive version file
            version_entry = self._find_zip_entry(safe_entries, "version")
            archive_version_entry = self._find_zip_entry(safe_entries, "archive/version")
            if version_entry is not None:
                version_bytes = self._read_bounded_version_metadata(
                    zipfile_obj,
                    version_entry,
                    result,
                    max_bytes=self.MAX_VERSION_METADATA_BYTES,
                )
                if version_bytes is not None:
                    version_info["pytorch_archive_version"] = version_bytes.decode("utf-8", errors="ignore").strip()
                    version_info["pytorch_version_source"] = "version"
            elif archive_version_entry is not None:
                version_bytes = self._read_bounded_version_metadata(
                    zipfile_obj,
                    archive_version_entry,
                    result,
                    max_bytes=self.MAX_VERSION_METADATA_BYTES,
                )
                if version_bytes is not None:
                    version_info["pytorch_archive_version"] = version_bytes.decode("utf-8", errors="ignore").strip()
                    version_info["pytorch_version_source"] = "archive/version"

            # Try to extract PyTorch framework version from pickle files
            # Look for torch.__version__ references in pickle GLOBAL opcodes
            for entry in safe_entries:
                name = self._get_zip_member_name(entry)
                if name.endswith(".pkl"):
                    try:
                        # Cap read for version probing to 1MB; adjust via config if needed
                        pickle_data = self._read_member_prefix(
                            zipfile_obj,
                            entry,
                            self.max_version_probe_bytes,
                            phase="version_probe",
                            result=result,
                        )
                        # Look for torch version patterns in pickle data
                        framework_version = self._extract_framework_version_from_pickle(pickle_data)
                        if framework_version:
                            version_info["pytorch_framework_version"] = framework_version
                            version_info["pytorch_version_source"] = f"pickle:{name}"
                            break
                    except Exception:
                        continue

            # Look for version information in other metadata files
            metadata_files = ["meta.json", "config.json", "pytorch_model.bin.index.json"]
            for meta_file in metadata_files:
                meta_entry = self._find_zip_entry(safe_entries, meta_file)
                if meta_entry is not None:
                    try:
                        metadata_bytes = self._read_bounded_version_metadata(
                            zipfile_obj,
                            meta_entry,
                            result,
                            max_bytes=self.MAX_VERSION_JSON_BYTES,
                        )
                        if metadata_bytes is None:
                            continue
                        meta_data = json.loads(metadata_bytes.decode("utf-8"))
                        # Look for framework-specific version fields in metadata.
                        # Avoid generic "version" keys, which often describe model/config
                        # schema versions and can cause false CVE attributions.
                        version_keys = ["pytorch_version", "torch_version"]
                        if self._metadata_declares_pytorch_framework(meta_data):
                            version_keys.append("framework_version")
                        for key in version_keys:
                            if key in meta_data and isinstance(meta_data[key], str):
                                candidate = meta_data[key].strip()
                                if self._looks_like_pytorch_version(candidate):
                                    version_info["pytorch_framework_version"] = candidate
                                    version_info["pytorch_version_source"] = f"metadata:{meta_file}:{key}"
                                    break
                    except (json.JSONDecodeError, UnicodeDecodeError):  # type: ignore[possibly-unresolved-reference]
                        continue

        except Exception:
            # Log but don't fail - version detection is best effort
            pass

        return version_info

    def _extract_framework_version_from_pickle(self, pickle_data: bytes) -> str | None:
        """Extract PyTorch framework version from pickle data by examining opcodes"""
        try:
            import io
            import pickletools

            # Use pickletools to examine opcodes without executing the pickle
            opcodes = []
            with io.BytesIO(pickle_data) as f:
                for opcode, arg, pos in pickletools.genops(f):
                    opcodes.append((opcode, arg, pos))

            string_opcode_names = {"UNICODE", "STRING", "SHORT_BINSTRING", "SHORT_BINUNICODE", "BINUNICODE"}

            # Look for GLOBAL opcodes that reference torch.__version__
            for i, (opcode, arg, _pos) in enumerate(opcodes):
                if opcode.name == "GLOBAL" and self._is_torch_version_global_arg(arg):
                    # Found a reference to torch version - try to get the value
                    # Look for subsequent opcodes that might contain the version string
                    for j in range(i + 1, min(i + 10, len(opcodes))):
                        next_opcode, next_arg, _next_pos = opcodes[j]
                        if (
                            next_opcode.name in string_opcode_names
                            and next_arg
                            and isinstance(next_arg, str)
                            and self._looks_like_pytorch_version(next_arg)
                        ):
                            return next_arg

            # Look for explicit torch/PyTorch version keys followed by a version literal.
            # Generic keys like "version" are model/config schema metadata, not
            # PyTorch producer evidence.
            explicit_version_keys = {
                "__version__",
                "producer_pytorch_version",
                "pytorch_version",
                "pytorch_framework_version",
                "torch.__version__",
                "torch_version",
            }
            for i, (opcode, arg, _pos) in enumerate(opcodes):
                if opcode.name not in string_opcode_names or not isinstance(arg, str):
                    continue
                normalized_key = arg.strip().lower()
                if normalized_key not in explicit_version_keys:
                    continue
                for next_opcode, next_arg, _next_pos in opcodes[i + 1 : min(i + 8, len(opcodes))]:
                    if (
                        next_opcode.name in string_opcode_names
                        and isinstance(next_arg, str)
                        and self._looks_like_pytorch_version(next_arg)
                    ):
                        return next_arg

        except Exception as exc:
            logger.debug("Unable to infer PyTorch version from pickle metadata: %s", exc)

        return None

    @classmethod
    def _is_torch_version_global_arg(cls, value: object) -> bool:
        global_name = cls._coerce_pickle_string_arg(value)
        if global_name is None:
            return False
        parts = global_name.split()
        if len(parts) == 2:
            module, name = parts
        elif "." in global_name:
            module, name = global_name.rsplit(".", 1)
        else:
            return False
        return module == "torch" and name == "__version__"

    @staticmethod
    def _metadata_declares_pytorch_framework(metadata: dict[str, Any]) -> bool:
        for key in ("framework", "library", "backend"):
            value = metadata.get(key)
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, str) and item.strip().lower() in {"pytorch", "torch"}:
                    return True
        return False

    def _looks_like_version(self, text: str) -> bool:
        """Check if a string looks like a version number"""
        # Match patterns like 2.5.1, 2.10.0a0, 2.2.3rc1, 1.13.0+cu117, 2.0.0.dev20230101.
        version_pattern = (
            r"^\d+\.\d+\.\d+"
            r"(?:(?:a|b|rc|alpha|beta|pre|preview)\d*|(?:\.?dev|\.?post)\d*)?"
            r"(?:\+[-.0-9A-Za-z]+)?$"
        )
        return bool(re.match(version_pattern, text.strip(), flags=re.IGNORECASE))

    def _looks_like_pytorch_version(self, text: str) -> bool:
        """Check if a string looks specifically like a PyTorch version"""
        if not self._looks_like_version(text):
            return False
        # PyTorch versions typically start with 1.x or 2.x
        return text.strip().startswith(("1.", "2."))

    def _get_detected_pytorch_version(
        self,
        version_info: dict[str, Any],
        *,
        installed_version: str | None | object = _INSTALLED_PYTORCH_VERSION_UNSET,
    ) -> tuple[str | None, str | None]:
        """Return raw PyTorch version evidence, preferring artifact metadata when present.

        Security-sensitive CVE gating should use _select_pytorch_version_for_check(),
        which flags any vulnerable source conservatively.
        """
        version = version_info.get("pytorch_framework_version")
        source = version_info.get("pytorch_version_source")
        if isinstance(version, str) and version.strip():
            return version.strip(), source if isinstance(source, str) else None

        if installed_version is _INSTALLED_PYTORCH_VERSION_UNSET:
            installed_version = self._get_installed_pytorch_version()
        if isinstance(installed_version, str) and installed_version:
            return installed_version, "local_environment"

        return None, source if isinstance(source, str) else None

    def _get_installed_pytorch_version(self) -> str | None:
        """Get installed PyTorch version without importing torch."""
        cached = self._installed_pytorch_version_cache
        if cached is not _INSTALLED_PYTORCH_VERSION_UNSET:
            return cached if isinstance(cached, str) else None

        version, metadata_path = self._resolve_installed_pytorch_version()
        self._installed_pytorch_version_cache = version
        self._installed_pytorch_metadata_path = metadata_path
        return version

    def _resolve_installed_pytorch_version(self) -> tuple[str | None, str | None]:
        """Resolve active PyTorch runtime metadata from trusted environment paths."""
        trusted_roots = self._trusted_python_package_roots()
        import_origin = self._resolve_torch_import_origin()

        try:
            from importlib import metadata
        except Exception as exc:
            logger.debug("Unable to load importlib.metadata for PyTorch version detection: %s", exc)
            return None, None

        distribution, metadata_path = self._trusted_torch_distribution(
            metadata,
            trusted_roots=trusted_roots,
            import_origin=import_origin,
        )
        if distribution is None:
            return self._trusted_imported_torch_module_version(trusted_roots)

        try:
            package_version: object = distribution.version
        except Exception as exc:
            logger.debug("Unable to read trusted torch package metadata: %s", exc)
            return None, None

        if not isinstance(package_version, str):
            logger.debug("Ignoring non-string installed torch package version metadata: %r", package_version)
            return None, None

        package_version = package_version.strip()
        if not package_version:
            logger.debug("Ignoring blank installed torch package version metadata")
            return None, None

        if not self._looks_like_pytorch_version(package_version):
            logger.debug("Using malformed installed torch package version metadata conservatively: %r", package_version)
        return package_version, str(metadata_path) if metadata_path is not None else None

    def _get_installed_pytorch_metadata_path(self) -> str | None:
        self._get_installed_pytorch_version()
        return self._installed_pytorch_metadata_path

    @staticmethod
    def _trusted_python_package_roots() -> tuple[os.PathLike[str], ...]:
        import site
        import sys
        import sysconfig

        roots: list[os.PathLike[str]] = []

        def add_root(value: object) -> None:
            if not isinstance(value, str) or not value.strip():
                return
            try:
                resolved = os.fspath(os.path.realpath(value))
            except OSError:
                return
            if resolved and resolved not in {os.fspath(root) for root in roots}:
                roots.append(Path(resolved))

        known_roots: list[Path] = []

        def add_known_root(value: object) -> None:
            if not isinstance(value, str) or not value.strip():
                return
            with suppress(OSError, RuntimeError, TypeError, ValueError):
                known_roots.append(Path(os.path.realpath(value)).resolve())

        for scheme_key in ("purelib", "platlib"):
            add_known_root(sysconfig.get_path(scheme_key))
        with suppress(Exception):
            for package_root in site.getsitepackages():
                add_known_root(package_root)
        with suppress(Exception):
            add_known_root(site.getusersitepackages())

        for search_path in sys.path:
            with suppress(OSError, RuntimeError, TypeError, ValueError):
                resolved_search_path = Path(os.path.realpath(search_path)).resolve()
                if any(resolved_search_path == root for root in known_roots):
                    add_root(str(resolved_search_path))

        return tuple(roots)

    @staticmethod
    def _canonical_package_name(name: object) -> str | None:
        if not isinstance(name, str):
            return None
        normalized = re.sub(r"[-_.]+", "-", name).strip().lower()
        return normalized or None

    @staticmethod
    def _path_is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
        except (OSError, RuntimeError, ValueError):
            return False
        return True

    @staticmethod
    def _distribution_metadata_path(distribution: Any, root: Path) -> Path:
        raw_path = getattr(distribution, "_path", None)
        if raw_path is not None:
            with suppress(OSError, RuntimeError, TypeError, ValueError):
                return Path(raw_path).resolve()
        with suppress(Exception):
            located = distribution.locate_file("")
            return Path(located).resolve()
        return root

    @staticmethod
    def _resolve_torch_import_origin() -> Path | None:
        with suppress(Exception):
            spec = importlib.machinery.PathFinder.find_spec("torch")
            if spec is None:
                return None
            raw_origin = spec.origin
            if isinstance(raw_origin, str) and raw_origin not in {"built-in", "frozen", "namespace"}:
                return Path(raw_origin).resolve()
            locations = getattr(spec, "submodule_search_locations", None)
            if locations:
                for location in locations:
                    if isinstance(location, str) and location.strip():
                        return Path(location).resolve()
        return None

    def _trusted_imported_torch_module_version(
        self,
        trusted_roots: tuple[os.PathLike[str], ...],
    ) -> tuple[str | None, str | None]:
        import sys

        torch_module = sys.modules.get("torch")
        if torch_module is None:
            return None, None

        module_path = getattr(torch_module, "__file__", None)
        if not isinstance(module_path, str) or not module_path.strip():
            return None, None

        with suppress(OSError, RuntimeError, TypeError, ValueError):
            resolved_module_path = Path(module_path).resolve()
            if not any(self._path_is_relative_to(resolved_module_path, Path(raw_root)) for raw_root in trusted_roots):
                logger.debug("Ignoring already-imported torch module outside trusted package roots")
                return None, None

            try:
                module_version = getattr(torch_module, "__version__", None)
            except Exception as exc:
                logger.debug("Unable to read already-imported torch.__version__: %s", exc)
                return None, None
            if isinstance(module_version, str) and module_version.strip():
                return module_version.strip(), str(resolved_module_path)
            if module_version is not None:
                logger.debug("Ignoring non-string already-imported torch.__version__: %r", module_version)
        return None, None

    def _trusted_torch_distribution(
        self,
        metadata: Any,
        *,
        trusted_roots: tuple[os.PathLike[str], ...],
        import_origin: Path | None,
    ) -> tuple[Any | None, Path | None]:
        resolved_roots: list[Path] = []
        for raw_root in trusted_roots:
            try:
                trusted_root = Path(raw_root).resolve()
            except (OSError, RuntimeError, TypeError, ValueError):
                continue
            if trusted_root not in resolved_roots:
                resolved_roots.append(trusted_root)

        trusted_import_root = None
        if import_origin is not None:
            trusted_import_root = next(
                (root for root in resolved_roots if self._path_is_relative_to(import_origin, root)),
                None,
            )
            if trusted_import_root is None:
                logger.debug("Ignoring trusted torch metadata because torch resolves outside trusted package roots")
                return None, None

        search_roots = [trusted_import_root] if trusted_import_root is not None else resolved_roots
        fallback_distribution: tuple[Any, Path] | None = None
        for trusted_root in search_roots:
            try:
                distributions = metadata.distributions(path=[str(trusted_root)])
            except Exception:
                logger.debug("Unable to inspect trusted Python package root during torch metadata lookup")
                continue
            for distribution in distributions:
                try:
                    package_name = distribution.metadata.get("Name")
                except Exception:
                    package_name = getattr(distribution, "name", None)
                if self._canonical_package_name(package_name) != "torch":
                    continue
                metadata_path = self._distribution_metadata_path(distribution, trusted_root)
                if not self._path_is_relative_to(metadata_path, trusted_root):
                    logger.debug("Ignoring torch metadata outside trusted root")
                    continue
                if fallback_distribution is None:
                    fallback_distribution = (distribution, metadata_path)
        if fallback_distribution is not None:
            return fallback_distribution
        return None, None

    def _select_pytorch_version_for_check(
        self,
        version_info: dict[str, Any],
        is_vulnerable: Callable[[str], bool],
    ) -> tuple[str | None, str | None]:
        """Select active runtime version evidence for package/runtime CVE gating."""
        del version_info, is_vulnerable
        installed_version = self._get_installed_pytorch_version()
        if installed_version:
            return installed_version, "local_environment"
        return None, None

    @staticmethod
    def _format_pytorch_version_source(version_source: str | None) -> str:
        """Return human-readable wording for the selected PyTorch version source."""
        if version_source == "local_environment":
            return "Local PyTorch"
        return "Artifact metadata indicates PyTorch"

    def _add_unknown_pytorch_runtime_version_check(
        self,
        result: ScanResult,
        path: str,
        *,
        check_name: str,
        cve_id: str,
        fix_version: str,
        description: str,
        remediation: str,
        fail_closed: bool,
        producer_version: str | None = None,
        producer_source: str | None = None,
        cvss: float | None = None,
        cwe: str | None = None,
    ) -> None:
        """Record explicit unknown applicability for runtime-version-gated CVEs."""
        if fail_closed:
            mark_inconclusive_scan_result(result, self.RUNTIME_VERSION_UNKNOWN_INCONCLUSIVE_REASON)

        details: dict[str, Any] = {
            "cve_id": cve_id,
            "description": description,
            "remediation": remediation,
            "producer_pytorch_version": producer_version,
            "producer_pytorch_version_source": producer_source,
            "installed_pytorch_version": None,
            "installed_pytorch_metadata_path": self._get_installed_pytorch_metadata_path(),
            "runtime_version_known": False,
            "runtime_cve_applicability": "unknown",
            "runtime_cve_version_gate": "local_environment_only",
            "analysis_incomplete": True,
            "fixed_in": f"PyTorch {fix_version}",
        }
        if fail_closed:
            details["scan_outcome_reason"] = self.RUNTIME_VERSION_UNKNOWN_INCONCLUSIVE_REASON
        if cvss is not None:
            details["cvss"] = cvss
        if cwe is not None:
            details["cwe"] = cwe

        result.checks.append(
            Check(
                name=check_name,
                status=CheckStatus.SKIPPED,
                message=(
                    f"PyTorch runtime version is unknown; cannot determine {cve_id} applicability "
                    f"(fixed in PyTorch {fix_version})."
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details=details,
            )
        )

    @staticmethod
    def _producer_framework_version_evidence(version_info: dict[str, Any]) -> tuple[str | None, str | None]:
        producer_version = version_info.get("pytorch_framework_version")
        if not isinstance(producer_version, str) or not producer_version.strip():
            return None, None
        producer_source = version_info.get("pytorch_version_source")
        return producer_version.strip(), producer_source if isinstance(producer_source, str) else None

    def _add_pytorch_version_provenance_check(
        self,
        version_info: dict[str, Any],
        result: ScanResult,
        path: str,
    ) -> None:
        """Record artifact producer version metadata separately from runtime CVE evidence."""
        producer_version = version_info.get("pytorch_framework_version")
        producer_source = version_info.get("pytorch_version_source")
        archive_version = version_info.get("pytorch_archive_version")
        installed_version = self._get_installed_pytorch_version()

        if not any(isinstance(value, str) and value.strip() for value in (producer_version, archive_version)):
            return

        if isinstance(producer_version, str) and producer_version.strip():
            producer_version = producer_version.strip()
        else:
            producer_version = None
        if isinstance(producer_source, str) and producer_source.strip():
            producer_source = producer_source.strip()
        else:
            producer_source = None
        if isinstance(archive_version, str) and archive_version.strip():
            archive_version = archive_version.strip()
        else:
            archive_version = None

        if installed_version:
            runtime_summary = f"active scanner/runtime PyTorch is {installed_version}"
            runtime_scope = "local_environment"
        else:
            runtime_summary = "active scanner/runtime PyTorch version is not known"
            runtime_scope = None

        producer_summary = (
            f"Artifact producer metadata records PyTorch {producer_version}"
            if producer_version
            else "Artifact contains PyTorch archive version metadata"
        )
        if producer_source:
            producer_summary = f"{producer_summary} from {producer_source}"

        result.add_check(
            name="PyTorch Version Provenance",
            passed=True,
            message=(
                f"{producer_summary}; {runtime_summary}. "
                "Producer metadata is provenance and is not used by itself for runtime CVE applicability."
            ),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "producer_pytorch_version": producer_version,
                "producer_pytorch_version_source": producer_source,
                "pytorch_archive_version": archive_version,
                "installed_pytorch_version": installed_version,
                "installed_pytorch_metadata_path": self._get_installed_pytorch_metadata_path(),
                "active_runtime_version": installed_version,
                "active_runtime_version_source": runtime_scope,
                "runtime_version_known": installed_version is not None,
                "runtime_cve_version_gate": "local_environment_only",
            },
        )

    def _check_cve_2025_32434_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2025-32434 using conservative PyTorch version evidence."""
        detected_version, version_source = self._select_pytorch_version_for_check(
            version_info, self._is_vulnerable_pytorch_version
        )
        if not detected_version:
            producer_version, producer_source = self._producer_framework_version_evidence(version_info)
            self._add_unknown_pytorch_runtime_version_check(
                result,
                path,
                check_name="CVE-2025-32434 PyTorch Version Check",
                cve_id=self.CVE_2025_32434_ID,
                fix_version=self.CVE_2025_32434_FIX_VERSION,
                description=self.CVE_2025_32434_DESCRIPTION,
                remediation=(
                    "Update to PyTorch 2.6.0 or later, avoid torch.load(weights_only=True) with untrusted models"
                ),
                fail_closed=producer_version is not None,
                producer_version=producer_version,
                producer_source=producer_source,
                cvss=9.8,
                cwe="CWE-502",
            )
            return

        is_vulnerable = self._is_vulnerable_pytorch_version(detected_version)
        source_prefix = self._format_pytorch_version_source(version_source)

        if is_vulnerable:
            result.add_check(
                name="CVE-2025-32434 PyTorch Version Check",
                passed=False,
                message=(
                    f"{source_prefix} {detected_version} is vulnerable to CVE-2025-32434 RCE. "
                    f"Upgrade to PyTorch 2.6.0 or later."
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": self.CVE_2025_32434_DESCRIPTION,
                    "remediation": (
                        "Update to PyTorch 2.6.0 or later, avoid torch.load(weights_only=True) with untrusted models"
                    ),
                    "detected_pytorch_version": detected_version,
                    "pytorch_version_source": version_source,
                    "installed_pytorch_version": self._get_installed_pytorch_version(),
                    "installed_pytorch_metadata_path": self._get_installed_pytorch_metadata_path(),
                    "runtime_version_known": True,
                    "runtime_cve_applicability": "vulnerable",
                    "vulnerability_description": "RCE when loading models with torch.load(weights_only=True)",
                    "fixed_in": f"PyTorch {self.CVE_2025_32434_FIX_VERSION}",
                    "recommendation": (
                        "Update to PyTorch 2.6.0 or later, avoid torch.load(weights_only=True) with untrusted models"
                    ),
                },
                rule_code="S902",
            )

    def _is_vulnerable_pytorch_version(self, version: str) -> bool:
        """Check if a PyTorch version is vulnerable to CVE-2025-32434 (≤2.5.1)"""
        return self._is_vulnerable_pytorch_version_for(version, *self.CVE_2025_32434_FIX_VERSION_PARTS)

    def _check_cve_2026_24747_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2026-24747 using conservative PyTorch version evidence."""
        detected_version, version_source = self._select_pytorch_version_for_check(
            version_info, self._is_vulnerable_pytorch_version_2026
        )
        if not detected_version:
            cve_info = CVE_COMBINED_PATTERNS[self.CVE_2026_24747_ID]
            producer_version, producer_source = self._producer_framework_version_evidence(version_info)
            self._add_unknown_pytorch_runtime_version_check(
                result,
                path,
                check_name="CVE-2026-24747 PyTorch Version Check",
                cve_id=self.CVE_2026_24747_ID,
                fix_version=self.CVE_2026_24747_FIX_VERSION,
                description=str(cve_info["description"]),
                remediation=str(cve_info["remediation"]),
                fail_closed=producer_version is not None,
                producer_version=producer_version,
                producer_source=producer_source,
                cvss=float(str(cve_info["cvss"])),
                cwe=str(cve_info["cwe"]),
            )
            return

        is_vulnerable = self._is_vulnerable_pytorch_version_2026(detected_version)
        source_prefix = self._format_pytorch_version_source(version_source)
        cve_info = CVE_COMBINED_PATTERNS[self.CVE_2026_24747_ID]
        if is_vulnerable:
            result.add_check(
                name="CVE-2026-24747 PyTorch Version Check",
                passed=False,
                message=(
                    f"{source_prefix} {detected_version} is vulnerable to CVE-2026-24747 "
                    f"(weights_only=True bypass via SETITEM abuse and tensor metadata mismatch). "
                    f"Upgrade to PyTorch {self.CVE_2026_24747_FIX_VERSION} or later."
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "cve_id": self.CVE_2026_24747_ID,
                    "cvss": cve_info["cvss"],
                    "cwe": cve_info["cwe"],
                    "description": cve_info["description"],
                    "remediation": cve_info["remediation"],
                    "detected_pytorch_version": detected_version,
                    "pytorch_version_source": version_source,
                    "installed_pytorch_version": self._get_installed_pytorch_version(),
                    "installed_pytorch_metadata_path": self._get_installed_pytorch_metadata_path(),
                    "runtime_version_known": True,
                    "runtime_cve_applicability": "vulnerable",
                    "vulnerability_description": self.CVE_2026_24747_DESCRIPTION,
                    "fixed_in": f"PyTorch {self.CVE_2026_24747_FIX_VERSION}",
                    "recommendation": (
                        "Update to PyTorch 2.10.0 or later. Use SafeTensors format "
                        "for inherent safety against deserialization attacks."
                    ),
                },
                why=(
                    "CVE-2026-24747 allows bypassing the weights_only=True restricted unpickler "
                    "via SETITEM/SETITEMS opcodes applied to non-dict objects and tensor storage "
                    "size mismatches, enabling heap layout manipulation and arbitrary code execution."
                ),
            )
        elif not self._version_metadata_analysis_incomplete(result):
            result.add_check(
                name="CVE-2026-24747 PyTorch Version Check",
                passed=True,
                message=(
                    f"{source_prefix} {detected_version} is not vulnerable to CVE-2026-24747 "
                    f"(fixed in {self.CVE_2026_24747_FIX_VERSION}+)."
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "cve_id": self.CVE_2026_24747_ID,
                    "detected_pytorch_version": detected_version,
                    "pytorch_version_source": version_source,
                    "installed_pytorch_version": self._get_installed_pytorch_version(),
                    "installed_pytorch_metadata_path": self._get_installed_pytorch_metadata_path(),
                    "runtime_version_known": True,
                    "runtime_cve_applicability": "not_vulnerable",
                    "fixed_in": f"PyTorch {self.CVE_2026_24747_FIX_VERSION}",
                },
            )

    def _is_vulnerable_pytorch_version_2026(self, version: str) -> bool:
        """Check if a PyTorch version is vulnerable to CVE-2026-24747 (< 2.10.0)."""
        return self._is_vulnerable_pytorch_version_for(version, *self.CVE_2026_24747_FIX_VERSION_PARTS)

    @staticmethod
    def _is_vulnerable_pytorch_version_for(version: str, fix_major: int, fix_minor: int, fix_patch: int) -> bool:
        """Check if a PyTorch version is vulnerable (< fix_major.fix_minor.fix_patch).

        Shared helper that DRYs up version comparison for multiple CVEs.
        Pre-release versions of the fix release are treated as vulnerable.
        """
        try:
            vstr = version.strip()
            version_match = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", vstr)
            if not version_match:
                return True  # Can't parse, assume vulnerable

            major, minor, patch = map(int, version_match.groups()[:3])
            suffix = (version_match.group(4) or "").strip().lower()

            is_prerelease = False
            if suffix:
                normalized_suffix = suffix.lstrip(".-")
                if re.fullmatch(
                    r"(?:a|b|rc|dev|alpha|beta|pre|preview)\d*(?:\+[-.0-9a-z]+)?",
                    normalized_suffix,
                ):
                    is_prerelease = True
                elif suffix.startswith("+") or suffix.startswith(".post") or suffix.startswith("post"):
                    is_prerelease = False
                else:
                    # Unknown suffix semantics -> conservative
                    return True

            if (major, minor, patch) < (fix_major, fix_minor, fix_patch):
                return True
            if (major, minor, patch) > (fix_major, fix_minor, fix_patch):
                return False
            # Equal to fix release: prerelease variants are still vulnerable
            return is_prerelease
        except Exception:
            return True

    def _check_metadata_driven_pytorch_version_vulnerability(
        self,
        version_info: dict[str, Any],
        result: ScanResult,
        path: str,
        cve_metadata: _PyTorchVersionCveMetadata,
    ) -> None:
        """Check for a version-gated PyTorch CVE using shared declarative metadata."""

        def is_vulnerable(version: str) -> bool:
            return self._is_vulnerable_pytorch_version_for(version, *cve_metadata.fix_version_parts)

        detected_version, version_source = self._select_pytorch_version_for_check(
            version_info,
            is_vulnerable,
        )
        if not detected_version:
            producer_version, producer_source = self._producer_framework_version_evidence(version_info)
            self._add_unknown_pytorch_runtime_version_check(
                result,
                path,
                check_name=cve_metadata.check_name,
                cve_id=cve_metadata.cve_id,
                fix_version=cve_metadata.fix_version,
                description=cve_metadata.description,
                remediation=cve_metadata.remediation,
                fail_closed=producer_version is not None,
                producer_version=producer_version,
                producer_source=producer_source,
                cvss=cve_metadata.cvss,
                cwe=cve_metadata.cwe,
            )
            return
        if not is_vulnerable(detected_version):
            return

        source_prefix = self._format_pytorch_version_source(version_source)
        result.add_check(
            name=cve_metadata.check_name,
            passed=False,
            message=(
                f"{source_prefix} {detected_version} is vulnerable to {cve_metadata.cve_id} "
                f"{cve_metadata.vulnerable_message_suffix}. "
                f"Upgrade to PyTorch {cve_metadata.fix_version} or later."
            ),
            severity=IssueSeverity.CRITICAL,
            location=path,
            details={
                "cve_id": cve_metadata.cve_id,
                "cvss": cve_metadata.cvss,
                "cwe": cve_metadata.cwe,
                "description": cve_metadata.description,
                "remediation": cve_metadata.remediation,
                "detected_pytorch_version": detected_version,
                "pytorch_version_source": version_source,
                "installed_pytorch_version": self._get_installed_pytorch_version(),
                "installed_pytorch_metadata_path": self._get_installed_pytorch_metadata_path(),
                "runtime_version_known": True,
                "runtime_cve_applicability": "vulnerable",
                "vulnerability_description": cve_metadata.description,
                "fixed_in": f"PyTorch {cve_metadata.fix_version}",
                "recommendation": cve_metadata.remediation,
            },
            why=cve_metadata.why,
        )

    def _check_cve_2022_45907_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2022-45907 using conservative PyTorch version evidence."""
        self._check_metadata_driven_pytorch_version_vulnerability(
            version_info,
            result,
            path,
            self._PYTORCH_VERSION_CVE_METADATA[self.CVE_2022_45907_ID],
        )

    def _check_cve_2024_5480_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2024-5480 using conservative PyTorch version evidence."""
        self._check_metadata_driven_pytorch_version_vulnerability(
            version_info,
            result,
            path,
            self._PYTORCH_VERSION_CVE_METADATA[self.CVE_2024_5480_ID],
        )

    def _check_cve_2024_48063_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2024-48063 using conservative PyTorch version evidence."""
        self._check_metadata_driven_pytorch_version_vulnerability(
            version_info,
            result,
            path,
            self._PYTORCH_VERSION_CVE_METADATA[self.CVE_2024_48063_ID],
        )

    def _validate_tensor_metadata_consistency(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        pickle_files: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
    ) -> None:
        """Validate tensor storage sizes declared in pickle match actual archive blob sizes.

        CVE-2026-24747 exploits mismatches between declared tensor metadata and
        actual storage blob sizes to manipulate heap layout.
        """

        # Collect actual blob sizes from data/ directory
        data_blob_sizes: dict[str, int] = {}
        trusted_storage_blob_members = self._pytorch_storage_layout_blob_members(safe_entries)
        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            if name in trusted_storage_blob_members:
                data_blob_sizes[name] = entry.file_size

        if not data_blob_sizes:
            return  # No tensor blobs to validate

        # Parse pickle to look for tensor rebuild patterns and cross-reference storage
        # Use bounded reads to avoid memory spikes on large pickle entries
        max_pkl_read = 10 * 1024 * 1024  # 10 MB limit for metadata validation
        trusted_storage_data_pkl_members = self._trusted_pytorch_storage_data_pkl_members(safe_entries)
        for pkl_info in pickle_files:
            pkl_name = self._get_zip_member_name(pkl_info)
            is_trusted_storage_data_pkl = pkl_name in trusted_storage_data_pkl_members
            try:
                if pkl_info.file_size > max_pkl_read:
                    if is_trusted_storage_data_pkl:
                        mark_inconclusive_scan_result(result, "pytorch_zip_tensor_metadata_validation_truncated")
                        result.add_check(
                            name="CVE-2026-24747 Tensor Metadata Validation",
                            passed=False,
                            message=(
                                f"Tensor metadata validation only inspected the first {max_pkl_read} bytes "
                                f"of oversized pickle member {pkl_name}"
                            ),
                            severity=IssueSeverity.INFO,
                            location=f"{path}:{pkl_name}",
                            details={
                                "cve_id": self.CVE_2026_24747_ID,
                                "analysis_incomplete": True,
                                "member_size": pkl_info.file_size,
                                "max_read_bytes": max_pkl_read,
                            },
                        )
                    pkl_data = self._read_member_prefix(
                        zip_file,
                        pkl_info,
                        max_pkl_read,
                        phase="tensor_metadata_validation",
                        result=result,
                    )
                else:
                    pkl_data = self._read_member_bytes(
                        zip_file,
                        pkl_info,
                        phase="tensor_metadata_validation",
                        result=result,
                    )
                mismatches, parse_complete = self._check_tensor_storage_mismatches(pkl_data, data_blob_sizes)
                if not parse_complete and pkl_info.file_size <= max_pkl_read and is_trusted_storage_data_pkl:
                    mark_inconclusive_scan_result(result, "pytorch_zip_tensor_metadata_validation_failed")
                    result.add_check(
                        name="CVE-2026-24747 Tensor Metadata Validation",
                        passed=False,
                        message=f"Tensor metadata validation could not parse pickle member {pkl_name}",
                        severity=IssueSeverity.INFO,
                        location=f"{path}:{pkl_name}",
                        details={
                            "cve_id": self.CVE_2026_24747_ID,
                            "analysis_incomplete": True,
                        },
                    )
                if mismatches:
                    result.add_check(
                        name="CVE-2026-24747 Tensor Metadata Validation",
                        passed=False,
                        message=(
                            f"Tensor storage size mismatches detected in {pkl_name}: "
                            f"{len(mismatches)} inconsistencies found"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{path}:{pkl_name}",
                        details={
                            "cve_id": self.CVE_2026_24747_ID,
                            "mismatches": mismatches[:10],
                            "total_mismatches": len(mismatches),
                        },
                        why=(
                            "CVE-2026-24747 exploits mismatches between declared tensor metadata "
                            "in pickle and actual binary blob sizes to manipulate heap layout "
                            "during deserialization. Legitimate models have consistent metadata."
                        ),
                    )
            except Exception as exc:
                mark_inconclusive_scan_result(result, "pytorch_zip_tensor_metadata_validation_failed")
                result.add_check(
                    name="CVE-2026-24747 Tensor Metadata Validation",
                    passed=False,
                    message=f"Tensor metadata validation could not be completed for {pkl_name}: {exc}",
                    severity=IssueSeverity.INFO,
                    location=f"{path}:{pkl_name}",
                    details={
                        "cve_id": self.CVE_2026_24747_ID,
                        "analysis_incomplete": True,
                        "exception_type": type(exc).__name__,
                    },
                )
                continue

    def _check_tensor_storage_mismatches(
        self, pkl_data: bytes, data_blob_sizes: dict[str, int]
    ) -> tuple[list[dict[str, Any]], bool]:
        """Check for mismatches between pickle tensor declarations and actual blob sizes.

        Return parsed mismatches plus whether pickle parsing completed.
        """
        import pickletools

        mismatches: list[dict[str, Any]] = []

        try:
            # Extract storage references and declared sizes from pickle opcodes
            # Look for _rebuild_tensor_v2 patterns which declare storage key + element count
            opcodes = list(pickletools.genops(pkl_data))
            for i, (opcode, arg, _pos) in enumerate(opcodes):
                # Resolve STACK_GLOBAL args (arg=None) by walking backwards
                # for the two preceding string-pushing opcodes (module + name).
                # Wider window handles MEMOIZE, BINGET, and BINUNICODE8 interleaving.
                resolved_arg = arg
                if opcode.name == "STACK_GLOBAL" and not arg:
                    string_ops = ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8")
                    parts: list[str] = []
                    for k in range(i - 1, max(0, i - 10) - 1, -1):
                        kop, karg, _ = opcodes[k]
                        if kop.name in string_ops and isinstance(karg, str) and karg:
                            parts.insert(0, karg)
                            if len(parts) == 2:
                                break
                    if parts:
                        resolved_arg = ".".join(parts)
                if (
                    opcode.name in ("GLOBAL", "STACK_GLOBAL")
                    and resolved_arg
                    and "_rebuild_tensor" in str(resolved_arg)
                ):
                    # Look ahead for the persistent storage reference pattern:
                    #   GLOBAL 'torch FloatStorage' -> storage_key (BINUNICODE) ->
                    #   device -> element_count (BININT*) -> TUPLE -> BINPERSID
                    # The element count is the BININT* that immediately precedes TUPLE/BINPERSID
                    storage_key = None
                    declared_size = None

                    # Find the storage GLOBAL (e.g., "torch FloatStorage")
                    for j in range(i + 1, min(i + 30, len(opcodes))):
                        next_op, next_arg, _next_pos = opcodes[j]
                        # Storage keys are small integer strings (e.g., "0", "1", "123")
                        if next_op.name in ("SHORT_BINUNICODE", "BINUNICODE") and next_arg:
                            arg_str = str(next_arg)
                            if self._is_ascii_decimal_digits(arg_str) and storage_key is None:
                                storage_key = arg_str
                        # The element count is the integer argument just before
                        # TUPLE/BINPERSID in the storage constructor call.
                        # Only capture the FIRST sizable integer after storage_key
                        # (subsequent small integers are shape/stride values).
                        if (
                            storage_key is not None
                            and declared_size is None
                            and next_op.name in ("BININT", "BININT1", "BININT2", "LONG1", "LONG4")
                            and isinstance(next_arg, int)
                            and next_arg > 0
                        ):
                            declared_size = next_arg
                        # Stop scanning at BINPERSID (end of storage reference)
                        if next_op.name == "BINPERSID":
                            break

                    if storage_key is not None and declared_size is not None:
                        # Find matching blob in archive
                        matching_blobs = [
                            (name, size) for name, size in data_blob_sizes.items() if name.endswith(f"/{storage_key}")
                        ]
                        for blob_name, actual_size in matching_blobs:
                            # Check if declared element count is wildly inconsistent with blob size
                            # Each float32 element = 4 bytes, float16 = 2 bytes
                            # A mismatch of more than 10x is suspicious
                            min_expected = declared_size  # At least 1 byte per element
                            max_expected = declared_size * 8  # At most 8 bytes per element (float64)
                            if actual_size < min_expected or actual_size > max_expected:
                                mismatches.append(
                                    {
                                        "storage_key": storage_key,
                                        "blob_name": blob_name,
                                        "declared_elements": declared_size,
                                        "actual_blob_bytes": actual_size,
                                        "expected_range": f"{min_expected}-{max_expected} bytes",
                                    }
                                )
        except Exception as exc:
            logger.debug("Unable to compare PyTorch storage blob sizes: %s", exc)
            return mismatches, False

        return mismatches, True

    def _check_safetensors_available(self, model_path: str) -> bool:
        """Check if a SafeTensors alternative exists in the same directory"""
        if repository_has_safetensors_sibling(model_path, self.config, self._repository_inventory_context):
            return True

        try:
            model_dir = os.path.dirname(model_path) or "."
            allowed_names = safetensors_alternative_filenames_for_member(os.path.basename(model_path))
            if not allowed_names:
                return False
            with os.scandir(model_dir) as entries:
                return any(
                    entry.name in allowed_names
                    and entry.is_file(follow_symlinks=False)
                    and self._is_plausible_safetensors_file(entry.path)
                    for entry in entries
                )
        except Exception:
            return False

    def _is_plausible_safetensors_file(self, path: str) -> bool:
        try:
            file_size = os.path.getsize(path)
        except OSError:
            return False
        if file_size <= 8:
            return False
        try:
            with open(path, "rb") as handle:
                header_prefix = handle.read(8)
                if len(header_prefix) != 8:
                    return False
                (header_size,) = struct.unpack("<Q", header_prefix)
                if header_size <= 0 or header_size > self.MAX_SAFETENSORS_HEADER_BYTES:
                    return False
                if 8 + header_size > file_size:
                    return False
                header = handle.read(header_size)
        except Exception:
            return False
        try:
            return isinstance(json.loads(header.decode("utf-8")), dict)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def _analyze_pickle_imports(self, pickle_result: ScanResult) -> dict[str, Any]:
        """Analyze pickle imports to distinguish legitimate vs malicious patterns"""
        # Standard PyTorch imports expected in benign state-dict archives.
        # Keep these as exact callable/class references so lookalikes such as
        # ``torch._utils.evil`` or ``collections.OrderedDictEvil`` are not
        # downgraded by substring matching.
        legitimate_imports = {
            "collections.OrderedDict",
            "numpy.dtype",
            "numpy.ndarray",
            "numpy.core.multiarray.scalar",
            "numpy._core.multiarray.scalar",
            "torch._rebuild_tensor",
            "torch._rebuild_tensor_v2",
            "torch.BFloat16Storage",
            "torch.BoolStorage",
            "torch.ByteStorage",
            "torch.CharStorage",
            "torch.ComplexDoubleStorage",
            "torch.ComplexFloatStorage",
            "torch.DoubleStorage",
            "torch.FloatStorage",
            "torch.HalfStorage",
            "torch.IntStorage",
            "torch.LongStorage",
            "torch.QInt32Storage",
            "torch.QInt8Storage",
            "torch.QUInt2x4Storage",
            "torch.QUInt4x2Storage",
            "torch.QUInt8Storage",
            "torch.ShortStorage",
            "torch.Storage",
            "torch.UntypedStorage",
            "torch._tensor._rebuild_from_type_v2",
            "torch._utils._rebuild_device_tensor_from_numpy",
            "torch._utils._rebuild_meta_tensor_no_storage",
            "torch._utils._rebuild_nested_tensor",
            "torch._utils._rebuild_parameter",
            "torch._utils._rebuild_parameter_with_state",
            "torch._utils._rebuild_qtensor",
            "torch._utils._rebuild_sparse_tensor",
            "torch._utils._rebuild_tensor",
            "torch._utils._rebuild_tensor_v2",
            "torch._utils._rebuild_tensor_v3",
            "torch._utils._rebuild_wrapper_subclass",
        }

        # Malicious imports that indicate actual attack. Match exact references
        # or dotted children only; unknown imports are handled as suspicious.
        malicious_imports = {
            "__builtin__.eval",
            "__builtin__.exec",
            "__builtin__.compile",
            "__builtin__.__import__",
            "__builtins__.eval",
            "__builtins__.exec",
            "__builtins__.compile",
            "__builtins__.__import__",
            "asyncio.subprocess",
            "builtins.eval",
            "builtins.exec",
            "builtins.compile",
            "builtins.__import__",
            "compile",
            "eval",
            "exec",
            "nt.system",
            "os.system",
            "posix.system",
            "runpy.run_module",
            "socket",
            "subprocess",
            "urllib",
            "urllib2",
            "urllib3",
            "webbrowser",
        }
        malicious_import_prefixes = (
            "asyncio.subprocess.",
            "os.",
            "subprocess.",
            "socket.",
            "urllib.",
            "urllib2.",
            "urllib3.",
            "webbrowser.",
        )

        found_imports = set()
        found_malicious = set()

        # Extract GLOBAL opcodes from ALL checks (both passed and failed)
        # This is important because legitimate imports are recorded as passed checks
        all_checks = pickle_result.issues + getattr(pickle_result, "checks", [])
        for check in all_checks:
            check_details = check.details or {}
            if "import_reference" in check_details:
                imp = check_details["import_reference"]
                found_imports.add(imp)
                # Check if this is a malicious import
                if imp in malicious_imports or any(imp.startswith(prefix) for prefix in malicious_import_prefixes):
                    found_malicious.add(imp)

        # Determine if all imports are legitimate
        all_legitimate = bool(found_imports) and all(imp in legitimate_imports for imp in found_imports)

        return {
            "total_imports": len(found_imports),
            "all_legitimate": all_legitimate,
            "found_malicious": list(found_malicious),
            "found_imports": list(found_imports),
        }

    def _add_weights_only_safety_warnings(
        self, pickle_result: ScanResult, pytorch_result: ScanResult, model_path: str, pickle_name: str
    ) -> None:
        """Add CVE-2025-32434 specific warnings with context-aware severity"""

        # Check for SafeTensors availability
        has_safetensors = self._check_safetensors_available(model_path)

        # Analyze imports to distinguish legitimate vs malicious
        import_analysis = self._analyze_pickle_imports(pickle_result)

        # Check if the pickle scan found any dangerous opcodes
        opcode_counts = self._pickle_code_execution_opcode_counts(pickle_result)
        dangerous_opcodes_found = list(opcode_counts)
        code_execution_risks = [risk for opcode, risk in _PICKLE_CODE_EXECUTION_OPCODE_RISKS if opcode in opcode_counts]
        nested_execution_opcode_evidence = self._has_nested_pickle_execution_opcode_evidence(pickle_result)
        nested_execution_rule_code = next(
            (
                issue.rule_code
                for issue in pickle_result.issues
                if (issue.details or {}).get("nested_has_execution_opcode") is True and issue.rule_code is not None
            ),
            None,
        )
        if nested_execution_opcode_evidence:
            code_execution_risks.append("Nested pickle code execution opcodes")

        # Analyze the pickle scan results for dangerous patterns
        for issue in pickle_result.issues:
            issue_msg = issue.message.lower()

            # Look for any code execution patterns
            if any(pattern in issue_msg for pattern in ["exec", "eval", "import", "subprocess", "__import__"]):
                code_execution_risks.append("Direct code execution patterns")

        # If dangerous opcodes were found, determine appropriate severity
        if dangerous_opcodes_found or code_execution_risks:
            # Determine severity based on context
            if import_analysis["found_malicious"]:
                # Malicious imports found - this is CRITICAL
                severity = IssueSeverity.CRITICAL
                message_prefix = "CRITICAL: Malicious code detected"
                recommendation = (
                    "DO NOT USE THIS MODEL - it contains malicious imports "
                    f"({', '.join(import_analysis['found_malicious'])}). "
                    "This is likely a supply chain attack."
                )
            elif has_safetensors and import_analysis["all_legitimate"]:
                # Legitimate opcodes using safe ML framework functions - this is INFO
                severity = IssueSeverity.INFO
                message_prefix = "Pickle serialization with safe ML framework operations (SafeTensors available)"
                # Handle all supported PyTorch extensions (.pt, .pth, .bin)
                base_name = os.path.splitext(os.path.basename(model_path))[0]
                safetensors_name = f"{base_name}.safetensors"
                recommendation = (
                    f"This model uses pickle format with legitimate ML framework operations. "
                    f"All REDUCE opcodes call safe functions from allowlisted ML frameworks. "
                    f"A safer SafeTensors version is available: {safetensors_name}. "
                    f"While current operations are safe, consider using SafeTensors for defense-in-depth "
                    f"(protects against environment tampering/supply chain attacks)."
                )
            elif import_analysis["all_legitimate"]:
                # Legitimate opcodes but no SafeTensors - this is INFO with recommendation
                severity = IssueSeverity.INFO
                message_prefix = "Pickle serialization format detected"
                recommendation = (
                    "This model uses pickle serialization format which allows code execution by design "
                    "(CVE-2025-32434). While the current opcodes appear legitimate, consider requesting "
                    "a SafeTensors version from the publisher for improved supply chain security."
                )
            else:
                # Suspicious but not definitively malicious - this is WARNING
                severity = IssueSeverity.WARNING
                message_prefix = "Suspicious patterns detected"
                recommendation = (
                    "Model contains unusual pickle patterns that require manual review. "
                    "Consider using SafeTensors format or verifying model source before deployment."
                )

            # Create opcode summary for evidence
            opcode_summary = ", ".join(f"{op}({count})" for op, count in opcode_counts.items())
            evidence_summary = (
                f"{opcode_summary} opcodes detected"
                if opcode_summary
                else (
                    "nested pickle code-execution opcodes detected"
                    if nested_execution_opcode_evidence
                    else "code-execution patterns detected without attributable opcode metadata"
                )
            )

            pytorch_result.add_check(
                name="CVE-2025-32434 Pickle Format Security Analysis",
                passed=False,
                message=f"{message_prefix}: {evidence_summary}",
                severity=severity,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "pickle_filename": pickle_name,
                    "opcode_counts": opcode_counts,
                    "total_dangerous_opcodes": sum(opcode_counts.values()),
                    "unique_opcode_types": dangerous_opcodes_found,
                    "code_execution_risks": list(set(code_execution_risks)),
                    "nested_execution_opcode_evidence": nested_execution_opcode_evidence,
                    "import_analysis": import_analysis,
                    "safetensors_available": has_safetensors,
                    "assessment": (
                        "malicious"
                        if import_analysis["found_malicious"]
                        else ("legitimate_but_risky_format" if import_analysis["all_legitimate"] else "suspicious")
                    ),
                    "vulnerability_description": (
                        "The weights_only=True parameter in torch.load() does not prevent code execution "
                        "from pickle files, contrary to common security assumptions."
                    ),
                    "recommendation": recommendation,
                    "affected_pytorch_versions": "All versions ≤2.5.1",
                    "fixed_in": f"PyTorch {self.CVE_2025_32434_FIX_VERSION}",
                },
                rule_code=nested_execution_rule_code
                if not opcode_counts and nested_execution_opcode_evidence
                else None,
            )

        else:
            # No dangerous opcodes found - add informational check
            pytorch_result.add_check(
                name="CVE-2025-32434 Pickle Format Security Analysis",
                passed=True,
                message=(
                    f"No dangerous pickle opcodes detected in {pickle_name}. However, pickle format "
                    f"should not be relied upon for security with untrusted models."
                ),
                severity=IssueSeverity.INFO,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "pickle_filename": pickle_name,
                    "dangerous_opcodes_found": False,
                    "safetensors_available": has_safetensors,
                    "recommendation": (
                        "Use SafeTensors format for better security. "
                        + (
                            "A SafeTensors version is available in the same directory."
                            if has_safetensors
                            else "Consider requesting a SafeTensors version from the publisher."
                        )
                    ),
                },
            )

    @staticmethod
    def _has_nested_pickle_execution_opcode_evidence(pickle_result: ScanResult) -> bool:
        return any((issue.details or {}).get("nested_has_execution_opcode") is True for issue in pickle_result.issues)

    @staticmethod
    def _metadata_pickle_opcode_count(opcode: str, *raw_count_maps: object) -> int | None:
        total = 0
        found = False
        for raw_counts in raw_count_maps:
            if not isinstance(raw_counts, dict):
                continue
            for key, value in raw_counts.items():
                if (
                    isinstance(key, str)
                    and key.upper() == opcode
                    and isinstance(value, int)
                    and not isinstance(value, bool)
                    and value > 0
                ):
                    total += value
                    found = True
        return total if found else None

    @classmethod
    def _pickle_code_execution_opcode_counts(cls, pickle_result: ScanResult) -> dict[str, int]:
        """Return exact counts for dangerous opcode types backed by findings."""
        evidence_counts: dict[str, int] = {}
        supporting_evidence_counts: dict[str, int] = {}
        raw_metadata_counts = pickle_result.metadata.get("opcode_counts")
        raw_nested_counts = pickle_result.metadata.get("nested_opcode_counts")
        raw_follow_on_counts = pickle_result.metadata.get("follow_on_opcode_counts")
        has_metadata_build = (
            cls._metadata_pickle_opcode_count(
                "BUILD",
                raw_metadata_counts,
                raw_nested_counts,
                raw_follow_on_counts,
            )
            is not None
        )
        for issue in pickle_result.issues:
            issue_details = issue.details or {}
            target_counts = (
                supporting_evidence_counts if issue_details.get("supporting_rule_code") is True else evidence_counts
            )
            for opcode, _risk in _PICKLE_CODE_EXECUTION_OPCODE_RISKS:
                count = cls._issue_pickle_opcode_count(issue.message, issue_details, opcode)
                if count > 0:
                    target_counts[opcode] = target_counts.get(opcode, 0) + count

            if issue.rule_code == "S207" and has_metadata_build:
                target_counts.setdefault("BUILD", 1)

        for opcode, count in supporting_evidence_counts.items():
            evidence_counts.setdefault(opcode, count)

        issue_import_references: set[str] = set()
        for issue in pickle_result.issues:
            issue_details = issue.details or {}
            for reference_key in (
                "import_reference",
                "invocation_import_reference",
                "opener_import_reference",
                "writer_import_reference",
            ):
                import_reference = issue_details.get(reference_key)
                if isinstance(import_reference, str) and import_reference:
                    issue_import_references.add(import_reference)

        raw_callable_invocations = pickle_result.metadata.get("callable_invocations")
        if issue_import_references and isinstance(raw_callable_invocations, list):
            dangerous_opcodes = {opcode for opcode, _risk in _PICKLE_CODE_EXECUTION_OPCODE_RISKS}
            for invocation in raw_callable_invocations:
                if not isinstance(invocation, dict):
                    continue
                invocation_reference = invocation.get("import_reference")
                if invocation_reference not in issue_import_references:
                    continue
                invocation_opcode = invocation.get("opcode")
                if isinstance(invocation_opcode, str) and invocation_opcode.upper() in dangerous_opcodes:
                    evidence_counts.setdefault(invocation_opcode.upper(), 1)

        if cls._has_nested_pickle_execution_opcode_evidence(pickle_result):
            for opcode, _risk in _PICKLE_CODE_EXECUTION_OPCODE_RISKS:
                if opcode not in _PICKLE_NESTED_EXECUTION_OPCODES:
                    continue
                metadata_count = cls._metadata_pickle_opcode_count(opcode, raw_nested_counts)
                if metadata_count is not None:
                    evidence_counts.setdefault(opcode, metadata_count)

        opcode_counts: dict[str, int] = {}
        for opcode, evidence_count in evidence_counts.items():
            metadata_count = cls._metadata_pickle_opcode_count(
                opcode,
                raw_metadata_counts,
                raw_nested_counts,
                raw_follow_on_counts,
            )
            opcode_counts[opcode] = metadata_count if metadata_count is not None else evidence_count
        return opcode_counts

    @staticmethod
    def _issue_pickle_opcode_count(issue_message: str, issue_details: dict[str, Any], opcode: str) -> int:
        """Read structured opcode evidence, with a narrow legacy-message fallback."""
        has_structured_evidence = False

        raw_opcode_counts = issue_details.get("opcode_counts")
        if isinstance(raw_opcode_counts, dict):
            for key, value in raw_opcode_counts.items():
                if not isinstance(key, str) or not key:
                    continue
                has_structured_evidence = True
                if key.upper() == opcode and isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    return value

        for key in ("opcode", "opcode_name"):
            value = issue_details.get(key)
            if isinstance(value, str) and value:
                has_structured_evidence = True
                if value.upper() == opcode:
                    return 1

        raw_opcodes = issue_details.get("opcodes")
        if isinstance(raw_opcodes, (list, tuple, set)):
            opcode_values = [value for value in raw_opcodes if isinstance(value, str) and value]
            has_structured_evidence = has_structured_evidence or bool(opcode_values)
            count = sum(value.upper() == opcode for value in opcode_values)
            if count > 0:
                return count

        if has_structured_evidence:
            return 0

        escaped_opcode = re.escape(opcode)
        explicit_opcode_pattern = (
            rf"(?<![A-Z0-9_])(?:{escaped_opcode}\s+OPCODES?|OPCODES?\s*[:=]?\s*{escaped_opcode})(?![A-Z0-9_])"
        )
        return int(re.search(explicit_opcode_pattern, issue_message.upper()) is not None)

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract PyTorch ZIP (torch.save format) metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            from .zip_scanner import open_preflighted_zip

            with open_preflighted_zip(file_path, self.config) as zip_file:
                archive_entries = zip_file.infolist()
                total_files = len(archive_entries)
                entries_to_process = archive_entries[: self.max_archive_entries]
                file_list = [entry.filename for entry in entries_to_process]
                files_truncated = total_files > len(file_list)
                member_records = [
                    (
                        entry,
                        entry.filename.replace("\\", "/").lstrip("/"),
                    )
                    for entry in entries_to_process
                ]
                member_parts = [
                    (
                        entry,
                        normalized_name,
                        normalized_name.rsplit("/", 1)[-1],
                        normalized_name.rsplit("/", 1)[0] if "/" in normalized_name else "",
                    )
                    for entry, normalized_name in member_records
                ]
                data_pkl_prefixes = {parent for _, _, basename, parent in member_parts if basename == "data.pkl"}
                has_data_pkl = bool(data_pkl_prefixes)
                has_version = any(
                    basename == "version" and (not data_pkl_prefixes or parent in data_pkl_prefixes)
                    for _, _, basename, parent in member_parts
                )

                # Analyze ZIP structure
                metadata.update(
                    {
                        "total_files": total_files,
                        "files": file_list,
                        "listed_files": len(file_list),
                        "max_archive_entries": self.max_archive_entries,
                        "files_truncated": files_truncated,
                        "omitted_files": total_files - len(file_list),
                        "metadata_analysis_incomplete": files_truncated,
                        "has_data_pkl": True if has_data_pkl else None if files_truncated else False,
                        "has_version": True if has_version else None if files_truncated else False,
                    }
                )

                # Check for model structure indicators
                pkl_files = [f for f in file_list if f.endswith(".pkl")]
                version_prefixes = {parent for _, _, basename, parent in member_parts if basename == "version"}
                model_prefixes = data_pkl_prefixes or version_prefixes
                storage_files = [
                    normalized_name
                    for _, normalized_name, _, _ in member_parts
                    if any(
                        normalized_name.startswith(f"{prefix}/data/" if prefix else "data/")
                        for prefix in model_prefixes
                    )
                ]

                metadata.update(
                    {
                        "pickle_files": pkl_files,
                        "storage_files": len(storage_files),
                    }
                )

                # Try to read version if available
                version_entry = next(
                    (
                        entry
                        for entry, _, basename, parent in member_parts
                        if basename == "version" and (not data_pkl_prefixes or parent in data_pkl_prefixes)
                    ),
                    None,
                )
                if version_entry is not None:
                    with suppress(Exception):
                        with zip_file.open(version_entry) as version_file:
                            version_data = version_file.read(self.MAX_VERSION_METADATA_BYTES + 1)
                        if len(version_data) <= self.MAX_VERSION_METADATA_BYTES:
                            metadata["pytorch_version"] = version_data.decode("utf-8").strip()

                # Estimate model complexity from file count and names
                param_indicators = sum(
                    1 for f in file_list if any(term in f.lower() for term in ["weight", "bias", "param", "layer"])
                )
                if param_indicators > 0:
                    metadata["estimated_parameters"] = param_indicators

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
