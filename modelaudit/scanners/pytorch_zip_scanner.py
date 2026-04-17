"""Scanner for PyTorch zip-archived model files (.pt, .pth)."""

import ast
import io
import logging
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, ClassVar

from ..detectors.suspicious_symbols import CVE_COMBINED_PATTERNS
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, embedded_pickle_scanner
from ..utils import sanitize_archive_path
from ..utils.file.detection import PROTO0_1_MAX_PROBE_BYTES, PROTO0_1_START_BYTES, _looks_like_proto0_or_1_pickle
from .archive_member_security import is_executable_archive_member_name
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner
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

logger = logging.getLogger(__name__)
_INSTALLED_PYTORCH_VERSION_UNSET = object()
_TORCHSCRIPT_DEBUG_PAYLOAD_MARKER = b"FORMAT_WITH_STRING_TABLE"
_TORCHSCRIPT_DEBUG_PREFIX_BYTES = 256
_TORCHSCRIPT_SOURCE_MAX_BYTES = 1024 * 1024
_TORCHSCRIPT_GENERATED_CLASS_PATTERN = re.compile(r"(?m)^class\s+[A-Za-z_][A-Za-z0-9_]*\(Module\):\s*$")
_TORCHSCRIPT_GENERATED_METHOD_PATTERN = re.compile(r"(?m)^\s+def\s+\w+\(self:\s+__torch__\.")
_TORCHSCRIPT_FORBIDDEN_SOURCE_PATTERN = re.compile(
    r"(?im)(?:^\s*(?:import|from)\s+|\b(?:__import__|eval|exec|compile|open)\s*\(|\b(?:os|subprocess|socket|requests)\s*\.)"
)
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
_JIT_SCAN_MEMBER_MAX_BYTES = 32 * 1024 * 1024
_PYTORCH_STORAGE_BLOB_MEMBER_PATTERN = re.compile(r"^(?:.+/)?data/[0-9]+$")


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

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        pickle_scanner, self.scanner_selection = embedded_pickle_scanner(self.config, PickleScanner)
        self.pickle_scanner: PickleScanner | None = pickle_scanner
        self.current_file_path = ""  # Will be set when scanning files
        self._relaxed_crc_tracker = RelaxedZipCrcTracker()
        # Configurable limits (can override class defaults via config)
        self.max_compression_ratio = self.config.get("max_compression_ratio", self.MAX_COMPRESSION_RATIO)
        self.min_compression_bomb_uncompressed_size = self._normalize_positive_int_config(
            self.config.get("min_compression_bomb_uncompressed_size"),
            self.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE,
        )
        self.max_archive_entries = self.config.get("max_archive_entries", self.MAX_ARCHIVE_ENTRIES)
        self.max_jit_scan_member_bytes = self._normalize_positive_int_config(
            self.config.get("max_jit_scan_member_bytes"),
            _JIT_SCAN_MEMBER_MAX_BYTES,
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

        try:
            # Initial validation and setup
            result = self._initialize_scan(path)
            if result.success is False:  # Early return for validation failures
                return result

            # Store the file path for use in issue locations
            self.current_file_path = path

            with zipfile.ZipFile(path, "r") as zip_file:
                # Validate ZIP entries and check for path traversal
                safe_entries = self._validate_zip_entries(zip_file, result, path)
                self._check_timeout()  # Check timeout after entry validation

                # Discover pickle files in the archive
                pickle_files = self._discover_pickle_files(zip_file, safe_entries, result)

                # Extract version info and check for CVE vulnerabilities
                self._check_pytorch_vulnerabilities(zip_file, safe_entries, result, path)

                # Scan all discovered pickle files
                trusted_pytorch_storage_data_pkl_members = self._trusted_pytorch_storage_data_pkl_members(safe_entries)
                bytes_scanned = self._scan_pickle_files(
                    zip_file,
                    pickle_files,
                    result,
                    path,
                    trusted_pytorch_storage_data_pkl_members=trusted_pytorch_storage_data_pkl_members,
                )
                self._check_timeout()  # Check timeout after pickle scanning

                # Validate tensor metadata consistency (CVE-2026-24747)
                self._validate_tensor_metadata_consistency(zip_file, safe_entries, pickle_files, result, path)

                # Check for JIT/Script code execution risks
                bytes_scanned += self._scan_for_jit_patterns(zip_file, safe_entries, pickle_files, result, path)

                # Detect suspicious non-pickle files
                self._detect_suspicious_files(zip_file, safe_entries, result, path)

                # Validate PyTorch model structure
                self._validate_pytorch_structure(pickle_files, result)

                # Check for blacklisted patterns across all files
                self._check_blacklist_patterns(zip_file, safe_entries, result)

                result.bytes_scanned += bytes_scanned

        except TimeoutError as e:
            # Handle timeout gracefully
            result.add_check(
                name="Scan Timeout",
                passed=False,
                message=f"Scan timed out: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"timeout_seconds": self.timeout},
            )
            result.finish(success=True)  # Partial results are still valid
            return result
        except zipfile.BadZipFile:
            return self._handle_bad_zip_error(path)
        except Exception as e:
            return self._handle_scan_error(path, e)

        result.finish(success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME)
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

    def _initialize_scan(self, path: str) -> ScanResult:
        """Initialize scan with basic validation and setup"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        # Validate ZIP format
        header = read_zip_header(path)
        if not header.startswith(b"PK"):
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

        try:
            # Force central directory parsing so malformed ZIPs fail fast here.
            with zipfile.ZipFile(path, "r") as z:
                z.namelist()
        except zipfile.BadZipFile:
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

        return result

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
        if entry_count > self.max_archive_entries:
            result.add_check(
                name="Archive Entry Limit",
                passed=False,
                message=f"Archive contains {entry_count} entries (max: {self.max_archive_entries})",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "entry_count": entry_count,
                    "max_entries": self.max_archive_entries,
                    "risk": "Excessive entries may indicate a decompression bomb attack",
                },
                why="Archives with excessive entries can exhaust system resources during extraction",
            )
        else:
            result.add_check(
                name="Archive Entry Limit",
                passed=True,
                message=f"Archive entry count ({entry_count}) is within limits",
                location=path,
                details={"entry_count": entry_count, "max_entries": self.max_archive_entries},
            )

        for info in archive_entries:
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
                    result.add_check(
                        name="Duplicate ZIP Entry Collision",
                        passed=False,
                        message=(
                            f"Duplicate archive entry {name} has conflicting metadata; "
                            "all copies will be scanned explicitly"
                        ),
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
            _, is_safe = sanitize_archive_path(name, temp_base)
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
            is_symlink = (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK
            if is_symlink:
                try:
                    # Read only a bounded prefix (4KB) to avoid DoS from a
                    # symlink entry that hides a large compressed payload.
                    # Real symlink targets are short filesystem paths.
                    target = self._read_member_prefix(
                        zip_file,
                        name,
                        4096,
                        phase="symlink_target_validation",
                        result=result,
                    ).decode("utf-8", "replace")
                except Exception:
                    target = "<unreadable>"
                result.add_check(
                    name="Symlink Safety Validation",
                    passed=False,
                    message=f"Symlink entry detected: {name} -> {target}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{name}",
                    details={
                        "entry": name,
                        "target": target,
                        "risk": "Symlinks in PyTorch models can be used for path traversal attacks",
                    },
                    why="Symlinks in model archives are unusual and may indicate an attack attempt",
                )
                symlink_issues_found = True
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
                        },
                        why="Decompression bombs use high compression ratios to exhaust system resources",
                    )
                    compression_issues_found = True
                    continue

            safe_entries.append(info)

        # Summary checks for clean archives
        if not path_traversal_found and archive_entries:
            result.add_check(
                name="Path Traversal Protection",
                passed=True,
                message="All archive entries have safe paths",
                location=path,
                details={"entries_checked": len(archive_entries)},
            )

        if not symlink_issues_found and archive_entries:
            result.add_check(
                name="Symlink Safety Validation",
                passed=True,
                message="No symlinks detected in archive",
                location=path,
            )

        if not compression_issues_found and archive_entries:
            result.add_check(
                name="Compression Ratio Check",
                passed=True,
                message="All entries have safe compression ratios",
                location=path,
                details={
                    "threshold": self.max_compression_ratio,
                    "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                },
            )

        if not duplicate_entry_collisions_found and archive_entries:
            result.add_check(
                name="Duplicate ZIP Entry Collision",
                passed=True,
                message="No conflicting duplicate archive entries found",
                location=path,
                details={"entries_checked": len(archive_entries)},
            )

        return safe_entries

    def _discover_pickle_files(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> list[zipfile.ZipInfo]:
        """Discover pickle files in the ZIP archive"""
        pickle_files: list[zipfile.ZipInfo] = []

        # First pass: Look for common pickle file patterns
        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            if name.endswith(".pkl") or name == "data.pkl" or name.endswith("/data.pkl"):
                pickle_files.append(entry)

        # Second pass: If no obvious pickle files found, check for pickle magic bytes
        if not pickle_files:
            for entry in safe_entries:
                try:
                    data_start = self._read_member_prefix(
                        zip_file,
                        entry,
                        _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
                        phase="pickle_discovery",
                        result=result,
                    )
                    if any(data_start.startswith(magic) for magic in _PICKLE_BINARY_PROTOCOL_PREFIXES):
                        pickle_files.append(entry)
                        continue

                    if not data_start or data_start[0] not in PROTO0_1_START_BYTES:
                        continue

                    if entry.file_size > len(data_start):
                        data_start = self._read_member_prefix(
                            zip_file,
                            entry,
                            PROTO0_1_MAX_PROBE_BYTES,
                            phase="pickle_discovery",
                            result=result,
                        )
                    if _looks_like_proto0_or_1_pickle(
                        data_start,
                        sample_is_prefix=entry.file_size > len(data_start),
                    ):
                        pickle_files.append(entry)
                except Exception as exc:
                    logger.debug("Unable to inspect ZIP member %s as a pickle: %s", entry.filename, exc)

        result.metadata["pickle_files"] = self._get_zip_member_names(pickle_files)
        return pickle_files

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
        trusted_pytorch_storage_data_pkl_members: dict[str, set[str]],
    ) -> int:
        """Scan all discovered pickle files for malicious content"""
        bytes_scanned = 0

        # Get the original ZIP file size for proper density calculations
        # This is crucial for CVE-2025-32434 detection to avoid false positives
        original_file_size = int(result.metadata.get("file_size") or 0)
        if original_file_size <= 0:
            try:
                original_file_size = os.path.getsize(path)
            except OSError:
                original_file_size = 1  # Avoid divide-by-zero in density calculations

        for info in pickle_files:
            name = self._get_zip_member_name(info)
            pickle_data_size = info.file_size
            pickle_source = f"{path}:{name}"

            if self.pickle_scanner is None:
                bytes_scanned += pickle_data_size
                add_scanner_selection_skip_check(
                    result,
                    pickle_source,
                    "pickle",
                    self.scanner_selection,
                    context="embedded PyTorch pickle analysis",
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
                    )
            sub_result.metadata.setdefault("archive_file_size", original_file_size)
            apply_pickle_member_context(sub_result, archive_path=path, member_name=name)
            normalized_name = name.replace("\\", "/").lstrip("/")
            trusted_storage_keys = trusted_pytorch_storage_data_pkl_members.get(normalized_name)
            if trusted_storage_keys is not None:
                self._downgrade_trusted_storage_persistent_ids(sub_result, trusted_storage_keys)

            # Add CVE-2025-32434 specific warnings
            self._add_weights_only_safety_warnings(sub_result, result, path, name)
            result.merge(sub_result)

        return bytes_scanned

    @classmethod
    def _trusted_pytorch_storage_data_pkl_members(cls, safe_entries: list[zipfile.ZipInfo]) -> dict[str, set[str]]:
        """Return data.pkl members with PyTorch ZIP storage keys under the same prefix."""
        members = [(cls._get_zip_member_name(entry).replace("\\", "/").lstrip("/"), entry) for entry in safe_entries]
        names = {name for name, _entry in members}
        trusted_members: dict[str, set[str]] = {}
        for name in names:
            if name.rsplit("/", 1)[-1] != "data.pkl":
                continue
            prefix = name[: -len("data.pkl")]
            if f"{prefix}version" not in names:
                continue
            data_prefix = f"{prefix}data/"
            storage_keys = {
                candidate[len(data_prefix) :]
                for candidate, entry in members
                if candidate.startswith(data_prefix)
                and cls._is_ascii_decimal_digits(candidate[len(data_prefix) :])
                and not entry.is_dir()
            }
            if storage_keys:
                trusted_members[name] = storage_keys
        return trusted_members

    @staticmethod
    def _is_ascii_decimal_digits(value: str) -> bool:
        return value.isascii() and value.isdecimal()

    @staticmethod
    def _is_pytorch_storage_persistent_id_record(details: dict[str, Any], trusted_storage_keys: set[str]) -> bool:
        storage_key = details.get("pytorch_storage_key")
        return (
            details.get("pickle_rule_code") == "PERSISTENT_ID"
            and details.get("opcode") == "BINPERSID"
            and details.get("pytorch_storage_persistent_id") is True
            and isinstance(storage_key, str)
            and storage_key in trusted_storage_keys
        )

    @classmethod
    def _downgrade_trusted_storage_persistent_ids(cls, result: ScanResult, trusted_storage_keys: set[str]) -> None:
        """Treat PyTorch storage persistent IDs as informational inside validated PyTorch ZIP data.pkl."""
        for check in result.checks:
            if not cls._is_pytorch_storage_persistent_id_record(check.details, trusted_storage_keys):
                continue
            check.status = CheckStatus.PASSED
            check.severity = IssueSeverity.INFO
            check.message = "PyTorch storage persistent ID found in validated PyTorch archive"
            check.details["trusted_pytorch_archive_context"] = True

        result.issues = [
            issue
            for issue in result.issues
            if not cls._is_pytorch_storage_persistent_id_record(issue.details, trusted_storage_keys)
        ]

    def _scan_for_jit_patterns(
        self,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        pickle_files: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
    ) -> int:
        """Check for JIT/Script code execution risks and network communication patterns"""
        bytes_scanned = 0
        all_jit_findings = []
        all_network_findings = []
        check_jit = self._get_bool_config("check_jit_script", True)
        check_net = self._get_bool_config("check_network_comm", True)
        pickle_member_names = {
            self._get_zip_member_name(entry).replace("\\", "/").lstrip("/") for entry in pickle_files
        }
        pickle_members_scanned = self.pickle_scanner is not None

        if safe_entries:
            if not check_jit:
                result.metadata.setdefault("disabled_checks", []).append("JIT/Script Code Execution Detection")
            if not check_net:
                result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")
        if not check_jit and not check_net:
            return 0

        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            normalized_name = name.replace("\\", "/").lstrip("/")
            try:
                if entry.is_dir() or normalized_name.endswith("/"):
                    continue
                # Skip numeric tensor data files to support different versions of PyTorch ZIP files
                # These are binary weight files that cause performance issues when scanned
                if _PYTORCH_STORAGE_BLOB_MEMBER_PATTERN.match(normalized_name):
                    continue
                if pickle_members_scanned and normalized_name in pickle_member_names:
                    continue
                if entry.file_size > self.max_jit_scan_member_bytes:
                    mark_inconclusive_scan_result(result, "pytorch_zip_jit_member_size_limit")
                    result.add_check(
                        name="JIT/Network Scan Size Limit",
                        passed=False,
                        message=(
                            f"PyTorch ZIP member {name} skipped by JIT/network scanning because it exceeds "
                            f"the bounded read limit ({entry.file_size} > {self.max_jit_scan_member_bytes})"
                        ),
                        severity=IssueSeverity.INFO,
                        location=f"{path}:{name}",
                        details={
                            "zip_entry": name,
                            "file_size": entry.file_size,
                            "max_scan_bytes": self.max_jit_scan_member_bytes,
                            "analysis_incomplete": True,
                        },
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
                    jit_findings = self.collect_jit_script_findings(
                        file_data,
                        model_type="pytorch",
                        context=f"{path}:{name}",
                    )
                    network_findings = self.collect_network_communication_findings(
                        file_data,
                        context=f"{path}:{name}",
                    )

                    all_jit_findings.extend(jit_findings)
                    all_network_findings.extend(network_findings)

            except Exception as e:
                logger.debug(f"Exception reading {name}: {e}")
                mark_inconclusive_scan_result(result, "pytorch_zip_jit_member_read_failed")
                result.add_check(
                    name="JIT/Network Scan Read Failure",
                    passed=False,
                    message=f"PyTorch ZIP member {name} could not be analyzed for JIT/network patterns: {e}",
                    severity=IssueSeverity.INFO,
                    location=f"{path}:{name}",
                    details={
                        "zip_entry": name,
                        "exception": str(e),
                        "exception_type": type(e).__name__,
                        "analysis_incomplete": True,
                    },
                )

        # Emit explicit checks for the entire ZIP file
        if safe_entries:  # Only create checks if we processed files
            if check_jit:
                self.add_jit_script_findings(
                    all_jit_findings,
                    result,
                    model_type="pytorch",
                    context=path,
                )

            if check_net:
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
    ) -> None:
        """Detect suspicious non-pickle files in the archive"""
        python_files_found = False
        executable_files_found = False
        member_names = {self._get_zip_member_name(entry).replace("\\", "/").lstrip("/") for entry in safe_entries}
        entries_by_normalized_name = {
            self._get_zip_member_name(entry).replace("\\", "/").lstrip("/"): entry for entry in safe_entries
        }

        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            normalized_name = name.replace("\\", "/").lstrip("/")
            normalized_name_lower = normalized_name.lower()
            # Check for Python code files
            if normalized_name_lower.endswith(".py"):
                debug_member_name = self._torchscript_debug_member_name(name, member_names)
                debug_entry = entries_by_normalized_name.get(debug_member_name or "")
                if debug_entry is not None and self._is_torchscript_generated_python(
                    zip_file,
                    entry,
                    debug_entry,
                    result,
                ):
                    continue
                result.add_check(
                    name="Python Code File Detection",
                    passed=False,
                    message=f"Python code file found in PyTorch model: {name}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{name}",
                    details={"file": name},
                )
                python_files_found = True
            # Check for shell scripts or other executable files
            elif is_executable_archive_member_name(normalized_name_lower):
                result.add_check(
                    name="Executable File Detection",
                    passed=False,
                    message=f"Executable file found in PyTorch model: {name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path}:{name}",
                    details={"file": name},
                )
                executable_files_found = True

        # Add positive checks if no suspicious files found
        if not python_files_found and safe_entries:
            result.add_check(
                name="Python Code File Detection",
                passed=True,
                message="No unexpected Python code files found in model",
                location=path,
            )

        if not executable_files_found and safe_entries:
            result.add_check(
                name="Executable File Detection",
                passed=True,
                message="No executable files found in model",
                location=path,
            )

    def _validate_pytorch_structure(self, pickle_files: list[zipfile.ZipInfo], result: ScanResult) -> None:
        """Validate that the PyTorch model has expected structure"""
        pickle_names = self._get_zip_member_names(pickle_files)
        if not pickle_files or "data.pkl" not in [os.path.basename(f) for f in pickle_names]:
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
        max_blacklist_scan_size = self.config.get("max_blacklist_scan_size", 100 * 1024 * 1024)  # 100MB default

        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            try:
                info = entry

                # Skip files that are too large
                if info.file_size > max_blacklist_scan_size:
                    result.add_check(
                        name="Blacklist Pattern Check",
                        passed=True,
                        message=(
                            f"File {name} too large for blacklist scanning "
                            f"(size: {info.file_size}, limit: {max_blacklist_scan_size})"
                        ),
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path} ({name})",
                        details={
                            "file_size": info.file_size,
                            "scan_limit": max_blacklist_scan_size,
                            "zip_entry": name,
                            "reason": "size_limit_exceeded",
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
        if isinstance(error, zipfile.BadZipFile):
            severity = IssueSeverity.WARNING
            error_type = "BadZipFile"
        elif isinstance(error, MemoryError):
            severity = IssueSeverity.WARNING
            error_type = "MemoryError"
        else:
            severity = IssueSeverity.DEBUG
            error_type = type(error).__name__

        result.add_check(
            name="ZIP Entry Read",
            passed=False,
            message=f"Error reading file {name}: {error!s}",
            severity=severity,
            location=f"{self.current_file_path} ({name})",
            details={
                "zip_entry": name,
                "exception": str(error),
                "exception_type": error_type,
                "scan_phase": "blacklist_check",
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
        )
        result.finish(success=False)
        return result

    def _handle_scan_error(self, path: str, error: Exception) -> ScanResult:
        """Handle general scan errors"""
        result = self._create_result()
        result.add_check(
            name="PyTorch ZIP Scan",
            passed=False,
            message=f"Error scanning PyTorch zip file: {error!s}",
            severity=IssueSeverity.CRITICAL,
            location=path,
            details={"exception": str(error), "exception_type": type(error).__name__},
        )
        result.finish(success=False)
        return result

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
                version_data = (
                    self._read_member_bytes(
                        zipfile_obj,
                        version_entry,
                        phase="version_probe",
                        result=result,
                    )
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
                version_info["pytorch_archive_version"] = version_data
                version_info["pytorch_version_source"] = "version"
            elif archive_version_entry is not None:
                version_data = (
                    self._read_member_bytes(
                        zipfile_obj,
                        archive_version_entry,
                        phase="version_probe",
                        result=result,
                    )
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
                version_info["pytorch_archive_version"] = version_data
                version_info["pytorch_version_source"] = "archive/version"

            # Try to extract PyTorch framework version from pickle files
            # Look for torch.__version__ references in pickle GLOBAL opcodes
            for entry in safe_entries:
                name = self._get_zip_member_name(entry)
                if name.endswith(".pkl"):
                    try:
                        # Cap read for version probing to 1MB; adjust via config if needed
                        cfg = self.config or {}
                        probe_bytes = cfg.get("version_probe_bytes", 1024 * 1024)  # 1MB default
                        pickle_data = self._read_member_prefix(
                            zipfile_obj,
                            entry,
                            probe_bytes,
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
                        import json

                        meta_data = json.loads(
                            self._read_member_bytes(
                                zipfile_obj,
                                meta_entry,
                                phase="version_probe",
                                result=result,
                            ).decode("utf-8")
                        )
                        # Look for framework-specific version fields in metadata.
                        # Avoid generic "version" keys, which often describe model/config
                        # schema versions and can cause false CVE attributions.
                        for key in ["pytorch_version", "torch_version", "framework_version"]:
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

            # Look for GLOBAL opcodes that reference torch.__version__
            for i, (opcode, arg, _pos) in enumerate(opcodes):
                if opcode.name == "GLOBAL" and arg and "torch" in arg and ("version" in arg or "__version__" in arg):
                    # Found a reference to torch version - try to get the value
                    # Look for subsequent opcodes that might contain the version string
                    for j in range(i + 1, min(i + 10, len(opcodes))):
                        next_opcode, next_arg, _next_pos = opcodes[j]
                        if (
                            next_opcode.name in ["UNICODE", "STRING", "SHORT_BINSTRING", "BINUNICODE"]
                            and next_arg
                            and isinstance(next_arg, str)
                            and self._looks_like_version(next_arg)
                        ):
                            return next_arg

            # Look for any version-like strings in the pickle
            for opcode, arg, _pos in opcodes:
                if (
                    opcode.name in ["UNICODE", "STRING", "SHORT_BINSTRING", "BINUNICODE"]
                    and arg
                    and isinstance(arg, str)
                    and self._looks_like_pytorch_version(arg)
                ):
                    return arg

        except Exception as exc:
            logger.debug("Unable to infer PyTorch version from pickle metadata: %s", exc)

        return None

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
        """Get PyTorch version from an already-imported module without importing torch."""
        try:
            import sys

            torch_module = sys.modules.get("torch")
            if torch_module is None:
                return None
            version = getattr(torch_module, "__version__", None)
            if isinstance(version, str) and version.strip():
                return version.strip()
        except Exception:
            return None

        return None

    def _select_pytorch_version_for_check(
        self,
        version_info: dict[str, Any],
        is_vulnerable: Callable[[str], bool],
    ) -> tuple[str | None, str | None]:
        """Select the most conservative PyTorch version source for CVE gating."""
        installed_version = self._get_installed_pytorch_version()
        metadata_version, metadata_source = self._get_detected_pytorch_version(
            version_info,
            installed_version=installed_version,
        )

        if installed_version and is_vulnerable(installed_version):
            return installed_version, "local_environment"
        if metadata_version and is_vulnerable(metadata_version):
            return metadata_version, metadata_source
        if installed_version:
            return installed_version, "local_environment"
        return metadata_version, metadata_source

    @staticmethod
    def _format_pytorch_version_source(version_source: str | None) -> str:
        """Return human-readable wording for the selected PyTorch version source."""
        if version_source == "local_environment":
            return "Local PyTorch"
        return "Artifact metadata indicates PyTorch"

    def _check_cve_2025_32434_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2025-32434 using conservative PyTorch version evidence."""
        detected_version, version_source = self._select_pytorch_version_for_check(
            version_info, self._is_vulnerable_pytorch_version
        )
        if not detected_version:
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
                    "detected_pytorch_version": detected_version,
                    "pytorch_version_source": version_source,
                    "installed_pytorch_version": self._get_installed_pytorch_version(),
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
            return

        is_vulnerable = self._is_vulnerable_pytorch_version_2026(detected_version)
        source_prefix = self._format_pytorch_version_source(version_source)
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
                    "detected_pytorch_version": detected_version,
                    "pytorch_version_source": version_source,
                    "installed_pytorch_version": self._get_installed_pytorch_version(),
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
        else:
            result.add_check(
                name="CVE-2026-24747 PyTorch Version Check",
                passed=True,
                message=(
                    f"{source_prefix} {detected_version} is not vulnerable to CVE-2026-24747 "
                    f"(fixed in {self.CVE_2026_24747_FIX_VERSION}+)."
                ),
                severity=IssueSeverity.INFO,
                location=path,
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
        if not detected_version or not is_vulnerable(detected_version):
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
        for entry in safe_entries:
            name = self._get_zip_member_name(entry)
            if _PYTORCH_STORAGE_BLOB_MEMBER_PATTERN.match(name):
                data_blob_sizes[name] = entry.file_size

        if not data_blob_sizes:
            return  # No tensor blobs to validate

        # Parse pickle to look for tensor rebuild patterns and cross-reference storage
        # Use bounded reads to avoid memory spikes on large pickle entries
        max_pkl_read = 10 * 1024 * 1024  # 10 MB limit for metadata validation
        for pkl_info in pickle_files:
            pkl_name = self._get_zip_member_name(pkl_info)
            try:
                if pkl_info.file_size > max_pkl_read:
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
                mismatches = self._check_tensor_storage_mismatches(pkl_data, data_blob_sizes)
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
            except Exception:
                continue

    def _check_tensor_storage_mismatches(
        self, pkl_data: bytes, data_blob_sizes: dict[str, int]
    ) -> list[dict[str, Any]]:
        """Check for mismatches between pickle tensor declarations and actual blob sizes.

        Best-effort parsing: returns empty list if pickle cannot be parsed.
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

        return mismatches

    def _check_safetensors_available(self, model_path: str) -> bool:
        """Check if a SafeTensors alternative exists in the same directory"""
        try:
            import glob

            # Get the directory containing the PyTorch model
            model_dir = os.path.dirname(model_path)
            if not model_dir:
                # If no directory (relative path), use current directory
                model_dir = "."

            # Look for .safetensors files in the same directory
            safetensors_pattern = os.path.join(model_dir, "*.safetensors")
            safetensors_files = glob.glob(safetensors_pattern)

            return len(safetensors_files) > 0
        except Exception:
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
        dangerous_opcodes_found: list[str] = []
        code_execution_risks: list[str] = []
        opcode_counts: dict[str, int] = {}

        # Analyze the pickle scan results for dangerous patterns
        for issue in pickle_result.issues:
            issue_msg = issue.message.lower()
            issue_details = issue.details or {}

            # Look for specific dangerous opcodes
            if "reduce" in issue_msg or "REDUCE" in str(issue_details):
                dangerous_opcodes_found.append("REDUCE")
                opcode_counts["REDUCE"] = opcode_counts.get("REDUCE", 0) + 1
                code_execution_risks.append("__reduce__ method exploitation")
            if "inst" in issue_msg or "INST" in str(issue_details):
                dangerous_opcodes_found.append("INST")
                opcode_counts["INST"] = opcode_counts.get("INST", 0) + 1
                code_execution_risks.append("Class instantiation code execution")
            if "obj" in issue_msg or "OBJ" in str(issue_details):
                dangerous_opcodes_found.append("OBJ")
                opcode_counts["OBJ"] = opcode_counts.get("OBJ", 0) + 1
                code_execution_risks.append("Object creation code execution")
            if "newobj" in issue_msg or "NEWOBJ" in str(issue_details):
                dangerous_opcodes_found.append("NEWOBJ")
                opcode_counts["NEWOBJ"] = opcode_counts.get("NEWOBJ", 0) + 1
                code_execution_risks.append("New-style object creation")
            if "stack_global" in issue_msg or "STACK_GLOBAL" in str(issue_details):
                dangerous_opcodes_found.append("STACK_GLOBAL")
                opcode_counts["STACK_GLOBAL"] = opcode_counts.get("STACK_GLOBAL", 0) + 1
                code_execution_risks.append("Dynamic import and attribute access")
            if "global" in issue_msg or "GLOBAL" in str(issue_details):
                dangerous_opcodes_found.append("GLOBAL")
                opcode_counts["GLOBAL"] = opcode_counts.get("GLOBAL", 0) + 1
                code_execution_risks.append("Module import and attribute access")
            if "build" in issue_msg or "BUILD" in str(issue_details):
                dangerous_opcodes_found.append("BUILD")
                opcode_counts["BUILD"] = opcode_counts.get("BUILD", 0) + 1
                code_execution_risks.append("__setstate__ method exploitation")

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

            pytorch_result.add_check(
                name="CVE-2025-32434 Pickle Format Security Analysis",
                passed=False,
                message=f"{message_prefix}: {opcode_summary} opcodes detected",
                severity=severity,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "opcode_counts": opcode_counts,
                    "total_dangerous_opcodes": sum(opcode_counts.values()),
                    "unique_opcode_types": list(set(dangerous_opcodes_found)),
                    "code_execution_risks": list(set(code_execution_risks)),
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

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract PyTorch ZIP (torch.save format) metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            with zipfile.ZipFile(file_path, "r") as zip_file:
                file_list = zip_file.namelist()

                # Analyze ZIP structure
                metadata.update(
                    {
                        "total_files": len(file_list),
                        "files": file_list,
                        "has_data_pkl": "data.pkl" in file_list,
                        "has_version": "version" in file_list,
                    }
                )

                # Check for model structure indicators
                pkl_files = [f for f in file_list if f.endswith(".pkl")]
                storage_files = [f for f in file_list if f.startswith("data/")]

                metadata.update(
                    {
                        "pickle_files": pkl_files,
                        "storage_files": len(storage_files),
                    }
                )

                # Try to read version if available
                if "version" in file_list:
                    with suppress(Exception):
                        version_data = zip_file.read("version")
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
