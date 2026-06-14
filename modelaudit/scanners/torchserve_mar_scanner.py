"""Scanner for TorchServe Model Archive (.mar) files."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import posixpath
import re
import shlex
import stat
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any, ClassVar, Generic, Protocol, TypeVar
from urllib.parse import urlparse, urlunparse

from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.helpers.assets import asset_from_scan_result
from ._archive_locations import rewrite_extracted_member_location
from .archive_member_security import (
    _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT,
    _CTYPES_LIBRARY_LOADER_TYPE_ALIASES,
    _CTYPES_LIBRARY_LOADER_TYPES,
    _normalized_high_risk_python_call_name,
    _wildcard_import_aliases,
    executable_archive_member_name_rule_code,
    executable_archive_member_rule_code,
    high_risk_python_calls_in_tree,
)
from .base import BaseScanner, IssueSeverity, ScanResult

CRITICAL_SYSTEM_PATHS = [
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
]

MANIFEST_ENTRY_PATH = "MAR-INF/MANIFEST.json"
URL_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
POPULAR_ML_PACKAGE_TYPOS = {
    "torcch": "torch",
    "numppy": "numpy",
    "scikit_learn": "scikit-learn",
    "tensorflo": "tensorflow",
    "trransformers": "transformers",
}
TRUSTED_PYPI_HOSTS = {"pypi.org", "files.pythonhosted.org", "test.pypi.org"}

SAFE_IMPORT_TIME_CALLS = {
    "logging.getLogger",
}

_DYNAMIC_IMPORT_HELPERS = frozenset({"__import__", "builtins.__import__", "importlib.import_module"})
_DYNAMIC_GETATTR_HELPERS = frozenset({"getattr", "builtins.getattr"})
_DYNAMIC_NAMESPACE_HELPERS = frozenset({"builtins.vars", "vars"})
_DYNAMIC_ASSIGNABLE_HELPERS = _DYNAMIC_IMPORT_HELPERS | _DYNAMIC_GETATTR_HELPERS
_EAGER_GENERATOR_CONSUMERS = frozenset(
    {
        "all",
        "any",
        "builtins.all",
        "builtins.any",
        "builtins.dict",
        "builtins.frozenset",
        "builtins.list",
        "builtins.max",
        "builtins.min",
        "builtins.next",
        "builtins.set",
        "builtins.sorted",
        "builtins.sum",
        "builtins.tuple",
        "dict",
        "frozenset",
        "list",
        "max",
        "min",
        "next",
        "set",
        "sorted",
        "sum",
        "tuple",
    }
)
_LAZY_GENERATOR_WRAPPERS = frozenset({"builtins.enumerate", "builtins.zip", "enumerate", "zip"})
_LAZY_CALLBACK_WRAPPERS = frozenset({"builtins.filter", "builtins.map", "filter", "map"})
_PARTIAL_CALL_HELPERS = frozenset({"functools.partial"})
_DYNAMIC_KNOWN_MODULE_ATTRIBUTES = {"math": frozenset({"sqrt"})}
_DynamicAstNode = TypeVar("_DynamicAstNode", bound=ast.AST)


class _DynamicAstAlternatives(Generic[_DynamicAstNode]):
    """Persistent collection used to merge branch aliases without quadratic copying."""

    __slots__ = ("nodes", "parents")

    def __init__(
        self,
        nodes: tuple[_DynamicAstNode, ...] = (),
        parents: tuple[_DynamicAstAlternatives[_DynamicAstNode], ...] = (),
    ) -> None:
        self.nodes = nodes
        self.parents = parents

    def __bool__(self) -> bool:
        return bool(self.nodes or self.parents)

    def __iter__(self) -> Iterator[_DynamicAstNode]:
        pending = [self]
        seen_alternatives: set[int] = set()
        seen_nodes: set[int] = set()
        while pending:
            alternatives = pending.pop()
            alternatives_id = id(alternatives)
            if alternatives_id in seen_alternatives:
                continue
            seen_alternatives.add(alternatives_id)
            pending.extend(reversed(alternatives.parents))
            for node in alternatives.nodes:
                node_id = id(node)
                if node_id not in seen_nodes:
                    seen_nodes.add(node_id)
                    yield node


def _merge_dynamic_ast_alternatives(
    left: _DynamicAstAlternatives[_DynamicAstNode] | None,
    right: _DynamicAstAlternatives[_DynamicAstNode] | None,
) -> _DynamicAstAlternatives[_DynamicAstNode] | None:
    if left is None:
        return right
    if right is None or left is right:
        return left
    return _DynamicAstAlternatives(parents=(left, right))


_DynamicGeneratorAliases = dict[str, _DynamicAstAlternatives[ast.GeneratorExp]]
_DynamicLambdaAliases = dict[str, _DynamicAstAlternatives[ast.Lambda]]
_DynamicLiteralIterableAliases = dict[str, _DynamicAstAlternatives[ast.List]]
_DynamicFunctionAliases = dict[str, _DynamicAstAlternatives[ast.FunctionDef]]
_DynamicAliasState = tuple[
    dict[str, frozenset[str]],
    dict[str, frozenset[str]],
    dict[str, frozenset[str]],
    dict[str, str],
    set[str],
    _DynamicGeneratorAliases,
    dict[str, bool],
    _DynamicLambdaAliases,
    _DynamicLiteralIterableAliases,
    _DynamicFunctionAliases,
]


class _DynamicTryNode(Protocol):
    body: list[ast.stmt]
    handlers: list[ast.ExceptHandler]
    orelse: list[ast.stmt]
    finalbody: list[ast.stmt]


def _canonical_dynamic_helper_name(name: str) -> str:
    return {
        "__builtins__.__import__": "__import__",
        "__builtins__.getattr": "getattr",
        "builtins.__import__": "__import__",
        "builtins.getattr": "getattr",
    }.get(name, name)


def redact_manifest_url_reference(value: str) -> str:
    """Return a display-safe URL reference for scan output."""
    parsed = urlparse(value)
    if not parsed.scheme:
        return "[redacted-url]"

    host = parsed.hostname
    if not host:
        return f"{parsed.scheme}://[redacted-url]"

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    try:
        port = parsed.port
    except ValueError:
        port = None

    netloc = f"{host}:{port}" if port else host
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


class TorchServeMarScanner(BaseScanner):
    """Scan TorchServe .mar archives and embedded payloads."""

    name = "torchserve_mar"
    description = "Scans TorchServe .mar archives for insecure handlers and embedded malicious payloads"
    supported_extensions: ClassVar[list[str]] = [".mar"]

    MAX_MANIFEST_BYTES: ClassVar[int] = 1 * 1024 * 1024
    MAX_REQUIREMENTS_TXT_BYTES: ClassVar[int] = 10 * 1024 * 1024
    DEFAULT_MAX_MEMBER_BYTES: ClassVar[int] = 64 * 1024 * 1024
    DEFAULT_MAX_UNCOMPRESSED_BYTES: ClassVar[int] = 512 * 1024 * 1024
    DEFAULT_MAX_ENTRIES: ClassVar[int] = 4096
    DEFAULT_MAX_DEPTH: ClassVar[int] = 3

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config=config)
        self.max_entries = self._get_int_config("max_mar_entries", self.DEFAULT_MAX_ENTRIES, minimum=1)
        self.max_member_bytes = self._get_int_config("max_mar_member_bytes", self.DEFAULT_MAX_MEMBER_BYTES, minimum=1)
        self.max_uncompressed_bytes = self._get_int_config(
            "max_mar_uncompressed_bytes",
            self.DEFAULT_MAX_UNCOMPRESSED_BYTES,
            minimum=1,
        )
        self.max_depth = self._get_int_config("max_mar_depth", self.DEFAULT_MAX_DEPTH, minimum=1)

    def _get_int_config(self, key: str, default: int, minimum: int = 0) -> int:
        """Return an integer config value with bounds and safe fallback."""
        raw_value = self.config.get(key, default)
        try:
            parsed = int(raw_value)
        except (TypeError, ValueError):
            parsed = default
        return max(parsed, minimum)

    @classmethod
    def _normalize_member_name(cls, member_name: str) -> str:
        normalized = member_name.replace("\\", "/").strip()
        while normalized.startswith("./"):
            normalized = normalized[2:]
        normalized = normalized.lstrip("/")
        normalized = re.sub(r"/+", "/", normalized)
        return str(PurePosixPath(normalized))

    @classmethod
    def _member_name_set(cls, archive: zipfile.ZipFile) -> set[str]:
        return {cls._normalize_member_name(name) for name in archive.namelist() if name and not name.endswith("/")}

    @classmethod
    def _build_member_lookup(
        cls,
        member_infos: list[zipfile.ZipInfo],
    ) -> dict[str, list[zipfile.ZipInfo]]:
        member_lookup: dict[str, list[zipfile.ZipInfo]] = {}
        for member_info in member_infos:
            if not member_info.filename or member_info.is_dir():
                continue
            normalized_member = cls._normalize_member_name(member_info.filename)
            member_lookup.setdefault(normalized_member, []).append(member_info)
        return member_lookup

    @staticmethod
    def _build_member_details(
        member_info: zipfile.ZipInfo,
        normalized_member: str,
        **details: Any,
    ) -> dict[str, Any]:
        return {
            **details,
            "zip_entry": normalized_member,
            "zip_entry_id": f"{normalized_member}@{member_info.header_offset}",
        }

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        try:
            from ..utils.file.detection import is_torchserve_mar_archive

            return is_torchserve_mar_archive(path)
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check_result = self._check_size_limit(path)
        if size_check_result:
            return size_check_result

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)
        self.add_file_integrity_check(path, result)

        current_depth = max(
            self._get_int_config("_mar_depth", 0, minimum=0),
            self._get_int_config("_archive_depth", 0, minimum=0),
        )
        if current_depth >= self.max_depth:
            mark_inconclusive_scan_result(result, "torchserve_mar_depth_limit")
            result.add_check(
                name="TorchServe MAR Depth Limit",
                passed=False,
                message=f"Maximum .mar recursion depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "depth": current_depth,
                    "max_depth": self.max_depth,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_mar_depth_limit",
                },
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="TorchServe MAR Depth Limit",
            passed=True,
            message="TorchServe .mar recursion depth is within safe limits",
            location=path,
            details={"depth": current_depth, "max_depth": self.max_depth},
        )

        from .zip_scanner import ZipPreflightRejected, open_preflighted_zip

        try:
            with open_preflighted_zip(path, self.config) as archive:
                member_infos = archive.infolist()
                member_set = self._member_name_set(archive)

                manifest_context = self._parse_manifest(path, archive, member_set, result)
                self._scan_archive_members(
                    archive_path=path,
                    archive=archive,
                    member_infos=member_infos,
                    manifest_context=manifest_context,
                    result=result,
                    current_depth=current_depth,
                )
        except ZipPreflightRejected as exc:
            return exc.result
        except zipfile.BadZipFile:
            result.add_check(
                name="TorchServe MAR Archive Validation",
                passed=False,
                message=f"Not a valid TorchServe .mar archive: {path}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        except Exception as exc:
            mark_inconclusive_scan_result(result, "torchserve_mar_scan_failed")
            result.add_check(
                name="TorchServe MAR Scan",
                passed=False,
                message=f"Error scanning TorchServe .mar archive: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_mar_scan_failed",
                },
            )
            result.finish(success=False)
            return result

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors
        )
        return result

    def _read_member_bounded(
        self,
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> bytes:
        if member_info.file_size > max_bytes:
            raise ValueError(
                f"Archive member {member_info.filename} exceeds size limit ({member_info.file_size} > {max_bytes})",
            )

        data = bytearray()
        with archive.open(member_info, "r") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise ValueError(f"Archive member {member_info.filename} exceeded bounded read limit ({max_bytes})")
        return bytes(data)

    def _extract_member_to_tempfile(
        self,
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        max_bytes: int,
    ) -> tuple[str, int]:
        safe_basename = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(member_info.filename))
        suffix = f"_{safe_basename}" if safe_basename else ".bin"

        temp_path = ""
        total_size = 0
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
                temp_path = temp_file.name
                with archive.open(member_info, "r") as entry_file:
                    while True:
                        chunk = entry_file.read(64 * 1024)
                        if not chunk:
                            break
                        total_size += len(chunk)
                        if total_size > max_bytes:
                            raise ValueError(
                                f"Archive member {member_info.filename} exceeds max allowed bytes ({max_bytes})",
                            )
                        temp_file.write(chunk)
        except Exception:
            if temp_path:
                with contextlib.suppress(OSError):
                    os.unlink(temp_path)
            raise

        return temp_path, total_size

    def _parse_manifest(
        self,
        archive_path: str,
        archive: zipfile.ZipFile,
        member_set: set[str],
        result: ScanResult,
    ) -> dict[str, Any]:
        manifest_context: dict[str, Any] = {
            "handler_paths": [],
            "serialized_paths": [],
            "path_references": [],
        }
        manifest_name = self._normalize_member_name(MANIFEST_ENTRY_PATH)

        all_manifest_infos = [
            info for info in archive.infolist() if self._normalize_member_name(info.filename) == manifest_name
        ]

        if not all_manifest_infos:
            result.add_check(
                name="TorchServe Manifest Presence",
                passed=False,
                message=f"Missing required TorchServe manifest: {MANIFEST_ENTRY_PATH}",
                severity=IssueSeverity.WARNING,
                location=archive_path,
            )
            return manifest_context

        result.add_check(
            name="TorchServe Manifest Presence",
            passed=True,
            message=f"Found required TorchServe manifest: {MANIFEST_ENTRY_PATH}",
            location=archive_path,
        )

        manifest_infos = all_manifest_infos
        if len(all_manifest_infos) > self.max_entries:
            manifest_infos = all_manifest_infos[: self.max_entries]
            mark_inconclusive_scan_result(result, "torchserve_manifest_entry_limit")
            result.add_check(
                name="TorchServe Manifest Entry Limit",
                passed=False,
                message=(
                    "Archive contains "
                    f"{len(all_manifest_infos)} manifest entries, exceeding max processed entries "
                    f"({self.max_entries}); manifest declarations after the entry cap were skipped and "
                    "scan results are incomplete"
                ),
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={
                    "manifest_entry_count": len(all_manifest_infos),
                    "max_entries": self.max_entries,
                    "dropped_manifest_count": len(all_manifest_infos) - self.max_entries,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_manifest_entry_limit",
                },
            )

        manifest_payload_count = 0
        first_manifest_digest: bytes | None = None
        has_conflicting_manifest_payloads = False
        scanned_manifest_count = 0
        processed_manifest_uncompressed = 0
        path_references: list[tuple[str, str]] = []
        handler_paths: list[str] = []
        serialized_paths: list[str] = []
        missing_required: set[str] = set()
        parsed_manifest_count = 0

        for manifest_info in manifest_infos:
            manifest_details = self._build_member_details(
                member_info=manifest_info,
                normalized_member=manifest_name,
                max_manifest_bytes=self.MAX_MANIFEST_BYTES,
            )

            processed_manifest_uncompressed += max(manifest_info.file_size, 0)
            if processed_manifest_uncompressed > self.max_uncompressed_bytes:
                mark_inconclusive_scan_result(result, "torchserve_manifest_uncompressed_budget")
                result.add_check(
                    name="TorchServe Manifest Uncompressed Size Budget",
                    passed=False,
                    message=(
                        "Manifest parsing uncompressed byte budget exceeded "
                        f"({processed_manifest_uncompressed} > {self.max_uncompressed_bytes}); "
                        "later manifest declarations were skipped and scan results are incomplete"
                    ),
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details={
                        "processed_uncompressed": processed_manifest_uncompressed,
                        "max_uncompressed_bytes": self.max_uncompressed_bytes,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "torchserve_manifest_uncompressed_budget",
                    },
                )
                break

            scanned_manifest_count += 1

            try:
                manifest_bytes = self._read_member_bounded(archive, manifest_info, self.MAX_MANIFEST_BYTES)
            except ValueError as exc:
                mark_inconclusive_scan_result(result, "torchserve_manifest_size_limit")
                result.add_check(
                    name="TorchServe Manifest Size Limit",
                    passed=False,
                    message=str(exc),
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details={
                        **manifest_details,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "torchserve_manifest_size_limit",
                    },
                )
                continue
            except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                mark_inconclusive_scan_result(result, "torchserve_manifest_read_failed")
                result.add_check(
                    name="TorchServe Manifest Read",
                    passed=False,
                    message=f"Unable to read TorchServe manifest entry: {exc}",
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details={
                        **manifest_details,
                        "exception_type": type(exc).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "torchserve_manifest_read_failed",
                    },
                )
                continue

            manifest_payload_count += 1
            manifest_digest = hashlib.sha256(manifest_bytes).digest()
            if first_manifest_digest is None:
                first_manifest_digest = manifest_digest
            elif manifest_digest != first_manifest_digest:
                has_conflicting_manifest_payloads = True

            try:
                manifest_data = json.loads(manifest_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                result.add_check(
                    name="TorchServe Manifest JSON Parse",
                    passed=False,
                    message=f"Failed to parse TorchServe manifest JSON: {exc}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details={**manifest_details, "exception_type": type(exc).__name__},
                )
                continue

            if not isinstance(manifest_data, dict):
                result.add_check(
                    name="TorchServe Manifest Structure",
                    passed=False,
                    message="TorchServe manifest must be a JSON object",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details=manifest_details,
                )
                continue

            parsed_manifest_count += 1
            (
                manifest_path_references,
                manifest_handler_paths,
                manifest_serialized_paths,
                manifest_missing_required,
            ) = self._collect_manifest_references(manifest_data)
            path_references.extend(manifest_path_references)
            handler_paths.extend(manifest_handler_paths)
            serialized_paths.extend(manifest_serialized_paths)
            missing_required.update(manifest_missing_required)

        if scanned_manifest_count > 1 and (
            parsed_manifest_count != scanned_manifest_count
            or manifest_payload_count != scanned_manifest_count
            or has_conflicting_manifest_payloads
        ):
            result.add_check(
                name="TorchServe Manifest Collision",
                passed=False,
                message="Archive contains multiple conflicting TorchServe manifest entries",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={
                    "manifest_entries": [
                        self._build_member_details(
                            member_info=manifest_info,
                            normalized_member=manifest_name,
                        )
                        for manifest_info in manifest_infos[:scanned_manifest_count]
                    ],
                    "parsed_manifest_count": parsed_manifest_count,
                    "scanned_manifest_count": scanned_manifest_count,
                },
            )

        if parsed_manifest_count == 0:
            return manifest_context

        path_references = list(dict.fromkeys(path_references))
        handler_paths = list(dict.fromkeys(handler_paths))
        serialized_paths = list(dict.fromkeys(serialized_paths))

        manifest_context["path_references"] = path_references
        manifest_context["handler_paths"] = handler_paths
        manifest_context["serialized_paths"] = serialized_paths

        if missing_required:
            result.add_check(
                name="TorchServe Manifest Required Fields",
                passed=False,
                message=f"TorchServe manifest is missing required field(s): {', '.join(sorted(missing_required))}",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={"missing_fields": sorted(missing_required)},
            )
        else:
            result.add_check(
                name="TorchServe Manifest Required Fields",
                passed=True,
                message="TorchServe manifest includes required fields",
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={"required_fields": ["model", "handler", "serializedFile"]},
            )

        self._validate_manifest_paths(
            archive_path=archive_path,
            path_references=path_references,
            member_set=member_set,
            result=result,
        )
        manifest_context["handler_trees"] = self._analyze_handlers(
            archive_path=archive_path,
            archive=archive,
            member_set=member_set,
            handler_paths=handler_paths,
            result=result,
        )

        return manifest_context

    def _collect_manifest_references(
        self,
        manifest_data: dict[str, Any],
    ) -> tuple[list[tuple[str, str]], list[str], list[str], set[str]]:
        path_references: list[tuple[str, str]] = []
        handler_paths: list[str] = []
        serialized_paths: list[str] = []

        model_section = manifest_data.get("model")
        model_dict = model_section if isinstance(model_section, dict) else {}
        missing_required: set[str] = set()

        if model_section is None:
            missing_required.add("model")

        if isinstance(model_section, str):
            path_references.append(("model", model_section))

        model_candidates = []
        if isinstance(model_dict, dict):
            model_candidates.extend(self._coerce_string_list(model_dict.get("model")))
            model_candidates.extend(self._coerce_string_list(model_dict.get("modelFile")))

        for model_path in model_candidates:
            path_references.append(("model", model_path))

        handler_candidates = []
        if isinstance(model_dict, dict):
            handler_candidates.extend(self._coerce_string_list(model_dict.get("handler")))
        handler_candidates.extend(self._coerce_string_list(manifest_data.get("handler")))
        if not handler_candidates:
            missing_required.add("handler")
        for handler_path in handler_candidates:
            path_references.append(("handler", handler_path))
            handler_paths.append(handler_path)

        serialized_candidates = []
        if isinstance(model_dict, dict):
            serialized_candidates.extend(self._coerce_string_list(model_dict.get("serializedFile")))
        serialized_candidates.extend(self._coerce_string_list(manifest_data.get("serializedFile")))
        if not serialized_candidates:
            missing_required.add("serializedFile")
        for serialized_path in serialized_candidates:
            path_references.append(("serializedFile", serialized_path))
            serialized_paths.append(serialized_path)

        extra_files = None
        if isinstance(model_dict, dict):
            extra_files = model_dict.get("extraFiles")
        if extra_files is None:
            extra_files = manifest_data.get("extraFiles")
        for extra_path in self._parse_extra_files(extra_files):
            path_references.append(("extraFiles", extra_path))

        return path_references, handler_paths, serialized_paths, missing_required

    def _coerce_string_list(self, value: Any) -> list[str]:
        if isinstance(value, str):
            stripped = value.strip()
            return [stripped] if stripped else []
        if isinstance(value, list):
            collected = []
            for item in value:
                if isinstance(item, str):
                    stripped = item.strip()
                    if stripped:
                        collected.append(stripped)
            return collected
        return []

    def _parse_extra_files(self, value: Any) -> list[str]:
        if isinstance(value, str):
            return [entry.strip() for entry in value.split(",") if entry.strip()]
        if isinstance(value, list):
            entries = []
            for item in value:
                if isinstance(item, str) and item.strip():
                    entries.append(item.strip())
            return entries
        return []

    def _is_path_like_reference(self, field: str, value: str) -> bool:
        normalized = value.replace("\\", "/").strip()
        suffix = PurePosixPath(normalized).suffix

        if field == "handler":
            return normalized.endswith(".py") or "/" in normalized or "\\" in value

        if field in {"serializedFile", "extraFiles"}:
            return True

        return bool(suffix) or "/" in normalized or "\\" in value

    def _resolve_handler_member_candidates(self, handler_reference: str) -> list[str]:
        """Resolve handler references to concrete archive member candidates."""
        normalized = handler_reference.replace("\\", "/").strip()
        if not normalized:
            return []

        reference_base = normalized.split(":", 1)[0].strip()
        if not reference_base:
            return []

        normalized_member = self._normalize_member_name(reference_base)
        if PurePosixPath(normalized_member).suffix:
            return [normalized_member]

        module_path = normalized_member.replace(".", "/").rstrip("/")
        if not module_path:
            return []

        return [
            self._normalize_member_name(f"{module_path}.py"),
            self._normalize_member_name(f"{module_path}/__init__.py"),
        ]

    def _validate_manifest_paths(
        self,
        archive_path: str,
        path_references: list[tuple[str, str]],
        member_set: set[str],
        result: ScanResult,
    ) -> None:
        missing_members: list[dict[str, str]] = []
        invalid_paths: list[dict[str, str]] = []
        url_like_paths: list[dict[str, str]] = []

        for field, reference in path_references:
            value = reference.strip()
            if not value:
                continue

            if URL_SCHEME_PATTERN.match(value):
                url_like_paths.append({"field": field, "value": redact_manifest_url_reference(value)})
                continue

            if is_absolute_archive_path(value):
                invalid_paths.append({"field": field, "value": value, "reason": "absolute_path"})
                continue

            _resolved, safe = sanitize_archive_path(value, tempfile.gettempdir())
            if not safe:
                invalid_paths.append({"field": field, "value": value, "reason": "path_traversal"})
                continue

            candidate_members = (
                self._resolve_handler_member_candidates(value)
                if field == "handler"
                else [self._normalize_member_name(value)]
                if self._is_path_like_reference(field, value)
                else []
            )
            if candidate_members and not any(candidate in member_set for candidate in candidate_members):
                missing_record = {"field": field, "value": value}
                if field == "handler":
                    missing_record["candidates"] = ", ".join(candidate_members)
                missing_members.append(missing_record)

        if invalid_paths:
            for invalid in invalid_paths:
                severity = IssueSeverity.CRITICAL if invalid["field"] == "handler" else IssueSeverity.WARNING
                result.add_check(
                    name="TorchServe Manifest Path Validation",
                    passed=False,
                    message=(f"Manifest {invalid['field']} reference points outside archive root: {invalid['value']}"),
                    severity=severity,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details=invalid,
                )
        else:
            result.add_check(
                name="TorchServe Manifest Path Validation",
                passed=True,
                message="Manifest file references stay within archive root",
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
            )

        if url_like_paths:
            result.add_check(
                name="TorchServe Manifest URL Reference Check",
                passed=False,
                message="Manifest contains URL-like references in local-only file fields",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={"references": url_like_paths},
            )
        else:
            result.add_check(
                name="TorchServe Manifest URL Reference Check",
                passed=True,
                message="Manifest local-only file fields do not contain URL-like references",
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
            )

        if missing_members:
            result.add_check(
                name="TorchServe Manifest Reference Integrity",
                passed=False,
                message="Manifest references file(s) not present in the archive",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={"missing_references": missing_members},
            )
        else:
            result.add_check(
                name="TorchServe Manifest Reference Integrity",
                passed=True,
                message="Manifest file references resolve to archive members",
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
            )

    def _analyze_handlers(
        self,
        archive_path: str,
        archive: zipfile.ZipFile,
        member_set: set[str],
        handler_paths: list[str],
        result: ScanResult,
    ) -> dict[str, list[ast.Module]]:
        analyzed_handler = False
        handler_trees: dict[str, list[ast.Module]] = {}
        member_lookup = self._build_member_lookup(archive.infolist())
        processed_handler_entries = 0
        processed_handler_uncompressed = 0
        handler_budget_exceeded = False

        for handler_path in handler_paths:
            if handler_budget_exceeded:
                break
            resolved_candidates = self._resolve_handler_member_candidates(handler_path)
            normalized_handlers = [
                candidate
                for candidate in dict.fromkeys(resolved_candidates)
                if candidate in member_set and candidate.endswith(".py")
            ]
            if not normalized_handlers:
                continue

            for normalized_handler in normalized_handlers:
                if handler_budget_exceeded:
                    break
                handler_infos = member_lookup.get(normalized_handler, [])
                if not handler_infos:
                    continue

                for handler_info in handler_infos:
                    if processed_handler_entries >= self.max_entries:
                        mark_inconclusive_scan_result(result, "torchserve_handler_entry_limit")
                        result.add_check(
                            name="TorchServe Handler Entry Limit",
                            passed=False,
                            message=(
                                "Handler static analysis reached the max processed entry budget "
                                f"({self.max_entries}); later handler files were skipped and scan results "
                                "are incomplete"
                            ),
                            severity=IssueSeverity.INFO,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                "processed_handler_entries": processed_handler_entries,
                                "max_entries": self.max_entries,
                                "skipped_handler": normalized_handler,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": "torchserve_handler_entry_limit",
                            },
                        )
                        handler_budget_exceeded = True
                        break

                    processed_handler_entries += 1
                    processed_handler_uncompressed += max(handler_info.file_size, 0)
                    if processed_handler_uncompressed > self.max_uncompressed_bytes:
                        mark_inconclusive_scan_result(result, "torchserve_handler_uncompressed_budget")
                        result.add_check(
                            name="TorchServe Handler Uncompressed Size Budget",
                            passed=False,
                            message=(
                                "Handler static analysis uncompressed byte budget exceeded "
                                f"({processed_handler_uncompressed} > {self.max_uncompressed_bytes}); "
                                "later handler files were skipped and scan results are incomplete"
                            ),
                            severity=IssueSeverity.INFO,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                "processed_uncompressed": processed_handler_uncompressed,
                                "max_uncompressed_bytes": self.max_uncompressed_bytes,
                                "handler": normalized_handler,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": "torchserve_handler_uncompressed_budget",
                            },
                        )
                        handler_budget_exceeded = True
                        break

                    analyzed_handler = True
                    handler_details = self._build_member_details(
                        member_info=handler_info,
                        normalized_member=normalized_handler,
                        handler=normalized_handler,
                    )
                    try:
                        handler_bytes = self._read_member_bounded(archive, handler_info, self.max_member_bytes)
                    except ValueError as exc:
                        mark_inconclusive_scan_result(result, "torchserve_handler_size_limit")
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=str(exc),
                            severity=IssueSeverity.INFO,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                **handler_details,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": "torchserve_handler_size_limit",
                            },
                        )
                        continue
                    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                        mark_inconclusive_scan_result(result, "torchserve_handler_read_failed")
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=f"Unable to read handler source for static analysis: {exc}",
                            severity=IssueSeverity.INFO,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                **handler_details,
                                "analysis_kind": "read",
                                "exception_type": type(exc).__name__,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": "torchserve_handler_read_failed",
                            },
                        )
                        continue

                    tree, parse_error = self._parse_python_source(handler_bytes)
                    if parse_error is not None:
                        mark_inconclusive_scan_result(result, "torchserve_handler_parse_failed")
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=f"Unable to parse handler source for static analysis: {parse_error}",
                            severity=IssueSeverity.INFO,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                **handler_details,
                                "analysis_kind": "syntax",
                                "analysis_incomplete": True,
                                "scan_outcome_reason": "torchserve_handler_parse_failed",
                            },
                        )
                        continue
                    assert tree is not None
                    handler_trees.setdefault(normalized_handler, []).append(tree)

                    risky_calls = self._find_high_risk_calls_from_tree(tree)
                    if risky_calls:
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=(
                                f"Handler contains high-risk execution primitives: {', '.join(sorted(risky_calls))}"
                            ),
                            severity=IssueSeverity.CRITICAL,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                **handler_details,
                                "risky_calls": sorted(risky_calls),
                            },
                        )
                    else:
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=True,
                            message="Handler source does not contain high-risk execution primitives",
                            location=f"{archive_path}:{normalized_handler}",
                            details=handler_details,
                        )

        if not analyzed_handler and handler_paths:
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=True,
                message="No Python handler files found for static analysis",
                location=archive_path,
            )

        return handler_trees

    def _resolve_handler_members(self, member_set: set[str], handler_paths: list[str]) -> set[str]:
        resolved_handlers: set[str] = set()
        for handler_path in handler_paths:
            resolved_candidates = self._resolve_handler_member_candidates(handler_path)
            for candidate in resolved_candidates:
                normalized_candidate = self._normalize_member_name(candidate)
                if normalized_candidate in member_set and normalized_candidate.endswith(".py"):
                    resolved_handlers.add(normalized_candidate)
        return resolved_handlers

    def _resolve_import_from_module(
        self,
        importing_member: str | None,
        level: int,
        module: str | None,
    ) -> str | None:
        if level == 0:
            return module
        if importing_member is None:
            # Relative imports need the importing module's package path for resolution.
            return None

        package_parts = [part for part in PurePosixPath(importing_member).parent.parts if part not in {"", "."}]
        trim = level - 1
        if trim > len(package_parts):
            return None
        base_parts = package_parts[: len(package_parts) - trim]
        if module:
            base_parts.extend(part for part in module.split(".") if part)
        if not base_parts:
            return None
        return ".".join(base_parts)

    def _collect_imported_modules(self, tree: ast.AST, importing_member: str | None = None) -> set[str]:
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name:
                        modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                base_module = self._resolve_import_from_module(importing_member, node.level, node.module)
                if not base_module:
                    continue
                modules.add(base_module)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    modules.add(f"{base_module}.{alias.name}")
        return modules

    def _is_safe_import_time_value(self, value: ast.expr | None, aliases: dict[str, str]) -> bool:
        if value is None:
            return True
        try:
            ast.literal_eval(value)
            return True
        except Exception:
            pass

        if not isinstance(value, ast.Call):
            return False

        call_name = self._resolve_call_name(value.func)
        if call_name is None:
            return False

        resolved_name = self._apply_alias(call_name, aliases)
        if resolved_name not in SAFE_IMPORT_TIME_CALLS:
            return False

        return sum(1 for node in ast.walk(value) if isinstance(node, ast.Call)) == 1

    def _is_safe_import_time_assignment(
        self,
        node: ast.Assign | ast.AnnAssign,
        aliases: dict[str, str],
    ) -> bool:
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value = node.value
        else:
            targets = [node.target]
            value = node.value

        def _is_simple_name_target(target: ast.expr) -> bool:
            if isinstance(target, ast.Name):
                return True
            if isinstance(target, (ast.Tuple, ast.List)):
                return all(_is_simple_name_target(elt) for elt in target.elts)
            return False

        if not targets or not all(_is_simple_name_target(target) for target in targets):
            return False
        return self._is_safe_import_time_value(value, aliases)

    def _is_non_executing_import_guard(
        self,
        node: ast.If,
        aliases: dict[str, str] | None = None,
        shadowed_names: set[str] | None = None,
    ) -> bool:
        test = node.test
        guard_name = self._resolve_call_name(test)
        aliases = aliases or {}
        shadowed_names = shadowed_names or set()
        if guard_name is not None and guard_name.split(".", maxsplit=1)[0] not in shadowed_names:
            resolved_guard_name = self._apply_alias(guard_name, aliases)
            if resolved_guard_name == "typing.TYPE_CHECKING" or (
                guard_name in {"TYPE_CHECKING", "typing.TYPE_CHECKING"} and guard_name not in aliases
            ):
                return True
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
        ):
            pairs = ((test.left, test.comparators[0]), (test.comparators[0], test.left))
            return any(
                isinstance(left, ast.Name)
                and left.id == "__name__"
                and isinstance(right, ast.Constant)
                and right.value == "__main__"
                for left, right in pairs
            )
        return False

    def _has_import_time_execution(self, tree: ast.Module) -> bool:
        aliases: dict[str, str] = {}
        shadowed_names: set[str] = set()
        static_truthiness_bindings: dict[str, bool] = {}

        def statements_have_import_time_execution(statements: list[ast.stmt]) -> bool:
            for node in statements:
                if (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    # Module docstring.
                    continue
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    # Bare module metadata constants do not execute code.
                    continue
                if isinstance(node, ast.Pass):
                    continue
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        binding_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                        aliases[binding_name] = alias.name if alias.asname else binding_name
                        shadowed_names.discard(binding_name)
                        static_truthiness_bindings.pop(binding_name, None)
                    continue
                if isinstance(node, ast.ImportFrom):
                    if node.module is not None:
                        for alias in node.names:
                            if alias.name == "*":
                                continue
                            binding_name = alias.asname or alias.name
                            if node.level:
                                aliases.pop(binding_name, None)
                                shadowed_names.add(binding_name)
                                static_truthiness_bindings.pop(binding_name, None)
                                continue
                            aliases[binding_name] = f"{node.module}.{alias.name}"
                            shadowed_names.discard(binding_name)
                            static_truthiness_bindings.pop(binding_name, None)
                    continue
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                    aliases.pop(node.name, None)
                    shadowed_names.add(node.name)
                    static_truthiness_bindings.pop(node.name, None)
                    continue
                if isinstance(node, ast.Assign | ast.AnnAssign):
                    is_safe_assignment = self._is_safe_import_time_assignment(node, aliases)
                    assignment_value = node.value
                    assignment_truthiness = (
                        self._static_truthiness(assignment_value) if assignment_value is not None else None
                    )
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for binding_name in self._target_binding_names(target):
                            aliases.pop(binding_name, None)
                            shadowed_names.add(binding_name)
                            if assignment_truthiness is None:
                                static_truthiness_bindings.pop(binding_name, None)
                            else:
                                static_truthiness_bindings[binding_name] = assignment_truthiness
                    if is_safe_assignment:
                        continue
                if (
                    isinstance(node, ast.If)
                    and isinstance(node.test, ast.Name)
                    and node.test.id in static_truthiness_bindings
                ):
                    selected_branch = node.body if static_truthiness_bindings[node.test.id] is True else node.orelse
                    if statements_have_import_time_execution(selected_branch):
                        return True
                    continue
                if isinstance(node, ast.If) and self._is_non_executing_import_guard(
                    node,
                    aliases,
                    shadowed_names,
                ):
                    if statements_have_import_time_execution(node.orelse):
                        return True
                    continue
                return True
            return False

        return statements_have_import_time_execution(tree.body)

    def _analyze_non_handler_python_files(
        self,
        archive_path: str,
        archive: zipfile.ZipFile,
        member_lookup: dict[str, list[zipfile.ZipInfo]],
        handler_members: set[str],
        handler_trees: dict[str, list[ast.Module]],
        result: ScanResult,
    ) -> None:
        python_members = sorted(name for name in member_lookup if name.endswith(".py"))
        non_handler_members = [name for name in python_members if name not in handler_members]

        if not non_handler_members:
            result.add_check(
                name="MAR Non-Handler Python Analysis",
                passed=True,
                message="No non-handler Python files found in archive",
                location=archive_path,
            )
            return

        relationships: list[dict[str, str]] = []
        relationship_keys: set[tuple[str, str, str]] = set()
        non_handler_set = set(non_handler_members)
        non_handler_findings = 0

        for member_name in non_handler_members:
            for member_info in member_lookup[member_name]:
                member_details = self._build_member_details(
                    member_info=member_info,
                    normalized_member=member_name,
                    member=member_name,
                )
                try:
                    source_bytes = self._read_member_bounded(archive, member_info, self.max_member_bytes)
                except ValueError as exc:
                    mark_inconclusive_scan_result(result, "torchserve_non_handler_python_size_limit")
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=str(exc),
                        severity=IssueSeverity.INFO,
                        location=f"{archive_path}:{member_name}",
                        details={
                            **member_details,
                            "analysis_kind": "bounded_read",
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "torchserve_non_handler_python_size_limit",
                        },
                    )
                    continue
                except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                    mark_inconclusive_scan_result(result, "torchserve_non_handler_python_read_failed")
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=f"Unable to read non-handler Python source for static analysis: {exc}",
                        severity=IssueSeverity.INFO,
                        location=f"{archive_path}:{member_name}",
                        details={
                            **member_details,
                            "analysis_kind": "read",
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "torchserve_non_handler_python_read_failed",
                        },
                    )
                    continue

                tree, parse_error = self._parse_python_source(source_bytes)
                if parse_error is not None:
                    mark_inconclusive_scan_result(result, "torchserve_non_handler_python_parse_failed")
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=f"Unable to parse non-handler Python source for static analysis: {parse_error}",
                        severity=IssueSeverity.INFO,
                        location=f"{archive_path}:{member_name}",
                        details={
                            **member_details,
                            "analysis_kind": "syntax",
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "torchserve_non_handler_python_parse_failed",
                        },
                    )
                    continue

                assert tree is not None
                risky_calls = self._find_high_risk_calls_from_tree(tree)
                has_import_time_execution = self._has_import_time_execution(tree)
                is_init_module = member_name.endswith("/__init__.py") or member_name == "__init__.py"

                if risky_calls or has_import_time_execution:
                    non_handler_findings += 1
                    finding_reasons: list[str] = []
                    if risky_calls:
                        finding_reasons.append(f"high-risk calls: {', '.join(sorted(risky_calls))}")
                    if has_import_time_execution:
                        finding_reasons.append("module-level code executes at import time")
                    if is_init_module:
                        finding_reasons.append("__init__.py executes during package import")

                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=f"Non-handler Python file is risky ({'; '.join(finding_reasons)})",
                        severity=IssueSeverity.WARNING,
                        location=f"{archive_path}:{member_name}",
                        details={
                            **member_details,
                            "risky_calls": sorted(risky_calls),
                            "has_import_time_execution": has_import_time_execution,
                            "is_init_module": is_init_module,
                        },
                    )
                else:
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=True,
                        message="Non-handler Python source has no high-risk calls or import-time execution",
                        location=f"{archive_path}:{member_name}",
                        details=member_details,
                    )

        for handler_member in sorted(handler_members):
            candidate_trees = list(handler_trees.get(handler_member, []))
            if not candidate_trees:
                for handler_info in member_lookup.get(handler_member, []):
                    try:
                        handler_source = self._read_member_bounded(archive, handler_info, self.max_member_bytes)
                    except (
                        SyntaxError,
                        ValueError,
                        OSError,
                        RuntimeError,
                        zipfile.BadZipFile,
                        zipfile.LargeZipFile,
                    ):
                        continue

                    handler_tree, parse_error = self._parse_python_source(handler_source)
                    if parse_error is None and handler_tree is not None:
                        candidate_trees.append(handler_tree)

            for handler_tree in candidate_trees:
                for module_name in sorted(self._collect_imported_modules(handler_tree, handler_member)):
                    module_path = module_name.replace(".", "/")
                    for candidate in (f"{module_path}.py", f"{module_path}/__init__.py"):
                        normalized_candidate = self._normalize_member_name(candidate)
                        relationship_key = (handler_member, module_name, normalized_candidate)
                        if normalized_candidate in non_handler_set and relationship_key not in relationship_keys:
                            relationship_keys.add(relationship_key)
                            relationships.append(
                                {
                                    "handler": handler_member,
                                    "imported_module": module_name,
                                    "resolved_member": normalized_candidate,
                                },
                            )

        if relationships:
            result.add_check(
                name="MAR Non-Handler Python Analysis",
                passed=(non_handler_findings == 0),
                message="Analyzed non-handler Python files and mapped handler import relationships",
                severity=IssueSeverity.WARNING if non_handler_findings else IssueSeverity.INFO,
                location=archive_path,
                details={
                    "non_handler_python_files": non_handler_members,
                    "import_relationships": relationships,
                },
            )

    def _collect_import_aliases(self, tree: ast.AST) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return aliases

    def _resolve_call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._resolve_call_name(node.value)
            if parent is None:
                return None
            return f"{parent}.{node.attr}"
        return None

    def _apply_alias(self, call_name: str, aliases: dict[str, str]) -> str:
        head, *tail = call_name.split(".")
        resolved_head = aliases.get(head, head)
        if not tail:
            return resolved_head
        return ".".join([resolved_head, *tail])

    def _apply_unshadowed_alias(self, call_name: str, aliases: dict[str, str], shadowed_names: set[str]) -> str:
        """Apply a file-level import alias unless the current scope has rebound its root name."""
        if call_name.split(".", maxsplit=1)[0] in shadowed_names:
            return call_name
        return self._apply_alias(call_name, aliases)

    def _resolve_getattr_call_name(self, node: ast.AST, aliases: dict[str, str]) -> str | None:
        if isinstance(node, ast.Attribute) and node.attr == "__call__":
            return self._resolve_getattr_call_name(node.value, aliases)

        if not isinstance(node, ast.Call):
            return None

        helper_name = self._resolve_call_name(node.func)
        if helper_name is None:
            return None

        resolved_helper_name = self._apply_alias(helper_name, aliases)
        if resolved_helper_name not in {"getattr", "builtins.getattr"}:
            return None

        target_root_node: ast.AST | None = node.args[0] if node.args else None
        attr_name_node: ast.AST | None = node.args[1] if len(node.args) >= 2 else None
        for keyword in node.keywords:
            if keyword.arg == "object" and target_root_node is None:
                target_root_node = keyword.value
            elif keyword.arg == "name" and attr_name_node is None:
                attr_name_node = keyword.value

        if target_root_node is None or attr_name_node is None:
            return None

        target_root = self._resolve_call_name(target_root_node)
        if target_root is None:
            return None

        if not isinstance(attr_name_node, ast.Constant) or not isinstance(attr_name_node.value, str):
            return None

        resolved_target_root = self._apply_alias(target_root, aliases)
        return f"{resolved_target_root}.{attr_name_node.value}"

    def _parse_python_source(self, source_bytes: bytes) -> tuple[ast.Module | None, str | None]:
        try:
            source = source_bytes.decode("utf-8")
        except UnicodeDecodeError:
            source = source_bytes.decode("utf-8", errors="replace")

        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError) as exc:
            return None, str(exc)

        return tree, None

    def _find_high_risk_calls_from_tree(self, tree: ast.AST) -> set[str]:
        risky_calls = {call.name for call in high_risk_python_calls_in_tree(tree)}
        risky_calls.update(self._find_dynamic_import_execution_calls(tree))
        return risky_calls

    @classmethod
    def _static_string_value(cls, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Subscript):
            selected_value = cls._literal_subscript_value(node)
            if selected_value is not None:
                return cls._static_string_value(selected_value)
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    return None
                parts.append(value.value)
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = cls._static_string_value(node.left)
            right = cls._static_string_value(node.right)
            if left is not None and right is not None:
                return f"{left}{right}"
        return None

    @staticmethod
    def _static_truthiness(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set | ast.Dict):
            return TorchServeMarScanner._static_iterable_truthiness(node)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            operand_truthiness = TorchServeMarScanner._static_truthiness(node.operand)
            return None if operand_truthiness is None else not operand_truthiness
        if isinstance(node, ast.BoolOp):
            value_truthiness = [TorchServeMarScanner._static_truthiness(value) for value in node.values]
            if isinstance(node.op, ast.And):
                if False in value_truthiness:
                    return False
                if all(value is True for value in value_truthiness):
                    return True
            elif isinstance(node.op, ast.Or):
                if True in value_truthiness:
                    return True
                if all(value is False for value in value_truthiness):
                    return False
        if isinstance(node, ast.IfExp):
            test_truthiness = TorchServeMarScanner._static_truthiness(node.test)
            if test_truthiness is True:
                return TorchServeMarScanner._static_truthiness(node.body)
            if test_truthiness is False:
                return TorchServeMarScanner._static_truthiness(node.orelse)
            body_truthiness = TorchServeMarScanner._static_truthiness(node.body)
            orelse_truthiness = TorchServeMarScanner._static_truthiness(node.orelse)
            if body_truthiness == orelse_truthiness:
                return body_truthiness
        return None

    @staticmethod
    def _static_iterable_truthiness(node: ast.AST) -> bool | None:
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            has_unknown_unpack = False
            for element in node.elts:
                if not isinstance(element, ast.Starred):
                    return True
                unpacked_truthiness = TorchServeMarScanner._static_iterable_truthiness(element.value)
                if unpacked_truthiness is True:
                    return True
                has_unknown_unpack |= unpacked_truthiness is None
            return None if has_unknown_unpack else False
        if isinstance(node, ast.Dict):
            has_unknown_unpack = False
            for key, value in zip(node.keys, node.values, strict=True):
                if key is not None:
                    return True
                unpacked_truthiness = TorchServeMarScanner._static_iterable_truthiness(value)
                if unpacked_truthiness is True:
                    return True
                has_unknown_unpack |= unpacked_truthiness is None
            return None if has_unknown_unpack else False
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            return bool(node.value)
        return None

    @staticmethod
    def _target_binding_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, ast.Starred):
            return TorchServeMarScanner._target_binding_names(target.value)
        if isinstance(target, ast.Tuple | ast.List):
            return {
                name
                for child_target in target.elts
                for name in TorchServeMarScanner._target_binding_names(child_target)
            }
        return set()

    @staticmethod
    def _callable_local_binding_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    ) -> set[str]:
        """Return names Python treats as local bindings in a callable body."""

        class LocalBindingVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.bound_names: set[str] = set()
                self.global_names: set[str] = set()
                self.nonlocal_names: set[str] = set()

            def _bind_target(self, target: ast.AST) -> None:
                if isinstance(target, ast.Name):
                    self.bound_names.add(target.id)
                elif isinstance(target, ast.Starred):
                    self._bind_target(target.value)
                elif isinstance(target, ast.Tuple | ast.List):
                    for child_target in target.elts:
                        self._bind_target(child_target)

            def visit_Global(self, declaration: ast.Global) -> None:
                self.global_names.update(declaration.names)

            def visit_Nonlocal(self, declaration: ast.Nonlocal) -> None:
                self.nonlocal_names.update(declaration.names)

            def visit_Assign(self, assignment: ast.Assign) -> None:
                self.visit(assignment.value)
                for target in assignment.targets:
                    self._bind_target(target)

            def visit_AnnAssign(self, assignment: ast.AnnAssign) -> None:
                self._bind_target(assignment.target)
                self.visit(assignment.annotation)
                if assignment.value is not None:
                    self.visit(assignment.value)

            def visit_AugAssign(self, assignment: ast.AugAssign) -> None:
                self._bind_target(assignment.target)
                self.visit(assignment.value)

            def visit_NamedExpr(self, expression: ast.NamedExpr) -> None:
                self.visit(expression.value)
                self._bind_target(expression.target)

            def _visit_for_binding(self, loop: ast.For | ast.AsyncFor) -> None:
                self.visit(loop.iter)
                self._bind_target(loop.target)
                for statement in [*loop.body, *loop.orelse]:
                    self.visit(statement)

            def visit_For(self, loop: ast.For) -> None:
                self._visit_for_binding(loop)

            def visit_AsyncFor(self, loop: ast.AsyncFor) -> None:
                self._visit_for_binding(loop)

            def _visit_with_binding(self, context: ast.With | ast.AsyncWith) -> None:
                for item in context.items:
                    self.visit(item.context_expr)
                    if item.optional_vars is not None:
                        self._bind_target(item.optional_vars)
                for statement in context.body:
                    self.visit(statement)

            def visit_With(self, context: ast.With) -> None:
                self._visit_with_binding(context)

            def visit_AsyncWith(self, context: ast.AsyncWith) -> None:
                self._visit_with_binding(context)

            def visit_Import(self, import_node: ast.Import) -> None:
                for alias in import_node.names:
                    self.bound_names.add(alias.asname or alias.name.split(".", maxsplit=1)[0])

            def visit_ImportFrom(self, import_node: ast.ImportFrom) -> None:
                for alias in import_node.names:
                    if alias.name != "*":
                        self.bound_names.add(alias.asname or alias.name)

            def visit_ExceptHandler(self, handler: ast.ExceptHandler) -> None:
                if handler.type is not None:
                    self.visit(handler.type)
                if handler.name is not None:
                    self.bound_names.add(handler.name)
                for statement in handler.body:
                    self.visit(statement)

            def visit_Delete(self, delete_node: ast.Delete) -> None:
                for target in delete_node.targets:
                    self._bind_target(target)

            def _bind_pattern(self, pattern: ast.pattern) -> None:
                if isinstance(pattern, ast.MatchAs):
                    if pattern.pattern is not None:
                        self._bind_pattern(pattern.pattern)
                    if pattern.name is not None:
                        self.bound_names.add(pattern.name)
                elif isinstance(pattern, ast.MatchStar):
                    if pattern.name is not None:
                        self.bound_names.add(pattern.name)
                elif isinstance(pattern, ast.MatchMapping):
                    for child_pattern in pattern.patterns:
                        self._bind_pattern(child_pattern)
                    if pattern.rest is not None:
                        self.bound_names.add(pattern.rest)
                elif isinstance(pattern, ast.MatchSequence | ast.MatchOr):
                    for child_pattern in pattern.patterns:
                        self._bind_pattern(child_pattern)
                elif isinstance(pattern, ast.MatchClass):
                    for child_pattern in [*pattern.patterns, *pattern.kwd_patterns]:
                        self._bind_pattern(child_pattern)

            def visit_Match(self, match_node: ast.Match) -> None:
                self.visit(match_node.subject)
                for case in match_node.cases:
                    self._bind_pattern(case.pattern)
                    if case.guard is not None:
                        self.visit(case.guard)
                    for statement in case.body:
                        self.visit(statement)

            def visit_FunctionDef(self, function: ast.FunctionDef) -> None:
                self.bound_names.add(function.name)

            def visit_AsyncFunctionDef(self, function: ast.AsyncFunctionDef) -> None:
                self.bound_names.add(function.name)

            def visit_ClassDef(self, class_node: ast.ClassDef) -> None:
                self.bound_names.add(class_node.name)

            def visit_Lambda(self, node: ast.Lambda) -> None:
                return

        collector = LocalBindingVisitor()
        if isinstance(node, ast.Lambda):
            collector.visit(node.body)
        else:
            for statement in node.body:
                collector.visit(statement)
        return collector.bound_names - collector.global_names - collector.nonlocal_names

    @staticmethod
    def _callable_declaration_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[set[str], set[str]]:
        class DeclarationVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.global_names: set[str] = set()
                self.nonlocal_names: set[str] = set()

            def visit_Global(self, declaration: ast.Global) -> None:
                self.global_names.update(declaration.names)

            def visit_Nonlocal(self, declaration: ast.Nonlocal) -> None:
                self.nonlocal_names.update(declaration.names)

            def visit_FunctionDef(self, function: ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(self, function: ast.AsyncFunctionDef) -> None:
                return

            def visit_ClassDef(self, class_node: ast.ClassDef) -> None:
                return

            def visit_Lambda(self, lambda_node: ast.Lambda) -> None:
                return

        visitor = DeclarationVisitor()
        for statement in node.body:
            visitor.visit(statement)
        return visitor.global_names, visitor.nonlocal_names

    @staticmethod
    def _callable_return_values(node: ast.FunctionDef) -> list[ast.expr]:
        if len(node.body) != 1 or not isinstance(node.body[0], ast.Return) or node.body[0].value is None:
            return []
        return [node.body[0].value]

    @classmethod
    def _expanded_literal_call_arguments(cls, arguments: list[ast.expr]) -> list[ast.expr] | None:
        expanded_arguments: list[ast.expr] = []
        for argument in arguments:
            if not isinstance(argument, ast.Starred):
                expanded_arguments.append(argument)
                continue
            if not isinstance(argument.value, ast.List | ast.Tuple):
                return None
            nested_arguments = cls._expanded_literal_call_arguments(list(argument.value.elts))
            if nested_arguments is None:
                return None
            expanded_arguments.extend(nested_arguments)
        return expanded_arguments

    @classmethod
    def _literal_keyword_mapping(cls, node: ast.AST) -> dict[str, ast.expr] | None:
        if not isinstance(node, ast.Dict):
            return None
        mapping: dict[str, ast.expr] = {}
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                nested_mapping = cls._literal_keyword_mapping(value)
                if nested_mapping is None:
                    return None
                mapping.update(nested_mapping)
                continue
            key_name = cls._static_string_value(key)
            if key_name is None:
                return None
            mapping[key_name] = value
        return mapping

    @classmethod
    def _expanded_literal_call_keywords(
        cls,
        keywords: list[ast.keyword],
    ) -> list[tuple[str, ast.expr]] | None:
        expanded_keywords: list[tuple[str, ast.expr]] = []
        for keyword in keywords:
            if keyword.arg is not None:
                expanded_keywords.append((keyword.arg, keyword.value))
                continue
            unpacked_keywords = cls._literal_keyword_mapping(keyword.value)
            if unpacked_keywords is None:
                return None
            expanded_keywords.extend(unpacked_keywords.items())
        return expanded_keywords

    @staticmethod
    def _static_integer_value(node: ast.AST) -> int | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.UAdd | ast.USub)
            and isinstance(node.operand, ast.Constant)
            and isinstance(node.operand.value, int)
        ):
            value = int(node.operand.value)
            return value if isinstance(node.op, ast.UAdd) else -value
        return None

    @classmethod
    def _literal_subscript_value(cls, node: ast.Subscript) -> ast.expr | None:
        if isinstance(node.value, ast.List | ast.Tuple):
            if any(isinstance(element, ast.Starred) for element in node.value.elts):
                return None
            index = cls._static_integer_value(node.slice)
            if index is None:
                return None
            try:
                return node.value.elts[index]
            except IndexError:
                return None
        if isinstance(node.value, ast.Dict):
            key_name = cls._static_string_value(node.slice)
            key_integer = cls._static_integer_value(node.slice)
            for key, value in reversed(list(zip(node.value.keys, node.value.values, strict=True))):
                if key is None:
                    return None
                if key_name is not None and cls._static_string_value(key) == key_name:
                    return value
                if key_integer is not None and cls._static_integer_value(key) == key_integer:
                    return value
        return None

    def _module_names_for_import_helpers(
        self,
        node: ast.Call,
        import_helpers: frozenset[str],
    ) -> frozenset[str]:
        if not import_helpers:
            return frozenset()

        module_names: set[str] = set()
        for resolved_helper_name in import_helpers:
            helper_parameters = (
                ("name", "globals", "locals", "fromlist", "level")
                if resolved_helper_name in {"__import__", "builtins.__import__"}
                else ("name", "package")
            )
            expanded_args = self._expanded_literal_call_arguments(node.args)
            if expanded_args is None or len(expanded_args) > len(helper_parameters):
                continue
            expanded_keywords = self._expanded_literal_call_keywords(node.keywords)
            if expanded_keywords is None:
                continue
            arguments_by_name = dict(zip(helper_parameters, expanded_args, strict=False))
            valid_call = True
            for keyword_name, keyword_value in expanded_keywords:
                if keyword_name not in helper_parameters or keyword_name in arguments_by_name:
                    valid_call = False
                    break
                arguments_by_name[keyword_name] = keyword_value
            if not valid_call:
                continue

            module_arg = arguments_by_name.get("name")
            if module_arg is None:
                continue
            module_name = self._static_string_value(module_arg)
            if not module_name:
                continue

            if resolved_helper_name in {"__import__", "builtins.__import__"}:
                level_node = arguments_by_name.get("level")
                if level_node is not None and self._static_integer_value(level_node) != 0:
                    continue

            fromlist_node = arguments_by_name.get("fromlist")
            fromlist_truthiness = self._static_truthiness(fromlist_node) if fromlist_node is not None else False
            if resolved_helper_name not in {"__import__", "builtins.__import__"} or fromlist_truthiness is True:
                module_names.add(module_name)
            elif fromlist_truthiness is False:
                module_names.add(module_name.split(".", maxsplit=1)[0])
            else:
                module_names.update({module_name, module_name.split(".", maxsplit=1)[0]})
        return frozenset(module_names)

    def _dynamic_import_module_names(
        self,
        node: ast.AST,
        aliases: dict[str, str],
        import_loader_aliases: dict[str, frozenset[str]],
        shadowed_names: set[str],
    ) -> frozenset[str]:
        if not isinstance(node, ast.Call):
            return frozenset()

        helper_node = node.func
        while True:
            if isinstance(helper_node, ast.NamedExpr):
                helper_node = helper_node.value
                continue
            if isinstance(helper_node, ast.Subscript):
                selected_helper = self._literal_subscript_value(helper_node)
                if selected_helper is not None:
                    helper_node = selected_helper
                    continue
            break
        helper_name = self._resolve_call_name(helper_node)
        if helper_name is None:
            return frozenset()

        resolved_helper_names = import_loader_aliases.get(helper_name)
        if resolved_helper_names is None:
            if helper_name.split(".", maxsplit=1)[0] in shadowed_names:
                return frozenset()
            resolved_helper_names = frozenset({self._apply_alias(helper_name, aliases)})
        resolved_helper_names = frozenset(
            _canonical_dynamic_helper_name(resolved_helper_name) for resolved_helper_name in resolved_helper_names
        )
        return self._module_names_for_import_helpers(node, resolved_helper_names & _DYNAMIC_IMPORT_HELPERS)

    def _resolve_dynamic_import_roots(
        self,
        node: ast.AST,
        aliases: dict[str, str],
        module_aliases: dict[str, frozenset[str]],
        import_loader_aliases: dict[str, frozenset[str]],
        shadowed_names: set[str],
    ) -> frozenset[str]:
        if isinstance(node, ast.Name):
            return module_aliases.get(node.id, frozenset())
        if isinstance(node, ast.NamedExpr):
            return self._resolve_dynamic_import_roots(
                node.value,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
        if isinstance(node, ast.Subscript):
            selected_value = self._literal_subscript_value(node)
            if selected_value is not None:
                return self._resolve_dynamic_import_roots(
                    selected_value,
                    aliases,
                    module_aliases,
                    import_loader_aliases,
                    shadowed_names,
                )
            container_name = self._resolve_call_name(node.value)
            key_name = self._static_string_value(node.slice)
            if container_name is not None and key_name is not None:
                mapped_name = f"{container_name}.{key_name}"
                if mapped_name in module_aliases:
                    return module_aliases[mapped_name]
        if isinstance(node, ast.Attribute):
            attribute_name = self._resolve_call_name(node)
            if attribute_name is not None and attribute_name in module_aliases:
                return module_aliases[attribute_name]
            parents = self._resolve_dynamic_import_roots(
                node.value,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
            if parents:
                return frozenset(f"{parent}.{node.attr}" for parent in parents)

        module_names = self._dynamic_import_module_names(node, aliases, import_loader_aliases, shadowed_names)
        if module_names:
            return module_names
        if isinstance(node, ast.Call):
            factory_roots = self._resolve_dynamic_import_roots(
                node.func,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
            if isinstance(node.func, ast.Call):
                factory_roots |= self._resolve_dynamic_import_getattr_roots(
                    node.func,
                    aliases,
                    module_aliases,
                    import_loader_aliases,
                    shadowed_names,
                )
            retained_roots = set(self._module_names_for_import_helpers(node, factory_roots & _DYNAMIC_IMPORT_HELPERS))
            retained_roots.update(root for root in factory_roots if root == "webbrowser.get")
            if "ctypes.LibraryLoader" in factory_roots:
                dlltype_node: ast.AST | None = node.args[0] if node.args else None
                for keyword in node.keywords:
                    if keyword.arg == "dlltype" and dlltype_node is None:
                        dlltype_node = keyword.value
                if dlltype_node is not None:
                    dlltype_roots = self._resolve_dynamic_import_roots(
                        dlltype_node,
                        aliases,
                        module_aliases,
                        import_loader_aliases,
                        shadowed_names,
                    )
                    if dlltype_roots & (_CTYPES_LIBRARY_LOADER_TYPES | _CTYPES_LIBRARY_LOADER_TYPE_ALIASES):
                        retained_roots.add(_CTYPES_LIBRARY_LOADER_INSTANCE_ROOT)
            return frozenset(retained_roots)
        return frozenset()

    def _resolve_dynamic_import_getattr_calls(
        self,
        node: ast.Call,
        aliases: dict[str, str],
        module_aliases: dict[str, frozenset[str]],
        import_loader_aliases: dict[str, frozenset[str]],
        shadowed_names: set[str],
    ) -> frozenset[str]:
        roots = self._resolve_dynamic_import_getattr_roots(
            node,
            aliases,
            module_aliases,
            import_loader_aliases,
            shadowed_names,
        )
        return frozenset(
            call_name for root in roots if (call_name := _normalized_high_risk_python_call_name(root)) is not None
        )

    def _resolve_dynamic_namespace_mapping_roots(
        self,
        node: ast.AST,
        aliases: dict[str, str],
        module_aliases: dict[str, frozenset[str]],
        import_loader_aliases: dict[str, frozenset[str]],
        shadowed_names: set[str],
    ) -> frozenset[str]:
        target_node: ast.AST | None = None
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            target_node = node.value
        elif isinstance(node, ast.Call):
            helper_name = self._resolve_call_name(node.func)
            resolved_helper_name = (
                self._apply_unshadowed_alias(helper_name, aliases, shadowed_names)
                if helper_name is not None and helper_name.split(".", maxsplit=1)[0] not in shadowed_names
                else None
            )
            expanded_args = self._expanded_literal_call_arguments(node.args)
            if (
                resolved_helper_name in _DYNAMIC_NAMESPACE_HELPERS
                and expanded_args is not None
                and len(expanded_args) == 1
                and not node.keywords
            ):
                target_node = expanded_args[0]
        if target_node is None:
            return frozenset()

        module_names = self._resolve_dynamic_import_roots(
            target_node,
            aliases,
            module_aliases,
            import_loader_aliases,
            shadowed_names,
        )
        target_name = self._resolve_call_name(target_node)
        if (
            target_name is not None
            and target_name.split(".", maxsplit=1)[0] not in shadowed_names
            and target_name.split(".", maxsplit=1)[0] in aliases
        ):
            module_names |= frozenset({self._apply_alias(target_name, aliases)})
        return module_names

    def _resolve_dynamic_import_getattr_roots(
        self,
        node: ast.Call,
        aliases: dict[str, str],
        module_aliases: dict[str, frozenset[str]],
        import_loader_aliases: dict[str, frozenset[str]],
        shadowed_names: set[str],
    ) -> frozenset[str]:
        helper_name = self._resolve_call_name(node.func)
        if helper_name is not None:
            if helper_name.split(".", maxsplit=1)[0] in shadowed_names:
                return frozenset()
            resolved_helper_names = frozenset({self._apply_alias(helper_name, aliases)})
        else:
            resolved_helper_names = self._resolve_dynamic_import_roots(
                node.func,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
        if not resolved_helper_names & _DYNAMIC_GETATTR_HELPERS:
            return frozenset()
        expanded_args = self._expanded_literal_call_arguments(node.args)
        if expanded_args is None or len(expanded_args) not in {2, 3} or node.keywords:
            return frozenset()

        target_node = expanded_args[0]
        attr_node = expanded_args[1]

        module_names = self._resolve_dynamic_import_roots(
            target_node,
            aliases,
            module_aliases,
            import_loader_aliases,
            shadowed_names,
        )
        target_name = self._resolve_call_name(target_node)
        if (
            target_name is not None
            and target_name.split(".", maxsplit=1)[0] not in shadowed_names
            and target_name.split(".", maxsplit=1)[0] in aliases
        ):
            module_names |= frozenset({self._apply_alias(target_name, aliases)})
        attr_name = self._static_string_value(attr_node)
        resolved_roots = (
            frozenset(f"{module_name}.{attr_name}" for module_name in module_names)
            if module_names and attr_name is not None
            else frozenset()
        )
        attribute_is_known_present = (
            bool(module_names)
            and attr_name is not None
            and all(
                attr_name in _DYNAMIC_KNOWN_MODULE_ATTRIBUTES.get(module_name, frozenset())
                for module_name in module_names
            )
        )
        if len(expanded_args) == 3 and not attribute_is_known_present:
            resolved_roots |= self._resolve_dynamic_import_roots(
                expanded_args[2],
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
        return resolved_roots

    def _resolve_dynamic_import_execution_calls(
        self,
        node: ast.AST,
        aliases: dict[str, str],
        module_aliases: dict[str, frozenset[str]],
        callable_aliases: dict[str, frozenset[str]],
        import_loader_aliases: dict[str, frozenset[str]],
        shadowed_names: set[str],
    ) -> frozenset[str]:
        if isinstance(node, ast.Name):
            call_names = set(callable_aliases.get(node.id, frozenset()))
            if node.id not in shadowed_names:
                resolved_name = self._apply_alias(node.id, aliases)
                if normalized_name := _normalized_high_risk_python_call_name(resolved_name):
                    call_names.add(normalized_name)
            return frozenset(call_names)

        if isinstance(node, ast.NamedExpr):
            return self._resolve_dynamic_import_execution_calls(
                node.value,
                aliases,
                module_aliases,
                callable_aliases,
                import_loader_aliases,
                shadowed_names,
            )

        if isinstance(node, ast.Attribute):
            attribute_name = self._resolve_call_name(node)
            direct_call_names = set(callable_aliases.get(attribute_name, frozenset())) if attribute_name else set()
            if (
                attribute_name is not None
                and attribute_name not in shadowed_names
                and attribute_name.split(".", maxsplit=1)[0] not in shadowed_names
            ):
                resolved_name = self._apply_alias(attribute_name, aliases)
                if normalized_name := _normalized_high_risk_python_call_name(resolved_name):
                    direct_call_names.add(normalized_name)
            if node.attr == "__call__":
                direct_call_names.update(
                    self._resolve_dynamic_import_execution_calls(
                        node.value,
                        aliases,
                        module_aliases,
                        callable_aliases,
                        import_loader_aliases,
                        shadowed_names,
                    )
                )
            module_names = self._resolve_dynamic_import_roots(
                node.value,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
            direct_call_names.update(
                call_name
                for module_name in module_names
                if (
                    call_name := _normalized_high_risk_python_call_name(
                        f"{module_name}.<dynamic>"
                        if module_name == _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT
                        and node.attr in {"LoadLibrary", "__getitem__"}
                        else f"{module_name}.{node.attr}"
                    )
                )
                is not None
            )
            return frozenset(direct_call_names)

        if isinstance(node, ast.Subscript):
            selected_value = self._literal_subscript_value(node)
            if selected_value is not None:
                return self._resolve_dynamic_import_execution_calls(
                    selected_value,
                    aliases,
                    module_aliases,
                    callable_aliases,
                    import_loader_aliases,
                    shadowed_names,
                )
            container_name = self._resolve_call_name(node.value)
            key_name = self._static_string_value(node.slice)
            if container_name is not None and key_name is not None:
                mapped_name = f"{container_name}.{key_name}"
                if mapped_name in callable_aliases:
                    return callable_aliases[mapped_name]
            namespace_module_names = self._resolve_dynamic_namespace_mapping_roots(
                node.value,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
            attr_name = self._static_string_value(node.slice)
            if namespace_module_names and attr_name is not None:
                return frozenset(
                    call_name
                    for module_name in namespace_module_names
                    if (call_name := _normalized_high_risk_python_call_name(f"{module_name}.{attr_name}")) is not None
                )
            module_names = self._resolve_dynamic_import_roots(
                node.value,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )
            return frozenset(
                call_name
                for module_name in module_names
                if (
                    call_name := _normalized_high_risk_python_call_name(
                        f"{module_name}.<dynamic>"
                        if module_name == _CTYPES_LIBRARY_LOADER_INSTANCE_ROOT
                        else f"{module_name}.__getitem__"
                    )
                )
                is not None
            )

        if isinstance(node, ast.Call):
            call_names = set(
                self._resolve_dynamic_import_getattr_calls(
                    node,
                    aliases,
                    module_aliases,
                    import_loader_aliases,
                    shadowed_names,
                )
            )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                expanded_args = self._expanded_literal_call_arguments(node.args)
                if expanded_args is not None and len(expanded_args) in {1, 2} and not node.keywords:
                    module_names = self._resolve_dynamic_namespace_mapping_roots(
                        node.func.value,
                        aliases,
                        module_aliases,
                        import_loader_aliases,
                        shadowed_names,
                    )
                    attr_name = self._static_string_value(expanded_args[0])
                    if attr_name is not None:
                        call_names.update(
                            call_name
                            for module_name in module_names
                            if (call_name := _normalized_high_risk_python_call_name(f"{module_name}.{attr_name}"))
                            is not None
                        )
                    if len(expanded_args) == 2:
                        call_names.update(
                            self._resolve_dynamic_import_execution_calls(
                                expanded_args[1],
                                aliases,
                                module_aliases,
                                callable_aliases,
                                import_loader_aliases,
                                shadowed_names,
                            )
                        )
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "__getattribute__"
                and len(node.args) == 1
                and not node.keywords
            ):
                module_names = self._resolve_dynamic_import_roots(
                    node.func.value,
                    aliases,
                    module_aliases,
                    import_loader_aliases,
                    shadowed_names,
                )
                attr_name = self._static_string_value(node.args[0])
                if attr_name is not None:
                    call_names.update(
                        call_name
                        for module_name in module_names
                        if (call_name := _normalized_high_risk_python_call_name(f"{module_name}.{attr_name}"))
                        is not None
                    )
            return frozenset(call_names)

        return frozenset()

    def _find_dynamic_import_execution_calls(self, tree: ast.AST) -> set[str]:
        scanner = self

        class DynamicImportExecutionVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.module_alias_stack: list[dict[str, frozenset[str]]] = [{}]
                self.callable_alias_stack: list[dict[str, frozenset[str]]] = [{}]
                self.import_loader_alias_stack: list[dict[str, frozenset[str]]] = [{}]
                self.import_alias_stack: list[dict[str, str]] = [{}]
                self.shadowed_name_stack: list[set[str]] = [set()]
                self.lazy_generator_alias_stack: list[_DynamicGeneratorAliases] = [{}]
                self.static_truthiness_alias_stack: list[dict[str, bool]] = [{}]
                self.lambda_alias_stack: list[_DynamicLambdaAliases] = [{}]
                self.literal_iterable_alias_stack: list[_DynamicLiteralIterableAliases] = [{}]
                self.scope_kind_stack: list[str] = ["module"]
                self.local_binding_name_stack: list[set[str]] = [set()]
                self.function_definition_stack: list[_DynamicFunctionAliases] = [{}]
                self.function_definition_states: dict[int, _DynamicAliasState] = {}
                self.class_parent_state_stack: list[_DynamicAliasState] = []
                self.class_name_stack: list[str] = []
                self.class_attribute_states: dict[str, _DynamicAliasState] = {}
                self.function_binding_state_stack: list[_DynamicAliasState] = []
                self.loop_break_state_stack: list[list[_DynamicAliasState]] = []
                self.try_exception_state_stack: list[list[_DynamicAliasState]] = []
                self.active_generator_ids: set[int] = set()
                self.active_lambda_ids: set[int] = set()
                self.active_lambda_return_ids: set[int] = set()
                self.active_function_ids: set[int] = set()
                self.active_function_return_ids: set[int] = set()
                self.called_function_global_persistence_stack: list[bool] = []
                self.risky_calls: set[str] = set()
                self.collecting_module_bindings = False
                self.collecting_class_attribute_bindings = False
                self.scope_depth = 0
                self.module_binding_state: _DynamicAliasState | None = None
                self.postponed_annotations = isinstance(tree, ast.Module) and any(
                    isinstance(statement, ast.ImportFrom)
                    and statement.module == "__future__"
                    and any(alias.name == "annotations" for alias in statement.names)
                    for statement in tree.body
                )
                self.post_definition_class_attributes: set[str] = set()
                if isinstance(tree, ast.Module):
                    defined_classes: set[str] = set()
                    for statement in tree.body:
                        if isinstance(statement, ast.ClassDef):
                            defined_classes.add(statement.name)
                            continue
                        targets: list[ast.AST] = []
                        if isinstance(statement, ast.Assign):
                            targets.extend(statement.targets)
                        elif isinstance(statement, ast.AnnAssign | ast.AugAssign):
                            targets.append(statement.target)
                        for target in targets:
                            target_name = scanner._resolve_call_name(target)
                            if target_name is not None and target_name.split(".", maxsplit=1)[0] in defined_classes:
                                self.post_definition_class_attributes.add(target_name)

            @property
            def module_aliases(self) -> dict[str, frozenset[str]]:
                return self.module_alias_stack[-1]

            @property
            def callable_aliases(self) -> dict[str, frozenset[str]]:
                return self.callable_alias_stack[-1]

            @property
            def import_loader_aliases(self) -> dict[str, frozenset[str]]:
                return self.import_loader_alias_stack[-1]

            @property
            def import_aliases(self) -> dict[str, str]:
                return self.import_alias_stack[-1]

            @property
            def shadowed_names(self) -> set[str]:
                return self.shadowed_name_stack[-1]

            @property
            def lazy_generator_aliases(self) -> _DynamicGeneratorAliases:
                return self.lazy_generator_alias_stack[-1]

            @property
            def static_truthiness_aliases(self) -> dict[str, bool]:
                return self.static_truthiness_alias_stack[-1]

            @property
            def lambda_aliases(self) -> _DynamicLambdaAliases:
                return self.lambda_alias_stack[-1]

            @property
            def literal_iterable_aliases(self) -> _DynamicLiteralIterableAliases:
                return self.literal_iterable_alias_stack[-1]

            @property
            def function_definitions(self) -> _DynamicFunctionAliases:
                return self.function_definition_stack[-1]

            def _snapshot_state(self) -> _DynamicAliasState:
                return (
                    dict(self.module_aliases),
                    dict(self.callable_aliases),
                    dict(self.import_loader_aliases),
                    dict(self.import_aliases),
                    set(self.shadowed_names),
                    dict(self.lazy_generator_aliases),
                    dict(self.static_truthiness_aliases),
                    dict(self.lambda_aliases),
                    dict(self.literal_iterable_aliases),
                    dict(self.function_definitions),
                )

            def _restore_state(self, state: _DynamicAliasState) -> None:
                self.module_alias_stack[-1] = dict(state[0])
                self.callable_alias_stack[-1] = dict(state[1])
                self.import_loader_alias_stack[-1] = dict(state[2])
                self.import_alias_stack[-1] = dict(state[3])
                self.shadowed_name_stack[-1] = set(state[4])
                self.lazy_generator_alias_stack[-1] = dict(state[5])
                self.static_truthiness_alias_stack[-1] = dict(state[6])
                self.lambda_alias_stack[-1] = dict(state[7])
                self.literal_iterable_alias_stack[-1] = dict(state[8])
                self.function_definition_stack[-1] = dict(state[9])

            @staticmethod
            def _merge_possible_aliases(
                left: dict[str, frozenset[str]],
                right: dict[str, frozenset[str]],
            ) -> dict[str, frozenset[str]]:
                return {
                    name: left.get(name, frozenset()) | right.get(name, frozenset())
                    for name in left.keys() | right.keys()
                }

            @staticmethod
            def _merge_import_aliases(left: dict[str, str], right: dict[str, str]) -> dict[str, str]:
                merged: dict[str, str] = {}
                for name in left.keys() | right.keys():
                    left_value = left.get(name)
                    right_value = right.get(name)
                    if (
                        left_value is not None
                        and right_value is not None
                        and _canonical_dynamic_helper_name(left_value) == _canonical_dynamic_helper_name(right_value)
                    ):
                        merged[name] = _canonical_dynamic_helper_name(left_value)
                    elif left_value == right_value:
                        if left_value is not None:
                            merged[name] = left_value
                    elif left_value is None:
                        if right_value is not None:
                            merged[name] = right_value
                    elif right_value is None:
                        merged[name] = left_value
                return merged

            @staticmethod
            def _merge_generator_aliases(
                left: _DynamicGeneratorAliases,
                right: _DynamicGeneratorAliases,
            ) -> _DynamicGeneratorAliases:
                merged: _DynamicGeneratorAliases = {}
                for name in left.keys() | right.keys():
                    alternatives = _merge_dynamic_ast_alternatives(left.get(name), right.get(name))
                    if alternatives:
                        merged[name] = alternatives
                return merged

            @staticmethod
            def _merge_lambda_aliases(
                left: _DynamicLambdaAliases,
                right: _DynamicLambdaAliases,
            ) -> _DynamicLambdaAliases:
                merged: _DynamicLambdaAliases = {}
                for name in left.keys() | right.keys():
                    alternatives = _merge_dynamic_ast_alternatives(left.get(name), right.get(name))
                    if alternatives:
                        merged[name] = alternatives
                return merged

            @staticmethod
            def _merge_literal_iterable_aliases(
                left: _DynamicLiteralIterableAliases,
                right: _DynamicLiteralIterableAliases,
            ) -> _DynamicLiteralIterableAliases:
                merged: _DynamicLiteralIterableAliases = {}
                for name in left.keys() | right.keys():
                    alternatives = _merge_dynamic_ast_alternatives(left.get(name), right.get(name))
                    if alternatives:
                        merged[name] = alternatives
                return merged

            @staticmethod
            def _merge_function_aliases(
                left: _DynamicFunctionAliases,
                right: _DynamicFunctionAliases,
            ) -> _DynamicFunctionAliases:
                merged: _DynamicFunctionAliases = {}
                for name in left.keys() | right.keys():
                    alternatives = _merge_dynamic_ast_alternatives(left.get(name), right.get(name))
                    if alternatives:
                        merged[name] = alternatives
                return merged

            @staticmethod
            def _merge_static_truthiness_aliases(
                left: dict[str, bool],
                right: dict[str, bool],
            ) -> dict[str, bool]:
                return {name: left[name] for name in left.keys() & right.keys() if left[name] is right[name]}

            def _merge_states(
                self,
                left: _DynamicAliasState,
                right: _DynamicAliasState,
            ) -> _DynamicAliasState:
                return (
                    self._merge_possible_aliases(left[0], right[0]),
                    self._merge_possible_aliases(left[1], right[1]),
                    self._merge_possible_aliases(left[2], right[2]),
                    self._merge_import_aliases(left[3], right[3]),
                    left[4] & right[4],
                    self._merge_generator_aliases(left[5], right[5]),
                    self._merge_static_truthiness_aliases(left[6], right[6]),
                    self._merge_lambda_aliases(left[7], right[7]),
                    self._merge_literal_iterable_aliases(left[8], right[8]),
                    self._merge_function_aliases(left[9], right[9]),
                )

            def _merge_state_list(self, states: list[_DynamicAliasState]) -> _DynamicAliasState:
                merged_state = states[0]
                for state in states[1:]:
                    merged_state = self._merge_states(merged_state, state)
                return merged_state

            def _push_scope(
                self,
                parameters: set[str],
                inherited_state: _DynamicAliasState | None = None,
                scope_kind: str = "function",
            ) -> None:
                state = inherited_state or self._snapshot_state()
                self.module_alias_stack.append(dict(state[0]))
                self.callable_alias_stack.append(dict(state[1]))
                self.import_loader_alias_stack.append(dict(state[2]))
                self.import_alias_stack.append(dict(state[3]))
                self.shadowed_name_stack.append(set(state[4]))
                self.lazy_generator_alias_stack.append(dict(state[5]))
                self.static_truthiness_alias_stack.append(dict(state[6]))
                self.lambda_alias_stack.append(dict(state[7]))
                self.literal_iterable_alias_stack.append(dict(state[8]))
                self.scope_kind_stack.append(scope_kind)
                self.local_binding_name_stack.append(set(parameters))
                self.function_definition_stack.append(dict(state[9]))
                self.scope_depth += 1
                for parameter in parameters:
                    self._invalidate_name(parameter)

            def _inherit_class_attribute_bindings(self, receiver_name: str | None) -> None:
                if receiver_name is None or not self.class_name_stack:
                    return
                attribute_state = self.class_attribute_states.get(self.class_name_stack[-1])
                if attribute_state is None:
                    return

                def receiver_attribute_name(name: str) -> str:
                    suffix = name.split(".", maxsplit=1)[1] if "." in name else name
                    return f"{receiver_name}.{suffix}"

                for source_name, values in attribute_state[0].items():
                    target_name = receiver_attribute_name(source_name)
                    self.module_aliases[target_name] = self.module_aliases.get(target_name, frozenset()) | values
                    self.shadowed_names.discard(target_name)
                for source_name, values in attribute_state[1].items():
                    target_name = receiver_attribute_name(source_name)
                    self.callable_aliases[target_name] = self.callable_aliases.get(target_name, frozenset()) | values
                    self.shadowed_names.discard(target_name)
                for source_name, values in attribute_state[2].items():
                    target_name = receiver_attribute_name(source_name)
                    self.import_loader_aliases[target_name] = (
                        self.import_loader_aliases.get(target_name, frozenset()) | values
                    )
                    self.shadowed_names.discard(target_name)
                for source_name, value in attribute_state[3].items():
                    target_name = receiver_attribute_name(source_name)
                    existing_value = self.import_aliases.get(target_name)
                    if existing_value is None or existing_value == value:
                        self.import_aliases[target_name] = value
                        self.shadowed_names.discard(target_name)
                    else:
                        self.import_aliases.pop(target_name, None)
                for source_name, generators in attribute_state[5].items():
                    target_name = receiver_attribute_name(source_name)
                    alternatives = _merge_dynamic_ast_alternatives(
                        self.lazy_generator_aliases.get(target_name),
                        generators,
                    )
                    if alternatives:
                        self.lazy_generator_aliases[target_name] = alternatives
                    self.shadowed_names.discard(target_name)
                for source_name, truthiness_value in attribute_state[6].items():
                    target_name = receiver_attribute_name(source_name)
                    existing_truthiness = self.static_truthiness_aliases.get(target_name)
                    if existing_truthiness is None or existing_truthiness is truthiness_value:
                        self.static_truthiness_aliases[target_name] = truthiness_value
                        self.shadowed_names.discard(target_name)
                    else:
                        self.static_truthiness_aliases.pop(target_name, None)
                for source_name, lambda_nodes in attribute_state[7].items():
                    target_name = receiver_attribute_name(source_name)
                    lambda_alternatives = _merge_dynamic_ast_alternatives(
                        self.lambda_aliases.get(target_name),
                        lambda_nodes,
                    )
                    if lambda_alternatives:
                        self.lambda_aliases[target_name] = lambda_alternatives
                    self.shadowed_names.discard(target_name)
                for source_name, iterable_nodes in attribute_state[8].items():
                    target_name = receiver_attribute_name(source_name)
                    iterable_alternatives = _merge_dynamic_ast_alternatives(
                        self.literal_iterable_aliases.get(target_name),
                        iterable_nodes,
                    )
                    if iterable_alternatives:
                        self.literal_iterable_aliases[target_name] = iterable_alternatives
                    self.shadowed_names.discard(target_name)

            def _pop_scope(self) -> None:
                self.module_alias_stack.pop()
                self.callable_alias_stack.pop()
                self.import_loader_alias_stack.pop()
                self.import_alias_stack.pop()
                self.shadowed_name_stack.pop()
                self.lazy_generator_alias_stack.pop()
                self.static_truthiness_alias_stack.pop()
                self.lambda_alias_stack.pop()
                self.literal_iterable_alias_stack.pop()
                self.scope_kind_stack.pop()
                self.local_binding_name_stack.pop()
                self.function_definition_stack.pop()
                self.scope_depth -= 1

            @staticmethod
            def _parameter_names(args: ast.arguments) -> set[str]:
                parameters: set[str] = set()
                positional_args = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                parameters.update(arg.arg for arg in positional_args)
                if args.vararg is not None:
                    parameters.add(args.vararg.arg)
                if args.kwarg is not None:
                    parameters.add(args.kwarg.arg)
                return parameters

            @staticmethod
            def _parameter_default_bindings(args: ast.arguments) -> list[tuple[str, ast.expr]]:
                positional_args = [*args.posonlyargs, *args.args]
                positional_defaults = zip(
                    positional_args[len(positional_args) - len(args.defaults) :],
                    args.defaults,
                    strict=True,
                )
                keyword_defaults = (
                    (arg.arg, default)
                    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
                    if default is not None
                )
                return [
                    *((arg.arg, default) for arg, default in positional_defaults),
                    *keyword_defaults,
                ]

            def _callable_inherited_state(self) -> _DynamicAliasState:
                if self.scope_kind_stack[-1] == "module":
                    inherited_state = self.module_binding_state or self._snapshot_state()
                elif self.scope_kind_stack[-1] == "class":
                    inherited_state = self.class_parent_state_stack[-1]
                elif self.scope_kind_stack[-1] == "function":
                    inherited_state = self.function_binding_state_stack[-1]
                else:
                    inherited_state = self._snapshot_state()
                return (*inherited_state[:9], dict(self.function_definitions))

            def _record_class_attribute_binding(self, name: str, *, replace: bool = False) -> None:
                if not self.class_name_stack:
                    return
                state = self.class_attribute_states.setdefault(
                    self.class_name_stack[-1],
                    ({}, {}, {}, {}, set(), {}, {}, {}, {}, {}),
                )
                if replace:
                    names_to_replace = {
                        candidate_name
                        for candidate_name in (
                            state[0].keys()
                            | state[1].keys()
                            | state[2].keys()
                            | state[3].keys()
                            | state[5].keys()
                            | state[6].keys()
                            | state[7].keys()
                            | state[8].keys()
                            | state[9].keys()
                        )
                        if candidate_name == name or candidate_name.startswith(f"{name}.")
                    }
                    for candidate_name in names_to_replace | {name}:
                        state[0].pop(candidate_name, None)
                        state[1].pop(candidate_name, None)
                        state[2].pop(candidate_name, None)
                        state[3].pop(candidate_name, None)
                        state[5].pop(candidate_name, None)
                        state[6].pop(candidate_name, None)
                        state[7].pop(candidate_name, None)
                        state[8].pop(candidate_name, None)
                        state[9].pop(candidate_name, None)
                if name in self.module_aliases:
                    state[0][name] = state[0].get(name, frozenset()) | self.module_aliases[name]
                if name in self.callable_aliases:
                    state[1][name] = state[1].get(name, frozenset()) | self.callable_aliases[name]
                if name in self.import_loader_aliases:
                    state[2][name] = state[2].get(name, frozenset()) | self.import_loader_aliases[name]
                if name in self.import_aliases:
                    existing_alias = state[3].get(name)
                    if existing_alias is None or existing_alias == self.import_aliases[name]:
                        state[3][name] = self.import_aliases[name]
                    else:
                        state[3].pop(name, None)
                if name in self.lazy_generator_aliases:
                    alternatives = _merge_dynamic_ast_alternatives(
                        state[5].get(name),
                        self.lazy_generator_aliases[name],
                    )
                    if alternatives:
                        state[5][name] = alternatives
                if name in self.static_truthiness_aliases:
                    existing_truthiness = state[6].get(name)
                    if existing_truthiness is None or existing_truthiness is self.static_truthiness_aliases[name]:
                        state[6][name] = self.static_truthiness_aliases[name]
                    else:
                        state[6].pop(name, None)
                if name in self.lambda_aliases:
                    lambda_alternatives = _merge_dynamic_ast_alternatives(
                        state[7].get(name),
                        self.lambda_aliases[name],
                    )
                    if lambda_alternatives:
                        state[7][name] = lambda_alternatives
                if name in self.literal_iterable_aliases:
                    iterable_alternatives = _merge_dynamic_ast_alternatives(
                        state[8].get(name),
                        self.literal_iterable_aliases[name],
                    )
                    if iterable_alternatives:
                        state[8][name] = iterable_alternatives
                if name in self.function_definitions:
                    function_alternatives = _merge_dynamic_ast_alternatives(
                        state[9].get(name),
                        self.function_definitions[name],
                    )
                    if function_alternatives:
                        state[9][name] = function_alternatives

            def _seed_class_attribute_bindings(
                self,
                class_name: str,
                source_state: _DynamicAliasState,
            ) -> None:
                state = self.class_attribute_states.setdefault(
                    class_name,
                    ({}, {}, {}, {}, set(), {}, {}, {}, {}, {}),
                )
                prefix = f"{class_name}."
                for name, module_values in source_state[0].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[0][name] = module_values
                for name, callable_values in source_state[1].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[1][name] = callable_values
                for name, loader_values in source_state[2].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[2][name] = loader_values
                for name, import_value in source_state[3].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[3][name] = import_value
                for name, generator_values in source_state[5].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[5][name] = generator_values
                for name, truthiness_value in source_state[6].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[6][name] = truthiness_value
                for name, lambda_values in source_state[7].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[7][name] = lambda_values
                for name, iterable_values in source_state[8].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[8][name] = iterable_values
                for name, function_values in source_state[9].items():
                    if name.startswith(prefix) and name in self.post_definition_class_attributes:
                        state[9][name] = function_values

            def _resolved_static_truthiness(self, node: ast.AST) -> bool | None:
                if isinstance(node, ast.Name):
                    return self.static_truthiness_aliases.get(node.id)
                if isinstance(node, ast.Call) and scanner._dynamic_import_module_names(
                    node,
                    self.import_aliases,
                    self.import_loader_aliases,
                    self.shadowed_names,
                ):
                    return True
                if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                    operand_truthiness = self._resolved_static_truthiness(node.operand)
                    return None if operand_truthiness is None else not operand_truthiness
                if isinstance(node, ast.BoolOp):
                    value_truthiness = [self._resolved_static_truthiness(value) for value in node.values]
                    if isinstance(node.op, ast.And):
                        if False in value_truthiness:
                            return False
                        if all(value is True for value in value_truthiness):
                            return True
                    elif isinstance(node.op, ast.Or):
                        if True in value_truthiness:
                            return True
                        if all(value is False for value in value_truthiness):
                            return False
                    return None
                if isinstance(node, ast.IfExp):
                    test_truthiness = self._resolved_static_truthiness(node.test)
                    if test_truthiness is True:
                        return self._resolved_static_truthiness(node.body)
                    if test_truthiness is False:
                        return self._resolved_static_truthiness(node.orelse)
                    body_truthiness = self._resolved_static_truthiness(node.body)
                    orelse_truthiness = self._resolved_static_truthiness(node.orelse)
                    if body_truthiness == orelse_truthiness:
                        return body_truthiness
                    return None
                return scanner._static_truthiness(node)

            def _invalidate_name(self, name: str) -> None:
                names_to_invalidate = {
                    candidate_name
                    for candidate_name in (
                        self.module_aliases.keys()
                        | self.callable_aliases.keys()
                        | self.import_loader_aliases.keys()
                        | self.import_aliases.keys()
                        | self.lazy_generator_aliases.keys()
                        | self.static_truthiness_aliases.keys()
                        | self.lambda_aliases.keys()
                        | self.literal_iterable_aliases.keys()
                        | self.function_definitions.keys()
                    )
                    if candidate_name == name or candidate_name.startswith(f"{name}.")
                }
                for candidate_name in names_to_invalidate | {name}:
                    self.module_aliases.pop(candidate_name, None)
                    self.callable_aliases.pop(candidate_name, None)
                    self.import_loader_aliases.pop(candidate_name, None)
                    self.import_aliases.pop(candidate_name, None)
                    self.lazy_generator_aliases.pop(candidate_name, None)
                    self.static_truthiness_aliases.pop(candidate_name, None)
                    self.lambda_aliases.pop(candidate_name, None)
                    self.literal_iterable_aliases.pop(candidate_name, None)
                    self.function_definitions.pop(candidate_name, None)
                self.shadowed_names.add(name)

            def _record_import_binding(self, name: str, resolved_name: str) -> None:
                resolved_name = _canonical_dynamic_helper_name(resolved_name)
                self.module_aliases.pop(name, None)
                self.callable_aliases.pop(name, None)
                self.lazy_generator_aliases.pop(name, None)
                self.static_truthiness_aliases.pop(name, None)
                self.lambda_aliases.pop(name, None)
                self.literal_iterable_aliases.pop(name, None)
                self.function_definitions.pop(name, None)
                if resolved_name in _DYNAMIC_IMPORT_HELPERS | _EAGER_GENERATOR_CONSUMERS:
                    self.import_loader_aliases[name] = frozenset({resolved_name})
                else:
                    self.import_loader_aliases.pop(name, None)
                self.import_aliases[name] = resolved_name
                self.shadowed_names.discard(name)

            def _record_default_parameter_assignment(
                self,
                name: str,
                value: ast.AST,
                definition_state: _DynamicAliasState,
            ) -> None:
                callable_state = self._snapshot_state()
                self._restore_state(definition_state)
                self._record_name_assignment(name, value)
                resolved_default_state = self._snapshot_state()
                self._restore_state(callable_state)

                self._invalidate_name(name)
                if name in resolved_default_state[0]:
                    self.module_aliases[name] = resolved_default_state[0][name]
                if name in resolved_default_state[1]:
                    self.callable_aliases[name] = resolved_default_state[1][name]
                if name in resolved_default_state[2]:
                    self.import_loader_aliases[name] = resolved_default_state[2][name]
                if name in resolved_default_state[3]:
                    self.import_aliases[name] = resolved_default_state[3][name]
                if name not in resolved_default_state[4]:
                    self.shadowed_names.discard(name)
                if name in resolved_default_state[5]:
                    self.lazy_generator_aliases[name] = resolved_default_state[5][name]
                if name in resolved_default_state[6]:
                    self.static_truthiness_aliases[name] = resolved_default_state[6][name]
                if name in resolved_default_state[7]:
                    self.lambda_aliases[name] = resolved_default_state[7][name]
                if name in resolved_default_state[8]:
                    self.literal_iterable_aliases[name] = resolved_default_state[8][name]
                if name in resolved_default_state[9]:
                    self.function_definitions[name] = resolved_default_state[9][name]

            def _record_name_assignment(self, name: str, value: ast.AST) -> None:
                if isinstance(value, ast.IfExp):
                    truthiness = self._resolved_static_truthiness(value.test)
                    if truthiness is True:
                        self._record_name_assignment(name, value.body)
                        return
                    if truthiness is False:
                        self._record_name_assignment(name, value.orelse)
                        return
                    initial_state = self._snapshot_state()
                    self._record_name_assignment(name, value.body)
                    body_state = self._snapshot_state()
                    self._restore_state(initial_state)
                    self._record_name_assignment(name, value.orelse)
                    self._restore_state(self._merge_states(body_state, self._snapshot_state()))
                    return
                if isinstance(value, ast.BoolOp):
                    possible_values: list[ast.expr] = []
                    for index, possible_value in enumerate(value.values):
                        if index == len(value.values) - 1:
                            possible_values.append(possible_value)
                            break
                        truthiness = self._resolved_static_truthiness(possible_value)
                        if isinstance(value.op, ast.And):
                            if truthiness is False:
                                possible_values.append(possible_value)
                                break
                            if truthiness is None:
                                possible_values.append(possible_value)
                        elif isinstance(value.op, ast.Or):
                            if truthiness is True:
                                possible_values.append(possible_value)
                                break
                            if truthiness is None:
                                possible_values.append(possible_value)

                    initial_state = self._snapshot_state()
                    possible_states = []
                    for possible_value in possible_values:
                        self._restore_state(initial_state)
                        self._record_name_assignment(name, possible_value)
                        possible_states.append(self._snapshot_state())
                    merged_state = possible_states[0]
                    for possible_state in possible_states[1:]:
                        merged_state = self._merge_states(merged_state, possible_state)
                    self._restore_state(merged_state)
                    return

                module_names = scanner._dynamic_import_module_names(
                    value,
                    self.import_aliases,
                    self.import_loader_aliases,
                    self.shadowed_names,
                )
                if not module_names:
                    module_names = scanner._resolve_dynamic_import_roots(
                        value,
                        self.import_aliases,
                        self.module_aliases,
                        self.import_loader_aliases,
                        self.shadowed_names,
                    )

                callable_names = scanner._resolve_dynamic_import_execution_calls(
                    value,
                    self.import_aliases,
                    self.module_aliases,
                    self.callable_aliases,
                    self.import_loader_aliases,
                    self.shadowed_names,
                )
                if isinstance(value, ast.Lambda):
                    callable_names |= self._lambda_execution_calls(value)
                if isinstance(value, ast.Call):
                    value_call_name = scanner._resolve_call_name(value.func)
                    resolved_value_call_name = (
                        scanner._apply_unshadowed_alias(
                            value_call_name,
                            self.import_aliases,
                            self.shadowed_names,
                        )
                        if value_call_name is not None
                        else None
                    )
                    if resolved_value_call_name in _PARTIAL_CALL_HELPERS:
                        callable_names |= frozenset(
                            normalized_name
                            for root in self._function_aware_roots(value)
                            if (normalized_name := _normalized_high_risk_python_call_name(root)) is not None
                        )

                value_name = scanner._resolve_call_name(value)
                resolved_value_names = (
                    self.import_loader_aliases.get(value_name, frozenset()) if value_name else frozenset()
                )
                if (
                    value_name
                    and not resolved_value_names
                    and value_name.split(".", maxsplit=1)[0] not in self.shadowed_names
                ):
                    resolved_value_names = frozenset({scanner._apply_alias(value_name, self.import_aliases)})
                resolved_value_names |= scanner._resolve_dynamic_import_roots(
                    value,
                    self.import_aliases,
                    self.module_aliases,
                    self.import_loader_aliases,
                    self.shadowed_names,
                )
                if isinstance(value, ast.Call):
                    resolved_value_names |= scanner._resolve_dynamic_import_getattr_roots(
                        value,
                        self.import_aliases,
                        self.module_aliases,
                        self.import_loader_aliases,
                        self.shadowed_names,
                    )
                helper_names = frozenset(
                    _canonical_dynamic_helper_name(helper_name)
                    for helper_name in resolved_value_names | callable_names
                    if helper_name in _DYNAMIC_ASSIGNABLE_HELPERS
                )
                eager_consumer_names = frozenset(
                    helper_name for helper_name in resolved_value_names if helper_name in _EAGER_GENERATOR_CONSUMERS
                )
                assignable_alias_names = helper_names | eager_consumer_names
                import_helper_names = helper_names & _DYNAMIC_IMPORT_HELPERS
                static_truthiness = self._resolved_static_truthiness(value)
                if static_truthiness is None and module_names:
                    static_truthiness = True

                self._invalidate_name(name)
                if isinstance(value, ast.GeneratorExp):
                    self.lazy_generator_aliases[name] = _DynamicAstAlternatives(nodes=(value,))
                elif isinstance(value, ast.Name) and value.id in self.lazy_generator_aliases:
                    self.lazy_generator_aliases[name] = self.lazy_generator_aliases[value.id]
                if isinstance(value, ast.Lambda):
                    self.lambda_aliases[name] = _DynamicAstAlternatives(nodes=(value,))
                elif isinstance(value, ast.Name) and value.id in self.lambda_aliases:
                    self.lambda_aliases[name] = self.lambda_aliases[value.id]
                if isinstance(value, ast.List):
                    self.literal_iterable_aliases[name] = _DynamicAstAlternatives(nodes=(value,))
                elif isinstance(value, ast.Name) and value.id in self.literal_iterable_aliases:
                    self.literal_iterable_aliases[name] = self.literal_iterable_aliases[value.id]
                if isinstance(value, ast.Name) and value.id in self.function_definitions:
                    self.function_definitions[name] = self.function_definitions[value.id]
                if static_truthiness is not None:
                    self.static_truthiness_aliases[name] = static_truthiness
                if module_names:
                    self.module_aliases[name] = module_names
                if callable_names:
                    self.callable_aliases[name] = callable_names
                loader_alias_names = import_helper_names | eager_consumer_names
                if loader_alias_names:
                    self.import_loader_aliases[name] = loader_alias_names
                if len(assignable_alias_names) == 1:
                    self.import_aliases[name] = next(iter(assignable_alias_names))
                    self.shadowed_names.discard(name)

            def _namespace_subscript_binding(self, target: ast.AST) -> tuple[str, str] | None:
                if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Call):
                    return None
                namespace_call = target.value
                if namespace_call.args or namespace_call.keywords:
                    return None
                helper_name = scanner._resolve_call_name(namespace_call.func)
                if helper_name is None:
                    return None
                if helper_name.split(".", maxsplit=1)[0] in self.shadowed_names:
                    return None
                resolved_helper = scanner._apply_unshadowed_alias(
                    helper_name,
                    self.import_aliases,
                    self.shadowed_names,
                )
                if resolved_helper not in {"builtins.globals", "builtins.vars", "globals", "vars"}:
                    return None
                binding_name = scanner._static_string_value(target.slice)
                if binding_name is None:
                    return None
                return resolved_helper.removeprefix("builtins."), binding_name

            def _record_target_assignment(self, target: ast.AST, value: ast.AST) -> None:
                namespace_binding = self._namespace_subscript_binding(target)
                if namespace_binding is not None:
                    namespace_helper, binding_name = namespace_binding
                    if self.scope_kind_stack[-1] in {"class", "module"} or namespace_helper == "globals":
                        self._record_name_assignment(binding_name, value)
                        if namespace_helper == "globals" and self.called_function_global_persistence_stack:
                            self._propagate_global_declared_name(binding_name, len(self.scope_kind_stack) - 2)
                    return
                if isinstance(target, ast.Name):
                    self._record_name_assignment(target.id, value)
                    if self.collecting_class_attribute_bindings and self.scope_kind_stack[-1] == "class":
                        self._record_class_attribute_binding(target.id, replace=True)
                    return
                if isinstance(target, ast.Attribute):
                    target_name = scanner._resolve_call_name(target)
                    if target_name is not None:
                        self._record_name_assignment(target_name, value)
                        if self.collecting_class_attribute_bindings:
                            self._record_class_attribute_binding(target_name)
                    return
                if isinstance(target, ast.Subscript):
                    container_name = scanner._resolve_call_name(target.value)
                    key_name = scanner._static_string_value(target.slice)
                    if container_name is not None and key_name is not None:
                        self._record_name_assignment(f"{container_name}.{key_name}", value)
                    return
                if isinstance(target, ast.Starred):
                    self._invalidate_target(target.value)
                    return
                if isinstance(target, ast.Tuple | ast.List):
                    if not isinstance(value, ast.Tuple | ast.List):
                        self._invalidate_target(target)
                        return

                    values = self._literal_iterable_elements(value)
                    if values is None or any(child_value is None for child_value in values):
                        self._invalidate_target(target)
                        return
                    resolved_values = [child_value for child_value in values if child_value is not None]
                    starred_indexes = [
                        index for index, child_target in enumerate(target.elts) if isinstance(child_target, ast.Starred)
                    ]
                    if not starred_indexes and len(target.elts) == len(resolved_values):
                        for child_target, child_value in zip(target.elts, resolved_values, strict=True):
                            self._record_target_assignment(child_target, child_value)
                        return
                    if len(starred_indexes) != 1 or len(resolved_values) < len(target.elts) - 1:
                        self._invalidate_target(target)
                        return

                    starred_index = starred_indexes[0]
                    trailing_count = len(target.elts) - starred_index - 1
                    for child_target, child_value in zip(
                        target.elts[:starred_index],
                        resolved_values[:starred_index],
                        strict=True,
                    ):
                        self._record_target_assignment(child_target, child_value)
                    self._invalidate_target(target.elts[starred_index])
                    if trailing_count:
                        for child_target, child_value in zip(
                            target.elts[-trailing_count:],
                            resolved_values[-trailing_count:],
                            strict=True,
                        ):
                            self._record_target_assignment(child_target, child_value)

            def _invalidate_target(self, target: ast.AST) -> None:
                namespace_binding = self._namespace_subscript_binding(target)
                if namespace_binding is not None:
                    namespace_helper, binding_name = namespace_binding
                    if self.scope_kind_stack[-1] in {"class", "module"} or (
                        namespace_helper == "globals" and binding_name not in self.shadowed_names
                    ):
                        self._invalidate_name(binding_name)
                elif isinstance(target, ast.Name):
                    self._invalidate_name(target.id)
                elif isinstance(target, ast.Attribute):
                    target_name = scanner._resolve_call_name(target)
                    if target_name is not None:
                        self._invalidate_name(target_name)
                elif isinstance(target, ast.Subscript):
                    container_name = scanner._resolve_call_name(target.value)
                    key_name = scanner._static_string_value(target.slice)
                    if container_name is not None and key_name is not None:
                        self._invalidate_name(f"{container_name}.{key_name}")
                elif isinstance(target, ast.Starred):
                    self._invalidate_target(target.value)
                elif isinstance(target, ast.Tuple | ast.List):
                    for child_target in target.elts:
                        self._invalidate_target(child_target)

            def _copy_name_binding_to_scope_index(self, name: str, destination_index: int) -> None:
                self.module_alias_stack[destination_index].pop(name, None)
                if name in self.module_aliases:
                    self.module_alias_stack[destination_index][name] = self.module_aliases[name]
                self.callable_alias_stack[destination_index].pop(name, None)
                if name in self.callable_aliases:
                    self.callable_alias_stack[destination_index][name] = self.callable_aliases[name]
                self.import_loader_alias_stack[destination_index].pop(name, None)
                if name in self.import_loader_aliases:
                    self.import_loader_alias_stack[destination_index][name] = self.import_loader_aliases[name]
                self.import_alias_stack[destination_index].pop(name, None)
                if name in self.import_aliases:
                    self.import_alias_stack[destination_index][name] = self.import_aliases[name]
                self.lazy_generator_alias_stack[destination_index].pop(name, None)
                if name in self.lazy_generator_aliases:
                    self.lazy_generator_alias_stack[destination_index][name] = self.lazy_generator_aliases[name]
                self.static_truthiness_alias_stack[destination_index].pop(name, None)
                if name in self.static_truthiness_aliases:
                    self.static_truthiness_alias_stack[destination_index][name] = self.static_truthiness_aliases[name]
                self.lambda_alias_stack[destination_index].pop(name, None)
                if name in self.lambda_aliases:
                    self.lambda_alias_stack[destination_index][name] = self.lambda_aliases[name]
                self.literal_iterable_alias_stack[destination_index].pop(name, None)
                if name in self.literal_iterable_aliases:
                    self.literal_iterable_alias_stack[destination_index][name] = self.literal_iterable_aliases[name]
                self.function_definition_stack[destination_index].pop(name, None)
                if name in self.function_definitions:
                    self.function_definition_stack[destination_index][name] = self.function_definitions[name]
                self.shadowed_name_stack[destination_index].discard(name)
                if name in self.shadowed_names:
                    self.shadowed_name_stack[destination_index].add(name)

            def _copy_name_binding_to_containing_scope(self, name: str) -> None:
                destination_index = len(self.scope_kind_stack) - 2
                while destination_index > 0 and self.scope_kind_stack[destination_index] == "comprehension":
                    destination_index -= 1
                self._copy_name_binding_to_scope_index(name, destination_index)

            def _literal_iterable_elements(self, iterable: ast.AST) -> list[ast.expr | None] | None:
                iterable_name = scanner._resolve_call_name(iterable)
                alternatives = self.literal_iterable_aliases.get(iterable_name) if iterable_name is not None else None
                if alternatives is not None:
                    merged_elements: list[ast.expr | None] = []
                    for alternative in alternatives:
                        alternative_elements = self._literal_iterable_elements(alternative)
                        if alternative_elements is None:
                            return None
                        merged_elements.extend(alternative_elements)
                    return merged_elements
                if isinstance(iterable, ast.Call):
                    wrapper_name = scanner._resolve_call_name(iterable.func)
                    resolved_wrapper_name = (
                        scanner._apply_unshadowed_alias(
                            wrapper_name,
                            self.import_aliases,
                            self.shadowed_names,
                        )
                        if wrapper_name is not None
                        else None
                    )
                    if (
                        resolved_wrapper_name in {"builtins.iter", "iter"}
                        and wrapper_name is not None
                        and wrapper_name.split(".", maxsplit=1)[0] not in self.shadowed_names
                        and len(iterable.args) == 1
                        and not iterable.keywords
                    ):
                        return self._literal_iterable_elements(iterable.args[0])
                if isinstance(iterable, ast.List | ast.Tuple | ast.Set):
                    literal_elements: list[ast.expr | None] = []
                    for element in iterable.elts:
                        if not isinstance(element, ast.Starred):
                            literal_elements.append(element)
                            continue
                        unpacked_elements = self._literal_iterable_elements(element.value)
                        if unpacked_elements is None:
                            literal_elements.append(None)
                        else:
                            literal_elements.extend(unpacked_elements)
                    return literal_elements
                if isinstance(iterable, ast.Dict):
                    literal_elements = []
                    for key, value in zip(iterable.keys, iterable.values, strict=True):
                        if key is not None:
                            literal_elements.append(key)
                            continue
                        unpacked_elements = self._literal_iterable_elements(value)
                        if unpacked_elements is None:
                            literal_elements.append(None)
                        else:
                            literal_elements.extend(unpacked_elements)
                    return literal_elements
                return None

            def _record_target_from_iterable(self, target: ast.AST, iterable: ast.AST) -> bool:
                elements = self._literal_iterable_elements(iterable)
                if not elements:
                    self._invalidate_target(target)
                    return False

                initial_state = self._snapshot_state()
                possible_states = []
                for element in elements:
                    self._restore_state(initial_state)
                    if element is None:
                        self._invalidate_target(target)
                    else:
                        self._record_target_assignment(target, element)
                    possible_states.append(self._snapshot_state())

                merged_state = possible_states[0]
                for possible_state in possible_states[1:]:
                    merged_state = self._merge_states(merged_state, possible_state)
                self._restore_state(merged_state)
                return True

            def _record_pattern_assignment(self, pattern: ast.pattern, value: ast.AST) -> None:
                if isinstance(pattern, ast.MatchAs):
                    if pattern.pattern is not None:
                        self._record_pattern_assignment(pattern.pattern, value)
                    if pattern.name is not None:
                        self._record_name_assignment(pattern.name, value)
                elif isinstance(pattern, ast.MatchStar):
                    if pattern.name is not None:
                        self._invalidate_name(pattern.name)
                elif isinstance(pattern, ast.MatchSequence):
                    starred_indexes = [
                        index
                        for index, child_pattern in enumerate(pattern.patterns)
                        if isinstance(child_pattern, ast.MatchStar)
                    ]
                    if (
                        isinstance(value, ast.List | ast.Tuple)
                        and not starred_indexes
                        and len(pattern.patterns) == len(value.elts)
                    ):
                        for child_pattern, child_value in zip(
                            pattern.patterns,
                            value.elts,
                            strict=True,
                        ):
                            self._record_pattern_assignment(child_pattern, child_value)
                    elif (
                        isinstance(value, ast.List | ast.Tuple)
                        and len(starred_indexes) == 1
                        and len(value.elts) >= len(pattern.patterns) - 1
                    ):
                        starred_index = starred_indexes[0]
                        trailing_count = len(pattern.patterns) - starred_index - 1
                        for child_pattern, child_value in zip(
                            pattern.patterns[:starred_index],
                            value.elts[:starred_index],
                            strict=True,
                        ):
                            self._record_pattern_assignment(child_pattern, child_value)
                        self._invalidate_pattern(pattern.patterns[starred_index])
                        if trailing_count:
                            for child_pattern, child_value in zip(
                                pattern.patterns[-trailing_count:],
                                value.elts[-trailing_count:],
                                strict=True,
                            ):
                                self._record_pattern_assignment(child_pattern, child_value)
                    else:
                        for child_pattern in pattern.patterns:
                            self._invalidate_pattern(child_pattern)
                elif isinstance(pattern, ast.MatchMapping):
                    matched_keys: set[object] = set()
                    if (
                        isinstance(value, ast.Dict)
                        and len(pattern.keys) == len(pattern.patterns)
                        and all(key is not None for key in value.keys)
                    ):
                        value_by_key: dict[object, ast.expr] = {}
                        for key, child_value in zip(value.keys, value.values, strict=True):
                            assert key is not None
                            key_is_known, literal_key = self._literal_mapping_key(key)
                            if key_is_known:
                                value_by_key[literal_key] = child_value
                        for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
                            key_is_known, literal_key = self._literal_mapping_key(key)
                            matched_value = value_by_key.get(literal_key) if key_is_known else None
                            if matched_value is None:
                                self._invalidate_pattern(child_pattern)
                            else:
                                matched_keys.add(literal_key)
                                self._record_pattern_assignment(child_pattern, matched_value)
                    else:
                        for child_pattern in pattern.patterns:
                            self._invalidate_pattern(child_pattern)
                    if pattern.rest is not None:
                        self._invalidate_name(pattern.rest)
                        if isinstance(value, ast.Dict) and all(key is not None for key in value.keys):
                            for rest_key, child_value in zip(value.keys, value.values, strict=True):
                                assert rest_key is not None
                                key_name = scanner._static_string_value(rest_key)
                                key_is_known, literal_key = self._literal_mapping_key(rest_key)
                                if key_name is not None and (not key_is_known or literal_key not in matched_keys):
                                    self._record_name_assignment(f"{pattern.rest}.{key_name}", child_value)
                elif isinstance(pattern, ast.MatchClass):
                    for child_pattern in [*pattern.patterns, *pattern.kwd_patterns]:
                        self._invalidate_pattern(child_pattern)
                elif isinstance(pattern, ast.MatchOr):
                    initial_state = self._snapshot_state()
                    possible_states = []
                    for child_pattern in pattern.patterns:
                        self._restore_state(initial_state)
                        self._record_pattern_assignment(child_pattern, value)
                        possible_states.append(self._snapshot_state())
                    merged_state = possible_states[0]
                    for possible_state in possible_states[1:]:
                        merged_state = self._merge_states(merged_state, possible_state)
                    self._restore_state(merged_state)

            @staticmethod
            def _literal_mapping_key(node: ast.AST) -> tuple[bool, object]:
                try:
                    value = ast.literal_eval(node)
                    hash(value)
                except (TypeError, ValueError):
                    return False, None
                return True, value

            @staticmethod
            def _pattern_definitely_does_not_match(pattern: ast.pattern, value: ast.AST) -> bool:
                if isinstance(pattern, ast.MatchValue):
                    if isinstance(pattern.value, ast.Constant) and isinstance(value, ast.Constant):
                        return pattern.value.value != value.value
                    return False
                if isinstance(pattern, ast.MatchSingleton):
                    return not isinstance(value, ast.Constant) or pattern.value is not value.value
                if isinstance(pattern, ast.MatchAs):
                    return (
                        pattern.pattern is not None
                        and DynamicImportExecutionVisitor._pattern_definitely_does_not_match(
                            pattern.pattern,
                            value,
                        )
                    )
                if isinstance(pattern, ast.MatchOr):
                    return all(
                        DynamicImportExecutionVisitor._pattern_definitely_does_not_match(
                            child_pattern,
                            value,
                        )
                        for child_pattern in pattern.patterns
                    )
                if isinstance(pattern, ast.MatchSequence) and isinstance(value, ast.List | ast.Tuple):
                    starred_indexes = [
                        index
                        for index, child_pattern in enumerate(pattern.patterns)
                        if isinstance(child_pattern, ast.MatchStar)
                    ]
                    if not starred_indexes:
                        if len(pattern.patterns) != len(value.elts):
                            return True
                        return any(
                            DynamicImportExecutionVisitor._pattern_definitely_does_not_match(
                                child_pattern,
                                child_value,
                            )
                            for child_pattern, child_value in zip(
                                pattern.patterns,
                                value.elts,
                                strict=True,
                            )
                        )
                    if len(starred_indexes) != 1 or len(value.elts) < len(pattern.patterns) - 1:
                        return True
                    starred_index = starred_indexes[0]
                    trailing_count = len(pattern.patterns) - starred_index - 1
                    leading_mismatch = any(
                        DynamicImportExecutionVisitor._pattern_definitely_does_not_match(
                            child_pattern,
                            child_value,
                        )
                        for child_pattern, child_value in zip(
                            pattern.patterns[:starred_index],
                            value.elts[:starred_index],
                            strict=True,
                        )
                    )
                    trailing_mismatch = trailing_count > 0 and any(
                        DynamicImportExecutionVisitor._pattern_definitely_does_not_match(
                            child_pattern,
                            child_value,
                        )
                        for child_pattern, child_value in zip(
                            pattern.patterns[-trailing_count:],
                            value.elts[-trailing_count:],
                            strict=True,
                        )
                    )
                    return leading_mismatch or trailing_mismatch
                if (
                    isinstance(pattern, ast.MatchMapping)
                    and isinstance(value, ast.Dict)
                    and all(key is not None for key in value.keys)
                ):
                    value_by_key: dict[object, ast.expr] = {}
                    for key, child_value in zip(value.keys, value.values, strict=True):
                        assert key is not None
                        key_is_known, literal_key = DynamicImportExecutionVisitor._literal_mapping_key(key)
                        if key_is_known:
                            value_by_key[literal_key] = child_value
                    for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
                        key_is_known, literal_key = DynamicImportExecutionVisitor._literal_mapping_key(key)
                        matched_value = value_by_key.get(literal_key) if key_is_known else None
                        if matched_value is None or (
                            DynamicImportExecutionVisitor._pattern_definitely_does_not_match(
                                child_pattern,
                                matched_value,
                            )
                        ):
                            return True
                    return False
                return False

            @staticmethod
            def _pattern_definitely_matches(pattern: ast.pattern, value: ast.AST) -> bool:
                if isinstance(pattern, ast.MatchValue):
                    return (
                        isinstance(pattern.value, ast.Constant)
                        and isinstance(value, ast.Constant)
                        and pattern.value.value == value.value
                    )
                if isinstance(pattern, ast.MatchSingleton):
                    return isinstance(value, ast.Constant) and pattern.value is value.value
                if isinstance(pattern, ast.MatchAs):
                    return pattern.pattern is None or DynamicImportExecutionVisitor._pattern_definitely_matches(
                        pattern.pattern,
                        value,
                    )
                if isinstance(pattern, ast.MatchStar):
                    return True
                if isinstance(pattern, ast.MatchOr):
                    return any(
                        DynamicImportExecutionVisitor._pattern_definitely_matches(
                            child_pattern,
                            value,
                        )
                        for child_pattern in pattern.patterns
                    )
                if isinstance(pattern, ast.MatchSequence) and isinstance(value, ast.List | ast.Tuple):
                    starred_indexes = [
                        index
                        for index, child_pattern in enumerate(pattern.patterns)
                        if isinstance(child_pattern, ast.MatchStar)
                    ]
                    if not starred_indexes:
                        return len(pattern.patterns) == len(value.elts) and all(
                            DynamicImportExecutionVisitor._pattern_definitely_matches(
                                child_pattern,
                                child_value,
                            )
                            for child_pattern, child_value in zip(
                                pattern.patterns,
                                value.elts,
                                strict=True,
                            )
                        )
                    if len(starred_indexes) != 1 or len(value.elts) < len(pattern.patterns) - 1:
                        return False
                    starred_index = starred_indexes[0]
                    trailing_count = len(pattern.patterns) - starred_index - 1
                    leading_matches = all(
                        DynamicImportExecutionVisitor._pattern_definitely_matches(
                            child_pattern,
                            child_value,
                        )
                        for child_pattern, child_value in zip(
                            pattern.patterns[:starred_index],
                            value.elts[:starred_index],
                            strict=True,
                        )
                    )
                    trailing_matches = trailing_count == 0 or all(
                        DynamicImportExecutionVisitor._pattern_definitely_matches(
                            child_pattern,
                            child_value,
                        )
                        for child_pattern, child_value in zip(
                            pattern.patterns[-trailing_count:],
                            value.elts[-trailing_count:],
                            strict=True,
                        )
                    )
                    return leading_matches and trailing_matches
                if (
                    isinstance(pattern, ast.MatchMapping)
                    and isinstance(value, ast.Dict)
                    and all(key is not None for key in value.keys)
                ):
                    value_by_key: dict[object, ast.expr] = {}
                    for key, child_value in zip(value.keys, value.values, strict=True):
                        assert key is not None
                        key_is_known, literal_key = DynamicImportExecutionVisitor._literal_mapping_key(key)
                        if key_is_known:
                            value_by_key[literal_key] = child_value
                    return all(
                        (key_data := DynamicImportExecutionVisitor._literal_mapping_key(key))[0]
                        and (matched_value := value_by_key.get(key_data[1])) is not None
                        and DynamicImportExecutionVisitor._pattern_definitely_matches(
                            child_pattern,
                            matched_value,
                        )
                        for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True)
                    )
                return False

            def _invalidate_pattern(self, pattern: ast.pattern) -> None:
                if isinstance(pattern, ast.MatchAs):
                    if pattern.pattern is not None:
                        self._invalidate_pattern(pattern.pattern)
                    if pattern.name is not None:
                        self._invalidate_name(pattern.name)
                elif isinstance(pattern, ast.MatchStar):
                    if pattern.name is not None:
                        self._invalidate_name(pattern.name)
                elif isinstance(pattern, ast.MatchMapping):
                    for child_pattern in pattern.patterns:
                        self._invalidate_pattern(child_pattern)
                    if pattern.rest is not None:
                        self._invalidate_name(pattern.rest)
                elif isinstance(pattern, ast.MatchSequence | ast.MatchOr):
                    for child_pattern in pattern.patterns:
                        self._invalidate_pattern(child_pattern)
                elif isinstance(pattern, ast.MatchClass):
                    for child_pattern in [*pattern.patterns, *pattern.kwd_patterns]:
                        self._invalidate_pattern(child_pattern)

            @staticmethod
            def _receiver_attribute_binding_names(
                node: ast.FunctionDef | ast.AsyncFunctionDef,
                receiver_name: str | None,
            ) -> set[str]:
                if receiver_name is None:
                    return set()

                class ReceiverBindingVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.names: set[str] = set()

                    def _record_target(self, target: ast.AST) -> None:
                        if isinstance(target, ast.Attribute):
                            target_name = scanner._resolve_call_name(target)
                            if target_name is not None and target_name.startswith(f"{receiver_name}."):
                                self.names.add(target_name)
                            return
                        if isinstance(target, ast.Starred):
                            self._record_target(target.value)
                            return
                        if isinstance(target, ast.Tuple | ast.List):
                            for child_target in target.elts:
                                self._record_target(child_target)

                    def visit_Assign(self, assignment: ast.Assign) -> None:
                        for target in assignment.targets:
                            self._record_target(target)
                        self.visit(assignment.value)

                    def visit_AnnAssign(self, assignment: ast.AnnAssign) -> None:
                        self._record_target(assignment.target)
                        if assignment.value is not None:
                            self.visit(assignment.value)

                    def visit_AugAssign(self, assignment: ast.AugAssign) -> None:
                        self._record_target(assignment.target)
                        self.visit(assignment.value)

                    def visit_Delete(self, deletion: ast.Delete) -> None:
                        for target in deletion.targets:
                            self._record_target(target)

                    def visit_For(self, loop: ast.For) -> None:
                        self._record_target(loop.target)
                        self.visit(loop.iter)
                        for statement in [*loop.body, *loop.orelse]:
                            self.visit(statement)

                    def visit_AsyncFor(self, loop: ast.AsyncFor) -> None:
                        self._record_target(loop.target)
                        self.visit(loop.iter)
                        for statement in [*loop.body, *loop.orelse]:
                            self.visit(statement)

                    def visit_With(self, with_node: ast.With) -> None:
                        for item in with_node.items:
                            self.visit(item.context_expr)
                            if item.optional_vars is not None:
                                self._record_target(item.optional_vars)
                        for statement in with_node.body:
                            self.visit(statement)

                    def visit_AsyncWith(self, with_node: ast.AsyncWith) -> None:
                        for item in with_node.items:
                            self.visit(item.context_expr)
                            if item.optional_vars is not None:
                                self._record_target(item.optional_vars)
                        for statement in with_node.body:
                            self.visit(statement)

                    def visit_FunctionDef(self, function: ast.FunctionDef) -> None:
                        return

                    def visit_AsyncFunctionDef(self, function: ast.AsyncFunctionDef) -> None:
                        return

                    def visit_ClassDef(self, class_node: ast.ClassDef) -> None:
                        return

                    def visit_Lambda(self, lambda_node: ast.Lambda) -> None:
                        return

                binding_visitor = ReceiverBindingVisitor()
                for statement in node.body:
                    binding_visitor.visit(statement)
                return binding_visitor.names

            @staticmethod
            def _returns_nested_handler(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
                nested_handler_names = {
                    statement.name
                    for statement in node.body
                    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef) and statement.name == "handle"
                }
                nested_handler_names.update(
                    statement.name
                    for statement in node.body
                    if isinstance(statement, ast.ClassDef)
                    and any(
                        isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef) and member.name == "handle"
                        for member in statement.body
                    )
                )
                if not nested_handler_names:
                    return False

                class ReturnNameVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.names: set[str] = set()

                    def visit_Return(self, return_node: ast.Return) -> None:
                        if isinstance(return_node.value, ast.Name):
                            self.names.add(return_node.value.id)

                    def visit_FunctionDef(self, function: ast.FunctionDef) -> None:
                        return

                    def visit_AsyncFunctionDef(self, function: ast.AsyncFunctionDef) -> None:
                        return

                    def visit_ClassDef(self, class_node: ast.ClassDef) -> None:
                        return

                return_visitor = ReturnNameVisitor()
                for statement in node.body:
                    return_visitor.visit(statement)
                return bool(return_visitor.names & nested_handler_names)

            def _visit_function_definition(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                receiver_name: str | None = None
                positional_parameters = [*node.args.posonlyargs, *node.args.args]
                is_static_method = any(
                    (decorator_name := scanner._resolve_call_name(decorator)) is not None
                    and decorator_name.split(".", maxsplit=1)[0] not in self.shadowed_names
                    and scanner._apply_unshadowed_alias(
                        decorator_name,
                        self.import_aliases,
                        self.shadowed_names,
                    )
                    in {"builtins.staticmethod", "staticmethod"}
                    for decorator in node.decorator_list
                )
                if self.class_name_stack and positional_parameters and not is_static_method:
                    receiver_name = positional_parameters[0].arg
                if self.collecting_class_attribute_bindings:
                    definition_state = self._snapshot_state()
                    receiver_attribute_names = self._receiver_attribute_binding_names(node, receiver_name)
                    self._push_scope(
                        self._parameter_names(node.args) | scanner._callable_local_binding_names(node),
                        self._callable_inherited_state(),
                        scope_kind="function",
                    )
                    self._inherit_class_attribute_bindings(receiver_name)
                    for parameter_name, default in self._parameter_default_bindings(node.args):
                        self._record_default_parameter_assignment(parameter_name, default, definition_state)
                    self.collecting_class_attribute_bindings = False
                    self._visit_statement_block(node.body)
                    self.collecting_class_attribute_bindings = True
                    for attribute_name in receiver_attribute_names:
                        self._record_class_attribute_binding(attribute_name, replace=True)
                    self._pop_scope()
                    return
                for decorator in node.decorator_list:
                    self.visit(decorator)
                definition_defaults: list[ast.expr] = [
                    *node.args.defaults,
                    *(default for default in node.args.kw_defaults if default is not None),
                ]
                for default_node in definition_defaults:
                    self.visit(default_node)
                if not self.postponed_annotations:
                    for parameter in [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]:
                        if parameter.annotation is not None:
                            self.visit(parameter.annotation)
                    if node.args.vararg is not None and node.args.vararg.annotation is not None:
                        self.visit(node.args.vararg.annotation)
                    if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
                        self.visit(node.args.kwarg.annotation)
                    if node.returns is not None:
                        self.visit(node.returns)
                definition_state = self._snapshot_state()
                self._invalidate_name(node.name)
                if self.collecting_module_bindings:
                    return
                if isinstance(node, ast.FunctionDef):
                    self.function_definition_stack[-1][node.name] = _DynamicAstAlternatives(nodes=(node,))
                    self.function_definition_states[id(node)] = definition_state
                is_entrypoint = (
                    node.name in {"handle", "initialize"}
                    or (
                        bool(self.class_name_stack)
                        and node.name in {"__init__", "preprocess", "inference", "postprocess"}
                    )
                    or self._returns_nested_handler(node)
                )
                if not is_entrypoint:
                    return
                inherited_state = self._callable_inherited_state()
                local_bindings = scanner._callable_local_binding_names(node)
                self._push_scope(
                    self._parameter_names(node.args) | local_bindings,
                    inherited_state,
                    scope_kind="function",
                )
                self._inherit_class_attribute_bindings(receiver_name)
                for parameter_name, default in self._parameter_default_bindings(node.args):
                    self._record_default_parameter_assignment(parameter_name, default, definition_state)
                initial_state = self._snapshot_state()
                self.collecting_module_bindings = True
                self._visit_statement_block(node.body)
                self.collecting_module_bindings = False
                self.function_binding_state_stack.append(self._snapshot_state())
                self._restore_state(initial_state)
                self._visit_statement_block(node.body)
                self.function_binding_state_stack.pop()
                self._pop_scope()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._visit_function_definition(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._visit_function_definition(node)

            def visit_Lambda(self, node: ast.Lambda) -> None:
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        self.visit(default)

            @staticmethod
            def _callable_call_argument_bindings(
                node: ast.Lambda | ast.FunctionDef | ast.AsyncFunctionDef,
                call: ast.Call,
            ) -> tuple[bool | None, dict[str, ast.expr]]:
                expanded_args = scanner._expanded_literal_call_arguments(call.args)
                expanded_keywords = scanner._expanded_literal_call_keywords(call.keywords)
                if expanded_args is None or expanded_keywords is None:
                    return None, {}

                positional_parameters = [*node.args.posonlyargs, *node.args.args]
                positional_only_names = {parameter.arg for parameter in node.args.posonlyargs}
                keyword_parameter_names = {parameter.arg for parameter in [*node.args.args, *node.args.kwonlyargs]}
                bindings: dict[str, ast.expr] = {}

                if len(expanded_args) > len(positional_parameters) and node.args.vararg is None:
                    return False, {}
                for parameter, argument in zip(positional_parameters, expanded_args, strict=False):
                    bindings[parameter.arg] = argument
                if node.args.vararg is not None:
                    bindings[node.args.vararg.arg] = ast.Tuple(
                        elts=expanded_args[len(positional_parameters) :],
                        ctx=ast.Load(),
                    )

                extra_keywords: list[tuple[str, ast.expr]] = []
                for keyword_name, keyword_value in expanded_keywords:
                    if keyword_name in positional_only_names or keyword_name in bindings:
                        return False, {}
                    if keyword_name in keyword_parameter_names:
                        bindings[keyword_name] = keyword_value
                    elif node.args.kwarg is not None:
                        extra_keywords.append((keyword_name, keyword_value))
                    else:
                        return False, {}

                required_positional_count = len(positional_parameters) - len(node.args.defaults)
                for index, parameter in enumerate(positional_parameters):
                    if parameter.arg in bindings:
                        continue
                    if index < required_positional_count:
                        return False, {}
                    bindings[parameter.arg] = node.args.defaults[index - required_positional_count]

                for parameter, default in zip(
                    node.args.kwonlyargs,
                    node.args.kw_defaults,
                    strict=True,
                ):
                    if parameter.arg in bindings:
                        continue
                    if default is None:
                        return False, {}
                    bindings[parameter.arg] = default

                if node.args.vararg is not None and node.args.vararg.arg not in bindings:
                    bindings[node.args.vararg.arg] = ast.Tuple(elts=[], ctx=ast.Load())
                if node.args.kwarg is not None:
                    bindings[node.args.kwarg.arg] = ast.Dict(
                        keys=[ast.Constant(keyword_name) for keyword_name, _ in extra_keywords],
                        values=[keyword_value for _, keyword_value in extra_keywords],
                    )
                return True, bindings

            def _lambda_execution_calls(
                self,
                node: ast.Lambda,
                call: ast.Call | None = None,
            ) -> frozenset[str]:
                lambda_id = id(node)
                if lambda_id in self.active_lambda_ids:
                    return frozenset()
                call_is_valid: bool | None = None
                argument_bindings: dict[str, ast.expr] = {}
                if call is not None:
                    call_is_valid, argument_bindings = self._callable_call_argument_bindings(node, call)
                    if call_is_valid is False:
                        return frozenset()

                initial_risky_calls = set(self.risky_calls)
                self.active_lambda_ids.add(lambda_id)
                try:
                    self._push_scope(
                        self._parameter_names(node.args) | scanner._callable_local_binding_names(node),
                        self._snapshot_state(),
                        scope_kind="function",
                    )
                    try:
                        if call_is_valid is True:
                            for parameter_name, argument in argument_bindings.items():
                                self._record_name_assignment(parameter_name, argument)
                        self.visit(node.body)
                        return frozenset(self.risky_calls - initial_risky_calls)
                    finally:
                        self._pop_scope()
                finally:
                    self.risky_calls = initial_risky_calls
                    self.active_lambda_ids.remove(lambda_id)

            def _lambda_nodes_for_callable(self, node: ast.AST) -> tuple[ast.Lambda, ...]:
                if isinstance(node, ast.Lambda):
                    return (node,)
                if isinstance(node, ast.Subscript):
                    selected_value = scanner._literal_subscript_value(node)
                    if selected_value is not None:
                        return self._lambda_nodes_for_callable(selected_value)
                callable_name = scanner._resolve_call_name(node)
                alternatives = self.lambda_aliases.get(callable_name) if callable_name is not None else None
                return tuple(alternatives) if alternatives is not None else ()

            def _lambda_return_roots(self, node: ast.Lambda, call: ast.Call) -> frozenset[str]:
                lambda_id = id(node)
                if lambda_id in self.active_lambda_return_ids:
                    return frozenset()
                call_is_valid, argument_bindings = self._callable_call_argument_bindings(node, call)
                if call_is_valid is False:
                    return frozenset()

                self.active_lambda_return_ids.add(lambda_id)
                self._push_scope(
                    self._parameter_names(node.args) | scanner._callable_local_binding_names(node),
                    self._snapshot_state(),
                    scope_kind="function",
                )
                try:
                    if call_is_valid is True:
                        for parameter_name, argument in argument_bindings.items():
                            self._record_name_assignment(parameter_name, argument)
                    return self._function_aware_roots(node.body)
                finally:
                    self._pop_scope()
                    self.active_lambda_return_ids.remove(lambda_id)

            def _list_nodes_for_value(self, node: ast.AST) -> tuple[ast.List, ...]:
                if isinstance(node, ast.List):
                    return (node,)
                value_name = scanner._resolve_call_name(node)
                alternatives = self.literal_iterable_aliases.get(value_name) if value_name is not None else None
                return tuple(alternatives) if alternatives is not None else ()

            def _visit_lambda_callback(self, callback: ast.AST, arguments: list[ast.expr]) -> bool:
                lambda_nodes = self._lambda_nodes_for_callable(callback)
                if not lambda_nodes:
                    return False
                synthetic_call = ast.Call(func=ast.Name(id="callback", ctx=ast.Load()), args=arguments, keywords=[])
                callback_calls: set[str] = set()
                for lambda_node in lambda_nodes:
                    callback_calls.update(self._lambda_execution_calls(lambda_node, synthetic_call))
                self.risky_calls.update(callback_calls)
                return True

            def _visit_callable_callback(
                self,
                callback: ast.AST,
                arguments: list[ast.expr] | None,
            ) -> bool:
                callback_calls = set(
                    scanner._resolve_dynamic_import_execution_calls(
                        callback,
                        self.import_aliases,
                        self.module_aliases,
                        self.callable_aliases,
                        self.import_loader_aliases,
                        self.shadowed_names,
                    )
                )
                callback_calls.update(
                    normalized_name
                    for root in self._function_aware_roots(callback)
                    if (normalized_name := _normalized_high_risk_python_call_name(root)) is not None
                )
                self.risky_calls.update(callback_calls)

                if arguments is None:
                    lambda_nodes = self._lambda_nodes_for_callable(callback)
                    lambda_calls = {
                        call_name
                        for lambda_node in lambda_nodes
                        for call_name in self._lambda_execution_calls(lambda_node)
                    }
                    self.risky_calls.update(lambda_calls)
                    return bool(callback_calls or lambda_nodes)

                return self._visit_lambda_callback(callback, arguments) or bool(callback_calls)

            def _propagate_declared_name(self, name: str, destination_index: int, caller_index: int) -> None:
                self._copy_name_binding_to_scope_index(name, destination_index)
                for scope_index in range(destination_index + 1, caller_index + 1):
                    if (
                        self.scope_kind_stack[scope_index] == "function"
                        and name in self.local_binding_name_stack[scope_index]
                    ):
                        break
                    self._copy_name_binding_to_scope_index(name, scope_index)

            def _propagate_global_declared_name(self, name: str, caller_index: int) -> None:
                if (
                    self.scope_kind_stack[caller_index] in {"class", "module"}
                    or self.called_function_global_persistence_stack[-1]
                ):
                    self._copy_name_binding_to_scope_index(name, 0)
                for scope_index in range(1, caller_index + 1):
                    if (
                        self.scope_kind_stack[scope_index] == "function"
                        and name in self.local_binding_name_stack[scope_index]
                    ):
                        break
                    self._copy_name_binding_to_scope_index(name, scope_index)

            def _apply_called_function_side_effects(self, node: ast.FunctionDef, call: ast.Call) -> None:
                function_id = id(node)
                if function_id in self.active_function_ids:
                    return
                global_names, nonlocal_names = scanner._callable_declaration_names(node)
                call_is_valid, argument_bindings = self._callable_call_argument_bindings(node, call)
                if call_is_valid is False:
                    return
                caller_state = self._snapshot_state()
                definition_state = self.function_definition_states.get(function_id, caller_state)
                default_ids = {
                    id(default) for default in [*node.args.defaults, *node.args.kw_defaults] if default is not None
                }

                caller_index = len(self.scope_kind_stack) - 1
                persist_global_side_effects = (
                    self.called_function_global_persistence_stack[-1]
                    if self.called_function_global_persistence_stack
                    else self.scope_kind_stack[caller_index] in {"class", "module"}
                )
                self.active_function_ids.add(function_id)
                self.called_function_global_persistence_stack.append(persist_global_side_effects)
                self._push_scope(
                    self._parameter_names(node.args) | scanner._callable_local_binding_names(node),
                    self._snapshot_state(),
                    scope_kind="function",
                )
                try:
                    if call_is_valid is True:
                        for parameter_name, argument in argument_bindings.items():
                            resolution_state = definition_state if id(argument) in default_ids else caller_state
                            self._record_default_parameter_assignment(parameter_name, argument, resolution_state)
                    self._visit_statement_block(node.body)
                    for name in global_names:
                        self._propagate_global_declared_name(name, caller_index)
                    for name in nonlocal_names:
                        destination_index = next(
                            (
                                scope_index
                                for scope_index in range(caller_index, 0, -1)
                                if self.scope_kind_stack[scope_index] == "function"
                                and name in self.local_binding_name_stack[scope_index]
                            ),
                            None,
                        )
                        if destination_index is not None:
                            self._propagate_declared_name(name, destination_index, caller_index)
                finally:
                    self._pop_scope()
                    self.called_function_global_persistence_stack.pop()
                    self.active_function_ids.remove(function_id)

            def _called_function_return_roots(self, node: ast.FunctionDef, call: ast.Call) -> frozenset[str]:
                function_id = id(node)
                if function_id in self.active_function_return_ids:
                    return frozenset()
                call_is_valid, argument_bindings = self._callable_call_argument_bindings(node, call)
                if call_is_valid is False:
                    return frozenset()
                caller_state = self._snapshot_state()
                definition_state = self.function_definition_states.get(function_id, caller_state)
                default_ids = {
                    id(default) for default in [*node.args.defaults, *node.args.kw_defaults] if default is not None
                }

                self.active_function_return_ids.add(function_id)
                self._push_scope(
                    self._parameter_names(node.args) | scanner._callable_local_binding_names(node),
                    self._snapshot_state(),
                    scope_kind="function",
                )
                try:
                    if call_is_valid is True:
                        for parameter_name, argument in argument_bindings.items():
                            resolution_state = definition_state if id(argument) in default_ids else caller_state
                            self._record_default_parameter_assignment(parameter_name, argument, resolution_state)
                    return_roots: set[str] = set()
                    for return_value in scanner._callable_return_values(node):
                        return_roots.update(
                            scanner._resolve_dynamic_import_roots(
                                return_value,
                                self.import_aliases,
                                self.module_aliases,
                                self.import_loader_aliases,
                                self.shadowed_names,
                            )
                        )
                        return_roots.update(
                            scanner._resolve_dynamic_import_execution_calls(
                                return_value,
                                self.import_aliases,
                                self.module_aliases,
                                self.callable_aliases,
                                self.import_loader_aliases,
                                self.shadowed_names,
                            )
                        )
                        return_name = scanner._resolve_call_name(return_value)
                        if return_name is not None:
                            return_roots.update(self.import_loader_aliases.get(return_name, frozenset()))
                    return frozenset(return_roots)
                finally:
                    self._pop_scope()
                    self.active_function_return_ids.remove(function_id)

            def _function_aware_roots(self, node: ast.AST) -> frozenset[str]:
                roots = set(
                    scanner._resolve_dynamic_import_roots(
                        node,
                        self.import_aliases,
                        self.module_aliases,
                        self.import_loader_aliases,
                        self.shadowed_names,
                    )
                )
                if isinstance(node, ast.Name):
                    roots.update(self.import_loader_aliases.get(node.id, frozenset()))
                    roots.update(self.callable_aliases.get(node.id, frozenset()))
                elif isinstance(node, ast.NamedExpr):
                    roots.update(self._function_aware_roots(node.value))
                elif isinstance(node, ast.Subscript):
                    selected_value = scanner._literal_subscript_value(node)
                    if selected_value is not None:
                        roots.update(self._function_aware_roots(selected_value))
                    container_name = scanner._resolve_call_name(node.value)
                    alternatives = (
                        self.literal_iterable_aliases.get(container_name) if container_name is not None else None
                    )
                    for alternative in alternatives or ():
                        selected_alternative = scanner._literal_subscript_value(
                            ast.Subscript(value=alternative, slice=node.slice, ctx=ast.Load())
                        )
                        if selected_alternative is not None:
                            roots.update(self._function_aware_roots(selected_alternative))
                elif isinstance(node, ast.Attribute):
                    roots.update(f"{parent}.{node.attr}" for parent in self._function_aware_roots(node.value))
                elif isinstance(node, ast.Call):
                    for lambda_node in self._lambda_nodes_for_callable(node.func):
                        roots.update(self._lambda_return_roots(lambda_node, node))
                    function_name = scanner._resolve_call_name(node.func)
                    function_nodes = (
                        self.function_definition_stack[-1].get(function_name) if function_name is not None else None
                    )
                    if function_nodes is not None:
                        for function_node in function_nodes:
                            roots.update(self._called_function_return_roots(function_node, node))
                    resolved_function_name = (
                        scanner._apply_unshadowed_alias(
                            function_name,
                            self.import_aliases,
                            self.shadowed_names,
                        )
                        if function_name is not None
                        else None
                    )
                    if resolved_function_name in _PARTIAL_CALL_HELPERS:
                        expanded_args = scanner._expanded_literal_call_arguments(node.args)
                        if expanded_args:
                            partial_target = expanded_args[0]
                            roots.update(self._function_aware_roots(partial_target))
                            roots.update(
                                scanner._resolve_dynamic_import_execution_calls(
                                    partial_target,
                                    self.import_aliases,
                                    self.module_aliases,
                                    self.callable_aliases,
                                    self.import_loader_aliases,
                                    self.shadowed_names,
                                )
                            )
                    factory_roots = self._function_aware_roots(node.func)
                    roots.update(
                        scanner._module_names_for_import_helpers(
                            node,
                            factory_roots & _DYNAMIC_IMPORT_HELPERS,
                        )
                    )
                return frozenset(roots)

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    binding_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                    resolved_name = alias.name if alias.asname else binding_name
                    self._record_import_binding(binding_name, resolved_name)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if node.module is None:
                    return
                if node.level:
                    for alias in node.names:
                        if alias.name != "*":
                            self._invalidate_name(alias.asname or alias.name)
                    return
                for alias in node.names:
                    if alias.name == "*":
                        for local_name, import_name in _wildcard_import_aliases(node.module):
                            self._record_import_binding(local_name, import_name)
                    else:
                        self._record_import_binding(alias.asname or alias.name, f"{node.module}.{alias.name}")

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                for decorator in node.decorator_list:
                    self.visit(decorator)
                for base in node.bases:
                    self.visit(base)
                for keyword in node.keywords:
                    self.visit(keyword.value)
                self._invalidate_name(node.name)
                if self.collecting_module_bindings:
                    return
                if self.scope_kind_stack[-1] == "module":
                    class_body_state = self._snapshot_state()
                    class_parent_state = self.module_binding_state or class_body_state
                elif self.scope_kind_stack[-1] == "class":
                    class_body_state = self.class_parent_state_stack[-1]
                    class_parent_state = self.class_parent_state_stack[-1]
                else:
                    class_body_state = self._snapshot_state()
                    class_parent_state = self.function_binding_state_stack[-1]
                self.class_parent_state_stack.append(class_parent_state)
                class_name = ".".join([*self.class_name_stack, node.name])
                self.class_name_stack.append(class_name)
                self._seed_class_attribute_bindings(class_name, class_parent_state)
                self._push_scope(set(), class_body_state, scope_kind="class")
                class_initial_state = self._snapshot_state()
                self.collecting_class_attribute_bindings = True
                for statement in node.body:
                    if (
                        isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef)
                        and statement.name in {"__init__", "initialize"}
                    ) or not isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                        self.visit(statement)
                self.collecting_class_attribute_bindings = False
                self._restore_state(class_initial_state)
                for statement in node.body:
                    self.visit(statement)
                self._pop_scope()
                self.class_name_stack.pop()
                self.class_parent_state_stack.pop()

            def visit_Module(self, node: ast.Module) -> None:
                initial_state = self._snapshot_state()
                self.collecting_module_bindings = True
                for statement in node.body:
                    self.visit(statement)
                self.collecting_module_bindings = False
                self.module_binding_state = self._snapshot_state()
                self._restore_state(initial_state)
                for statement in node.body:
                    self.visit(statement)

            def visit_Assign(self, node: ast.Assign) -> None:
                self.visit(node.value)
                for target in node.targets:
                    self._record_target_assignment(target, node.value)

            def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                if node.value is not None:
                    self.visit(node.value)
                    self._record_target_assignment(node.target, node.value)
                if not self.postponed_annotations and self.scope_kind_stack[-1] in {"class", "module"}:
                    self.visit(node.annotation)

            def visit_AugAssign(self, node: ast.AugAssign) -> None:
                self.visit(node.target)
                self.visit(node.value)
                self._invalidate_target(node.target)

            def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
                self.visit(node.value)
                self._record_target_assignment(node.target, node.value)
                if self.scope_kind_stack[-1] == "comprehension" and isinstance(node.target, ast.Name):
                    self._copy_name_binding_to_containing_scope(node.target.id)

            def visit_Delete(self, node: ast.Delete) -> None:
                for target in node.targets:
                    self._invalidate_target(target)

            def visit_Raise(self, node: ast.Raise) -> None:
                if node.exc is not None:
                    self.visit(node.exc)
                if node.cause is not None:
                    self.visit(node.cause)
                if self.try_exception_state_stack:
                    self.try_exception_state_stack[-1].append(self._snapshot_state())

            def visit_Break(self, node: ast.Break) -> None:
                if self.loop_break_state_stack:
                    self.loop_break_state_stack[-1].append(self._snapshot_state())

            def visit_BoolOp(self, node: ast.BoolOp) -> None:
                possible_exit_states = []
                for index, value in enumerate(node.values):
                    self.visit(value)
                    value_state = self._snapshot_state()
                    if index == len(node.values) - 1:
                        possible_exit_states.append(value_state)
                        break
                    truthiness = self._resolved_static_truthiness(value)
                    if isinstance(node.op, ast.And) and truthiness is False:
                        possible_exit_states.append(value_state)
                        break
                    if isinstance(node.op, ast.Or) and truthiness is True:
                        possible_exit_states.append(value_state)
                        break
                    if truthiness is None:
                        possible_exit_states.append(value_state)

                merged_state = possible_exit_states[0]
                for possible_state in possible_exit_states[1:]:
                    merged_state = self._merge_states(merged_state, possible_state)
                self._restore_state(merged_state)

            def visit_IfExp(self, node: ast.IfExp) -> None:
                self.visit(node.test)
                truthiness = self._resolved_static_truthiness(node.test)
                if truthiness is True:
                    self.visit(node.body)
                    return
                if truthiness is False:
                    self.visit(node.orelse)
                    return
                initial_state = self._snapshot_state()
                self.visit(node.body)
                body_state = self._snapshot_state()
                self._restore_state(initial_state)
                self.visit(node.orelse)
                self._restore_state(self._merge_states(body_state, self._snapshot_state()))

            def _statement_definitely_terminates(self, statement: ast.stmt) -> bool:
                if isinstance(statement, ast.Return | ast.Raise | ast.Break | ast.Continue):
                    return True
                if isinstance(statement, ast.For | ast.AsyncFor):
                    return scanner._static_iterable_truthiness(
                        statement.iter
                    ) is True and self._statements_definitely_exit_scope(statement.body)
                if isinstance(statement, ast.While):
                    return self._resolved_static_truthiness(statement.test) is True and not self._loop_body_may_break(
                        statement.body
                    )
                if isinstance(statement, ast.Try):
                    if self._statements_definitely_terminate(statement.finalbody):
                        return True
                    if self._statements_definitely_do_not_raise(
                        statement.body
                    ) and self._statements_definitely_terminate(statement.orelse):
                        return True
                    normal_path_terminates = self._statements_definitely_terminate(
                        statement.body
                    ) or self._statements_definitely_terminate(statement.orelse)
                    return normal_path_terminates and all(
                        self._statements_definitely_terminate(handler.body) for handler in statement.handlers
                    )
                if not isinstance(statement, ast.If):
                    return False

                truthiness = self._resolved_static_truthiness(statement.test)
                if truthiness is True:
                    return self._statements_definitely_terminate(statement.body)
                if truthiness is False:
                    return self._statements_definitely_terminate(statement.orelse)
                return (
                    bool(statement.orelse)
                    and self._statements_definitely_terminate(statement.body)
                    and self._statements_definitely_terminate(statement.orelse)
                )

            def _statements_definitely_terminate(self, statements: list[ast.stmt]) -> bool:
                return any(self._statement_definitely_terminates(statement) for statement in statements)

            def _statement_definitely_exits_scope(self, statement: ast.stmt) -> bool:
                if isinstance(statement, ast.Return | ast.Raise):
                    return True
                if not isinstance(statement, ast.If):
                    return False
                truthiness = self._resolved_static_truthiness(statement.test)
                if truthiness is True:
                    return self._statements_definitely_exit_scope(statement.body)
                if truthiness is False:
                    return self._statements_definitely_exit_scope(statement.orelse)
                return (
                    bool(statement.orelse)
                    and self._statements_definitely_exit_scope(statement.body)
                    and self._statements_definitely_exit_scope(statement.orelse)
                )

            def _statements_definitely_exit_scope(self, statements: list[ast.stmt]) -> bool:
                return any(self._statement_definitely_exits_scope(statement) for statement in statements)

            def _statement_definitely_prevents_loop_else(self, statement: ast.stmt) -> bool:
                if isinstance(statement, ast.Break | ast.Return | ast.Raise):
                    return True
                if not isinstance(statement, ast.If):
                    return False
                truthiness = self._resolved_static_truthiness(statement.test)
                if truthiness is True:
                    return self._statements_definitely_prevent_loop_else(statement.body)
                if truthiness is False:
                    return self._statements_definitely_prevent_loop_else(statement.orelse)
                return (
                    bool(statement.orelse)
                    and self._statements_definitely_prevent_loop_else(statement.body)
                    and self._statements_definitely_prevent_loop_else(statement.orelse)
                )

            def _statements_definitely_prevent_loop_else(self, statements: list[ast.stmt]) -> bool:
                return any(self._statement_definitely_prevents_loop_else(statement) for statement in statements)

            @staticmethod
            def _expression_definitely_does_not_raise(node: ast.AST) -> bool:
                if isinstance(node, ast.Constant):
                    return True
                if isinstance(node, ast.List | ast.Tuple | ast.Set):
                    return all(
                        DynamicImportExecutionVisitor._expression_definitely_does_not_raise(element)
                        for element in node.elts
                    )
                if isinstance(node, ast.Dict):
                    return all(
                        (
                            isinstance(value, ast.Dict)
                            and DynamicImportExecutionVisitor._expression_definitely_does_not_raise(value)
                        )
                        if key is None
                        else DynamicImportExecutionVisitor._expression_definitely_does_not_raise(key)
                        for key, value in zip(node.keys, node.values, strict=True)
                    ) and all(
                        DynamicImportExecutionVisitor._expression_definitely_does_not_raise(value)
                        for value in node.values
                    )
                return False

            def _statement_definitely_exits_without_exception(self, statement: ast.stmt) -> bool:
                if isinstance(statement, ast.Return):
                    return statement.value is None or self._expression_definitely_does_not_raise(statement.value)
                if isinstance(statement, ast.Break | ast.Continue):
                    return True
                if not isinstance(statement, ast.If) or not self._expression_definitely_does_not_raise(statement.test):
                    return False

                truthiness = self._resolved_static_truthiness(statement.test)
                if truthiness is True:
                    return self._statements_definitely_exit_without_exception(statement.body)
                if truthiness is False:
                    return self._statements_definitely_exit_without_exception(statement.orelse)
                return (
                    bool(statement.orelse)
                    and self._statements_definitely_exit_without_exception(statement.body)
                    and self._statements_definitely_exit_without_exception(statement.orelse)
                )

            def _statements_definitely_exit_without_exception(self, statements: list[ast.stmt]) -> bool:
                for statement in statements:
                    if self._statement_definitely_exits_without_exception(statement):
                        return True
                    if not isinstance(statement, ast.Pass):
                        return False
                return False

            def _statements_definitely_do_not_raise(self, statements: list[ast.stmt]) -> bool:
                return all(self._statement_definitely_does_not_raise(statement) for statement in statements)

            def _statement_definitely_does_not_raise(self, statement: ast.stmt) -> bool:
                if isinstance(statement, ast.Pass | ast.Break | ast.Continue):
                    return True
                if isinstance(statement, ast.Expr):
                    return self._expression_definitely_does_not_raise(statement.value)
                if isinstance(statement, ast.Assign):
                    return all(isinstance(target, ast.Name) for target in statement.targets) and (
                        self._expression_definitely_does_not_raise(statement.value)
                    )
                if isinstance(statement, ast.Return):
                    return statement.value is None or self._expression_definitely_does_not_raise(statement.value)
                if isinstance(statement, ast.Delete):
                    return all(
                        isinstance(target, ast.Name)
                        and any(
                            target.id in aliases
                            for aliases in (
                                self.module_aliases,
                                self.callable_aliases,
                                self.import_loader_aliases,
                                self.import_aliases,
                                self.lazy_generator_aliases,
                                self.static_truthiness_aliases,
                                self.lambda_aliases,
                                self.literal_iterable_aliases,
                                self.function_definitions,
                            )
                        )
                        for target in statement.targets
                    )
                return False

            def _visit_try_body(self, statements: list[ast.stmt]) -> list[_DynamicAliasState]:
                exception_states: list[_DynamicAliasState] = []
                self.try_exception_state_stack.append(exception_states)
                try:
                    for statement in statements:
                        statement_cannot_raise = self._statement_definitely_does_not_raise(statement)
                        state_before_statement = self._snapshot_state()
                        self.visit(statement)
                        state_after_statement = self._snapshot_state()
                        if not statement_cannot_raise:
                            exception_states.extend((state_before_statement, state_after_statement))
                        if self._statement_definitely_terminates(statement):
                            break
                finally:
                    self.try_exception_state_stack.pop()
                return exception_states

            def _visit_statement_block(self, statements: list[ast.stmt]) -> None:
                for statement in statements:
                    self.visit(statement)
                    if self._statement_definitely_terminates(statement):
                        break

            @staticmethod
            def _loop_body_rebinds_target(target: ast.AST, body: list[ast.stmt]) -> bool:
                target_names = {child.id for child in ast.walk(target) if isinstance(child, ast.Name)}
                if not target_names:
                    return False

                class TargetBindingVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.rebound = False

                    def visit_Name(self, node: ast.Name) -> None:
                        if isinstance(node.ctx, ast.Store | ast.Del) and node.id in target_names:
                            self.rebound = True

                    def visit_Import(self, node: ast.Import) -> None:
                        self.rebound |= any(
                            (alias.asname or alias.name.split(".", maxsplit=1)[0]) in target_names
                            for alias in node.names
                        )

                    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                        self.rebound |= any(
                            alias.name != "*" and (alias.asname or alias.name) in target_names for alias in node.names
                        )

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        self.rebound |= node.name in target_names

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        self.rebound |= node.name in target_names

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        self.rebound |= node.name in target_names

                    def visit_Lambda(self, node: ast.Lambda) -> None:
                        return

                binding_visitor = TargetBindingVisitor()
                for statement in body:
                    binding_visitor.visit(statement)
                return binding_visitor.rebound

            def _loop_body_may_break(self, body: list[ast.stmt]) -> bool:
                visitor = self

                class BreakVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.found = False

                    def visit_Break(self, node: ast.Break) -> None:
                        self.found = True

                    def visit_If(self, node: ast.If) -> None:
                        truthiness = visitor._resolved_static_truthiness(node.test)
                        if truthiness is True:
                            for statement in node.body:
                                self.visit(statement)
                            return
                        if truthiness is False:
                            for statement in node.orelse:
                                self.visit(statement)
                            return
                        self.generic_visit(node)

                    def visit_Try(self, node: ast.Try) -> None:
                        if node.finalbody and visitor._statements_definitely_terminate(node.finalbody):
                            for statement in node.finalbody:
                                self.visit(statement)
                            return
                        self.generic_visit(node)

                    def visit_For(self, node: ast.For) -> None:
                        return

                    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
                        return

                    def visit_While(self, node: ast.While) -> None:
                        return

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        return

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        return

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        return

                    def visit_Lambda(self, node: ast.Lambda) -> None:
                        return

                break_visitor = BreakVisitor()
                for statement in body:
                    break_visitor.visit(statement)
                return break_visitor.found

            def _visit_consumed_generator_value(
                self,
                value: ast.AST,
                *,
                first_only: bool = False,
                short_circuit_on: bool | None = None,
            ) -> bool:
                if isinstance(value, ast.GeneratorExp):
                    self._visit_eager_generator_expression(
                        value,
                        first_only=first_only,
                        short_circuit_on=short_circuit_on,
                    )
                    return True
                if isinstance(value, ast.Name):
                    generators = self.lazy_generator_aliases.get(value.id)
                    for generator in generators or ():
                        self._visit_eager_generator_expression(
                            generator,
                            first_only=first_only,
                            short_circuit_on=short_circuit_on,
                        )
                    return bool(generators)
                if isinstance(value, ast.Attribute):
                    attribute_name = scanner._resolve_call_name(value)
                    generators = self.lazy_generator_aliases.get(attribute_name) if attribute_name is not None else None
                    for generator in generators or ():
                        self._visit_eager_generator_expression(
                            generator,
                            first_only=first_only,
                            short_circuit_on=short_circuit_on,
                        )
                    return bool(generators)
                if isinstance(value, ast.Call):
                    wrapper_name = scanner._resolve_call_name(value.func)
                    resolved_wrapper_name = (
                        scanner._apply_unshadowed_alias(
                            wrapper_name,
                            self.import_aliases,
                            self.shadowed_names,
                        )
                        if wrapper_name is not None
                        else None
                    )
                    if resolved_wrapper_name in _LAZY_CALLBACK_WRAPPERS:
                        expanded_args = scanner._expanded_literal_call_arguments(value.args)
                        valid_filter = (
                            resolved_wrapper_name.removeprefix("builtins.") == "filter"
                            and expanded_args is not None
                            and len(expanded_args) == 2
                            and not value.keywords
                        )
                        valid_map = (
                            resolved_wrapper_name.removeprefix("builtins.") == "map"
                            and expanded_args is not None
                            and len(expanded_args) >= 2
                            and not value.keywords
                        )
                        if valid_filter or valid_map:
                            assert expanded_args is not None
                            self.visit(value.func)
                            self.visit(expanded_args[0])
                            callback_arguments: list[ast.expr] = []
                            callback_arguments_known = True
                            iterable_elements = [
                                self._literal_iterable_elements(iterable) for iterable in expanded_args[1:]
                            ]
                            has_empty_input = any(elements == [] for elements in iterable_elements)
                            for iterable, elements in zip(expanded_args[1:], iterable_elements, strict=True):
                                if elements != [] and (elements is None or elements[0] is None):
                                    callback_arguments_known = False
                                elif elements:
                                    first_element = elements[0]
                                    if first_element is not None:
                                        callback_arguments.append(first_element)
                                if has_empty_input or not self._visit_consumed_generator_value(iterable):
                                    self.visit(iterable)
                            if not has_empty_input:
                                self._visit_callable_callback(
                                    expanded_args[0],
                                    callback_arguments if callback_arguments_known else None,
                                )
                            return True
                    if resolved_wrapper_name in _LAZY_GENERATOR_WRAPPERS:
                        consumed_generator = False
                        wrapped_first_only = first_only or short_circuit_on is True
                        self.visit(value.func)
                        for argument in value.args:
                            if self._visit_consumed_generator_value(
                                argument,
                                first_only=wrapped_first_only,
                            ):
                                consumed_generator = True
                            else:
                                self.visit(argument)
                        for keyword in value.keywords:
                            self.visit(keyword.value)
                        return consumed_generator
                return False

            def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
                if not self._visit_consumed_generator_value(node.iter):
                    self.visit(node.iter)
                literal_elements = self._literal_iterable_elements(node.iter)
                if isinstance(node, ast.AsyncFor) and (
                    literal_elements is not None
                    or (isinstance(node.iter, ast.Constant) and isinstance(node.iter.value, str | bytes))
                ):
                    return
                if scanner._static_iterable_truthiness(node.iter) is False:
                    self._visit_statement_block(node.orelse)
                    return
                model_first_iteration = bool(
                    literal_elements
                    and literal_elements[0] is not None
                    and self._statements_definitely_prevent_loop_else(node.body)
                )
                if model_first_iteration and literal_elements is not None:
                    first_element = literal_elements[0]
                    if first_element is not None:
                        self._record_target_assignment(node.target, first_element)
                else:
                    self._record_target_from_iterable(node.target, node.iter)
                self.loop_break_state_stack.append([])
                self._visit_statement_block(node.body)
                break_states = self.loop_break_state_stack.pop()
                if (
                    not model_first_iteration
                    and isinstance(node.iter, ast.List | ast.Tuple | ast.Dict)
                    and literal_elements
                    and all(element is not None for element in literal_elements)
                    and not self._loop_body_rebinds_target(node.target, node.body)
                    and not self._loop_body_may_break(node.body)
                ):
                    last_element = literal_elements[-1]
                    if last_element is not None:
                        self._record_target_assignment(node.target, last_element)
                if not (
                    scanner._static_iterable_truthiness(node.iter) is True
                    and self._statements_definitely_prevent_loop_else(node.body)
                ):
                    self._visit_statement_block(node.orelse)
                    if break_states:
                        self._restore_state(
                            self._merge_states(self._snapshot_state(), self._merge_state_list(break_states))
                        )
                elif break_states:
                    self._restore_state(self._merge_state_list(break_states))

            def visit_For(self, node: ast.For) -> None:
                self._visit_for(node)

            def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
                self._visit_for(node)

            def _visit_comprehension(
                self,
                generators: list[ast.comprehension],
                result_nodes: list[ast.AST],
                *,
                first_only: bool = False,
                short_circuit_on: bool | None = None,
            ) -> None:
                self._push_scope(set(), scope_kind="comprehension")
                literal_elements = self._literal_iterable_elements(generators[0].iter) if generators else None
                model_first_item = False
                if (
                    first_only
                    and len(generators) == 1
                    and not generators[0].ifs
                    and literal_elements
                    and literal_elements[0] is not None
                ):
                    model_first_item = True
                if (
                    not model_first_item
                    and short_circuit_on is not None
                    and len(generators) == 1
                    and not generators[0].ifs
                    and len(result_nodes) == 1
                    and literal_elements
                    and literal_elements[0] is not None
                ):
                    initial_state = self._snapshot_state()
                    first_element = literal_elements[0]
                    assert first_element is not None
                    self._record_target_assignment(generators[0].target, first_element)
                    result_truthiness = self._resolved_static_truthiness(result_nodes[0])
                    if (
                        result_truthiness is None
                        and isinstance(generators[0].target, ast.Name)
                        and isinstance(first_element, ast.Lambda)
                        and isinstance(result_nodes[0], ast.Call)
                        and not result_nodes[0].args
                        and not result_nodes[0].keywords
                        and scanner._resolve_call_name(result_nodes[0].func) == generators[0].target.id
                    ):
                        result_truthiness = self._resolved_static_truthiness(first_element.body)
                    self._restore_state(initial_state)
                    model_first_item = result_truthiness is short_circuit_on
                for generator_index, generator in enumerate(generators):
                    if not self._visit_consumed_generator_value(generator.iter):
                        self.visit(generator.iter)
                    if scanner._static_iterable_truthiness(generator.iter) is False:
                        self._pop_scope()
                        return
                    if model_first_item and generator_index == 0 and literal_elements is not None:
                        current_first_element = literal_elements[0]
                        if current_first_element is not None:
                            self._record_target_assignment(generator.target, current_first_element)
                    else:
                        self._record_target_from_iterable(generator.target, generator.iter)
                    for condition in generator.ifs:
                        self.visit(condition)
                        if self._resolved_static_truthiness(condition) is False:
                            self._pop_scope()
                            return
                for result_node in result_nodes:
                    self.visit(result_node)
                self._pop_scope()

            def visit_ListComp(self, node: ast.ListComp) -> None:
                self._visit_comprehension(node.generators, [node.elt])

            def visit_SetComp(self, node: ast.SetComp) -> None:
                self._visit_comprehension(node.generators, [node.elt])

            def _visit_eager_generator_expression(
                self,
                node: ast.GeneratorExp,
                *,
                first_only: bool = False,
                short_circuit_on: bool | None = None,
            ) -> None:
                generator_id = id(node)
                if generator_id in self.active_generator_ids:
                    return
                self.active_generator_ids.add(generator_id)
                try:
                    self._visit_comprehension(
                        node.generators,
                        [node.elt],
                        first_only=first_only,
                        short_circuit_on=short_circuit_on,
                    )
                finally:
                    self.active_generator_ids.remove(generator_id)

            def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
                if node.generators:
                    self.visit(node.generators[0].iter)

            def visit_DictComp(self, node: ast.DictComp) -> None:
                self._visit_comprehension(node.generators, [node.key, node.value])

            def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
                if not self._visit_consumed_generator_value(node.value):
                    self.visit(node.value)

            def visit_Starred(self, node: ast.Starred) -> None:
                if not self._visit_consumed_generator_value(node.value):
                    self.visit(node.value)

            def visit_If(self, node: ast.If) -> None:
                self.visit(node.test)
                truthiness = self._resolved_static_truthiness(node.test)
                if truthiness is True:
                    self._visit_statement_block(node.body)
                    return
                if truthiness is False:
                    self._visit_statement_block(node.orelse)
                    return
                if scanner._is_non_executing_import_guard(
                    node,
                    self.import_aliases,
                    self.shadowed_names,
                ):
                    self._visit_statement_block(node.orelse)
                    return
                initial_state = self._snapshot_state()
                self._visit_statement_block(node.body)
                body_state = self._snapshot_state()
                body_terminates = self._statements_definitely_terminate(node.body)
                self._restore_state(initial_state)
                self._visit_statement_block(node.orelse)
                orelse_state = self._snapshot_state()
                orelse_terminates = self._statements_definitely_terminate(node.orelse)
                continuing_states = []
                if not body_terminates:
                    continuing_states.append(body_state)
                if not orelse_terminates:
                    continuing_states.append(orelse_state)
                if not continuing_states:
                    self._restore_state(initial_state)
                    return
                merged_state = continuing_states[0]
                for continuing_state in continuing_states[1:]:
                    merged_state = self._merge_states(merged_state, continuing_state)
                self._restore_state(merged_state)

            def visit_While(self, node: ast.While) -> None:
                self.visit(node.test)
                truthiness = self._resolved_static_truthiness(node.test)
                if truthiness is False:
                    self._visit_statement_block(node.orelse)
                    return

                initial_state = self._snapshot_state()
                self.loop_break_state_stack.append([])
                self._visit_statement_block(node.body)
                break_states = self.loop_break_state_stack.pop()
                body_state = self._snapshot_state()
                if truthiness is True:
                    if break_states:
                        self._restore_state(self._merge_state_list(break_states))
                    return

                self._restore_state(self._merge_states(initial_state, body_state))
                self._visit_statement_block(node.orelse)
                normal_exit_state = self._merge_states(body_state, self._snapshot_state())
                if break_states:
                    normal_exit_state = self._merge_states(normal_exit_state, self._merge_state_list(break_states))
                self._restore_state(normal_exit_state)

            def _visit_try(self, node: _DynamicTryNode, *, sequential_handlers: bool) -> None:
                break_state_start = len(self.loop_break_state_stack[-1]) if self.loop_break_state_stack else None
                initial_state = self._snapshot_state()
                body_exits_without_exception = self._statements_definitely_exit_without_exception(node.body)
                body_cannot_raise = self._statements_definitely_do_not_raise(node.body)
                exception_states = self._visit_try_body(node.body)
                body_state = self._snapshot_state()
                body_terminates = self._statements_definitely_terminate(node.body)
                possible_states = []
                if not body_terminates:
                    self._visit_statement_block(node.orelse)
                    if not self._statements_definitely_terminate(node.orelse):
                        possible_states.append(self._snapshot_state())

                handler_initial_state = (
                    self._merge_state_list(exception_states)
                    if exception_states
                    else self._merge_states(initial_state, body_state)
                )
                if not body_exits_without_exception and not body_cannot_raise:
                    handler_state = handler_initial_state
                    for handler in node.handlers:
                        self._restore_state(handler_state if sequential_handlers else handler_initial_state)
                        if handler.type is not None:
                            self.visit(handler.type)
                        if handler.name is not None:
                            self._invalidate_name(handler.name)
                        self._visit_statement_block(handler.body)
                        if handler.name is not None:
                            self._invalidate_name(handler.name)
                        handled_state = self._snapshot_state()
                        if sequential_handlers:
                            handler_state = self._merge_states(handler_state, handled_state)
                        else:
                            possible_states.append(handled_state)
                    if sequential_handlers:
                        possible_states.append(handler_state)

                if possible_states:
                    merged_state = possible_states[0]
                    for possible_state in possible_states[1:]:
                        merged_state = self._merge_states(merged_state, possible_state)
                    self._restore_state(merged_state)
                else:
                    self._restore_state(body_state)

                pending_break_states: list[_DynamicAliasState] = []
                if break_state_start is not None:
                    pending_break_states = self.loop_break_state_stack[-1][break_state_start:]
                    del self.loop_break_state_stack[-1][break_state_start:]
                normal_exit_state = self._snapshot_state()
                transformed_break_states: list[_DynamicAliasState] = []
                for break_state in pending_break_states:
                    # A finally block runs before the pending break leaves the loop.
                    self._restore_state(break_state)
                    nested_break_start = len(self.loop_break_state_stack[-1])
                    self._visit_statement_block(node.finalbody)
                    nested_break_states = self.loop_break_state_stack[-1][nested_break_start:]
                    del self.loop_break_state_stack[-1][nested_break_start:]
                    transformed_break_states.extend(nested_break_states)
                    if not self._statements_definitely_terminate(node.finalbody):
                        transformed_break_states.append(self._snapshot_state())

                self._restore_state(normal_exit_state)
                self._visit_statement_block(node.finalbody)
                if self.loop_break_state_stack:
                    self.loop_break_state_stack[-1].extend(transformed_break_states)

            def visit_Try(self, node: _DynamicTryNode) -> None:
                self._visit_try(node, sequential_handlers=False)

            def visit_TryStar(self, node: _DynamicTryNode) -> None:
                self._visit_try(node, sequential_handlers=True)

            def visit_Match(self, node: ast.Match) -> None:
                self.visit(node.subject)
                remaining_state: _DynamicAliasState | None = self._snapshot_state()
                possible_states: list[_DynamicAliasState] = []
                for case in node.cases:
                    if remaining_state is None:
                        break
                    case_initial_state = remaining_state
                    self._restore_state(case_initial_state)
                    if self._pattern_definitely_does_not_match(case.pattern, node.subject):
                        continue
                    case_definitely_matches = self._pattern_definitely_matches(
                        case.pattern,
                        node.subject,
                    )
                    self._record_pattern_assignment(case.pattern, node.subject)
                    guard_truthiness: bool | None = True
                    if case.guard is not None:
                        self.visit(case.guard)
                        guard_state = self._snapshot_state()
                        guard_truthiness = self._resolved_static_truthiness(case.guard)
                    else:
                        guard_state = self._snapshot_state()

                    if guard_truthiness is not False:
                        self._visit_statement_block(case.body)
                        possible_states.append(self._snapshot_state())

                    continuing_states: list[_DynamicAliasState] = []
                    if not case_definitely_matches:
                        continuing_states.append(case_initial_state)
                    if case.guard is not None and guard_truthiness is not True:
                        continuing_states.append(guard_state)
                    if not continuing_states:
                        remaining_state = None
                        break
                    remaining_state = continuing_states[0]
                    for continuing_state in continuing_states[1:]:
                        remaining_state = self._merge_states(remaining_state, continuing_state)

                if remaining_state is not None:
                    possible_states.append(remaining_state)
                if not possible_states:
                    return
                merged_state = possible_states[0]
                for possible_state in possible_states[1:]:
                    merged_state = self._merge_states(merged_state, possible_state)
                self._restore_state(merged_state)

            @staticmethod
            def _nullcontext_enter_result(call: ast.Call) -> ast.expr | None:
                if len(call.args) == 1 and not call.keywords:
                    return call.args[0]
                if not call.args and len(call.keywords) == 1 and call.keywords[0].arg == "enter_result":
                    return call.keywords[0].value
                return None

            def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
                for item in node.items:
                    self.visit(item.context_expr)
                    if item.optional_vars is not None:
                        bound_value: ast.expr | None = None
                        if isinstance(item.context_expr, ast.Call):
                            helper_name = scanner._resolve_call_name(item.context_expr.func)
                            helper_roots = self._function_aware_roots(item.context_expr.func)
                            if helper_name is not None:
                                helper_roots |= frozenset(
                                    {
                                        scanner._apply_unshadowed_alias(
                                            helper_name,
                                            self.import_aliases,
                                            self.shadowed_names,
                                        )
                                    }
                                )
                            if "contextlib.nullcontext" in helper_roots:
                                enter_result = self._nullcontext_enter_result(item.context_expr)
                                if enter_result is not None:
                                    bound_value = enter_result
                        if bound_value is None:
                            self._invalidate_target(item.optional_vars)
                        else:
                            self._record_target_assignment(item.optional_vars, bound_value)
                self._visit_statement_block(node.body)

            def visit_With(self, node: ast.With) -> None:
                self._visit_with(node)

            def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
                self._visit_with(node)

            @staticmethod
            def _eager_generator_argument_indexes(
                node: ast.Call,
                resolved_call_name: str | None,
            ) -> set[int]:
                if resolved_call_name is None:
                    return set()
                expanded_args = scanner._expanded_literal_call_arguments(node.args)
                if expanded_args is None:
                    return set()

                consumer_name = resolved_call_name.removeprefix("builtins.")
                keyword_names = [keyword.arg for keyword in node.keywords]
                if any(keyword_name is None for keyword_name in keyword_names):
                    return set()
                named_keywords = {keyword_name for keyword_name in keyword_names if keyword_name is not None}
                if len(named_keywords) != len(keyword_names):
                    return set()

                if consumer_name in {"all", "any", "frozenset", "list", "set", "tuple"}:
                    return {0} if len(expanded_args) == 1 and not keyword_names else set()
                if consumer_name == "dict":
                    return {0} if len(expanded_args) == 1 else set()
                if consumer_name == "sorted":
                    return {0} if len(expanded_args) == 1 and named_keywords <= {"key", "reverse"} else set()
                if consumer_name == "sum":
                    if len(expanded_args) not in {1, 2} or named_keywords - {"start"}:
                        return set()
                    if len(expanded_args) == 2 and "start" in named_keywords:
                        return set()
                    return {0}
                if consumer_name in {"max", "min"}:
                    return {0} if len(expanded_args) == 1 and named_keywords <= {"default", "key"} else set()
                if consumer_name == "next":
                    return {0} if len(expanded_args) in {1, 2} and not keyword_names else set()
                return set()

            def visit_Call(self, node: ast.Call) -> None:
                call_name = scanner._resolve_call_name(node.func)
                called_functions = self.function_definition_stack[-1].get(call_name) if call_name is not None else None
                lambda_nodes = self._lambda_nodes_for_callable(node.func)
                lambda_call_names = frozenset(
                    call_name
                    for lambda_node in lambda_nodes
                    for call_name in self._lambda_execution_calls(lambda_node, node)
                )
                call_names = scanner._resolve_dynamic_import_execution_calls(
                    node.func,
                    self.import_aliases,
                    self.module_aliases,
                    self.callable_aliases,
                    self.import_loader_aliases,
                    self.shadowed_names,
                )
                call_names |= frozenset(
                    normalized_name
                    for root in self._function_aware_roots(node.func)
                    if (normalized_name := _normalized_high_risk_python_call_name(root)) is not None
                )
                call_names |= lambda_call_names
                self.risky_calls.update(call_names)
                resolved_call_names = (
                    self.import_loader_aliases.get(call_name, frozenset()) if call_name is not None else frozenset()
                )
                if (
                    call_name is not None
                    and not resolved_call_names
                    and call_name.split(".", maxsplit=1)[0] not in self.shadowed_names
                ):
                    resolved_call_names = frozenset(
                        {
                            scanner._apply_unshadowed_alias(
                                call_name,
                                self.import_aliases,
                                self.shadowed_names,
                            )
                        }
                    )
                consumed_generator_indexes: set[int] = set()
                for resolved_call_name in resolved_call_names:
                    consumed_generator_indexes.update(
                        self._eager_generator_argument_indexes(
                            node,
                            resolved_call_name,
                        )
                    )
                consume_first_only = bool(resolved_call_names) and all(
                    resolved_call_name.removeprefix("builtins.") == "next" for resolved_call_name in resolved_call_names
                )
                consumer_names = {
                    resolved_call_name.removeprefix("builtins.") for resolved_call_name in resolved_call_names
                }
                key_keywords = [keyword for keyword in node.keywords if keyword.arg == "key"]
                if len(key_keywords) == 1 and consumer_names & {"max", "min", "sorted"}:
                    callback_arguments: list[ast.expr] | None = None
                    callback_may_run = False
                    if "sorted" in consumer_names and len(node.args) == 1:
                        elements = self._literal_iterable_elements(node.args[0])
                        callback_may_run = elements != []
                        if elements and elements[0] is not None:
                            callback_arguments = [elements[0]]
                    if not callback_may_run and consumer_names & {"max", "min"}:
                        expanded_callback_args = scanner._expanded_literal_call_arguments(node.args)
                        if expanded_callback_args:
                            if len(expanded_callback_args) == 1:
                                elements = self._literal_iterable_elements(expanded_callback_args[0])
                                callback_may_run = elements != []
                                if elements and elements[0] is not None:
                                    callback_arguments = [elements[0]]
                            else:
                                callback_may_run = True
                                callback_arguments = [expanded_callback_args[0]]
                    if callback_may_run:
                        self._visit_callable_callback(key_keywords[0].value, callback_arguments)
                if (
                    len(key_keywords) == 1
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "sort"
                    and not node.args
                    and all(keyword.arg in {"key", "reverse"} for keyword in node.keywords)
                ):
                    for list_node in self._list_nodes_for_value(node.func.value):
                        if list_node.elts:
                            callback_arguments = (
                                None if isinstance(list_node.elts[0], ast.Starred) else [list_node.elts[0]]
                            )
                            self._visit_callable_callback(key_keywords[0].value, callback_arguments)
                short_circuit_on = True if consumer_names == {"any"} else False if consumer_names == {"all"} else None
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"__next__", "send"}:
                    self._visit_consumed_generator_value(node.func.value, first_only=True)
                self.visit(node.func)
                expanded_args = (
                    scanner._expanded_literal_call_arguments(node.args)
                    if any(isinstance(argument, ast.Starred) for argument in node.args)
                    else node.args
                )
                arguments_to_visit = expanded_args if expanded_args is not None else node.args
                for argument_index, argument in enumerate(arguments_to_visit):
                    if not (
                        argument_index in consumed_generator_indexes
                        and self._visit_consumed_generator_value(
                            argument,
                            first_only=consume_first_only,
                            short_circuit_on=short_circuit_on,
                        )
                    ):
                        self.visit(argument)
                for keyword in node.keywords:
                    self.visit(keyword.value)
                resolved_direct_call_name = (
                    scanner._apply_unshadowed_alias(
                        call_name,
                        self.import_aliases,
                        self.shadowed_names,
                    )
                    if call_name is not None
                    else None
                )
                if (
                    resolved_direct_call_name in {"builtins.setattr", "setattr"}
                    and call_name is not None
                    and call_name.split(".", maxsplit=1)[0] not in self.shadowed_names
                    and expanded_args is not None
                    and len(expanded_args) == 3
                    and not node.keywords
                ):
                    target_name = scanner._resolve_call_name(expanded_args[0])
                    attribute_name = scanner._static_string_value(expanded_args[1])
                    if target_name is not None and attribute_name is not None:
                        self._record_name_assignment(f"{target_name}.{attribute_name}", expanded_args[2])
                if called_functions is not None:
                    initial_state = self._snapshot_state()
                    side_effect_states: list[_DynamicAliasState] = []
                    for called_function in called_functions:
                        self._restore_state(initial_state)
                        self._apply_called_function_side_effects(called_function, node)
                        side_effect_states.append(self._snapshot_state())
                    if side_effect_states:
                        self._restore_state(self._merge_state_list(side_effect_states))

        visitor = DynamicImportExecutionVisitor()
        visitor.visit(tree)
        return visitor.risky_calls

    def _find_high_risk_calls(self, source_bytes: bytes) -> tuple[set[str], str | None]:
        tree, parse_error = self._parse_python_source(source_bytes)
        if tree is None:
            return set(), parse_error

        return self._find_high_risk_calls_from_tree(tree), None

    @staticmethod
    def _add_executable_extra_file_finding(
        result: ScanResult,
        *,
        archive_path: str,
        member_name: str,
        rule_code: str,
    ) -> None:
        result.add_check(
            name="TorchServe Executable Extra File Detection",
            passed=False,
            message=f"Executable file found in TorchServe MAR extraFiles member: {member_name}",
            severity=IssueSeverity.WARNING,
            rule_code=rule_code,
            location=f"{archive_path}:{member_name}",
            details={"entry": member_name, "manifest_field": "extraFiles"},
        )

    @classmethod
    def _add_skipped_named_executable_extra_file_findings(
        cls,
        result: ScanResult,
        *,
        archive_path: str,
        member_infos: list[zipfile.ZipInfo],
        extra_file_refs: set[str],
    ) -> None:
        for member_info in member_infos:
            member_name = member_info.filename
            normalized_member = cls._normalize_member_name(member_name)
            if not member_name or member_name.endswith("/") or normalized_member not in extra_file_refs:
                continue

            rule_code = executable_archive_member_name_rule_code(normalized_member)
            if rule_code is not None:
                cls._add_executable_extra_file_finding(
                    result,
                    archive_path=archive_path,
                    member_name=member_name,
                    rule_code=rule_code,
                )

    def _scan_archive_members(
        self,
        archive_path: str,
        archive: zipfile.ZipFile,
        member_infos: list[zipfile.ZipInfo],
        manifest_context: dict[str, Any],
        result: ScanResult,
        current_depth: int,
    ) -> None:
        contents: list[dict[str, Any]] = []
        serialized_refs = {
            self._normalize_member_name(path)
            for path in manifest_context.get("serialized_paths", [])
            if self._is_path_like_reference("serializedFile", path)
        }
        extra_file_refs = {
            self._normalize_member_name(path)
            for field, path in manifest_context.get("path_references", [])
            if field == "extraFiles" and self._is_path_like_reference(field, path)
        }
        archive_member_names = {
            self._normalize_member_name(info.filename)
            for info in member_infos
            if info.filename and not info.filename.endswith("/")
        }
        referenced_payloads = {
            self._normalize_member_name(path)
            for field, path in manifest_context.get("path_references", [])
            if field in {"serializedFile", "extraFiles"}
            and self._is_path_like_reference(field, path)
            and self._normalize_member_name(path) in archive_member_names
        }
        scanned_referenced_payloads: set[str] = set()
        serialized_findings: dict[str, list[IssueSeverity]] = {}

        total_entries = len(member_infos)
        if total_entries > self.max_entries:
            result.add_check(
                name="TorchServe MAR Entry Limit",
                passed=False,
                message=(
                    f"Archive contains {total_entries} entries, exceeding max processed entries ({self.max_entries})"
                ),
                severity=IssueSeverity.INFO,
                location=archive_path,
                details={
                    "entry_count": total_entries,
                    "max_entries": self.max_entries,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_mar_entry_limit",
                },
            )
            mark_inconclusive_scan_result(result, "torchserve_mar_entry_limit")
            entries_to_process = member_infos[: self.max_entries]
            self._add_skipped_named_executable_extra_file_findings(
                result,
                archive_path=archive_path,
                member_infos=member_infos[self.max_entries :],
                extra_file_refs=extra_file_refs,
            )
        else:
            result.add_check(
                name="TorchServe MAR Entry Limit",
                passed=True,
                message="Archive entry count is within configured limits",
                location=archive_path,
                details={"entry_count": total_entries, "max_entries": self.max_entries},
            )
            entries_to_process = member_infos

        processed_uncompressed = 0
        analyzable_member_lookup: dict[str, list[zipfile.ZipInfo]] = {}
        requirements_member_lookup = self._build_requirements_member_lookup(member_infos)
        for member_index, member_info in enumerate(entries_to_process):
            self.check_interrupted()

            member_name = member_info.filename
            normalized_member = self._normalize_member_name(member_name)

            if not member_name or member_name.endswith("/"):
                continue

            named_executable_rule_code = (
                executable_archive_member_name_rule_code(normalized_member)
                if normalized_member in extra_file_refs
                else None
            )

            if PurePosixPath(normalized_member).name == "requirements.txt":
                self._analyze_requirements_txt(
                    archive_path=archive_path,
                    archive=archive,
                    member_info=member_info,
                    members_by_normalized=requirements_member_lookup,
                    normalized_member=normalized_member,
                    result=result,
                )

            processed_uncompressed += max(member_info.file_size, 0)
            if processed_uncompressed > self.max_uncompressed_bytes:
                result.add_check(
                    name="TorchServe MAR Uncompressed Size Budget",
                    passed=False,
                    message=(
                        "Archive uncompressed byte budget exceeded "
                        f"({processed_uncompressed} > {self.max_uncompressed_bytes})"
                    ),
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{member_name}",
                    details={
                        "processed_uncompressed": processed_uncompressed,
                        "max_uncompressed_bytes": self.max_uncompressed_bytes,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "torchserve_mar_uncompressed_budget",
                    },
                )
                mark_inconclusive_scan_result(result, "torchserve_mar_uncompressed_budget")
                self._add_skipped_named_executable_extra_file_findings(
                    result,
                    archive_path=archive_path,
                    member_infos=entries_to_process[member_index:],
                    extra_file_refs=extra_file_refs,
                )
                break

            if member_info.compress_size > 0:
                compression_ratio = member_info.file_size / member_info.compress_size
                if compression_ratio > 100:
                    result.add_check(
                        name="TorchServe MAR Compression Ratio Check",
                        passed=False,
                        message=(
                            f"Suspicious compression ratio ({compression_ratio:.1f}x) in archive entry: {member_name}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{archive_path}:{member_name}",
                        details={
                            "entry": member_name,
                            "compressed_size": member_info.compress_size,
                            "uncompressed_size": member_info.file_size,
                            "ratio": compression_ratio,
                            "threshold": 100,
                        },
                    )

            temp_base = os.path.join(tempfile.gettempdir(), "extract_mar")
            resolved_member, is_safe_path = sanitize_archive_path(member_name, temp_base)
            if not is_safe_path:
                result.add_check(
                    name="TorchServe MAR Path Traversal Protection",
                    passed=False,
                    message=f"Archive entry attempted path traversal outside extraction root: {member_name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}:{member_name}",
                    details={
                        "entry": member_name,
                        "cve_id": "CVE-2023-48299",
                        "cvss": 7.5,
                        "cwe": "CWE-22",
                        "description": (
                            "TorchServe MAR archives with traversal entries can write files outside the "
                            "intended extraction directory."
                        ),
                        "remediation": (
                            "Upgrade TorchServe to a patched version and reject .mar archives containing "
                            "absolute paths or parent-directory traversal."
                        ),
                    },
                    why=(
                        "CVE-2023-48299 is a ZipSlip-style TorchServe MAR extraction vulnerability. "
                        "This archive member would escape the extraction root if extracted naively."
                    ),
                )
                continue

            is_symlink = (member_info.external_attr >> 16) & 0o170000 == stat.S_IFLNK
            if is_symlink:
                self._check_symlink_target(
                    archive_path=archive_path,
                    archive=archive,
                    member_info=member_info,
                    resolved_member_path=resolved_member,
                    result=result,
                )
                continue

            analyzable_member_lookup.setdefault(normalized_member, []).append(member_info)

            try:
                temp_path, total_size = self._extract_member_to_tempfile(
                    archive=archive,
                    member_info=member_info,
                    max_bytes=self.max_member_bytes,
                )
            except ValueError as exc:
                result.add_check(
                    name="TorchServe MAR Member Size Limit",
                    passed=False,
                    message=str(exc),
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{member_name}",
                    details={
                        "entry": member_name,
                        "max_member_bytes": self.max_member_bytes,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "torchserve_mar_member_size_limit",
                    },
                )
                mark_inconclusive_scan_result(result, "torchserve_mar_member_size_limit")
                if named_executable_rule_code is not None:
                    self._add_executable_extra_file_finding(
                        result,
                        archive_path=archive_path,
                        member_name=member_name,
                        rule_code=named_executable_rule_code,
                    )
                continue
            except Exception as exc:
                result.add_check(
                    name="TorchServe MAR Member Extraction",
                    passed=False,
                    message=f"Failed to extract archive member for scanning: {exc!s}",
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{member_name}",
                    details={
                        "entry": member_name,
                        "exception_type": type(exc).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "torchserve_mar_member_extraction_failed",
                    },
                )
                mark_inconclusive_scan_result(result, "torchserve_mar_member_extraction_failed")
                if named_executable_rule_code is not None:
                    self._add_executable_extra_file_finding(
                        result,
                        archive_path=archive_path,
                        member_name=member_name,
                        rule_code=named_executable_rule_code,
                    )
                continue

            try:
                from .. import core

                executable_rule_code = (
                    executable_archive_member_rule_code(normalized_member, temp_path)
                    if normalized_member in extra_file_refs
                    else None
                )
                if executable_rule_code is not None:
                    self._add_executable_extra_file_finding(
                        result,
                        archive_path=archive_path,
                        member_name=member_name,
                        rule_code=executable_rule_code,
                    )

                nested_config = dict(self.config)
                nested_config["_mar_depth"] = current_depth + 1
                nested_config["_archive_depth"] = current_depth + 1
                # Extracted members are deleted below, so their temporary paths cannot be reused as cache keys.
                nested_config["cache_enabled"] = False
                file_result = core.scan_file(temp_path, nested_config)
                self._rewrite_scan_locations(
                    file_result=file_result,
                    temp_path=temp_path,
                    archive_path=archive_path,
                    member_name=member_name,
                )
                result.merge_member_result(file_result, member_name)

                asset_entry = asset_from_scan_result(f"{archive_path}:{member_name}", file_result)
                asset_entry.setdefault("size", member_info.file_size)
                contents.append(asset_entry)

                if file_result.scanner_name == "unknown":
                    result.bytes_scanned += total_size

                if normalized_member in referenced_payloads:
                    scanned_referenced_payloads.add(normalized_member)

                if normalized_member in serialized_refs:
                    severities = [
                        issue.severity
                        for issue in file_result.issues
                        if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
                    ]
                    if severities:
                        serialized_findings[normalized_member] = severities
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(temp_path)

        handler_members = self._resolve_handler_members(
            member_set=set(analyzable_member_lookup),
            handler_paths=manifest_context.get("handler_paths", []),
        )
        self._analyze_non_handler_python_files(
            archive_path=archive_path,
            archive=archive,
            member_lookup=analyzable_member_lookup,
            handler_members=handler_members,
            handler_trees=manifest_context.get("handler_trees", {}),
            result=result,
        )

        unscanned_referenced_payloads = referenced_payloads - scanned_referenced_payloads
        if unscanned_referenced_payloads:
            mark_inconclusive_scan_result(result, "torchserve_mar_manifest_payload_scan_incomplete")
            result.add_check(
                name="TorchServe Manifest Referenced Payload Coverage",
                passed=False,
                message="Manifest-referenced payloads were not fully scanned",
                severity=IssueSeverity.INFO,
                location=archive_path,
                details={
                    "unscanned_payload_members": sorted(unscanned_referenced_payloads),
                    "analysis_incomplete": True,
                },
            )

        if serialized_refs and not (serialized_refs - scanned_referenced_payloads):
            if serialized_findings:
                highest_severity = IssueSeverity.WARNING
                if any(
                    severity == IssueSeverity.CRITICAL
                    for severities in serialized_findings.values()
                    for severity in severities
                ):
                    highest_severity = IssueSeverity.CRITICAL

                result.add_check(
                    name="TorchServe Serialized Payload Security",
                    passed=False,
                    message="Serialized payload referenced by manifest produced embedded scanner findings",
                    severity=highest_severity,
                    location=archive_path,
                    details={"flagged_serialized_members": sorted(serialized_findings.keys())},
                )
            else:
                result.add_check(
                    name="TorchServe Serialized Payload Security",
                    passed=True,
                    message="No embedded scanner findings for manifest-referenced serialized payloads",
                    location=archive_path,
                    details={"serialized_members": sorted(serialized_refs)},
                )

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(archive_path)

    def _analyze_requirements_txt(
        self,
        archive_path: str,
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        members_by_normalized: dict[str, list[zipfile.ZipInfo]],
        normalized_member: str,
        result: ScanResult,
    ) -> None:
        location = f"{archive_path}:{normalized_member}"
        member_details = self._build_member_details(
            member_info=member_info,
            normalized_member=normalized_member,
        )
        requirement_findings, incomplete_members = self._collect_requirements_findings(
            archive,
            members_by_normalized,
            member_info,
            normalized_member,
            visited=set(),
        )

        if requirement_findings:
            highest_severity = (
                IssueSeverity.CRITICAL
                if any(finding["severity"] == IssueSeverity.CRITICAL for finding in requirement_findings)
                else IssueSeverity.WARNING
            )
            result.add_check(
                name="TorchServe Requirements Supply Chain Analysis",
                passed=False,
                message="requirements.txt contains potential supply-chain attack patterns",
                severity=highest_severity,
                location=location,
                details={**member_details, "findings": requirement_findings},
            )

        if incomplete_members:
            mark_inconclusive_scan_result(result, "torchserve_requirements_size_limit")
            result.add_check(
                name="TorchServe Requirements Supply Chain Coverage",
                passed=False,
                message="requirements.txt analysis was incomplete because a referenced file exceeded the size limit",
                severity=IssueSeverity.INFO,
                location=location,
                details={
                    **member_details,
                    "incomplete_requirements_members": incomplete_members,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_requirements_size_limit",
                },
            )

        if requirement_findings or incomplete_members:
            return

        result.add_check(
            name="TorchServe Requirements Supply Chain Analysis",
            passed=True,
            message="requirements.txt does not contain known supply-chain attack patterns",
            location=location,
            details=member_details,
        )

    @classmethod
    def _build_requirements_member_lookup(
        cls,
        member_infos: list[zipfile.ZipInfo],
    ) -> dict[str, list[zipfile.ZipInfo]]:
        members_by_normalized: dict[str, list[zipfile.ZipInfo]] = {}
        for member_info in member_infos:
            if member_info.is_dir() or not member_info.filename:
                continue
            include_key = cls._normalize_archive_member_name(member_info.filename)
            members_by_normalized.setdefault(include_key, []).append(member_info)
        return members_by_normalized

    @classmethod
    def _normalize_archive_member_name(cls, member_name: str) -> str:
        return posixpath.normpath(cls._normalize_member_name(member_name))

    def _resolve_local_requirements_reference(self, current_member: str, reference: str) -> str | None:
        stripped_reference = reference.strip().strip("'\"")
        if not stripped_reference:
            return None
        if URL_SCHEME_PATTERN.match(stripped_reference):
            return None

        normalized_reference = stripped_reference.replace("\\", "/")
        if re.match(r"^[a-zA-Z]:/", normalized_reference) or normalized_reference.startswith("/"):
            return None

        current_dir = posixpath.dirname(current_member)
        resolved = posixpath.normpath(posixpath.join(current_dir, normalized_reference))
        if resolved in {"", "."} or resolved.startswith("../"):
            return None
        return resolved

    def _is_external_requirements_reference(self, reference: str) -> bool:
        stripped_reference = reference.strip().strip("'\"")
        if not stripped_reference:
            return False

        if URL_SCHEME_PATTERN.match(stripped_reference):
            parsed = urlparse(stripped_reference)
            return parsed.scheme.lower() == "file"

        normalized_reference = stripped_reference.replace("\\", "/")
        if re.match(r"^[a-zA-Z]:/", normalized_reference) or normalized_reference.startswith("/"):
            return True

        return posixpath.normpath(normalized_reference).startswith("../")

    def _strip_inline_requirement_comment(self, line: str) -> str:
        in_single_quote = False
        in_double_quote = False
        escaped = False

        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if (
                char == "#"
                and not in_single_quote
                and not in_double_quote
                and (index == 0 or line[index - 1].isspace())
            ):
                return line[:index].strip()

        return line.strip()

    def _extract_direct_requirement_url(self, line: str) -> str | None:
        direct_url = line.strip()
        if not direct_url:
            return None

        direct_reference_match = re.match(r"^[A-Za-z0-9_.\-\[\],]+\s*@\s*(.+)$", direct_url)
        if direct_reference_match is not None:
            direct_url = direct_reference_match.group(1).strip()

        direct_url = direct_url.split(";", 1)[0].strip()
        if not direct_url:
            return None

        if not self._is_remote_requirement_url(direct_url):
            return None

        return direct_url

    def _build_requirements_finding(
        self,
        *,
        requirements_file: str,
        line_number: int,
        line_content: str,
        severity: IssueSeverity,
        reason: str,
        message: str,
    ) -> dict[str, Any]:
        return {
            "line": line_number,
            "line_content": line_content,
            "requirements_file": requirements_file,
            "severity": severity,
            "reason": reason,
            "message": message,
        }

    def _collect_requirements_findings(
        self,
        archive: zipfile.ZipFile,
        members_by_normalized: dict[str, list[zipfile.ZipInfo]],
        member_info: zipfile.ZipInfo,
        normalized_member: str,
        *,
        visited: set[tuple[str, int]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        visit_key = (member_info.filename, member_info.header_offset)
        if visit_key in visited:
            return [], []
        visited.add(visit_key)

        try:
            requirements_bytes = self._read_member_bounded(archive, member_info, self.MAX_REQUIREMENTS_TXT_BYTES)
        except ValueError as exc:
            return [], [{"requirements_file": normalized_member, "message": str(exc)}]

        try:
            requirements_text = requirements_bytes.decode("utf-8")
        except UnicodeDecodeError:
            requirements_text = requirements_bytes.decode("utf-8", errors="replace")

        findings: list[dict[str, Any]] = []
        incomplete_members: list[dict[str, str]] = []
        for line_number, raw_line in enumerate(requirements_text.splitlines(), start=1):
            line = self._strip_inline_requirement_comment(raw_line)
            if not line:
                continue

            lowered = line.lower()

            include_target = self._extract_pip_option_value(
                line,
                long_options=("--requirement", "--constraint"),
                short_options=("-r", "-c"),
                allow_concatenated_short=True,
            )
            if include_target is not None:
                if self._is_remote_requirement_url(include_target):
                    findings.append(
                        self._build_requirements_finding(
                            requirements_file=normalized_member,
                            line_number=line_number,
                            line_content=line,
                            severity=IssueSeverity.WARNING,
                            reason="remote_requirements_include",
                            message="requirements.txt includes a remote requirements file",
                        )
                    )
                    continue

                if self._is_external_requirements_reference(include_target):
                    findings.append(
                        self._build_requirements_finding(
                            requirements_file=normalized_member,
                            line_number=line_number,
                            line_content=line,
                            severity=IssueSeverity.WARNING,
                            reason="external_requirements_include",
                            message="requirements.txt includes a local requirements file outside the archive",
                        )
                    )
                    continue

                resolved_include = self._resolve_local_requirements_reference(normalized_member, include_target)
                if resolved_include:
                    for included_member_info in members_by_normalized.get(resolved_include, []):
                        included_findings, included_incomplete_members = self._collect_requirements_findings(
                            archive,
                            members_by_normalized,
                            included_member_info,
                            self._normalize_member_name(included_member_info.filename),
                            visited=visited,
                        )
                        findings.extend(included_findings)
                        incomplete_members.extend(included_incomplete_members)
                continue

            index_url = self._extract_pip_option_value(
                line,
                long_options=("--index-url", "--extra-index-url"),
                short_options=("-i",),
                allow_concatenated_short=True,
            )
            if index_url is not None:
                if self._is_non_pypi_index(index_url):
                    findings.append(
                        self._build_requirements_finding(
                            requirements_file=normalized_member,
                            line_number=line_number,
                            line_content=line,
                            severity=IssueSeverity.CRITICAL,
                            reason="non_pypi_index_url",
                            message="requirements.txt redirects package resolution to a non-PyPI index",
                        )
                    )
                if "http://" in lowered:
                    findings.append(
                        self._build_requirements_finding(
                            requirements_file=normalized_member,
                            line_number=line_number,
                            line_content=line,
                            severity=IssueSeverity.WARNING,
                            reason="insecure_http_transport",
                            message="requirements.txt uses insecure HTTP transport",
                        )
                    )
                continue

            find_links_url = self._extract_pip_option_value(
                line,
                long_options=("--find-links",),
                short_options=("-f",),
                allow_concatenated_short=True,
            )
            if find_links_url is not None:
                if self._is_remote_requirement_url(find_links_url):
                    findings.append(
                        self._build_requirements_finding(
                            requirements_file=normalized_member,
                            line_number=line_number,
                            line_content=line,
                            severity=IssueSeverity.WARNING,
                            reason="remote_find_links",
                            message="requirements.txt uses remote --find-links source",
                        )
                    )
                if "http://" in find_links_url.lower():
                    findings.append(
                        self._build_requirements_finding(
                            requirements_file=normalized_member,
                            line_number=line_number,
                            line_content=line,
                            severity=IssueSeverity.WARNING,
                            reason="insecure_http_transport",
                            message="requirements.txt uses insecure HTTP transport",
                        )
                    )
                continue

            editable_target = self._extract_pip_option_value(
                line,
                long_options=("--editable",),
                short_options=("-e",),
                allow_concatenated_short=True,
            )
            if editable_target is not None:
                findings.append(
                    self._build_requirements_finding(
                        requirements_file=normalized_member,
                        line_number=line_number,
                        line_content=line,
                        severity=IssueSeverity.WARNING,
                        reason="editable_install",
                        message="requirements.txt uses editable install, which can execute arbitrary setup code",
                    )
                )

            if "git+" in lowered:
                findings.append(
                    self._build_requirements_finding(
                        requirements_file=normalized_member,
                        line_number=line_number,
                        line_content=line,
                        severity=IssueSeverity.WARNING,
                        reason="git_install",
                        message="requirements.txt installs directly from git, which can execute arbitrary setup code",
                    )
                )

            direct_url = self._extract_direct_requirement_url(line)
            if direct_url is not None:
                findings.append(
                    self._build_requirements_finding(
                        requirements_file=normalized_member,
                        line_number=line_number,
                        line_content=line,
                        severity=IssueSeverity.WARNING,
                        reason="direct_url_install",
                        message="requirements.txt installs package directly from a remote URL",
                    )
                )

            if "http://" in lowered:
                findings.append(
                    self._build_requirements_finding(
                        requirements_file=normalized_member,
                        line_number=line_number,
                        line_content=line,
                        severity=IssueSeverity.WARNING,
                        reason="insecure_http_transport",
                        message="requirements.txt uses insecure HTTP transport",
                    )
                )

            package_name = self._extract_requirement_name(line)
            typo_target = POPULAR_ML_PACKAGE_TYPOS.get(package_name)
            if typo_target:
                findings.append(
                    self._build_requirements_finding(
                        requirements_file=normalized_member,
                        line_number=line_number,
                        line_content=line,
                        severity=IssueSeverity.WARNING,
                        reason="typosquatting_pattern",
                        message=f"Potential typosquatting package '{package_name}' (did you mean '{typo_target}'?)",
                    )
                )

        return findings, incomplete_members

    def _extract_pip_option_value(
        self,
        line: str,
        *,
        long_options: tuple[str, ...],
        short_options: tuple[str, ...] = (),
        allow_concatenated_short: bool = False,
    ) -> str | None:
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError:
            tokens = line.split()

        if not tokens:
            return None

        first_token = tokens[0]
        lowered_first = first_token.lower()
        for option in (*long_options, *short_options):
            option_prefix = f"{option}="
            if lowered_first == option:
                return tokens[1].strip() if len(tokens) > 1 else None
            if lowered_first.startswith(option_prefix):
                return first_token[len(option_prefix) :].strip()
            if allow_concatenated_short and option in short_options and lowered_first.startswith(option):
                value = first_token[len(option) :].strip()
                if value:
                    return value
        return None

    def _is_non_pypi_index(self, url: str) -> bool:
        stripped_url = url.strip().strip("'\"")
        if not stripped_url:
            return False

        parsed = urlparse(stripped_url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return True
        return hostname not in TRUSTED_PYPI_HOSTS

    def _is_remote_requirement_url(self, url: str) -> bool:
        stripped_url = url.strip().strip("'\"")
        if not stripped_url or not URL_SCHEME_PATTERN.match(stripped_url):
            return False

        parsed = urlparse(stripped_url)
        return parsed.scheme.lower() != "file"

    def _extract_requirement_name(self, line: str) -> str:
        return re.split(r"[;@<>=!~\s\[#]", line, maxsplit=1)[0].strip().lower()

    def _check_symlink_target(
        self,
        archive_path: str,
        archive: zipfile.ZipFile,
        member_info: zipfile.ZipInfo,
        resolved_member_path: str,
        result: ScanResult,
    ) -> None:
        member_name = member_info.filename
        try:
            raw_target = self._read_member_bounded(archive, member_info, 4096)
            target = raw_target.decode("utf-8", "replace")
        except Exception as exc:
            mark_inconclusive_scan_result(result, "torchserve_mar_symlink_target_read_failed")
            result.add_check(
                name="TorchServe MAR Symlink Safety Validation",
                passed=False,
                message=f"Unable to read symlink target for safety validation: {exc!s}",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:{member_name}",
                details={
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_mar_symlink_target_read_failed",
                },
            )
            return

        target_base = os.path.dirname(resolved_member_path)
        _resolved_target, target_is_safe = sanitize_archive_path(target, target_base)

        if not target_is_safe:
            message = f"Symlink {member_name} resolves outside extraction directory"
            severity = IssueSeverity.CRITICAL
        elif is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
            message = f"Symlink {member_name} points to critical system path: {target}"
            severity = IssueSeverity.CRITICAL
        else:
            result.add_check(
                name="TorchServe MAR Symlink Safety Validation",
                passed=True,
                message=f"Symlink {member_name} target is within archive boundaries",
                location=f"{archive_path}:{member_name}",
                details={"target": target},
            )
            return

        result.add_check(
            name="TorchServe MAR Symlink Safety Validation",
            passed=False,
            message=message,
            severity=severity,
            location=f"{archive_path}:{member_name}",
            details={"target": target},
        )

    def _rewrite_scan_locations(
        self,
        file_result: ScanResult,
        temp_path: str,
        archive_path: str,
        member_name: str,
    ) -> None:
        archive_location = f"{archive_path}:{member_name}"

        for issue in file_result.issues:
            issue.location = rewrite_extracted_member_location(
                issue.location,
                temp_path,
                archive_location,
                preserve_non_delimited_suffix=True,
            )
            issue.details = dict(issue.details or {})
            issue.details.setdefault("mar_entry", member_name)

        for check in file_result.checks:
            check.location = rewrite_extracted_member_location(
                check.location,
                temp_path,
                archive_location,
                preserve_non_delimited_suffix=True,
            )
            check.details = dict(check.details or {})
            check.details.setdefault("mar_entry", member_name)
