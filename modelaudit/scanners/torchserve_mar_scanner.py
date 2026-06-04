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
from pathlib import PurePosixPath
from typing import Any, ClassVar
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
_DYNAMIC_ASSIGNABLE_HELPERS = _DYNAMIC_IMPORT_HELPERS | _DYNAMIC_GETATTR_HELPERS


def _canonical_dynamic_helper_name(name: str) -> str:
    return {
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

        try:
            with zipfile.ZipFile(path, "r") as archive:
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

    def _is_non_executing_import_guard(self, node: ast.If) -> bool:
        test = node.test
        if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
            return True
        if (
            isinstance(test, ast.Attribute)
            and isinstance(test.value, ast.Name)
            and test.value.id == "typing"
            and test.attr == "TYPE_CHECKING"
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
        aliases = self._collect_import_aliases(tree)
        for node in tree.body:
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
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and self._is_safe_import_time_assignment(node, aliases):
                continue
            if isinstance(node, ast.If) and self._is_non_executing_import_guard(node):
                continue
            return True
        return False

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

    @staticmethod
    def _static_string_value(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = TorchServeMarScanner._static_string_value(node.left)
            right = TorchServeMarScanner._static_string_value(node.right)
            if left is not None and right is not None:
                return f"{left}{right}"
        return None

    @staticmethod
    def _static_truthiness(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return bool(node.elts)
        if isinstance(node, ast.Dict):
            return bool(node.keys)
        return None

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

    def _module_names_for_import_helpers(
        self,
        node: ast.Call,
        import_helpers: frozenset[str],
    ) -> frozenset[str]:
        if not import_helpers:
            return frozenset()

        module_arg = node.args[0] if node.args else None
        for keyword in node.keywords:
            if keyword.arg in {"name", "module"} and module_arg is None:
                module_arg = keyword.value
        if module_arg is None:
            return frozenset()

        module_name = self._static_string_value(module_arg)
        if not module_name:
            return frozenset()

        fromlist_node: ast.AST | None = node.args[3] if len(node.args) >= 4 else None
        for keyword in node.keywords:
            if keyword.arg == "fromlist" and fromlist_node is None:
                fromlist_node = keyword.value
        fromlist_truthiness = self._static_truthiness(fromlist_node) if fromlist_node is not None else False

        module_names: set[str] = set()
        for resolved_helper_name in import_helpers:
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

        helper_name = self._resolve_call_name(node.func)
        if helper_name is None:
            return frozenset()

        resolved_helper_names = import_loader_aliases.get(helper_name)
        if resolved_helper_names is None:
            if helper_name.split(".", maxsplit=1)[0] in shadowed_names:
                return frozenset()
            resolved_helper_names = frozenset({self._apply_alias(helper_name, aliases)})
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
        if isinstance(node, ast.Attribute):
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

        target_node: ast.AST | None = node.args[0] if node.args else None
        attr_node: ast.AST | None = node.args[1] if len(node.args) >= 2 else None
        for keyword in node.keywords:
            if keyword.arg == "object" and target_node is None:
                target_node = keyword.value
            elif keyword.arg == "name" and attr_node is None:
                attr_node = keyword.value
        if target_node is None or attr_node is None:
            return frozenset()

        module_names = self._resolve_dynamic_import_roots(
            target_node,
            aliases,
            module_aliases,
            import_loader_aliases,
            shadowed_names,
        )
        attr_name = self._static_string_value(attr_node)
        if not module_names or attr_name is None:
            return frozenset()

        return frozenset(f"{module_name}.{attr_name}" for module_name in module_names)

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
            return callable_aliases.get(node.id, frozenset())

        if isinstance(node, ast.Attribute):
            if node.attr == "__call__":
                return self._resolve_dynamic_import_execution_calls(
                    node.value,
                    aliases,
                    module_aliases,
                    callable_aliases,
                    import_loader_aliases,
                    shadowed_names,
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
                        and node.attr in {"LoadLibrary", "__getitem__"}
                        else f"{module_name}.{node.attr}"
                    )
                )
                is not None
            )

        if isinstance(node, ast.Subscript):
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
            return self._resolve_dynamic_import_getattr_calls(
                node,
                aliases,
                module_aliases,
                import_loader_aliases,
                shadowed_names,
            )

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
                self.scope_kind_stack: list[str] = ["module"]
                self.class_parent_state_stack: list[
                    tuple[
                        dict[str, frozenset[str]],
                        dict[str, frozenset[str]],
                        dict[str, frozenset[str]],
                        dict[str, str],
                        set[str],
                    ]
                ] = []
                self.function_binding_state_stack: list[
                    tuple[
                        dict[str, frozenset[str]],
                        dict[str, frozenset[str]],
                        dict[str, frozenset[str]],
                        dict[str, str],
                        set[str],
                    ]
                ] = []
                self.risky_calls: set[str] = set()
                self.collecting_module_bindings = False
                self.scope_depth = 0
                self.module_binding_state: (
                    tuple[
                        dict[str, frozenset[str]],
                        dict[str, frozenset[str]],
                        dict[str, frozenset[str]],
                        dict[str, str],
                        set[str],
                    ]
                    | None
                ) = None

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

            def _snapshot_state(
                self,
            ) -> tuple[
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
                dict[str, str],
                set[str],
            ]:
                return (
                    dict(self.module_aliases),
                    dict(self.callable_aliases),
                    dict(self.import_loader_aliases),
                    dict(self.import_aliases),
                    set(self.shadowed_names),
                )

            def _restore_state(
                self,
                state: tuple[
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, str],
                    set[str],
                ],
            ) -> None:
                self.module_alias_stack[-1] = dict(state[0])
                self.callable_alias_stack[-1] = dict(state[1])
                self.import_loader_alias_stack[-1] = dict(state[2])
                self.import_alias_stack[-1] = dict(state[3])
                self.shadowed_name_stack[-1] = set(state[4])

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

            def _merge_states(
                self,
                left: tuple[
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, str],
                    set[str],
                ],
                right: tuple[
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, str],
                    set[str],
                ],
            ) -> tuple[
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
                dict[str, str],
                set[str],
            ]:
                return (
                    self._merge_possible_aliases(left[0], right[0]),
                    self._merge_possible_aliases(left[1], right[1]),
                    self._merge_possible_aliases(left[2], right[2]),
                    self._merge_import_aliases(left[3], right[3]),
                    left[4] & right[4],
                )

            def _push_scope(
                self,
                parameters: set[str],
                inherited_state: tuple[
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, str],
                    set[str],
                ]
                | None = None,
                scope_kind: str = "function",
            ) -> None:
                state = inherited_state or self._snapshot_state()
                self.module_alias_stack.append(dict(state[0]))
                self.callable_alias_stack.append(dict(state[1]))
                self.import_loader_alias_stack.append(dict(state[2]))
                self.import_alias_stack.append(dict(state[3]))
                self.shadowed_name_stack.append(set(state[4]))
                self.scope_kind_stack.append(scope_kind)
                self.scope_depth += 1
                for parameter in parameters:
                    self._invalidate_name(parameter)

            def _pop_scope(self) -> None:
                self.module_alias_stack.pop()
                self.callable_alias_stack.pop()
                self.import_loader_alias_stack.pop()
                self.import_alias_stack.pop()
                self.shadowed_name_stack.pop()
                self.scope_kind_stack.pop()
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

            def _callable_inherited_state(
                self,
            ) -> tuple[
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
                dict[str, str],
                set[str],
            ]:
                if self.scope_kind_stack[-1] == "module":
                    return self.module_binding_state or self._snapshot_state()
                if self.scope_kind_stack[-1] == "class":
                    return self.class_parent_state_stack[-1]
                if self.scope_kind_stack[-1] == "function":
                    return self.function_binding_state_stack[-1]
                return self._snapshot_state()

            def _invalidate_name(self, name: str) -> None:
                self.module_aliases.pop(name, None)
                self.callable_aliases.pop(name, None)
                self.import_loader_aliases.pop(name, None)
                self.import_aliases.pop(name, None)
                self.shadowed_names.add(name)

            def _record_import_binding(self, name: str, resolved_name: str) -> None:
                resolved_name = _canonical_dynamic_helper_name(resolved_name)
                self.module_aliases.pop(name, None)
                self.callable_aliases.pop(name, None)
                if resolved_name in _DYNAMIC_IMPORT_HELPERS:
                    self.import_loader_aliases[name] = frozenset({resolved_name})
                else:
                    self.import_loader_aliases.pop(name, None)
                self.import_aliases[name] = resolved_name
                self.shadowed_names.discard(name)

            def _record_default_parameter_assignment(
                self,
                name: str,
                value: ast.AST,
                definition_state: tuple[
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, frozenset[str]],
                    dict[str, str],
                    set[str],
                ],
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

            def _record_name_assignment(self, name: str, value: ast.AST) -> None:
                if isinstance(value, ast.IfExp):
                    initial_state = self._snapshot_state()
                    self._record_name_assignment(name, value.body)
                    body_state = self._snapshot_state()
                    self._restore_state(initial_state)
                    self._record_name_assignment(name, value.orelse)
                    self._restore_state(self._merge_states(body_state, self._snapshot_state()))
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
                import_helper_names = helper_names & _DYNAMIC_IMPORT_HELPERS

                self._invalidate_name(name)
                if module_names:
                    self.module_aliases[name] = module_names
                if callable_names:
                    self.callable_aliases[name] = callable_names
                if import_helper_names:
                    self.import_loader_aliases[name] = import_helper_names
                if len(helper_names) == 1:
                    self.import_aliases[name] = next(iter(helper_names))
                    self.shadowed_names.discard(name)

            def _record_target_assignment(self, target: ast.AST, value: ast.AST) -> None:
                if isinstance(target, ast.Name):
                    self._record_name_assignment(target.id, value)
                    return
                if isinstance(target, ast.Starred):
                    self._invalidate_target(target.value)
                    return
                if isinstance(target, ast.Tuple | ast.List):
                    if isinstance(value, ast.Tuple | ast.List) and len(target.elts) == len(value.elts):
                        for child_target, child_value in zip(target.elts, value.elts, strict=True):
                            self._record_target_assignment(child_target, child_value)
                    else:
                        self._invalidate_target(target)

            def _invalidate_target(self, target: ast.AST) -> None:
                if isinstance(target, ast.Name):
                    self._invalidate_name(target.id)
                elif isinstance(target, ast.Starred):
                    self._invalidate_target(target.value)
                elif isinstance(target, ast.Tuple | ast.List):
                    for child_target in target.elts:
                        self._invalidate_target(child_target)

            def _copy_name_binding_to_containing_scope(self, name: str) -> None:
                destination_index = len(self.scope_kind_stack) - 2
                while destination_index > 0 and self.scope_kind_stack[destination_index] == "comprehension":
                    destination_index -= 1

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
                self.shadowed_name_stack[destination_index].discard(name)
                if name in self.shadowed_names:
                    self.shadowed_name_stack[destination_index].add(name)

            def _record_target_from_iterable(self, target: ast.AST, iterable: ast.AST) -> bool:
                if not isinstance(iterable, ast.List | ast.Tuple | ast.Set) or not iterable.elts:
                    self._invalidate_target(target)
                    return False

                initial_state = self._snapshot_state()
                possible_states = []
                for element in iterable.elts:
                    self._restore_state(initial_state)
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
                    if isinstance(value, ast.List | ast.Tuple) and len(pattern.patterns) == len(value.elts):
                        for child_pattern, child_value in zip(pattern.patterns, value.elts, strict=True):
                            self._record_pattern_assignment(child_pattern, child_value)
                    else:
                        for child_pattern in pattern.patterns:
                            self._invalidate_pattern(child_pattern)
                elif isinstance(pattern, ast.MatchMapping):
                    if (
                        isinstance(value, ast.Dict)
                        and len(pattern.keys) == len(pattern.patterns)
                        and all(key is not None for key in value.keys)
                    ):
                        value_by_key = {
                            ast.dump(key): child_value
                            for key, child_value in zip(value.keys, value.values, strict=True)
                            if key is not None
                        }
                        for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
                            matched_value: ast.expr | None = value_by_key.get(ast.dump(key))
                            if matched_value is None:
                                self._invalidate_pattern(child_pattern)
                            else:
                                self._record_pattern_assignment(child_pattern, matched_value)
                    else:
                        for child_pattern in pattern.patterns:
                            self._invalidate_pattern(child_pattern)
                    if pattern.rest is not None:
                        self._invalidate_name(pattern.rest)
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

            def _visit_function_definition(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                for decorator in node.decorator_list:
                    self.visit(decorator)
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        self.visit(default)
                definition_state = self._snapshot_state()
                self._invalidate_name(node.name)
                if self.collecting_module_bindings:
                    return
                inherited_state = self._callable_inherited_state()
                local_bindings = scanner._callable_local_binding_names(node)
                self._push_scope(
                    self._parameter_names(node.args) | local_bindings,
                    inherited_state,
                    scope_kind="function",
                )
                for parameter_name, default in self._parameter_default_bindings(node.args):
                    self._record_default_parameter_assignment(parameter_name, default, definition_state)
                initial_state = self._snapshot_state()
                self.collecting_module_bindings = True
                for statement in node.body:
                    self.visit(statement)
                self.collecting_module_bindings = False
                self.function_binding_state_stack.append(self._snapshot_state())
                self._restore_state(initial_state)
                for statement in node.body:
                    self.visit(statement)
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
                definition_state = self._snapshot_state()
                if self.collecting_module_bindings:
                    return

                inherited_state = self._callable_inherited_state()
                self._push_scope(
                    self._parameter_names(node.args) | scanner._callable_local_binding_names(node),
                    inherited_state,
                    scope_kind="function",
                )
                for parameter_name, default in self._parameter_default_bindings(node.args):
                    self._record_default_parameter_assignment(parameter_name, default, definition_state)
                self.visit(node.body)
                self._pop_scope()

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    binding_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                    resolved_name = alias.name if alias.asname else binding_name
                    self._record_import_binding(binding_name, resolved_name)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if node.module is None:
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
                self._push_scope(set(), class_body_state, scope_kind="class")
                for statement in node.body:
                    self.visit(statement)
                self._pop_scope()
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

            def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
                self.visit(node.value)
                self._record_target_assignment(node.target, node.value)
                if self.scope_kind_stack[-1] == "comprehension" and isinstance(node.target, ast.Name):
                    self._copy_name_binding_to_containing_scope(node.target.id)

            def visit_Delete(self, node: ast.Delete) -> None:
                for target in node.targets:
                    self._invalidate_target(target)

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

            def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
                self.visit(node.iter)
                self._record_target_from_iterable(node.target, node.iter)
                for statement in node.body:
                    self.visit(statement)
                if (
                    isinstance(node.iter, ast.List | ast.Tuple)
                    and node.iter.elts
                    and not self._loop_body_rebinds_target(node.target, node.body)
                ):
                    self._record_target_assignment(node.target, node.iter.elts[-1])
                for statement in node.orelse:
                    self.visit(statement)

            def visit_For(self, node: ast.For) -> None:
                self._visit_for(node)

            def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
                self._visit_for(node)

            def _visit_comprehension(
                self,
                generators: list[ast.comprehension],
                result_nodes: list[ast.AST],
            ) -> None:
                self._push_scope(set(), scope_kind="comprehension")
                for generator in generators:
                    self.visit(generator.iter)
                    self._record_target_from_iterable(generator.target, generator.iter)
                    for condition in generator.ifs:
                        self.visit(condition)
                for result_node in result_nodes:
                    self.visit(result_node)
                self._pop_scope()

            def visit_ListComp(self, node: ast.ListComp) -> None:
                self._visit_comprehension(node.generators, [node.elt])

            def visit_SetComp(self, node: ast.SetComp) -> None:
                self._visit_comprehension(node.generators, [node.elt])

            def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
                self._visit_comprehension(node.generators, [node.elt])

            def visit_DictComp(self, node: ast.DictComp) -> None:
                self._visit_comprehension(node.generators, [node.key, node.value])

            def visit_If(self, node: ast.If) -> None:
                self.visit(node.test)
                if scanner._is_non_executing_import_guard(node):
                    for statement in node.orelse:
                        self.visit(statement)
                    return
                initial_state = self._snapshot_state()
                for statement in node.body:
                    self.visit(statement)
                body_state = self._snapshot_state()
                self._restore_state(initial_state)
                for statement in node.orelse:
                    self.visit(statement)
                orelse_state = self._snapshot_state()
                self._restore_state(self._merge_states(body_state, orelse_state))

            def visit_Try(self, node: ast.Try) -> None:
                initial_state = self._snapshot_state()
                for statement in node.body:
                    self.visit(statement)
                body_state = self._snapshot_state()
                for statement in node.orelse:
                    self.visit(statement)
                possible_states = [self._snapshot_state()]

                handler_initial_state = self._merge_states(initial_state, body_state)
                for handler in node.handlers:
                    self._restore_state(handler_initial_state)
                    if handler.type is not None:
                        self.visit(handler.type)
                    if handler.name is not None:
                        self._invalidate_name(handler.name)
                    for statement in handler.body:
                        self.visit(statement)
                    if handler.name is not None:
                        self._invalidate_name(handler.name)
                    possible_states.append(self._snapshot_state())

                merged_state = possible_states[0]
                for possible_state in possible_states[1:]:
                    merged_state = self._merge_states(merged_state, possible_state)
                self._restore_state(merged_state)
                for statement in node.finalbody:
                    self.visit(statement)

            def visit_Match(self, node: ast.Match) -> None:
                self.visit(node.subject)
                initial_state = self._snapshot_state()
                possible_states = [initial_state]
                for case in node.cases:
                    self._restore_state(initial_state)
                    self._record_pattern_assignment(case.pattern, node.subject)
                    if case.guard is not None:
                        self.visit(case.guard)
                    for statement in case.body:
                        self.visit(statement)
                    possible_states.append(self._snapshot_state())

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
                        bound_value = item.context_expr
                        if isinstance(bound_value, ast.Call):
                            helper_name = scanner._resolve_call_name(bound_value.func)
                            if (
                                helper_name is not None
                                and scanner._apply_unshadowed_alias(
                                    helper_name,
                                    self.import_aliases,
                                    self.shadowed_names,
                                )
                                == "contextlib.nullcontext"
                            ):
                                enter_result = self._nullcontext_enter_result(bound_value)
                                if enter_result is not None:
                                    bound_value = enter_result
                        self._record_target_assignment(item.optional_vars, bound_value)
                for statement in node.body:
                    self.visit(statement)

            def visit_With(self, node: ast.With) -> None:
                self._visit_with(node)

            def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
                self._visit_with(node)

            def visit_Call(self, node: ast.Call) -> None:
                call_names = scanner._resolve_dynamic_import_execution_calls(
                    node.func,
                    self.import_aliases,
                    self.module_aliases,
                    self.callable_aliases,
                    self.import_loader_aliases,
                    self.shadowed_names,
                )
                self.risky_calls.update(call_names)
                self.generic_visit(node)

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
                result.merge(file_result)

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
