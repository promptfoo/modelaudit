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
from urllib.parse import urlparse

from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.helpers.assets import asset_from_scan_result
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

HIGH_RISK_CALLS = {
    "__import__",
    "builtins.__import__",
    "builtins.eval",
    "builtins.exec",
    "eval",
    "exec",
    "importlib.import_module",
    "os.popen",
    "os.system",
    "pickle.load",
    "pickle.loads",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}

SAFE_IMPORT_TIME_CALLS = {
    "logging.getLogger",
}


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
            result.add_check(
                name="TorchServe MAR Depth Limit",
                passed=False,
                message=f"Maximum .mar recursion depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"depth": current_depth, "max_depth": self.max_depth},
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
            result.add_check(
                name="TorchServe MAR Scan",
                passed=False,
                message=f"Error scanning TorchServe .mar archive: {exc!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(exc), "exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
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

        total_size = 0
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
            result.add_check(
                name="TorchServe Manifest Entry Limit",
                passed=False,
                message=(
                    "Archive contains "
                    f"{len(all_manifest_infos)} manifest entries, exceeding max processed entries "
                    f"({self.max_entries}); manifest declarations after the entry cap were skipped and "
                    "scan results are incomplete"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={
                    "manifest_entry_count": len(all_manifest_infos),
                    "max_entries": self.max_entries,
                    "dropped_manifest_count": len(all_manifest_infos) - self.max_entries,
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
                result.add_check(
                    name="TorchServe Manifest Uncompressed Size Budget",
                    passed=False,
                    message=(
                        "Manifest parsing uncompressed byte budget exceeded "
                        f"({processed_manifest_uncompressed} > {self.max_uncompressed_bytes}); "
                        "later manifest declarations were skipped and scan results are incomplete"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details={
                        "processed_uncompressed": processed_manifest_uncompressed,
                        "max_uncompressed_bytes": self.max_uncompressed_bytes,
                    },
                )
                break

            scanned_manifest_count += 1

            try:
                manifest_bytes = self._read_member_bounded(archive, manifest_info, self.MAX_MANIFEST_BYTES)
            except ValueError as exc:
                result.add_check(
                    name="TorchServe Manifest Size Limit",
                    passed=False,
                    message=str(exc),
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details=manifest_details,
                )
                continue
            except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                result.add_check(
                    name="TorchServe Manifest Read",
                    passed=False,
                    message=f"Unable to read TorchServe manifest entry: {exc}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                    details={**manifest_details, "exception_type": type(exc).__name__},
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
                url_like_paths.append({"field": field, "value": value})
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
                        result.add_check(
                            name="TorchServe Handler Entry Limit",
                            passed=False,
                            message=(
                                "Handler static analysis reached the max processed entry budget "
                                f"({self.max_entries}); later handler files were skipped and scan results "
                                "are incomplete"
                            ),
                            severity=IssueSeverity.CRITICAL,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                "processed_handler_entries": processed_handler_entries,
                                "max_entries": self.max_entries,
                                "skipped_handler": normalized_handler,
                            },
                        )
                        handler_budget_exceeded = True
                        break

                    processed_handler_entries += 1
                    processed_handler_uncompressed += max(handler_info.file_size, 0)
                    if processed_handler_uncompressed > self.max_uncompressed_bytes:
                        result.add_check(
                            name="TorchServe Handler Uncompressed Size Budget",
                            passed=False,
                            message=(
                                "Handler static analysis uncompressed byte budget exceeded "
                                f"({processed_handler_uncompressed} > {self.max_uncompressed_bytes}); "
                                "later handler files were skipped and scan results are incomplete"
                            ),
                            severity=IssueSeverity.CRITICAL,
                            location=f"{archive_path}:{normalized_handler}",
                            details={
                                "processed_uncompressed": processed_handler_uncompressed,
                                "max_uncompressed_bytes": self.max_uncompressed_bytes,
                                "handler": normalized_handler,
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
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=str(exc),
                            severity=IssueSeverity.WARNING,
                            location=f"{archive_path}:{normalized_handler}",
                            details=handler_details,
                        )
                        continue
                    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=f"Unable to read handler source for static analysis: {exc}",
                            severity=IssueSeverity.WARNING,
                            location=f"{archive_path}:{normalized_handler}",
                            details={**handler_details, "analysis_kind": "read", "exception_type": type(exc).__name__},
                        )
                        continue

                    tree, parse_error = self._parse_python_source(handler_bytes)
                    if parse_error is not None:
                        result.add_check(
                            name="TorchServe Handler Static Analysis",
                            passed=False,
                            message=f"Unable to parse handler source for static analysis: {parse_error}",
                            severity=IssueSeverity.WARNING,
                            location=f"{archive_path}:{normalized_handler}",
                            details=handler_details,
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
                    non_handler_findings += 1
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=str(exc),
                        severity=IssueSeverity.WARNING,
                        location=f"{archive_path}:{member_name}",
                        details={**member_details, "analysis_kind": "bounded_read"},
                    )
                    continue
                except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                    non_handler_findings += 1
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=f"Unable to read non-handler Python source for static analysis: {exc}",
                        severity=IssueSeverity.WARNING,
                        location=f"{archive_path}:{member_name}",
                        details={**member_details, "analysis_kind": "read"},
                    )
                    continue

                tree, parse_error = self._parse_python_source(source_bytes)
                if parse_error is not None:
                    non_handler_findings += 1
                    result.add_check(
                        name="MAR Non-Handler Python Analysis",
                        passed=False,
                        message=f"Unable to parse non-handler Python source for static analysis: {parse_error}",
                        severity=IssueSeverity.WARNING,
                        location=f"{archive_path}:{member_name}",
                        details={**member_details, "analysis_kind": "syntax"},
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
        aliases = self._collect_import_aliases(tree)
        risky_calls: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._resolve_call_name(node.func)
            resolved_name = (
                self._apply_alias(call_name, aliases)
                if call_name is not None
                else self._resolve_getattr_call_name(node.func, aliases)
            )
            if resolved_name is None:
                continue
            if resolved_name in HIGH_RISK_CALLS:
                risky_calls.add(resolved_name)
                continue
            if resolved_name.startswith("subprocess."):
                risky_calls.add(resolved_name)

        return risky_calls

    def _find_high_risk_calls(self, source_bytes: bytes) -> tuple[set[str], str | None]:
        tree, parse_error = self._parse_python_source(source_bytes)
        if tree is None:
            return set(), parse_error

        return self._find_high_risk_calls_from_tree(tree), None

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
        serialized_findings: dict[str, list[IssueSeverity]] = {}

        total_entries = len(member_infos)
        if total_entries > self.max_entries:
            result.add_check(
                name="TorchServe MAR Entry Limit",
                passed=False,
                message=(
                    f"Archive contains {total_entries} entries, exceeding max processed entries ({self.max_entries})"
                ),
                severity=IssueSeverity.WARNING,
                location=archive_path,
                details={"entry_count": total_entries, "max_entries": self.max_entries},
            )
            entries_to_process = member_infos[: self.max_entries]
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
        for member_info in entries_to_process:
            self.check_interrupted()

            member_name = member_info.filename
            normalized_member = self._normalize_member_name(member_name)

            if not member_name or member_name.endswith("/"):
                continue

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
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{member_name}",
                    details={
                        "processed_uncompressed": processed_uncompressed,
                        "max_uncompressed_bytes": self.max_uncompressed_bytes,
                    },
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
                    details={"entry": member_name},
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
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{member_name}",
                    details={"entry": member_name, "max_member_bytes": self.max_member_bytes},
                )
                continue
            except Exception as exc:
                result.add_check(
                    name="TorchServe MAR Member Extraction",
                    passed=False,
                    message=f"Failed to extract archive member for scanning: {exc!s}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{member_name}",
                    details={"entry": member_name, "exception_type": type(exc).__name__},
                )
                continue

            try:
                from .. import core

                nested_config = dict(self.config)
                nested_config["_mar_depth"] = current_depth + 1
                nested_config["_archive_depth"] = current_depth + 1
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

        if serialized_refs:
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
        findings = self._collect_requirements_findings(
            archive,
            members_by_normalized,
            member_info,
            normalized_member,
            visited=set(),
        )

        if findings:
            highest_severity = (
                IssueSeverity.CRITICAL
                if any(finding["severity"] == IssueSeverity.CRITICAL for finding in findings)
                else IssueSeverity.WARNING
            )
            result.add_check(
                name="TorchServe Requirements Supply Chain Analysis",
                passed=False,
                message="requirements.txt contains potential supply-chain attack patterns",
                severity=highest_severity,
                location=location,
                details={**member_details, "findings": findings},
            )
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
    ) -> list[dict[str, Any]]:
        visit_key = (member_info.filename, member_info.header_offset)
        if visit_key in visited:
            return []
        visited.add(visit_key)

        try:
            requirements_bytes = self._read_member_bounded(archive, member_info, self.MAX_REQUIREMENTS_TXT_BYTES)
        except ValueError as exc:
            return [
                self._build_requirements_finding(
                    requirements_file=normalized_member,
                    line_number=0,
                    line_content="",
                    severity=IssueSeverity.WARNING,
                    reason="requirements_read_error",
                    message=str(exc),
                )
            ]

        try:
            requirements_text = requirements_bytes.decode("utf-8")
        except UnicodeDecodeError:
            requirements_text = requirements_bytes.decode("utf-8", errors="replace")

        findings: list[dict[str, Any]] = []
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
                        findings.extend(
                            self._collect_requirements_findings(
                                archive,
                                members_by_normalized,
                                included_member_info,
                                self._normalize_member_name(included_member_info.filename),
                                visited=visited,
                            )
                        )
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

        return findings

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
        except Exception:
            target = ""

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
            if issue.location:
                if issue.location.startswith(temp_path):
                    issue.location = issue.location.replace(temp_path, archive_location, 1)
                else:
                    issue.location = f"{archive_location} {issue.location}"
            else:
                issue.location = archive_location
            issue.details = dict(issue.details or {})
            issue.details.setdefault("mar_entry", member_name)

        for check in file_result.checks:
            if check.location:
                if check.location.startswith(temp_path):
                    check.location = check.location.replace(temp_path, archive_location, 1)
                else:
                    check.location = f"{archive_location} {check.location}"
            else:
                check.location = archive_location
            check.details = dict(check.details or {})
            check.details.setdefault("mar_entry", member_name)
