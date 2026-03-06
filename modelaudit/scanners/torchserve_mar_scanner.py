"""Scanner for TorchServe Model Archive (.mar) files."""

from __future__ import annotations

import ast
import contextlib
import json
import os
import re
import stat
import tempfile
import zipfile
from pathlib import PurePosixPath
from typing import Any, ClassVar

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


class TorchServeMarScanner(BaseScanner):
    """Scan TorchServe .mar archives and embedded payloads."""

    name = "torchserve_mar"
    description = "Scans TorchServe .mar archives for insecure handlers and embedded malicious payloads"
    supported_extensions: ClassVar[list[str]] = [".mar"]

    MAX_MANIFEST_BYTES: ClassVar[int] = 1 * 1024 * 1024
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
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if os.path.splitext(path)[1].lower() not in cls.supported_extensions:
            return False

        try:
            with open(path, "rb") as handle:
                if not handle.read(4).startswith(b"PK"):
                    return False

            with zipfile.ZipFile(path, "r") as archive:
                member_names = cls._member_name_set(archive)
                return cls._normalize_member_name(MANIFEST_ENTRY_PATH) in member_names
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
            return False
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

        current_depth = self._get_int_config("_mar_depth", 0, minimum=0)
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

        manifest_info = None
        for info in archive.infolist():
            if self._normalize_member_name(info.filename) == manifest_name:
                manifest_info = info
                break

        if manifest_info is None:
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

        try:
            manifest_bytes = self._read_member_bounded(archive, manifest_info, self.MAX_MANIFEST_BYTES)
        except ValueError as exc:
            result.add_check(
                name="TorchServe Manifest Size Limit",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={"max_manifest_bytes": self.MAX_MANIFEST_BYTES},
            )
            return manifest_context

        try:
            manifest_data = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            result.add_check(
                name="TorchServe Manifest JSON Parse",
                passed=False,
                message=f"Failed to parse TorchServe manifest JSON: {exc}",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
                details={"exception_type": type(exc).__name__},
            )
            return manifest_context

        if not isinstance(manifest_data, dict):
            result.add_check(
                name="TorchServe Manifest Structure",
                passed=False,
                message="TorchServe manifest must be a JSON object",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{MANIFEST_ENTRY_PATH}",
            )
            return manifest_context

        path_references, handler_paths, serialized_paths, missing_required = self._collect_manifest_references(
            manifest_data,
        )
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
        self._analyze_handlers(
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

        if self._is_path_like_reference("handler", reference_base):
            return [self._normalize_member_name(reference_base)]

        module_path = reference_base.replace(".", "/")
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
    ) -> None:
        analyzed_handler = False
        member_lookup = {
            self._normalize_member_name(member_info.filename): member_info
            for member_info in archive.infolist()
            if member_info.filename and not member_info.filename.endswith("/")
        }

        for handler_path in handler_paths:
            resolved_candidates = self._resolve_handler_member_candidates(handler_path)
            normalized_handler = next((candidate for candidate in resolved_candidates if candidate in member_set), None)
            if normalized_handler is None or not normalized_handler.endswith(".py"):
                continue

            analyzed_handler = True
            handler_info = member_lookup.get(normalized_handler)
            if handler_info is None:
                continue
            try:
                handler_bytes = self._read_member_bounded(archive, handler_info, self.max_member_bytes)
            except ValueError as exc:
                result.add_check(
                    name="TorchServe Handler Static Analysis",
                    passed=False,
                    message=str(exc),
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{normalized_handler}",
                )
                continue

            risky_calls, parse_error = self._find_high_risk_calls(handler_bytes)
            if parse_error is not None:
                result.add_check(
                    name="TorchServe Handler Static Analysis",
                    passed=False,
                    message=f"Unable to parse handler source for static analysis: {parse_error}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{normalized_handler}",
                    details={"handler": normalized_handler},
                )
                continue

            if risky_calls:
                result.add_check(
                    name="TorchServe Handler Static Analysis",
                    passed=False,
                    message=(f"Handler contains high-risk execution primitives: {', '.join(sorted(risky_calls))}"),
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}:{normalized_handler}",
                    details={"handler": normalized_handler, "risky_calls": sorted(risky_calls)},
                )
            else:
                result.add_check(
                    name="TorchServe Handler Static Analysis",
                    passed=True,
                    message="Handler source does not contain high-risk execution primitives",
                    location=f"{archive_path}:{normalized_handler}",
                    details={"handler": normalized_handler},
                )

        if not analyzed_handler and handler_paths:
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=True,
                message="No Python handler files found for static analysis",
                location=archive_path,
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

    def _find_high_risk_calls(self, source_bytes: bytes) -> tuple[set[str], str | None]:
        try:
            source = source_bytes.decode("utf-8")
        except UnicodeDecodeError:
            source = source_bytes.decode("utf-8", errors="replace")

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return set(), str(exc)

        aliases = self._collect_import_aliases(tree)
        risky_calls: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._resolve_call_name(node.func)
            if call_name is None:
                continue

            resolved_name = self._apply_alias(call_name, aliases)
            if resolved_name in HIGH_RISK_CALLS:
                risky_calls.add(resolved_name)
                continue
            if resolved_name.startswith("subprocess."):
                risky_calls.add(resolved_name)

        return risky_calls, None

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
        for member_info in entries_to_process:
            self.check_interrupted()

            member_name = member_info.filename
            normalized_member = self._normalize_member_name(member_name)

            if not member_name or member_name.endswith("/"):
                continue

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
