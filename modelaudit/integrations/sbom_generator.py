import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from importlib.metadata import version as _pkg_version
from typing import Any

from cyclonedx.model import HashType, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import LicenseExpression
from cyclonedx.output import OutputFormat, SchemaVersion, make_outputter

from ..models import FileMetadataModel, ModelAuditResultModel
from ..scanner_results import Issue, IssueSeverity
from .source_redaction import redact_source_identifier, redact_source_reference, redact_source_value

SCANNER_VERSION = f"v{_pkg_version('modelaudit')}"
_MAX_SYMLINK_HOPS = 40
_DESCRIPTOR_WALK_SUPPORTED = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "fwalk")
    and os.open in os.supports_dir_fd
    and os.readlink in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
)


def _sbom_property_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _serialize_member_file_hashes(value: object) -> str:
    return json.dumps(redact_source_value(value), sort_keys=True, separators=(",", ":"))


def _append_member_file_hash_summary_properties(props: list[Property], metadata: FileMetadataModel) -> None:
    summary_values = {
        "modelaudit:member_file_hashes_total": metadata.member_file_hashes_total,
        "modelaudit:member_file_hashes_truncated": metadata.member_file_hashes_truncated,
        "modelaudit:member_file_hashes_omitted": metadata.member_file_hashes_omitted,
    }
    for name, value in summary_values.items():
        if value is not None:
            props.append(Property(name=name, value=_sbom_property_value(value)))


def _append_member_file_hash_summary_properties_from_dict(props: list[Property], metadata: dict[str, Any]) -> None:
    summary_values = {
        "modelaudit:member_file_hashes_total": metadata.get("member_file_hashes_total"),
        "modelaudit:member_file_hashes_truncated": metadata.get("member_file_hashes_truncated"),
        "modelaudit:member_file_hashes_omitted": metadata.get("member_file_hashes_omitted"),
    }
    for name, value in summary_values.items():
        if isinstance(value, (bool, int)):
            props.append(Property(name=name, value=_sbom_property_value(value)))


@dataclass
class _BomRefState:
    counts: dict[str, int] = field(default_factory=dict)
    reserved: set[str] = field(default_factory=set)
    used: set[str] = field(default_factory=set)

    def allocate(self, base_reference: str, *, literal_reference: bool) -> str:
        if literal_reference and base_reference not in self.used:
            self.used.add(base_reference)
            return base_reference

        occurrence = self.counts.get(base_reference, 0)
        while True:
            occurrence += 1
            candidate = base_reference if occurrence == 1 else f"{base_reference}#modelaudit-component-{occurrence}"
            if candidate not in self.used and candidate not in self.reserved:
                self.counts[base_reference] = occurrence
                self.used.add(candidate)
                return candidate


def _get_component_type(path: str, metadata: dict[str, Any] | None) -> ComponentType:
    """Determine the appropriate CycloneDX v1.6 component type for a file."""
    # ML model file types should use MACHINE_LEARNING_MODEL component type
    ml_extensions = {
        ".pkl",
        ".pickle",
        ".safetensors",
        ".gguf",
        ".ggml",
        ".ggmf",
        ".ggjt",
        ".ggla",
        ".ggsa",
        ".h5",
        ".hdf5",
        ".onnx",
        ".bin",
        ".pth",
        ".pt",
        ".pb",
        ".tflite",
        ".mlmodel",
        ".joblib",
        ".joblib.gz",
        ".dill",
        ".xgb",
        ".lgb",
        ".cbm",
        ".pmml",
    }

    file_ext = os.path.splitext(path.lower())[1]

    # Check if it's a machine learning model
    if file_ext in ml_extensions:
        return ComponentType.MACHINE_LEARNING_MODEL

    # Check metadata for model indicators
    if metadata and (metadata.get("is_model") or metadata.get("tensors")):
        return ComponentType.MACHINE_LEARNING_MODEL

    # Archive/container types
    if file_ext in {".zip", ".tar", ".gz", ".7z", ".bz2"}:
        return ComponentType.CONTAINER

    # Data files
    if file_ext in {".json", ".yaml", ".yml", ".xml", ".csv", ".txt", ".md"}:
        return ComponentType.DATA

    # Default to FILE for everything else
    return ComponentType.FILE


def _is_path_within_directory(path: str, directory: str) -> bool:
    try:
        normalized_path = os.path.normcase(os.path.realpath(path))
        normalized_directory = os.path.normcase(os.path.normpath(directory))
        return os.path.commonpath([normalized_path, normalized_directory]) == normalized_directory
    except (OSError, ValueError):
        return False


def _lstat_size(path: str) -> int:
    try:
        return os.lstat(path).st_size
    except OSError:
        return 0


def _supports_descriptor_walk() -> bool:
    return _DESCRIPTOR_WALK_SUPPORTED


def _directory_open_flags(*, readable: bool) -> int:
    if readable:
        flags = os.O_RDONLY
    elif hasattr(os, "O_PATH"):
        flags = os.O_PATH
    elif hasattr(os, "O_SEARCH"):
        flags = os.O_SEARCH
    else:
        flags = os.O_RDONLY
    flags |= os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_scan_root_fd(scan_root: str, *, readable: bool = False) -> int | None:
    if not _supports_descriptor_walk():
        return None

    components = [component for component in scan_root.split(os.path.sep) if component]
    ancestor_flags = _directory_open_flags(readable=False)
    root_flags = _directory_open_flags(readable=readable)

    current_fd = -1
    try:
        current_fd = os.open(os.path.sep, root_flags if not components else ancestor_flags)
        for index, component in enumerate(components):
            flags = root_flags if index == len(components) - 1 else ancestor_flags
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError:
        if current_fd >= 0:
            os.close(current_fd)
        return None


def _iter_scan_root_files(
    input_path: str,
    scan_root_fd: int | None,
    *,
    require_stable_root: bool,
) -> Iterable[tuple[str, str]]:
    """Yield display and root-relative paths from a pinned directory when available."""
    if scan_root_fd is not None:
        try:
            for relative_root, _, files, _ in os.fwalk(
                os.curdir,
                follow_symlinks=False,
                dir_fd=scan_root_fd,
            ):
                for filename in files:
                    relative_path = os.path.normpath(os.path.join(relative_root, filename))
                    yield os.path.join(input_path, relative_path), relative_path
        except OSError:
            return
        return

    if require_stable_root:
        return

    for root, _, files in os.walk(input_path):
        for filename in files:
            display_path = os.path.join(root, filename)
            yield display_path, os.path.relpath(display_path, input_path)


def _relative_path_parts(path: str) -> list[str] | None:
    if os.path.isabs(path):
        return None

    normalized = os.path.normpath(path)
    if normalized in {"", os.curdir}:
        return []

    parts = normalized.split(os.sep)
    if any(part in {"", os.curdir, os.pardir} for part in parts):
        return None
    return parts


def _symlink_target_parts(target: str, resolved_parts: list[str], scan_root: str) -> list[str] | None:
    if os.path.isabs(target):
        resolved_target = os.path.realpath(target)
        if not _is_path_within_directory(resolved_target, scan_root):
            return None
        relative_target = os.path.relpath(resolved_target, scan_root)
    else:
        relative_target = os.path.join(*resolved_parts, target) if resolved_parts else target

    return _relative_path_parts(relative_target)


def _open_file_beneath_root(root_fd: int, relative_path: str, scan_root: str) -> int | None:
    """Open a root-relative file without following mutable parent paths."""
    pending_parts = _relative_path_parts(relative_path)
    if not pending_parts:
        return None

    resolved_parts: list[str] = []
    symlink_hops = 0
    try:
        current_fd = os.dup(root_fd)
    except OSError:
        return None
    try:
        while pending_parts:
            component = pending_parts.pop(0)
            try:
                component_stat = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except OSError:
                return None

            if stat.S_ISLNK(component_stat.st_mode):
                symlink_hops += 1
                if symlink_hops > _MAX_SYMLINK_HOPS:
                    return None
                try:
                    target = os.readlink(component, dir_fd=current_fd)
                except OSError:
                    return None
                try:
                    current_stat = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                except OSError:
                    return None
                if (component_stat.st_dev, component_stat.st_ino) != (current_stat.st_dev, current_stat.st_ino):
                    return None
                target_parts = _symlink_target_parts(target, resolved_parts, scan_root)
                if target_parts is None:
                    return None
                pending_parts = target_parts + pending_parts
                os.close(current_fd)
                current_fd = -1
                try:
                    current_fd = os.dup(root_fd)
                except OSError:
                    return None
                resolved_parts.clear()
                continue

            flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            is_final_component = not pending_parts
            if is_final_component:
                if not stat.S_ISREG(component_stat.st_mode):
                    return None
            else:
                if not stat.S_ISDIR(component_stat.st_mode):
                    return None
                flags |= os.O_DIRECTORY
            if is_final_component and hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK

            try:
                opened_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError:
                return None

            if is_final_component:
                return opened_fd

            os.close(current_fd)
            current_fd = opened_fd
            resolved_parts.append(component)
    finally:
        if current_fd >= 0:
            os.close(current_fd)

    return None


def _opened_file_size_and_sha256(
    path: str,
    scan_root: str | None,
    *,
    scan_root_fd: int | None = None,
    relative_path: str | None = None,
    require_stable_root: bool = False,
) -> tuple[int, str] | None:
    """Hash one opened file descriptor after binding it to a contained path."""
    if scan_root is not None and scan_root_fd is not None and relative_path is not None:
        fd = _open_file_beneath_root(scan_root_fd, relative_path, scan_root)
        if fd is None:
            return None
    else:
        if require_stable_root:
            return None
        hash_path = os.path.realpath(path) if scan_root is not None else path
        if scan_root is not None and not _is_path_within_directory(hash_path, scan_root):
            return None

        try:
            candidate_stat = os.stat(hash_path, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(candidate_stat.st_mode):
            return None

        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK

        try:
            fd = os.open(hash_path, flags)
        except OSError:
            return None

    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            return None
        if scan_root is not None and scan_root_fd is None:
            current_path = os.path.realpath(path)
            if os.path.normcase(current_path) != os.path.normcase(hash_path) or not _is_path_within_directory(
                current_path, scan_root
            ):
                return None
            try:
                current_stat = os.stat(current_path, follow_symlinks=False)
            except OSError:
                return None
            if (opened_stat.st_dev, opened_stat.st_ino) != (current_stat.st_dev, current_stat.st_ino):
                return None

        h = hashlib.sha256()
        with os.fdopen(fd, "rb") as f:
            fd = -1
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return opened_stat.st_size, h.hexdigest()
    finally:
        if fd >= 0:
            os.close(fd)


def _resolve_component_size_and_sha256(
    path: str,
    metadata: FileMetadataModel | dict[str, Any] | None,
    scan_root: str | None = None,
    *,
    allow_metadata_fallback: bool = True,
    scan_root_fd: int | None = None,
    relative_path: str | None = None,
    require_stable_root: bool = False,
) -> tuple[int, str]:
    """Resolve component size/hash from disk, falling back to recorded metadata."""
    if scan_root is not None:
        if require_stable_root and scan_root_fd is None:
            return 0, ""
        if scan_root_fd is None and not _is_path_within_directory(path, scan_root):
            return 0, ""

    path_exists = os.path.lexists(path)
    if scan_root is not None or path_exists or not allow_metadata_fallback:
        opened_file = _opened_file_size_and_sha256(
            path,
            scan_root,
            scan_root_fd=scan_root_fd,
            relative_path=relative_path,
            require_stable_root=require_stable_root,
        )
        if opened_file is not None:
            return opened_file
    if scan_root is not None:
        return 0, ""
    if path_exists:
        return _lstat_size(path), ""
    if not allow_metadata_fallback:
        return 0, ""

    file_size = 0
    sha256 = ""

    if isinstance(metadata, FileMetadataModel):
        if metadata.file_size is not None:
            file_size = metadata.file_size
        if metadata.file_hashes and metadata.file_hashes.sha256:
            sha256 = metadata.file_hashes.sha256
    elif isinstance(metadata, dict):
        raw_size = metadata.get("file_size")
        if isinstance(raw_size, int):
            file_size = raw_size
        raw_hashes = metadata.get("file_hashes")
        if isinstance(raw_hashes, dict):
            raw_sha256 = raw_hashes.get("sha256")
            if isinstance(raw_sha256, str):
                sha256 = raw_sha256

    return file_size, sha256


def _should_skip_sbom_file(path: str) -> bool:
    """Skip cache bookkeeping files that are not model artifacts."""
    filename = os.path.basename(path)

    if filename.endswith(".metadata") or filename.endswith(".lock"):
        return True

    if filename in {".gitignore", ".gitattributes", "main", "HEAD"}:
        return True

    normalized_path = path.replace("\\", "/")
    return "/refs/" in normalized_path and filename in {"main", "HEAD"}


def _is_non_filesystem_identifier(path: str) -> bool:
    """Return whether metadata identifies a remote source rather than a local path."""
    return "://" in path


def _redacted_component_identity(
    path: str,
    sha256: str = "",
    bom_ref_state: _BomRefState | None = None,
) -> tuple[str, str]:
    """Return credential-safe component name and bom-ref values for exported SBOMs."""
    safe_identifier = redact_source_identifier(path)
    component_name = os.path.basename(safe_identifier) or safe_identifier
    if safe_identifier == path:
        base_reference = safe_identifier
    else:
        base_reference = redact_source_reference(path)
        if sha256:
            base_reference = f"{base_reference}#modelaudit-content-sha256-{sha256}"

    if bom_ref_state is None:
        return component_name, base_reference
    return component_name, bom_ref_state.allocate(
        base_reference,
        literal_reference=safe_identifier == path,
    )


def _trusted_metadata_fallback_paths(assets: Iterable[Any] | None) -> set[str]:
    """Collect ephemeral streamed assets whose scan-time metadata is authoritative."""
    trusted_paths: set[str] = set()
    if assets is None:
        return trusted_paths
    for asset in assets:
        if isinstance(asset, dict):
            asset_path = asset.get("path")
            asset_type = asset.get("type")
            is_streamed = asset.get("is_streamed")
        else:
            asset_path = getattr(asset, "path", None)
            asset_type = getattr(asset, "type", None)
            is_streamed = getattr(asset, "is_streamed", None)
        if (is_streamed is True or asset_type == "streaming") and isinstance(asset_path, str):
            trusted_paths.add(asset_path)
    return trusted_paths


def _calculate_risk_score(path: str, issues: list[Issue]) -> int:
    """Calculate risk score for a file based on associated issues."""
    score = 0
    for issue in issues:
        if issue.location == path:
            if issue.severity == IssueSeverity.CRITICAL:
                score += 5
            elif issue.severity == IssueSeverity.WARNING:
                score += 2
            elif issue.severity == IssueSeverity.INFO:
                score += 1
    return min(score, 10)  # Cap at 10


def _calculate_legacy_risk_score(path: str, issues: Iterable[dict[str, Any]]) -> int:
    """Calculate the legacy dict-based risk score for a component."""
    score = 0
    for issue in issues:
        if issue.get("location") != path:
            continue
        severity = issue.get("severity")
        if severity == "critical":
            score += 5
        elif severity == "warning":
            score += 2
        elif severity == "info":
            score += 1
    return min(score, 10)


def _stable_source_order(
    paths: Iterable[str],
    risk_score: Callable[[str], int],
    metadata_identity: Callable[[str], str] | None = None,
) -> list[str]:
    """Order sources so colliding redacted refs keep deterministic risk attribution."""
    grouped_paths: dict[str, list[str]] = {}
    seen_paths: set[str] = set()
    for path in paths:
        if path in seen_paths:
            continue
        seen_paths.add(path)
        reference = redact_source_reference(path)
        grouped_paths.setdefault(reference, []).append(path)

    ordered_paths: list[str] = []
    for reference in sorted(grouped_paths):
        ordered_paths.extend(
            sorted(
                grouped_paths[reference],
                key=lambda path: (
                    redact_source_identifier(path) != path,
                    -risk_score(path),
                    metadata_identity(path) if metadata_identity is not None else "",
                ),
            )
        )
    return ordered_paths


def _metadata_identity_sort_key(metadata: Any) -> str:
    if hasattr(metadata, "model_dump"):
        metadata = metadata.model_dump(mode="python")
    safe_metadata = redact_source_value(metadata or {})
    if isinstance(safe_metadata, dict):
        safe_metadata.pop("risk_score", None)
        safe_metadata.pop("scan_timestamp", None)
    serialized = json.dumps(safe_metadata, sort_keys=True, separators=(",", ":"), default=repr)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _extract_license_expressions(metadata: FileMetadataModel) -> list[LicenseExpression]:
    """Extract license expressions from file metadata."""
    license_expressions: list[LicenseExpression] = []
    license_identifiers: list[str] = []

    # Check for legacy license field
    if metadata.license:
        license_identifiers.append(str(metadata.license))

    # Check for new license metadata
    if metadata.license_info:
        for lic in metadata.license_info:
            if lic.spdx_id:
                license_identifiers.append(str(lic.spdx_id))
            elif lic.name:
                license_identifiers.append(str(lic.name))

    # Remove duplicates while preserving order
    unique_licenses: list[str] = []
    seen = set()
    for lic_id in license_identifiers:
        if lic_id not in seen:
            unique_licenses.append(lic_id)
            seen.add(lic_id)

    # Create license expressions
    if len(unique_licenses) == 1:
        license_expressions.append(LicenseExpression(unique_licenses[0]))
    elif len(unique_licenses) > 1:
        compound_expression = " OR ".join(unique_licenses)
        license_expressions.append(LicenseExpression(compound_expression))

    return license_expressions


def _create_metadata_properties(metadata: FileMetadataModel) -> list[Property]:
    """Create CycloneDX v1.6 enhanced properties from file metadata."""
    props: list[Property] = []

    # ML/AI model properties (enhanced for v1.6 ML-BOM support)
    if metadata.is_dataset:
        props.append(Property(name="ml:is_dataset", value="true"))
    if metadata.is_model:
        props.append(Property(name="ml:is_model", value="true"))

    # Add ML context information if available
    if hasattr(metadata, "ml_context") and metadata.ml_context:
        ml_ctx = metadata.ml_context
        if hasattr(ml_ctx, "framework") and ml_ctx.framework:
            props.append(Property(name="ml:framework", value=str(ml_ctx.framework)))
        if hasattr(ml_ctx, "model_type") and ml_ctx.model_type:
            props.append(Property(name="ml:model_type", value=str(ml_ctx.model_type)))
        if hasattr(ml_ctx, "confidence") and ml_ctx.confidence is not None:
            props.append(Property(name="ml:confidence_score", value=str(ml_ctx.confidence)))

    # Add copyright information
    if metadata.copyright_notices:
        copyright_holders = []
        for cr in metadata.copyright_notices:
            if cr.holder:
                copyright_holders.append(cr.holder)

        if copyright_holders:
            props.append(
                Property(
                    name="copyright_holders",
                    value=", ".join(copyright_holders),
                )
            )

    # Add license files information
    if metadata.license_files_nearby:
        props.append(Property(name="license_files_found", value=str(len(metadata.license_files_nearby))))

    if metadata.member_file_hashes:
        props.append(
            Property(
                name="modelaudit:member_file_hashes",
                value=_serialize_member_file_hashes(
                    {
                        member_path: record.model_dump(mode="json", exclude_none=True)
                        for member_path, record in metadata.member_file_hashes.items()
                    }
                ),
            )
        )
    _append_member_file_hash_summary_properties(props, metadata)

    # Security and compliance properties
    props.append(Property(name="security:scanned", value="true"))
    props.append(Property(name="security:scanner", value="ModelAudit"))
    props.append(Property(name="security:scanner_version", value=SCANNER_VERSION))

    return props


def _component_for_file_pydantic(
    path: str,
    metadata: FileMetadataModel | None,
    issues: list[Issue],
    scan_root: str | None = None,
    *,
    allow_metadata_fallback: bool = True,
    scan_root_fd: int | None = None,
    relative_path: str | None = None,
    require_stable_root: bool = False,
    bom_ref_state: _BomRefState | None = None,
) -> Component:
    """Create a CycloneDX component from Pydantic models (type-safe version)."""
    size, sha256 = _resolve_component_size_and_sha256(
        path,
        metadata,
        scan_root,
        allow_metadata_fallback=allow_metadata_fallback,
        scan_root_fd=scan_root_fd,
        relative_path=relative_path,
        require_stable_root=require_stable_root,
    )

    # Start with basic properties
    props = [Property(name="size", value=str(size))]

    # Calculate and add risk score
    risk_score = _calculate_risk_score(path, issues)
    props.append(Property(name="risk_score", value=str(risk_score)))

    # Add metadata-based properties if available
    license_expressions: list[LicenseExpression] = []
    if metadata:
        license_expressions = _extract_license_expressions(metadata)
        props.extend(_create_metadata_properties(metadata))

    # Determine appropriate component type for CycloneDX v1.6
    component_type = _get_component_type(path, metadata.model_dump() if metadata else None)
    component_name, bom_ref = _redacted_component_identity(path, sha256, bom_ref_state)

    # Create the component
    component = Component(
        name=component_name,
        bom_ref=bom_ref,
        type=component_type,
        hashes=[HashType.from_hashlib_alg("sha256", sha256)] if sha256 else [],
        properties=props,
    )

    # Add license expressions
    for license_expr in license_expressions:
        component.licenses.add(license_expr)

    return component


def _component_for_file(
    path: str,
    metadata: dict[str, Any],
    issues: Iterable[dict[str, Any]],
    scan_root: str | None = None,
    *,
    allow_metadata_fallback: bool = True,
    scan_root_fd: int | None = None,
    relative_path: str | None = None,
    require_stable_root: bool = False,
    bom_ref_state: _BomRefState | None = None,
) -> Component:
    size, sha256 = _resolve_component_size_and_sha256(
        path,
        metadata,
        scan_root,
        allow_metadata_fallback=allow_metadata_fallback,
        scan_root_fd=scan_root_fd,
        relative_path=relative_path,
        require_stable_root=require_stable_root,
    )
    props = [Property(name="size", value=str(size))]

    # Compute risk score based on issues related to this file
    score = _calculate_legacy_risk_score(path, issues)
    props.append(Property(name="risk_score", value=str(score)))

    # Enhanced license handling
    license_expressions = []
    if isinstance(metadata, dict):
        # Collect all license identifiers
        license_identifiers = []

        # Check for legacy license field
        legacy_license = metadata.get("license")
        if legacy_license:
            license_identifiers.append(str(legacy_license))

        # Check for new license metadata
        detected_licenses = metadata.get("license_info", [])
        for lic in detected_licenses:
            if isinstance(lic, dict) and lic.get("spdx_id"):
                license_identifiers.append(str(lic["spdx_id"]))
            elif isinstance(lic, dict) and lic.get("name"):
                license_identifiers.append(str(lic["name"]))

        # Create a single license expression to comply with CycloneDX
        if license_identifiers:
            # Remove duplicates while preserving order
            unique_licenses = []
            seen = set()
            for lic_id in license_identifiers:
                if lic_id not in seen:
                    unique_licenses.append(lic_id)
                    seen.add(lic_id)

            if len(unique_licenses) == 1:
                license_expressions.append(LicenseExpression(unique_licenses[0]))
            else:
                # Create compound license expression for multiple licenses
                compound_expression = " OR ".join(unique_licenses)
                license_expressions.append(LicenseExpression(compound_expression))

        # Add ML/AI-related properties (enhanced for v1.6 ML-BOM support)
        if metadata.get("is_dataset"):
            props.append(Property(name="ml:is_dataset", value="true"))
        if metadata.get("is_model"):
            props.append(Property(name="ml:is_model", value="true"))

        # Add ML context if available
        ml_context = metadata.get("ml_context")
        if ml_context and isinstance(ml_context, dict):
            if ml_context.get("framework"):
                props.append(Property(name="ml:framework", value=str(ml_context["framework"])))
            if ml_context.get("model_type"):
                props.append(Property(name="ml:model_type", value=str(ml_context["model_type"])))
            if ml_context.get("confidence") is not None:
                props.append(Property(name="ml:confidence_score", value=str(ml_context["confidence"])))

        # Add copyright information
        copyrights = metadata.get("copyright_notices", [])
        if copyrights:
            copyright_holders = [cr.get("holder", "") for cr in copyrights if isinstance(cr, dict)]
            if copyright_holders:
                props.append(
                    Property(
                        name="copyright_holders",
                        value=", ".join(copyright_holders),
                    ),
                )

        # Add license files information
        license_files = metadata.get("license_files_nearby", [])
        if license_files:
            props.append(
                Property(name="license_files_found", value=str(len(license_files))),
            )

        member_file_hashes = metadata.get("member_file_hashes")
        if isinstance(member_file_hashes, dict) and member_file_hashes:
            props.append(
                Property(
                    name="modelaudit:member_file_hashes",
                    value=_serialize_member_file_hashes(member_file_hashes),
                )
            )
        _append_member_file_hash_summary_properties_from_dict(props, metadata)

    # Security and compliance properties (added for all files)
    props.append(Property(name="security:scanned", value="true"))
    props.append(Property(name="security:scanner", value="ModelAudit"))
    props.append(Property(name="security:scanner_version", value=SCANNER_VERSION))

    # Determine appropriate component type for CycloneDX v1.6
    component_type = _get_component_type(path, metadata if isinstance(metadata, dict) else None)
    component_name, bom_ref = _redacted_component_identity(path, sha256, bom_ref_state)

    component = Component(
        name=component_name,
        bom_ref=bom_ref,
        type=component_type,
        hashes=[HashType.from_hashlib_alg("sha256", sha256)] if sha256 else [],
        properties=props,
    )

    if license_expressions:
        for license_expr in license_expressions:
            component.licenses.add(license_expr)

    return component


def generate_sbom(paths: Iterable[str], results: dict[str, Any] | Any) -> str:
    bom = Bom()
    issues = results.get("issues", [])
    # Convert issues to dicts if they are Pydantic models
    issues_dicts = []
    for issue in issues:
        if hasattr(issue, "model_dump"):
            issues_dicts.append(issue.model_dump())
        else:
            issues_dicts.append(issue)

    file_meta: dict[str, Any] = results.get("file_metadata", {})
    trusted_metadata_paths = _trusted_metadata_fallback_paths(results.get("assets", []))

    ordered_paths = _stable_source_order(
        paths,
        lambda path: _calculate_legacy_risk_score(path, issues_dicts),
        lambda path: _metadata_identity_sort_key(file_meta.get(path)),
    )
    bom_ref_state = _BomRefState(
        reserved={redact_source_reference(path) for path in ordered_paths if redact_source_identifier(path) == path}
    )
    for input_path in ordered_paths:
        if os.path.isdir(input_path):
            scan_root = os.path.realpath(input_path)
            require_stable_root = _supports_descriptor_walk()
            scan_root_fd = _open_scan_root_fd(scan_root, readable=True)
            try:
                for fp, relative_path in _iter_scan_root_files(
                    input_path,
                    scan_root_fd,
                    require_stable_root=require_stable_root,
                ):
                    if _should_skip_sbom_file(fp):
                        continue
                    meta_model = file_meta.get(fp)
                    # Convert Pydantic model to dict if needed
                    if meta_model is not None and hasattr(meta_model, "model_dump"):
                        meta = meta_model.model_dump()
                    else:
                        meta = meta_model or {}
                    component = _component_for_file(
                        fp,
                        meta,
                        issues_dicts,
                        scan_root,
                        allow_metadata_fallback=False,
                        scan_root_fd=scan_root_fd,
                        relative_path=relative_path,
                        require_stable_root=require_stable_root,
                        bom_ref_state=bom_ref_state,
                    )
                    bom.components.add(component)
            finally:
                if scan_root_fd is not None:
                    os.close(scan_root_fd)
        else:
            is_remote_identifier = _is_non_filesystem_identifier(input_path)
            allow_metadata_fallback = (
                is_remote_identifier or input_path in trusted_metadata_paths
            ) and not os.path.lexists(input_path)
            input_directory = os.path.dirname(input_path) or "."
            single_scan_root: str | None = None if allow_metadata_fallback else os.path.realpath(input_directory)
            require_stable_root = single_scan_root is not None and _supports_descriptor_walk()
            scan_root_fd = _open_scan_root_fd(single_scan_root) if single_scan_root is not None else None
            try:
                meta_model = file_meta.get(input_path)
                # Convert Pydantic model to dict if needed
                if meta_model is not None and hasattr(meta_model, "model_dump"):
                    meta = meta_model.model_dump()
                else:
                    meta = meta_model or {}
                component = _component_for_file(
                    input_path,
                    meta,
                    issues_dicts,
                    single_scan_root,
                    allow_metadata_fallback=allow_metadata_fallback,
                    scan_root_fd=scan_root_fd,
                    relative_path=(None if single_scan_root is None else os.path.relpath(input_path, input_directory)),
                    require_stable_root=require_stable_root,
                    bom_ref_state=bom_ref_state,
                )
                bom.components.add(component)
            finally:
                if scan_root_fd is not None:
                    os.close(scan_root_fd)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return str(outputter.output_as_string(indent=2))


def generate_sbom_pydantic(paths: Iterable[str], results: ModelAuditResultModel) -> str:
    """
    Generate SBOM directly from Pydantic models (type-safe version).

    This is the preferred method that works directly with Pydantic models
    without any dict conversions, providing full type safety.
    """
    bom = Bom()

    # Use Pydantic models directly
    issues: list[Issue] = results.issues or []
    file_metadata: dict[str, FileMetadataModel] = results.file_metadata or {}
    trusted_metadata_paths = _trusted_metadata_fallback_paths(results.assets)

    ordered_paths = _stable_source_order(
        paths,
        lambda path: _calculate_risk_score(path, issues),
        lambda path: _metadata_identity_sort_key(file_metadata.get(path)),
    )
    bom_ref_state = _BomRefState(
        reserved={redact_source_reference(path) for path in ordered_paths if redact_source_identifier(path) == path}
    )
    for input_path in ordered_paths:
        if os.path.isdir(input_path):
            scan_root = os.path.realpath(input_path)
            require_stable_root = _supports_descriptor_walk()
            scan_root_fd = _open_scan_root_fd(scan_root, readable=True)
            try:
                for fp, relative_path in _iter_scan_root_files(
                    input_path,
                    scan_root_fd,
                    require_stable_root=require_stable_root,
                ):
                    if _should_skip_sbom_file(fp):
                        continue
                    metadata = file_metadata.get(fp)
                    component = _component_for_file_pydantic(
                        fp,
                        metadata,
                        issues,
                        scan_root,
                        allow_metadata_fallback=False,
                        scan_root_fd=scan_root_fd,
                        relative_path=relative_path,
                        require_stable_root=require_stable_root,
                        bom_ref_state=bom_ref_state,
                    )
                    bom.components.add(component)
            finally:
                if scan_root_fd is not None:
                    os.close(scan_root_fd)
        else:
            is_remote_identifier = _is_non_filesystem_identifier(input_path)
            allow_metadata_fallback = (
                is_remote_identifier or input_path in trusted_metadata_paths
            ) and not os.path.lexists(input_path)
            input_directory = os.path.dirname(input_path) or "."
            single_scan_root: str | None = None if allow_metadata_fallback else os.path.realpath(input_directory)
            require_stable_root = single_scan_root is not None and _supports_descriptor_walk()
            scan_root_fd = _open_scan_root_fd(single_scan_root) if single_scan_root is not None else None
            try:
                metadata = file_metadata.get(input_path)
                component = _component_for_file_pydantic(
                    input_path,
                    metadata,
                    issues,
                    single_scan_root,
                    allow_metadata_fallback=allow_metadata_fallback,
                    scan_root_fd=scan_root_fd,
                    relative_path=(None if single_scan_root is None else os.path.relpath(input_path, input_directory)),
                    require_stable_root=require_stable_root,
                    bom_ref_state=bom_ref_state,
                )
                bom.components.add(component)
            finally:
                if scan_root_fd is not None:
                    os.close(scan_root_fd)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return str(outputter.output_as_string(indent=2))
