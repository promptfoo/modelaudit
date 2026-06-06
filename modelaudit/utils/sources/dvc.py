import hashlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DVC_ANALYSIS_INCOMPLETE_REASON = "dvc_outputs_unresolved"
DVC_OUTPUT_LIMIT_EXCEEDED_REASON = "dvc_output_limit_exceeded"
DVC_POINTER_TOO_LARGE_REASON = "dvc_pointer_too_large"
MAX_DVC_OUTPUTS = 100
MAX_DVC_POINTER_BYTES = 10 * 1024 * 1024
MAX_DVC_METADATA_VALIDATION_FILES = 100_000
MAX_DVC_TAIL_DECLARATIONS = MAX_DVC_OUTPUTS * 100
MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS = MAX_DVC_OUTPUTS + 1


@dataclass(frozen=True)
class DvcResolution:
    """Resolved DVC outputs plus unresolved and capped coverage gaps."""

    resolved_paths: tuple[str, ...] = ()
    unresolved_outputs: tuple[str, ...] = ()
    incomplete_reason: str | None = None
    declared_output_count: int = 0
    output_limit: int = MAX_DVC_OUTPUTS
    omitted_output_count: int = 0
    omitted_targets: list[str] = field(default_factory=list)
    unresolved_omitted_output_count: int = 0
    unverified_omitted_output_count: int = 0
    source_digest: str | None = None
    tail_verification_truncated: bool = False

    @property
    def targets(self) -> list[str]:
        """Return resolved paths using the legacy list-shaped interface."""
        return list(self.resolved_paths)

    @property
    def analysis_incomplete(self) -> bool:
        """Return True when declared DVC outputs were not fully resolved."""
        return bool(self.unresolved_outputs or self.incomplete_reason)

    @property
    def has_non_cap_gap(self) -> bool:
        """Return whether coverage is incomplete for a reason other than the output cap."""
        return bool(
            self.unresolved_outputs
            or (self.incomplete_reason is not None and self.incomplete_reason != DVC_OUTPUT_LIMIT_EXCEEDED_REASON)
        )


def _load_dvc_data(pointer_bytes: bytes) -> Any:
    """Parse DVC YAML while rejecting duplicate mapping keys."""
    import yaml

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping)
    return yaml.load(pointer_bytes, Loader=UniqueKeyLoader) or {}


def _matches_resolved_artifact(target: Path, resolved_paths: list[str]) -> bool:
    """Return whether target aliases an artifact already selected for scanning."""
    for resolved_path in resolved_paths:
        try:
            if target.samefile(resolved_path):
                return True
        except OSError:
            continue
    return False


def _declared_output_metadata_gap(output: dict[Any, Any], target: Path) -> str | None:
    """Return a definite local coverage gap from DVC size/count lower bounds."""
    declared_size = output.get("size")
    declared_nfiles = output.get("nfiles")
    for field_name, value in (("size", declared_size), ("nfiles", declared_nfiles)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            return f"invalid-{field_name}"

    if declared_size is None and declared_nfiles is None:
        return None

    try:
        if target.is_file():
            actual_size = target.stat().st_size
            if isinstance(declared_size, int) and actual_size < declared_size:
                return "declared-size-not-materialized"
            if isinstance(declared_nfiles, int) and declared_nfiles > 1:
                return "declared-file-count-not-materialized"
            return None

        actual_size = 0
        actual_nfiles = 0
        for root, _dirs, files in os.walk(target, followlinks=False):
            for filename in files:
                file_path = Path(root) / filename
                if not file_path.is_file():
                    return "metadata-validation-failed"
                actual_nfiles += 1
                actual_size += file_path.stat().st_size
                if actual_nfiles > MAX_DVC_METADATA_VALIDATION_FILES:
                    return "metadata-validation-limit-exceeded"
            size_satisfied = not isinstance(declared_size, int) or actual_size >= declared_size
            count_satisfied = not isinstance(declared_nfiles, int) or actual_nfiles >= declared_nfiles
            if size_satisfied and count_satisfied:
                return None
    except OSError:
        return "metadata-validation-failed"

    if isinstance(declared_nfiles, int) and actual_nfiles < declared_nfiles:
        return "declared-file-count-not-materialized"
    if isinstance(declared_size, int) and actual_size < declared_size:
        return "declared-size-not-materialized"
    return None


def _resolve_output_base(path: Path, data: dict[Any, Any]) -> Path | None:
    """Resolve and validate the DVC working directory."""
    dvc_dir = path.parent.resolve()
    wdir = data.get("wdir", ".")
    if not isinstance(wdir, str) or not wdir.strip():
        logger.warning(f"DVC file {path} has invalid 'wdir' value")
        return None
    try:
        output_base = (dvc_dir / wdir).resolve()
        if output_base.is_relative_to(dvc_dir):
            return output_base
    except (OSError, ValueError):
        pass
    logger.warning(f"DVC working directory outside safe boundaries: {path} -> {wdir}")
    return None


def _canonical_output_target(
    output_base: Path,
    dvc_dir: Path,
    resolved_pointer: Path,
    out_path: str,
) -> Path | None:
    """Resolve one declared output without allowing pointer or boundary escapes."""
    try:
        target = (output_base / out_path).resolve()
        if not target.is_relative_to(dvc_dir):
            return None
        if target == resolved_pointer or target.suffix.lower() == ".dvc":
            return None
        return target
    except (OSError, ValueError):
        return None


def resolve_dvc_file(file_path: str) -> list[str]:
    """Return local paths of artifacts tracked by a DVC pointer file."""
    return list(resolve_dvc_file_status(file_path).resolved_paths)


def resolve_dvc_file_with_metadata(file_path: str) -> DvcResolution:
    """Return resolved DVC outputs and capped-coverage metadata."""
    return resolve_dvc_file_status(file_path)


def resolve_dvc_file_status(file_path: str) -> DvcResolution:
    """Return resolved DVC outputs and unresolved coverage state."""
    path = Path(file_path)
    if not path.is_file() or path.suffix.lower() != ".dvc":
        return DvcResolution()
    pointer_location = path.absolute()
    resolved_pointer = path.resolve()

    try:
        import yaml  # noqa: F401
    except Exception:
        logger.debug("pyyaml not installed, cannot parse DVC file")
        return DvcResolution(incomplete_reason="dvc_yaml_unavailable")

    try:
        with path.open("rb") as pointer_file:
            pointer_bytes = pointer_file.read(MAX_DVC_POINTER_BYTES + 1)
        if len(pointer_bytes) > MAX_DVC_POINTER_BYTES:
            logger.warning(f"DVC pointer exceeds maximum size: {file_path}")
            return DvcResolution(incomplete_reason=DVC_POINTER_TOO_LARGE_REASON)
        data = _load_dvc_data(pointer_bytes)
    except Exception as exc:  # pragma: no cover - YAML errors are rare
        logger.warning(f"Failed to parse DVC file {file_path}: {exc}")
        return DvcResolution(incomplete_reason="dvc_parse_failed")

    if not isinstance(data, dict):
        logger.warning(f"DVC file {file_path} has invalid top-level structure")
        return DvcResolution(incomplete_reason="dvc_invalid_structure")

    declared_outs = data.get("outs", [])
    if not isinstance(declared_outs, list):
        logger.warning(f"DVC file {file_path} has invalid 'outs' structure")
        return DvcResolution(incomplete_reason="dvc_invalid_outputs")

    output_base = _resolve_output_base(path, data)
    if output_base is None:
        return DvcResolution(incomplete_reason="dvc_invalid_wdir")

    declared_output_count = len(declared_outs)
    omitted_output_count = max(declared_output_count - MAX_DVC_OUTPUTS, 0)
    verification_limit = MAX_DVC_OUTPUTS * 2
    bounded_outs = declared_outs[:verification_limit]
    dvc_dir = path.parent.resolve()

    resolved: list[str] = []
    resolved_seen: set[str] = set()
    unresolved: list[str] = []
    omitted_targets: list[str] = []
    omitted_seen: set[str] = set()
    bounded_declared_targets: set[str] = set()
    unresolved_omitted_output_count = 0

    for index, out in enumerate(bounded_outs):
        is_omitted = index >= MAX_DVC_OUTPUTS
        if not isinstance(out, dict) or "path" not in out:
            logger.debug("Invalid output entry in DVC file %s: %s", file_path, out)
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append("<invalid-output-entry>")
            continue

        out_path = out["path"]
        if not isinstance(out_path, str):
            logger.debug("Invalid path type in DVC file %s: %s", file_path, type(out_path))
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(f"<invalid-output-path:{type(out_path).__name__}>")
            continue
        if not out_path.strip():
            logger.debug("Empty output path in DVC file %s", file_path)
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append("<empty-output-path>")
            continue

        target = _canonical_output_target(output_base, dvc_dir, resolved_pointer, out_path)
        if target is None:
            logger.warning(f"DVC target path is unsafe or points to a pointer: {file_path} -> {out_path}")
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(out_path)
            continue
        bounded_declared_targets.add(str(target))

        if target.is_dir() and (pointer_location.is_relative_to(target) or resolved_pointer.is_relative_to(target)):
            logger.warning(f"DVC target directory contains its own pointer: {file_path} -> {target}")
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(out_path)
            continue

        try:
            target_exists = target.exists()
            if target_exists and target.samefile(resolved_pointer):
                raise ValueError("output is a hardlink to its own pointer")
            if target_exists and not target.is_file() and not target.is_dir():
                raise ValueError("output is not a regular file or directory")
            metadata_gap = _declared_output_metadata_gap(out, target) if target_exists else None
        except (OSError, ValueError) as exc:
            logger.warning(f"Error resolving DVC target path {out_path}: {exc}")
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(out_path)
            continue

        if not target_exists:
            logger.debug(f"DVC target missing: {target}")
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(str(target))
            continue
        target_str = str(target)
        if not is_omitted and target_str not in resolved_seen and not _matches_resolved_artifact(target, resolved):
            resolved.append(target_str)
            resolved_seen.add(target_str)

        if metadata_gap is not None:
            logger.warning(
                "DVC output metadata indicates incomplete local materialization: %s -> %s (%s)",
                file_path,
                target,
                metadata_gap,
            )
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(f"{target} ({metadata_gap})")
            continue

        if (
            is_omitted
            and target_str not in resolved_seen
            and target_str not in omitted_seen
            and not _matches_resolved_artifact(target, resolved)
        ):
            omitted_targets.append(target_str)
            omitted_seen.add(target_str)

    unverified_output_targets: set[str] = set()
    invalid_unverified_output_count = 0
    unverified_outs = declared_outs[verification_limit:]
    tail_verification_truncated = len(unverified_outs) > MAX_DVC_TAIL_DECLARATIONS
    for out in unverified_outs[:MAX_DVC_TAIL_DECLARATIONS]:
        if not isinstance(out, dict):
            invalid_unverified_output_count += 1
        else:
            out_path = out.get("path")
            if not isinstance(out_path, str) or not out_path.strip():
                invalid_unverified_output_count += 1
            else:
                target = _canonical_output_target(output_base, dvc_dir, resolved_pointer, out_path)
                if target is None:
                    invalid_unverified_output_count += 1
                elif str(target) not in bounded_declared_targets:
                    unverified_output_targets.add(str(target))
        if len(unverified_output_targets) + invalid_unverified_output_count >= MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS:
            break

    unverified_omitted_output_count = min(
        len(unverified_output_targets) + invalid_unverified_output_count,
        MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS,
    )
    cap_has_gap = bool(
        omitted_targets
        or unresolved_omitted_output_count
        or unverified_omitted_output_count
        or tail_verification_truncated
    )
    incomplete_reason = DVC_OUTPUT_LIMIT_EXCEEDED_REASON if cap_has_gap else None
    if unresolved and incomplete_reason is None:
        incomplete_reason = DVC_ANALYSIS_INCOMPLETE_REASON
    if not declared_outs:
        incomplete_reason = "dvc_no_outputs"

    if omitted_output_count:
        logger.warning(
            f"DVC file {file_path} has too many outputs ({declared_output_count}), limiting to {MAX_DVC_OUTPUTS}"
        )

    return DvcResolution(
        resolved_paths=tuple(resolved),
        unresolved_outputs=tuple(unresolved),
        incomplete_reason=incomplete_reason,
        declared_output_count=declared_output_count,
        output_limit=MAX_DVC_OUTPUTS,
        omitted_output_count=omitted_output_count,
        omitted_targets=omitted_targets,
        unresolved_omitted_output_count=unresolved_omitted_output_count,
        unverified_omitted_output_count=unverified_omitted_output_count,
        source_digest=hashlib.sha256(pointer_bytes).hexdigest(),
        tail_verification_truncated=tail_verification_truncated,
    )


def dvc_omitted_outputs_covered(
    file_path: str,
    resolution: DvcResolution,
    is_covered: Callable[[Path], bool],
    *,
    coverage_budget: int,
) -> bool:
    """Return whether independently scanned paths cover every omitted DVC output."""
    if resolution.unresolved_outputs or resolution.unresolved_omitted_output_count > 0:
        return False
    if resolution.source_digest is None or resolution.tail_verification_truncated:
        return False
    try:
        with Path(file_path).open("rb") as pointer_file:
            pointer_bytes = pointer_file.read(MAX_DVC_POINTER_BYTES + 1)
    except OSError:
        return False
    if len(pointer_bytes) > MAX_DVC_POINTER_BYTES:
        return False
    if hashlib.sha256(pointer_bytes).hexdigest() != resolution.source_digest:
        return False
    if not all(is_covered(Path(target)) for target in resolution.omitted_targets):
        return False

    unverified_count = resolution.unverified_omitted_output_count
    if unverified_count == 0:
        return True
    if unverified_count > coverage_budget:
        return False

    try:
        data = _load_dvc_data(pointer_bytes)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    outs = data.get("outs", [])
    if not isinstance(outs, list) or len(outs) != resolution.declared_output_count:
        return False
    if len(outs) - MAX_DVC_OUTPUTS * 2 > MAX_DVC_TAIL_DECLARATIONS:
        return False

    path = Path(file_path)
    output_base = _resolve_output_base(path, data)
    if output_base is None:
        return False
    dvc_dir = path.parent.resolve()
    resolved_pointer = path.resolve()
    known_targets: set[str] = set()
    for out in outs[: MAX_DVC_OUTPUTS * 2]:
        if not isinstance(out, dict):
            continue
        out_path = out.get("path")
        if not isinstance(out_path, str):
            continue
        target = _canonical_output_target(output_base, dvc_dir, resolved_pointer, out_path)
        if target is not None:
            known_targets.add(str(target))

    verified_targets: set[str] = set()
    for out in outs[MAX_DVC_OUTPUTS * 2 :]:
        if not isinstance(out, dict):
            return False
        out_path = out.get("path")
        if not isinstance(out_path, str) or not out_path.strip():
            return False
        target = _canonical_output_target(output_base, dvc_dir, resolved_pointer, out_path)
        if target is None:
            return False
        target_str = str(target)
        if target_str in known_targets or target_str in verified_targets:
            continue
        if not target.exists() or (not target.is_file() and not target.is_dir()):
            return False
        if _declared_output_metadata_gap(out, target) is not None:
            return False
        if len(verified_targets) >= coverage_budget or not is_covered(target):
            return False
        verified_targets.add(target_str)
    return True
