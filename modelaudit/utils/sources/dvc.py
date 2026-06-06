import hashlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DVC_ANALYSIS_INCOMPLETE_REASON = "dvc_outputs_unresolved"
DVC_OUTPUT_LIMIT_EXCEEDED_REASON = "dvc_output_limit_exceeded"
DVC_POINTER_TOO_LARGE_REASON = "dvc_pointer_too_large"
MAX_DVC_POINTER_BYTES = 10 * 1024 * 1024
MAX_DVC_METADATA_VALIDATION_FILES = 100_000
MAX_DVC_OUTPUTS = 100
MAX_DVC_VERIFICATION_OUTPUTS = MAX_DVC_OUTPUTS * 2
MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS = MAX_DVC_OUTPUTS + 1
MAX_DVC_TAIL_INSPECTIONS = 10_000


@dataclass(frozen=True)
class DvcResolution:
    """Resolved DVC outputs plus unresolved coverage gaps."""

    resolved_paths: tuple[str, ...] = ()
    unresolved_outputs: tuple[str, ...] = ()
    incomplete_reason: str | None = None
    declared_output_count: int = 0
    output_limit: int = MAX_DVC_OUTPUTS
    omitted_output_count: int = 0
    omitted_targets: tuple[str, ...] = ()
    unresolved_omitted_output_count: int = 0
    unverified_omitted_output_count: int = 0
    pointer_digest: str | None = None

    @property
    def output_limit_analysis_incomplete(self) -> bool:
        """Return True when capped outputs still require independent coverage."""
        return self.omitted_output_count > 0

    @property
    def analysis_incomplete(self) -> bool:
        """Return True when declared DVC outputs were not fully resolved."""
        return bool(self.unresolved_outputs or self.incomplete_reason or self.output_limit_analysis_incomplete)


def _load_dvc_pointer(path: Path) -> tuple[Any | None, str | None, str | None]:
    """Load a bounded DVC pointer while rejecting duplicate YAML keys."""
    try:
        import yaml
    except Exception:
        logger.debug("pyyaml not installed, cannot parse DVC file")
        return None, "dvc_yaml_unavailable", None

    try:
        with path.open("rb") as pointer_file:
            pointer_bytes = pointer_file.read(MAX_DVC_POINTER_BYTES + 1)
        if len(pointer_bytes) > MAX_DVC_POINTER_BYTES:
            logger.warning("DVC pointer exceeds maximum size: %s", path)
            return None, DVC_POINTER_TOO_LARGE_REASON, None
        pointer_digest = hashlib.sha256(pointer_bytes).hexdigest()

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
        return yaml.load(pointer_bytes, Loader=UniqueKeyLoader) or {}, None, pointer_digest
    except Exception as exc:  # pragma: no cover - YAML errors are rare
        logger.warning("Failed to parse DVC file %s: %s", path, exc)
        return None, "dvc_parse_failed", None


def _resolve_output_base(path: Path, data: dict[Any, Any]) -> tuple[Path | None, str | None]:
    """Resolve a DVC working directory while keeping outputs beside the pointer."""
    dvc_dir = path.parent.resolve()
    wdir = data.get("wdir", ".")
    if not isinstance(wdir, str) or not wdir.strip():
        return None, "dvc_invalid_wdir"
    try:
        output_base = (dvc_dir / wdir).resolve()
        if not output_base.is_relative_to(dvc_dir):
            return None, "dvc_unsafe_wdir"
    except (OSError, ValueError):
        return None, "dvc_invalid_wdir"
    return output_base, None


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


def _resolve_declared_output(
    output: Any,
    *,
    output_base: Path,
    dvc_dir: Path,
    pointer_location: Path,
    resolved_pointer: Path,
    validate_metadata: bool = True,
) -> tuple[Path | None, str]:
    """Resolve one declared output or return a stable coverage-gap label."""
    if not isinstance(output, dict) or "path" not in output:
        return None, "<invalid-output-entry>"

    out_path = output["path"]
    if not isinstance(out_path, str):
        return None, f"<invalid-output-path:{type(out_path).__name__}>"
    if not out_path.strip():
        return None, "<empty-output-path>"

    try:
        target = (output_base / out_path).resolve()
        if not target.is_relative_to(dvc_dir):
            return None, out_path
        if target == resolved_pointer or target.suffix.lower() == ".dvc":
            return None, out_path
        if target.is_dir() and (pointer_location.is_relative_to(target) or resolved_pointer.is_relative_to(target)):
            return None, out_path
        if not target.exists():
            return None, str(target)
        if target.samefile(resolved_pointer):
            return None, out_path
        if not target.is_file() and not target.is_dir():
            return None, out_path
        if validate_metadata and (metadata_gap := _declared_output_metadata_gap(output, target)):
            return target, f"{target} ({metadata_gap})"
        return target, ""
    except (OSError, ValueError):
        return None, out_path


def resolve_dvc_file(file_path: str) -> list[str]:
    """Return local paths of artifacts tracked by a DVC pointer file.

    Security considerations:
    - Validates paths to prevent directory traversal
    - Limits number of outputs to prevent resource exhaustion
    - Validates DVC file structure
    """
    return list(resolve_dvc_file_status(file_path).resolved_paths)


def resolve_dvc_file_status(file_path: str) -> DvcResolution:
    """Return resolved DVC outputs and unresolved coverage state."""
    path = Path(file_path)
    if not path.is_file() or path.suffix.lower() != ".dvc":
        return DvcResolution()
    pointer_location = path.absolute()
    resolved_pointer = path.resolve()

    data, load_error, pointer_digest = _load_dvc_pointer(path)
    if load_error is not None:
        return DvcResolution(incomplete_reason=load_error)

    if not isinstance(data, dict):
        logger.warning(f"DVC file {file_path} has invalid top-level structure")
        return DvcResolution(incomplete_reason="dvc_invalid_structure")

    outs = data.get("outs", [])
    if not isinstance(outs, list):
        logger.warning(f"DVC file {file_path} has invalid 'outs' structure")
        return DvcResolution(incomplete_reason="dvc_invalid_outputs")

    output_base, base_error = _resolve_output_base(path, data)
    if output_base is None:
        logger.warning("DVC file %s has invalid working directory", file_path)
        return DvcResolution(incomplete_reason=base_error)
    dvc_dir = path.parent.resolve()

    declared_output_count = len(outs)
    omitted_output_count = max(declared_output_count - MAX_DVC_OUTPUTS, 0)
    if omitted_output_count:
        logger.warning(
            "DVC file %s has too many outputs (%s), limiting direct expansion to %s",
            file_path,
            declared_output_count,
            MAX_DVC_OUTPUTS,
        )

    resolved: list[str] = []
    resolved_seen: set[str] = set()
    unresolved: list[str] = []
    omitted_targets: list[str] = []
    all_bounded_targets: list[str] = []
    unresolved_omitted_output_count = 0

    for index, output in enumerate(outs[:MAX_DVC_VERIFICATION_OUTPUTS]):
        target, gap = _resolve_declared_output(
            output,
            output_base=output_base,
            dvc_dir=dvc_dir,
            pointer_location=pointer_location,
            resolved_pointer=resolved_pointer,
        )
        is_omitted = index >= MAX_DVC_OUTPUTS
        if target is None:
            if is_omitted:
                unresolved_omitted_output_count += 1
            else:
                unresolved.append(gap)
            continue

        target_str = str(target)
        if not _matches_resolved_artifact(target, all_bounded_targets):
            all_bounded_targets.append(target_str)
        if is_omitted:
            if gap:
                unresolved_omitted_output_count += 1
                continue
            if not _matches_resolved_artifact(target, resolved) and not _matches_resolved_artifact(
                target, omitted_targets
            ):
                omitted_targets.append(target_str)
        elif target_str not in resolved_seen and not _matches_resolved_artifact(target, resolved):
            resolved.append(target_str)
            resolved_seen.add(target_str)
        if gap and not is_omitted:
            unresolved.append(gap)

    unverified_targets: list[str] = []
    invalid_unverified_output_count = 0
    for tail_inspections, output in enumerate(outs[MAX_DVC_VERIFICATION_OUTPUTS:], start=1):
        if tail_inspections > MAX_DVC_TAIL_INSPECTIONS:
            invalid_unverified_output_count = MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS
            break
        target, _gap = _resolve_declared_output(
            output,
            output_base=output_base,
            dvc_dir=dvc_dir,
            pointer_location=pointer_location,
            resolved_pointer=resolved_pointer,
            validate_metadata=False,
        )
        if target is None:
            invalid_unverified_output_count += 1
        elif not _matches_resolved_artifact(target, all_bounded_targets) and not _matches_resolved_artifact(
            target, unverified_targets
        ):
            unverified_targets.append(str(target))
        if len(unverified_targets) + invalid_unverified_output_count >= MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS:
            break

    unverified_omitted_output_count = min(
        len(unverified_targets) + invalid_unverified_output_count,
        MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS,
    )
    cap_incomplete = omitted_output_count > 0
    incomplete_reason = DVC_ANALYSIS_INCOMPLETE_REASON if unresolved else None
    if incomplete_reason is None and cap_incomplete:
        incomplete_reason = DVC_OUTPUT_LIMIT_EXCEEDED_REASON
    if not outs:
        incomplete_reason = "dvc_no_outputs"

    return DvcResolution(
        resolved_paths=tuple(resolved),
        unresolved_outputs=tuple(unresolved),
        incomplete_reason=incomplete_reason,
        declared_output_count=declared_output_count,
        omitted_output_count=omitted_output_count,
        omitted_targets=tuple(omitted_targets),
        unresolved_omitted_output_count=unresolved_omitted_output_count,
        unverified_omitted_output_count=unverified_omitted_output_count,
        pointer_digest=pointer_digest,
    )


def dvc_omitted_outputs_covered(
    file_path: str,
    resolution: DvcResolution,
    is_covered: Callable[[Path], bool],
    *,
    coverage_budget: int,
) -> bool:
    """Return whether independently scanned paths cover every capped output."""
    if not resolution.output_limit_analysis_incomplete:
        return True
    if resolution.unresolved_omitted_output_count > 0:
        return False
    if resolution.unverified_omitted_output_count > coverage_budget:
        return False

    path = Path(file_path)
    data, load_error, pointer_digest = _load_dvc_pointer(path)
    if (
        load_error is not None
        or not isinstance(data, dict)
        or pointer_digest is None
        or pointer_digest != resolution.pointer_digest
    ):
        return False
    outs = data.get("outs", [])
    if not isinstance(outs, list) or len(outs) != resolution.declared_output_count:
        return False
    output_base, base_error = _resolve_output_base(path, data)
    if output_base is None or base_error is not None:
        return False

    dvc_dir = path.parent.resolve()
    pointer_location = path.absolute()
    resolved_pointer = path.resolve()
    known_targets = list(resolution.resolved_paths)
    verified_targets: list[str] = []
    for index, output in enumerate(outs[MAX_DVC_OUTPUTS:]):
        if index >= MAX_DVC_TAIL_INSPECTIONS + MAX_DVC_OUTPUTS:
            return False
        target, _gap = _resolve_declared_output(
            output,
            output_base=output_base,
            dvc_dir=dvc_dir,
            pointer_location=pointer_location,
            resolved_pointer=resolved_pointer,
        )
        if target is None:
            return False
        if _gap:
            return False
        if _matches_resolved_artifact(target, known_targets) or _matches_resolved_artifact(target, verified_targets):
            continue
        if len(verified_targets) >= coverage_budget or not is_covered(target):
            return False
        verified_targets.append(str(target))
    return True
