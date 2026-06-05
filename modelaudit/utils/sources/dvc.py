import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_DVC_OUTPUTS = 100
MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS = MAX_DVC_OUTPUTS + 1


@dataclass(frozen=True)
class DvcResolution:
    """Resolved DVC pointer targets plus coverage metadata."""

    targets: list[str]
    declared_output_count: int = 0
    output_limit: int = MAX_DVC_OUTPUTS
    omitted_output_count: int = 0
    omitted_targets: list[str] = field(default_factory=list)
    unresolved_omitted_output_count: int = 0
    unverified_omitted_output_count: int = 0

    @property
    def analysis_incomplete(self) -> bool:
        if self.omitted_output_count == 0:
            return False
        if self.unresolved_omitted_output_count > 0 or self.unverified_omitted_output_count > 0:
            return True
        resolved_targets = set(self.targets)
        return any(target not in resolved_targets for target in self.omitted_targets)


def resolve_dvc_file(file_path: str) -> list[str]:
    """Return local paths of artifacts tracked by a DVC pointer file."""
    return resolve_dvc_file_with_metadata(file_path).targets


def resolve_dvc_file_with_metadata(file_path: str) -> DvcResolution:
    """Return local paths of artifacts tracked by a DVC pointer file.

    Security considerations:
    - Validates paths to prevent directory traversal
    - Limits number of outputs to prevent resource exhaustion
    - Validates DVC file structure
    """
    try:
        import yaml
    except Exception:
        logger.debug("pyyaml not installed, cannot parse DVC file")
        return DvcResolution(targets=[])

    path = Path(file_path)
    if not path.is_file() or path.suffix != ".dvc":
        return DvcResolution(targets=[])

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # pragma: no cover - YAML errors are rare
        logger.warning(f"Failed to parse DVC file {file_path}: {exc}")
        return DvcResolution(targets=[])

    declared_outs = data.get("outs", [])
    if not isinstance(declared_outs, list):
        logger.warning(f"DVC file {file_path} has invalid 'outs' structure")
        return DvcResolution(targets=[])

    # Limit number of outputs to prevent resource exhaustion
    declared_output_count = len(declared_outs)
    omitted_output_count = max(declared_output_count - MAX_DVC_OUTPUTS, 0)
    verification_limit = MAX_DVC_OUTPUTS * 2
    outs = declared_outs[:verification_limit]
    dvc_dir = path.parent.resolve()

    def canonical_target(output_path: str) -> str | None:
        try:
            target = (dvc_dir / output_path).resolve()
            return str(target) if target.is_relative_to(dvc_dir) else None
        except (OSError, ValueError):
            return None

    bounded_declared_targets: set[str] = set()
    for out in outs:
        if not isinstance(out, dict) or not isinstance(out.get("path"), str):
            continue
        bounded_target = canonical_target(out["path"])
        if bounded_target is not None:
            bounded_declared_targets.add(bounded_target)
    unverified_output_targets: set[str] = set()
    invalid_unverified_output_count = 0
    for out in declared_outs[verification_limit:]:
        if not isinstance(out, dict) or not isinstance(out.get("path"), str):
            invalid_unverified_output_count += 1
        else:
            unverified_target = canonical_target(out["path"])
            if unverified_target is None:
                invalid_unverified_output_count += 1
            elif unverified_target not in bounded_declared_targets:
                unverified_output_targets.add(unverified_target)
        if len(unverified_output_targets) + invalid_unverified_output_count >= MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS:
            break
    unverified_omitted_output_count = min(
        len(unverified_output_targets) + invalid_unverified_output_count,
        MAX_TRACKED_UNVERIFIED_DVC_OUTPUTS,
    )
    if omitted_output_count:
        logger.warning(
            f"DVC file {file_path} has too many outputs ({declared_output_count}), limiting to {MAX_DVC_OUTPUTS}"
        )

    resolved: list[str] = []
    resolved_targets: set[str] = set()
    omitted_targets: list[str] = []
    unique_omitted_targets: set[str] = set()
    unresolved_omitted_output_count = 0
    for index, out in enumerate(outs):
        is_omitted = index >= MAX_DVC_OUTPUTS
        if not isinstance(out, dict) or "path" not in out:
            logger.debug("Invalid output entry in DVC file %s: %s", file_path, out)
            unresolved_omitted_output_count += int(is_omitted)
            continue

        out_path = out["path"]
        if not isinstance(out_path, str):
            logger.debug("Invalid path type in DVC file %s: %s", file_path, type(out_path))
            unresolved_omitted_output_count += int(is_omitted)
            continue

        # Security: Resolve target path and validate it's within safe boundaries
        try:
            target = (dvc_dir / out_path).resolve()

            try:
                is_safe = target.is_relative_to(dvc_dir)
            except (AttributeError, ValueError):
                # Python < 3.9 or different drives on Windows
                try:
                    import os

                    common = os.path.commonpath([target, dvc_dir])
                    is_safe = Path(common) == dvc_dir
                except (ValueError, OSError):
                    is_safe = False

            if not is_safe:
                logger.warning(f"DVC target path outside safe boundaries: {file_path} -> {target}")
                unresolved_omitted_output_count += int(is_omitted)
                continue

            if target.exists():
                target_str = str(target)
                if index < MAX_DVC_OUTPUTS:
                    if target_str not in resolved_targets:
                        resolved.append(target_str)
                        resolved_targets.add(target_str)
                elif target_str not in resolved_targets and target_str not in unique_omitted_targets:
                    omitted_targets.append(target_str)
                    unique_omitted_targets.add(target_str)
            else:
                logger.debug(f"DVC target missing: {target}")
                unresolved_omitted_output_count += int(is_omitted)

        except (OSError, ValueError) as e:
            logger.warning(f"Error resolving DVC target path {out_path}: {e}")
            unresolved_omitted_output_count += int(is_omitted)
            continue

    return DvcResolution(
        targets=resolved,
        declared_output_count=declared_output_count,
        output_limit=MAX_DVC_OUTPUTS,
        omitted_output_count=omitted_output_count,
        omitted_targets=omitted_targets,
        unresolved_omitted_output_count=unresolved_omitted_output_count,
        unverified_omitted_output_count=unverified_omitted_output_count,
    )


def unverified_dvc_outputs_covered_by_paths(
    file_path: str,
    resolution: DvcResolution,
    covered_paths: set[str],
) -> bool:
    """Verify an omitted DVC tail with work bounded by already discovered paths."""
    return dvc_omitted_outputs_covered(
        file_path,
        resolution,
        lambda target: str(target) in covered_paths,
        coverage_budget=len(covered_paths),
        verify_bounded_targets=False,
    )


def dvc_omitted_outputs_covered(
    file_path: str,
    resolution: DvcResolution,
    is_covered: Callable[[Path], bool],
    *,
    coverage_budget: int,
    verify_bounded_targets: bool = True,
) -> bool:
    """Return whether independently scanned paths cover every omitted DVC output."""
    if resolution.unresolved_omitted_output_count > 0:
        return False
    if verify_bounded_targets and not all(is_covered(Path(target)) for target in resolution.omitted_targets):
        return False

    unverified_count = resolution.unverified_omitted_output_count
    if unverified_count == 0:
        return True
    if unverified_count > coverage_budget:
        return False

    try:
        import yaml
    except Exception:
        return False

    path = Path(file_path)
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return False
    outs = data.get("outs", [])
    if not isinstance(outs, list) or len(outs) != resolution.declared_output_count:
        return False

    dvc_dir = path.parent.resolve()
    verified_targets: set[str] = set()
    for out in outs[MAX_DVC_OUTPUTS * 2 :]:
        if not isinstance(out, dict):
            return False
        out_path = out.get("path")
        if not isinstance(out_path, str):
            return False
        try:
            target = (dvc_dir / out_path).resolve()
            target_str = str(target)
            if not target.is_relative_to(dvc_dir):
                return False
            if target_str in verified_targets:
                continue
            if len(verified_targets) >= coverage_budget or not is_covered(target):
                return False
            verified_targets.add(target_str)
        except (OSError, ValueError):
            return False
    return True
