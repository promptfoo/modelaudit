import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_DVC_OUTPUTS = 100


@dataclass(frozen=True)
class DvcResolution:
    """Resolved DVC pointer targets plus coverage metadata."""

    targets: list[str]
    declared_output_count: int = 0
    output_limit: int = MAX_DVC_OUTPUTS
    omitted_output_count: int = 0
    omitted_targets: list[str] = field(default_factory=list)
    unverified_omitted_output_count: int = 0

    @property
    def analysis_incomplete(self) -> bool:
        return self.omitted_output_count > 0


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

    outs = data.get("outs", [])
    if not isinstance(outs, list):
        logger.warning(f"DVC file {file_path} has invalid 'outs' structure")
        return DvcResolution(targets=[])

    # Limit number of outputs to prevent resource exhaustion
    declared_output_count = len(outs)
    omitted_output_count = max(declared_output_count - MAX_DVC_OUTPUTS, 0)
    if omitted_output_count:
        logger.warning(
            f"DVC file {file_path} has too many outputs ({declared_output_count}), limiting to {MAX_DVC_OUTPUTS}"
        )
        # Resolve one additional bounded window for directory-walk coverage
        # verification without expanding those omitted targets for scanning.
        outs = outs[: MAX_DVC_OUTPUTS * 2]

    resolved: list[str] = []
    omitted_targets: list[str] = []
    dvc_dir = path.parent.resolve()

    for index, out in enumerate(outs):
        if not isinstance(out, dict) or "path" not in out:
            logger.debug("Invalid output entry in DVC file %s: %s", file_path, out)
            continue

        out_path = out["path"]
        if not isinstance(out_path, str):
            logger.debug("Invalid path type in DVC file %s: %s", file_path, type(out_path))
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
                continue

            if target.exists():
                target_list = resolved if index < MAX_DVC_OUTPUTS else omitted_targets
                target_list.append(str(target))
            else:
                logger.debug(f"DVC target missing: {target}")

        except (OSError, ValueError) as e:
            logger.warning(f"Error resolving DVC target path {out_path}: {e}")
            continue

    return DvcResolution(
        targets=resolved,
        declared_output_count=declared_output_count,
        output_limit=MAX_DVC_OUTPUTS,
        omitted_output_count=omitted_output_count,
        omitted_targets=omitted_targets,
        unverified_omitted_output_count=max(declared_output_count - MAX_DVC_OUTPUTS * 2, 0),
    )
