import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DVC_ANALYSIS_INCOMPLETE_REASON = "dvc_outputs_unresolved"


@dataclass(frozen=True)
class DvcResolution:
    """Resolved DVC outputs plus unresolved coverage gaps."""

    resolved_paths: tuple[str, ...] = ()
    unresolved_outputs: tuple[str, ...] = ()
    incomplete_reason: str | None = None

    @property
    def analysis_incomplete(self) -> bool:
        """Return True when declared DVC outputs were not fully resolved."""
        return bool(self.unresolved_outputs or self.incomplete_reason)


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
    if not path.is_file() or path.suffix != ".dvc":
        return DvcResolution()

    try:
        import yaml
    except Exception:
        logger.debug("pyyaml not installed, cannot parse DVC file")
        return DvcResolution(incomplete_reason="dvc_yaml_unavailable")

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # pragma: no cover - YAML errors are rare
        logger.warning(f"Failed to parse DVC file {file_path}: {exc}")
        return DvcResolution(incomplete_reason="dvc_parse_failed")

    outs = data.get("outs", [])
    if not isinstance(outs, list):
        logger.warning(f"DVC file {file_path} has invalid 'outs' structure")
        return DvcResolution(incomplete_reason="dvc_invalid_outputs")

    # Limit number of outputs to prevent resource exhaustion
    MAX_OUTPUTS = 100
    if len(outs) > MAX_OUTPUTS:
        logger.warning(f"DVC file {file_path} has too many outputs ({len(outs)}), limiting to {MAX_OUTPUTS}")
        outs = outs[:MAX_OUTPUTS]

    resolved: list[str] = []
    unresolved: list[str] = []
    dvc_dir = path.parent.resolve()

    for out in outs:
        if not isinstance(out, dict) or "path" not in out:
            logger.debug("Invalid output entry in DVC file %s: %s", file_path, out)
            unresolved.append("<invalid-output-entry>")
            continue

        out_path = out["path"]
        if not isinstance(out_path, str):
            logger.debug("Invalid path type in DVC file %s: %s", file_path, type(out_path))
            unresolved.append(f"<invalid-output-path:{type(out_path).__name__}>")
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
                unresolved.append(out_path)
                continue

            if target.exists():
                resolved.append(str(target))
            else:
                logger.debug(f"DVC target missing: {target}")
                unresolved.append(str(target))

        except (OSError, ValueError) as e:
            logger.warning(f"Error resolving DVC target path {out_path}: {e}")
            unresolved.append(out_path)
            continue

    incomplete_reason = DVC_ANALYSIS_INCOMPLETE_REASON if unresolved else None
    if not outs:
        incomplete_reason = "dvc_no_outputs"

    return DvcResolution(
        resolved_paths=tuple(resolved),
        unresolved_outputs=tuple(unresolved),
        incomplete_reason=incomplete_reason,
    )
