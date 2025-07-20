import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_dvc_file(file_path: str) -> list[str]:
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
        return []

    path = Path(file_path)
    if not path.is_file() or path.suffix != ".dvc":
        return []

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # pragma: no cover - YAML errors are rare
        logger.warning("Failed to parse DVC file %s: %s", file_path, exc)
        return []

    outs = data.get("outs", [])
    if not isinstance(outs, list):
        logger.warning("DVC file %s has invalid 'outs' structure", file_path)
        return []

    # Limit number of outputs to prevent resource exhaustion
    MAX_OUTPUTS = 100
    if len(outs) > MAX_OUTPUTS:
        logger.warning("DVC file %s has too many outputs (%d), limiting to %d", file_path, len(outs), MAX_OUTPUTS)
        outs = outs[:MAX_OUTPUTS]

    resolved: list[str] = []
    dvc_dir = path.parent.resolve()

    for out in outs:
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

            # Check if target is within the DVC directory (or a reasonable parent)
            # Allow up to 2 levels up to handle common DVC patterns
            max_parent_levels = 2
            current_check = dvc_dir
            is_safe = False

            for _ in range(max_parent_levels + 1):
                try:
                    if target.is_relative_to(current_check):
                        is_safe = True
                        break
                except (AttributeError, ValueError):
                    # Python < 3.9 or different drives on Windows
                    try:
                        import os

                        common = os.path.commonpath([target, current_check])
                        if Path(common) == current_check:
                            is_safe = True
                            break
                    except (ValueError, OSError):
                        pass
                current_check = current_check.parent

            if not is_safe:
                logger.warning("DVC target path outside safe boundaries: %s -> %s", file_path, target)
                continue

            if target.exists():
                resolved.append(str(target))
            else:
                logger.debug("DVC target missing: %s", target)

        except (OSError, ValueError) as e:
            logger.warning("Error resolving DVC target path %s: %s", out_path, e)
            continue

    return resolved
