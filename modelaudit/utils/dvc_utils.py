import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


def resolve_dvc_file(file_path: str) -> List[str]:
    """Return local paths of artifacts tracked by a DVC pointer file."""
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
    resolved: List[str] = []
    for out in outs:
        if isinstance(out, dict) and "path" in out:
            target = Path(file_path).parent / out["path"]
            if target.exists():
                resolved.append(str(target))
            else:
                logger.debug("DVC target missing: %s", target)
    return resolved
