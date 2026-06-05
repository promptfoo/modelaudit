import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DVC_ANALYSIS_INCOMPLETE_REASON = "dvc_outputs_unresolved"
DVC_OUTPUT_LIMIT_EXCEEDED_REASON = "dvc_output_limit_exceeded"
DVC_POINTER_TOO_LARGE_REASON = "dvc_pointer_too_large"
MAX_DVC_POINTER_BYTES = 10 * 1024 * 1024


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
    if not path.is_file() or path.suffix.lower() != ".dvc":
        return DvcResolution()
    pointer_location = path.absolute()
    resolved_pointer = path.resolve()

    try:
        import yaml
    except Exception:
        logger.debug("pyyaml not installed, cannot parse DVC file")
        return DvcResolution(incomplete_reason="dvc_yaml_unavailable")

    try:
        with path.open("rb") as pointer_file:
            pointer_bytes = pointer_file.read(MAX_DVC_POINTER_BYTES + 1)
        if len(pointer_bytes) > MAX_DVC_POINTER_BYTES:
            logger.warning(f"DVC pointer exceeds maximum size: {file_path}")
            return DvcResolution(incomplete_reason=DVC_POINTER_TOO_LARGE_REASON)

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
        data = yaml.load(pointer_bytes, Loader=UniqueKeyLoader) or {}
    except Exception as exc:  # pragma: no cover - YAML errors are rare
        logger.warning(f"Failed to parse DVC file {file_path}: {exc}")
        return DvcResolution(incomplete_reason="dvc_parse_failed")

    if not isinstance(data, dict):
        logger.warning(f"DVC file {file_path} has invalid top-level structure")
        return DvcResolution(incomplete_reason="dvc_invalid_structure")

    outs = data.get("outs", [])
    if not isinstance(outs, list):
        logger.warning(f"DVC file {file_path} has invalid 'outs' structure")
        return DvcResolution(incomplete_reason="dvc_invalid_outputs")

    # Limit number of outputs to prevent resource exhaustion
    MAX_OUTPUTS = 100
    output_limit_exceeded = len(outs) > MAX_OUTPUTS
    if output_limit_exceeded:
        logger.warning(f"DVC file {file_path} has too many outputs ({len(outs)}), limiting to {MAX_OUTPUTS}")
        outs = outs[:MAX_OUTPUTS]

    resolved: list[str] = []
    resolved_seen: set[str] = set()
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
        if not out_path.strip():
            logger.debug("Empty output path in DVC file %s", file_path)
            unresolved.append("<empty-output-path>")
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

            if target == resolved_pointer or target.suffix.lower() == ".dvc":
                logger.warning(f"DVC output resolves to a pointer instead of an artifact: {file_path} -> {target}")
                unresolved.append(out_path)
                continue

            if target.is_dir() and (pointer_location.is_relative_to(target) or resolved_pointer.is_relative_to(target)):
                logger.warning(f"DVC target directory contains its own pointer: {file_path} -> {target}")
                unresolved.append(out_path)
                continue

            target_exists = target.exists()
            if target_exists and target.samefile(resolved_pointer):
                logger.warning(f"DVC output is a hardlink to its own pointer: {file_path} -> {target}")
                unresolved.append(out_path)
                continue

            if target_exists and not target.is_file() and not target.is_dir():
                logger.warning(f"DVC output is not a regular file or directory: {file_path} -> {target}")
                unresolved.append(out_path)
                continue

            if target_exists:
                target_str = str(target)
                if target_str not in resolved_seen:
                    resolved.append(target_str)
                    resolved_seen.add(target_str)
            else:
                logger.debug(f"DVC target missing: {target}")
                unresolved.append(str(target))

        except (OSError, ValueError) as e:
            logger.warning(f"Error resolving DVC target path {out_path}: {e}")
            unresolved.append(out_path)
            continue

    incomplete_reason = DVC_OUTPUT_LIMIT_EXCEEDED_REASON if output_limit_exceeded else None
    if unresolved and incomplete_reason is None:
        incomplete_reason = DVC_ANALYSIS_INCOMPLETE_REASON
    if not outs:
        incomplete_reason = "dvc_no_outputs"

    return DvcResolution(
        resolved_paths=tuple(resolved),
        unresolved_outputs=tuple(unresolved),
        incomplete_reason=incomplete_reason,
    )
