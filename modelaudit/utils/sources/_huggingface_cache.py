"""Internal helpers for identifying HuggingFace cache layouts."""

from __future__ import annotations

import os
from pathlib import Path


def _resolve_hf_cache_path(path: Path) -> Path:
    """Resolve cache paths without depending on strict-aware Path.resolve()."""
    expanded_path = path.expanduser()
    try:
        return expanded_path.resolve(strict=False)
    except TypeError:
        return expanded_path.resolve()
    except OSError:
        return expanded_path.absolute()


def _get_hf_cache_roots() -> tuple[Path, ...]:
    """Return configured HuggingFace hub cache roots plus the default fallback."""
    roots: list[Path] = []

    hf_hub_cache = os.environ.get("HF_HUB_CACHE")
    if hf_hub_cache:
        roots.append(_resolve_hf_cache_path(Path(hf_hub_cache)))

    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        roots.append(_resolve_hf_cache_path(Path(hf_home) / "hub"))

    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        roots.append(_resolve_hf_cache_path(Path(HF_HUB_CACHE)))
    except Exception:
        pass

    default_root = _resolve_hf_cache_path(Path.home() / ".cache" / "huggingface" / "hub")
    if default_root not in roots:
        roots.append(default_root)

    return tuple(roots)


def _path_has_part(path: Path, part: str) -> bool:
    """Return True if any path segment matches part (case-insensitive)."""
    part_lower = part.lower()
    return any(segment.lower() == part_lower for segment in path.parts)


def _find_hf_cache_root(path: Path) -> Path | None:
    """Return the HuggingFace cache root containing models--* if present."""
    resolved_path = _resolve_hf_cache_path(path)
    cache_roots = _get_hf_cache_roots()
    default_layout_suffix = (".cache", "huggingface", "hub")

    for index, segment in enumerate(resolved_path.parts):
        if not segment.lower().startswith("models--"):
            continue

        candidate = Path(*resolved_path.parts[: index + 1])
        hub_root = candidate.parent
        if hub_root in cache_roots or hub_root.parts[-3:] == default_layout_suffix:
            return candidate

    return None
