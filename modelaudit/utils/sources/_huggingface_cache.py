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
        try:
            return expanded_path.resolve()
        except (OSError, RuntimeError):
            return expanded_path.absolute()
    except (OSError, RuntimeError):
        return expanded_path.absolute()


def _absolute_hf_cache_path(path: Path) -> Path:
    """Return an absolute lexical cache path without resolving symlinks."""
    return Path(os.path.abspath(path.expanduser()))


def _get_hf_cache_root_spellings() -> tuple[Path, ...]:
    """Return configured HuggingFace hub cache root spellings before symlink resolution."""
    roots: list[Path] = []

    hf_hub_cache = os.environ.get("HF_HUB_CACHE")
    if hf_hub_cache:
        roots.append(_absolute_hf_cache_path(Path(hf_hub_cache)))

    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        roots.append(_absolute_hf_cache_path(Path(hf_home) / "hub"))

    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        roots.append(_absolute_hf_cache_path(Path(HF_HUB_CACHE)))
    except Exception:
        # huggingface_hub is optional and may be unavailable or misconfigured.
        pass

    default_root = _absolute_hf_cache_path(Path.home() / ".cache" / "huggingface" / "hub")
    if default_root not in roots:
        roots.append(default_root)

    return tuple(roots)


def _get_hf_cache_roots() -> tuple[Path, ...]:
    """Return configured HuggingFace hub cache roots plus the default fallback."""
    roots: list[Path] = []

    for root in _get_hf_cache_root_spellings():
        resolved_root = _resolve_hf_cache_path(root)
        if resolved_root not in roots:
            roots.append(resolved_root)

    return tuple(roots)


def _path_has_part(path: Path, part: str) -> bool:
    """Return True if any path segment matches part (case-insensitive)."""
    part_lower = part.lower()
    return any(segment.lower() == part_lower for segment in path.parts)


def _hf_cache_snapshot_revision(path: Path, cache_root: Path | None = None) -> str | None:
    """Return the lexical HF snapshot revision for ``snapshots/<revision>/...`` aliases."""
    absolute_path = _absolute_hf_cache_path(path)
    if cache_root is not None:
        resolved_cache_root = _resolve_hf_cache_path(cache_root)
        cache_root_spellings = [_absolute_hf_cache_path(cache_root)]
        for hub_root in _get_hf_cache_root_spellings():
            model_cache_root = hub_root / resolved_cache_root.name
            if _resolve_hf_cache_path(model_cache_root) == resolved_cache_root:
                cache_root_spellings.append(model_cache_root)

        for cache_root_spelling in dict.fromkeys(cache_root_spellings):
            try:
                relative_parts = absolute_path.relative_to(cache_root_spelling).parts
            except ValueError:
                continue
            if (
                len(relative_parts) >= 3
                and relative_parts[0].lower() == "snapshots"
                and relative_parts[1] not in {"", ".", ".."}
            ):
                return relative_parts[1]
            return None
        return None

    for index, segment in enumerate(absolute_path.parts):
        if not segment.lower().startswith("models--"):
            continue
        relative_parts = absolute_path.parts[index + 1 :]
        if (
            len(relative_parts) >= 3
            and relative_parts[0].lower() == "snapshots"
            and relative_parts[1] not in {"", ".", ".."}
        ):
            return relative_parts[1]
    return None


def _is_hf_cache_snapshot_alias(path: Path, cache_root: Path | None = None) -> bool:
    """Return True only for lexical aliases below ``snapshots/<revision>/...``."""
    return _hf_cache_snapshot_revision(path, cache_root) is not None


def _find_hf_cache_root(path: Path) -> Path | None:
    """Return the HuggingFace cache root containing models--* if present."""
    resolved_path = _resolve_hf_cache_path(path)
    cache_roots = _get_hf_cache_roots()

    for index, segment in enumerate(resolved_path.parts):
        if not segment.lower().startswith("models--"):
            continue

        candidate = Path(*resolved_path.parts[: index + 1])
        hub_root = candidate.parent
        if hub_root in cache_roots:
            return candidate

    return None


def _trusted_hf_blobs_root(cache_root: Path) -> Path | None:
    """Return the canonical blobs directory only when it stays inside the model cache."""
    blobs_root = cache_root / "blobs"
    try:
        if blobs_root.is_symlink():
            return None
        resolved_cache_root = cache_root.resolve(strict=True)
        resolved_blobs_root = blobs_root.resolve(strict=True)
        if not resolved_blobs_root.is_dir() or not resolved_blobs_root.is_relative_to(resolved_cache_root):
            return None
    except (OSError, RuntimeError):
        return None
    return resolved_blobs_root
