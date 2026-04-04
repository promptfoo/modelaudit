"""Internal helpers for identifying HuggingFace cache layouts."""

from pathlib import Path


def _path_has_part(path: Path, part: str) -> bool:
    """Return True if any path segment matches part (case-insensitive)."""
    part_lower = part.lower()
    return any(segment.lower() == part_lower for segment in path.parts)


def _find_hf_cache_root(path: Path) -> Path | None:
    """Return the HuggingFace cache root containing models--* if present."""
    for index, segment in enumerate(path.parts):
        if (
            segment.lower().startswith("models--")
            and index >= 3
            and [part.lower() for part in path.parts[index - 3 : index]] == [".cache", "huggingface", "hub"]
        ):
            return Path(*path.parts[: index + 1])
    return None
