"""Shared SafeTensors shard-name parsing without package import cycles."""

import re
from dataclasses import dataclass

SAFETENSORS_SHARD_KIND = "safetensors"
_SAFETENSORS_PATTERN_MARKER = "(?#modelaudit-safetensors-shard)"
_SAFETENSORS_SHARD_SHAPE = re.compile(
    r"(?P<stem>.+)-(?P<index>\d+)-of-(?P<total>\d+)\.safetensors",
    re.IGNORECASE | re.DOTALL,
)
_CANONICAL_SAFETENSORS_SHARD = re.compile(
    r"(?P<stem>.+)-(?P<index>\d{5})-of-(?P<total>\d{5})\.safetensors",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class SafetensorsShardName:
    """Parsed shard name and its case-insensitive family identity."""

    stem: str
    normalized_stem: str
    index: int
    total: int

    @property
    def family(self) -> tuple[str, int]:
        return self.normalized_stem, self.total


def _parsed_shard(match: re.Match[str] | None) -> SafetensorsShardName | None:
    if match is None:
        return None
    stem = match.group("stem")
    return SafetensorsShardName(
        stem=stem,
        normalized_stem=stem.casefold(),
        index=int(match.group("index")),
        total=int(match.group("total")),
    )


def parse_safetensors_shard_shape(filename: str) -> SafetensorsShardName | None:
    """Parse an arbitrary-width SafeTensors shard basename."""
    if not filename or "/" in filename or "\\" in filename:
        return None
    return _parsed_shard(_SAFETENSORS_SHARD_SHAPE.fullmatch(filename))


def parse_canonical_safetensors_shard(filename: str) -> SafetensorsShardName | None:
    """Parse a canonical five-digit, one-based remote shard basename."""
    if not filename or "/" in filename or "\\" in filename:
        return None
    parsed = _parsed_shard(_CANONICAL_SAFETENSORS_SHARD.fullmatch(filename))
    if parsed is None or parsed.index < 1 or parsed.total < 2 or parsed.index > parsed.total:
        return None
    return parsed


def safetensors_family_pattern(stem: str) -> str:
    """Return a marked, case-insensitive regex with index/total in groups 1/2."""
    return f"{_SAFETENSORS_PATTERN_MARKER}(?i:{re.escape(stem)}-(\\d+)-of-(\\d+)\\.safetensors)"


def is_safetensors_family_pattern(pattern: str) -> bool:
    """Return whether a family regex was produced by this module."""
    return pattern.startswith(_SAFETENSORS_PATTERN_MARKER)
