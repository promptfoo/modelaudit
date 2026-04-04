"""Shared scanner config parsing for nested archive recursion."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def get_archive_depth(config: Mapping[str, Any], key: str = "_archive_depth") -> int:
    """Return a non-negative archive depth from scanner config."""
    raw_depth = config.get(key, 0)
    try:
        depth = int(raw_depth)
    except (TypeError, ValueError):
        return 0
    return max(depth, 0)
