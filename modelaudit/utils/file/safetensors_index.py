"""Prove when a complete SafeTensors index only maps tensor names to local shards."""

import json
import re
from typing import Any

from ..helpers.json_limits import validate_json_structural_limits

# Match the existing remote SafeTensors index limits.
INDEX_PROBE_BYTES = 32 * 1024 * 1024
_INDEX_MAX_TENSORS = 250_000
_TENSOR_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
_SHARD_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.safetensors")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate index key")
    return obj


def is_plain_safetensors_index(raw: bytes) -> bool:
    if len(raw) > INDEX_PROBE_BYTES:
        return False
    try:
        validate_json_structural_limits(raw, _INDEX_MAX_TENSORS + 4, "SafeTensors index")
        index = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError):
        return False
    if not isinstance(index, dict) or set(index) - {"metadata", "weight_map"}:
        return False
    metadata = index.get("metadata", {})
    if (
        not isinstance(metadata, dict)
        or set(metadata) - {"total_size", "total_parameters"}
        or not all(type(count) is int and count >= 0 for count in metadata.values())
    ):
        return False
    weight_map = index.get("weight_map")
    return (
        isinstance(weight_map, dict)
        and 0 < len(weight_map) <= _INDEX_MAX_TENSORS
        and all(
            _TENSOR_NAME.fullmatch(name) and isinstance(shard, str) and _SHARD_NAME.fullmatch(shard)
            for name, shard in weight_map.items()
        )
    )
