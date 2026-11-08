"""Recognize model repository metadata that shares the JSON dataset extension."""

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from ..utils.helpers.json_limits import validate_json_structural_limits

_MAX_METADATA_BYTES = 8 * 1024 * 1024
_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON key")
    return result


def _read_metadata(path: Path) -> dict[str, Any] | None:
    def open_nonblocking(name: str, flags: int) -> int:
        return os.open(name, flags | getattr(os, "O_NONBLOCK", 0))

    try:
        with open(path, "rb", opener=open_nonblocking) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_METADATA_BYTES:
                return None
            raw = source.read(info.st_size + 1)
        if len(raw) != info.st_size:
            return None
        validate_json_structural_limits(raw, 200_000, "Dataset license metadata")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (OSError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _is_hub_tree_entry(entry: object) -> bool:
    if not isinstance(entry, dict) or entry.keys() - {"size", "blob_id", "lfs_sha256", "lfs_size", "xet_hash"}:
        return False
    if not _nonnegative_integer(entry.get("size")) or not isinstance(entry.get("blob_id"), str):
        return False
    if not _SHA1.fullmatch(entry["blob_id"]):
        return False
    for key in ("lfs_sha256", "xet_hash"):
        if key in entry and not (isinstance(entry[key], str) and _SHA256.fullmatch(entry[key])):
            return False
    return ("lfs_size" in entry) == ("lfs_sha256" in entry) and (
        "lfs_size" not in entry or _nonnegative_integer(entry["lfs_size"])
    )


def is_model_repository_metadata(path: Path) -> bool:
    """Require a complete, bounded document matching a recognized producer schema."""
    name = path.name.lower()
    is_index = name.endswith((".safetensors.index.json", ".bin.index.json"))
    is_hub_tree = path.parts[-4:-1] == (".cache", "huggingface", "trees") and _SHA1.fullmatch(path.stem)
    if not (is_index or is_hub_tree or name in {"chat_template.json", "added_tokens.json"}):
        return False
    data = _read_metadata(path)
    if not data:
        return False

    if is_index:
        weights = data.get("weight_map")
        metadata = data.get("metadata", {})
        suffix = ".safetensors" if name.endswith(".safetensors.index.json") else ".bin"
        return (
            data.keys() <= {"metadata", "weight_map"}
            and isinstance(metadata, dict)
            and metadata.keys() <= {"total_size", "total_parameters"}
            and all(_nonnegative_integer(value) for value in metadata.values())
            and isinstance(weights, dict)
            and bool(weights)
            and all(tensor and isinstance(shard, str) and shard.endswith(suffix) for tensor, shard in weights.items())
        )
    if is_hub_tree:
        files = data.get("files")
        return (
            data.keys() == {"format_version", "files"}
            and type(data["format_version"]) is int
            and data["format_version"] == 1
            and isinstance(files, dict)
            and bool(files)
            and all(name and _is_hub_tree_entry(entry) for name, entry in files.items())
        )
    if name == "chat_template.json":
        template = data.get("chat_template")
        return data.keys() == {"chat_template"} and isinstance(template, str) and ("{{" in template or "{%" in template)
    # An arbitrary label-to-integer mapping could also be a dataset.
    return any(re.fullmatch(r"<[^<>]+>|\[[^\[\]]+\]", token) for token in data) and all(
        token and _nonnegative_integer(token_id) for token, token_id in data.items()
    )
