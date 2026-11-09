"""Recognize model repository metadata that shares the JSON dataset extension."""

import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

from ..utils.file.safetensors_index import INDEX_PROBE_BYTES, is_plain_safetensors_index
from ..utils.helpers.json_limits import validate_json_structural_limits

_MAX_METADATA_BYTES = 8 * 1024 * 1024
_MAX_METADATA_TOKENS = 200_000
_SHA1 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COREML_ITEM_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.IGNORECASE)

_PROCESSOR_CONFIG_NAMES = {"processor_config.json", "video_preprocessor_config.json"}
_PROCESSOR_NUMERIC_OPTIONS = {
    "dither",
    "feature_size",
    "fft_length",
    "frame_length",
    "hop_length",
    "input_scale_factor",
    "max_frequency",
    "mel_floor",
    "min_frequency",
    "padding_value",
    "preemphasis",
    "sampling_rate",
    "image_seq_length",
    "max_soft_tokens",
    "patch_size",
    "pooling_kernel_size",
    "resample",
    "rescale_factor",
    "num_frames",
    "fps",
    "merge_size",
    "max_frames",
    "min_frames",
    "temporal_patch_size",
}
_PROCESSOR_FLAGS = {
    "do_convert_rgb",
    "do_normalize",
    "do_rescale",
    "do_resize",
    "do_sample_frames",
    "return_metadata",
    "return_attention_mask",
    "fft_overdrive",
    "preemphasis_htk_flavor",
}


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON key")
    return result


def _read_metadata_bytes(path: Path, size_limit: int) -> bytes | None:
    def open_nonblocking(name: str, flags: int) -> int:
        return os.open(name, flags | getattr(os, "O_NONBLOCK", 0))

    try:
        with open(path, "rb", opener=open_nonblocking) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > size_limit:
                return None
            raw = source.read(info.st_size + 1)
        return raw if len(raw) == info.st_size else None
    except (OSError, ValueError):
        return None


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


def _is_coreml_package_manifest(data: dict[str, Any]) -> bool:
    if (
        data.keys() != {"fileFormatVersion", "itemInfoEntries", "rootModelIdentifier"}
        or data["fileFormatVersion"] != "1.0.0"
    ):
        return False
    entries = data["itemInfoEntries"]
    root = data["rootModelIdentifier"]
    if not isinstance(entries, dict) or not isinstance(root, str) or root not in entries:
        return False
    for identifier, item in entries.items():
        if not _COREML_ITEM_ID.fullmatch(identifier) or not isinstance(item, dict):
            return False
        if item.keys() != {"author", "description", "name", "path"} or not all(
            isinstance(v, str) for v in item.values()
        ):
            return False
        author, name = item["author"], item["name"]
        if any(
            not part or part in {".", ".."} or "/" in part or "\\" in part or "\x00" in part for part in (author, name)
        ):
            return False
        if item["path"] != f"{author}/{name}" or (identifier == root and not name.endswith(".mlmodel")):
            return False
    return True


def _is_finite_number(value: object) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _is_processor_component(value: object, type_key: str, type_suffix: str) -> bool:
    if not isinstance(value, dict):
        return False
    class_name = value.get(type_key)
    if not isinstance(class_name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*" + type_suffix, class_name):
        return False
    for key, option in value.items():
        if key == type_key:
            continue
        if key in _PROCESSOR_FLAGS and type(option) is bool:
            continue
        if key in _PROCESSOR_NUMERIC_OPTIONS and _is_finite_number(option):
            continue
        if (
            key in {"image_mean", "image_std"}
            and isinstance(option, list)
            and len(option) in (1, 3, 4)
            and all(_is_finite_number(n) for n in option)
        ):
            continue
        if (
            key == "size"
            and isinstance(option, dict)
            and option.keys() == {"shortest_edge", "longest_edge"}
            and all(_nonnegative_integer(n) for n in option.values())
        ):
            continue
        if key == "padding_side" and option in ("left", "right"):
            continue
        if key in {"per_bin_mean", "per_bin_stddev"} and option is None:
            continue
        return False
    return True


def _is_transformers_processor(name: str, data: dict[str, Any]) -> bool:
    processor = data.get("processor_class")
    if not isinstance(processor, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*Processor", processor):
        return False
    settings = {key: value for key, value in data.items() if key != "processor_class"}
    if name == "video_preprocessor_config.json":
        return "patch_size" in settings and _is_processor_component(settings, "video_processor_type", "VideoProcessor")
    components = {
        "feature_extractor": "FeatureExtractor",
        "image_processor": "ImageProcessor",
        "video_processor": "VideoProcessor",
    }
    return not settings.keys().isdisjoint(components) and all(
        _is_processor_component(value, key + "_type", components[key])
        if key in components
        else key in {"audio_ms_per_token", "audio_seq_length", "image_seq_length"} and _nonnegative_integer(value)
        for key, value in settings.items()
    )


def _is_modelopt_quant_config(data: dict[str, Any]) -> bool:
    producer = data.get("producer")
    quant = data.get("quantization")
    if (
        data.keys() != {"producer", "quantization"}
        or not isinstance(producer, dict)
        or producer.keys() != {"name", "version"}
        or producer["name"] != "modelopt"
        or not isinstance(producer["version"], str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", producer["version"])
        or not isinstance(quant, dict)
        or quant.keys() != {"quant_algo", "kv_cache_quant_algo", "quantized_layers", "exclude_modules"}
        or quant["quant_algo"] != "MIXED_PRECISION"
        or quant["kv_cache_quant_algo"] != "FP8"
    ):
        return False
    layers, excluded = quant["quantized_layers"], quant["exclude_modules"]
    if not isinstance(layers, dict) or not layers or not isinstance(excluded, list):
        return False
    if not all(isinstance(pattern, str) and re.fullmatch(r"[\w.*]+", pattern) for pattern in excluded):
        return False
    for name, spec in layers.items():
        if not re.fullmatch(r"\w+(?:\.\w+)*", name) or not isinstance(spec, dict):
            return False
        if spec.keys() - {"quant_algo", "group_size"} or spec.get("quant_algo") not in ("FP8", "NVFP4", "W4A16_NVFP4"):
            return False
        if "group_size" in spec and not (type(spec["group_size"]) is int and spec["group_size"] > 0):
            return False
    return True


def _is_sparse_attention_config(layers: list[Any]) -> bool:
    if not layers or not isinstance(layers[0], dict) or not layers[0]:
        return False
    head_count = len(layers[0])
    for layer in layers:
        if not isinstance(layer, dict) or len(layer) != head_count:
            return False
        for head in range(head_count):
            pattern = layer.get(str(head))
            if not (
                isinstance(pattern, list)
                and len(pattern) == 4
                and pattern[0] == "vertical_and_slash"
                and type(pattern[1]) is int
                and pattern[1] > 0
                and type(pattern[2]) is int
                and pattern[2] > 0
                and type(pattern[3]) is float
                and 0 <= pattern[3] < float("inf")
            ):
                return False
    return True


def is_model_repository_metadata(path: Path) -> bool:
    """Require a complete, bounded document matching a recognized producer schema."""
    name = path.name.lower()
    is_safetensors_index = name.endswith(".safetensors.index.json")
    is_index = is_safetensors_index or name.endswith(".bin.index.json")
    is_hub_tree = path.parts[-4:-1] == (".cache", "huggingface", "trees") and _SHA1.fullmatch(path.stem)
    is_coreml_manifest = path.name == "Manifest.json" and path.parent.suffix.lower() == ".mlpackage"
    if not (
        is_index
        or is_hub_tree
        or is_coreml_manifest
        or name in _PROCESSOR_CONFIG_NAMES
        or name in {"chat_template.json", "added_tokens.json", "hf_quant_config.json", "sparse_attention_config.json"}
    ):
        return False
    size_limit = INDEX_PROBE_BYTES if is_safetensors_index else _MAX_METADATA_BYTES
    raw = _read_metadata_bytes(path, size_limit)
    if raw is None:
        return False
    if len(raw) > _MAX_METADATA_BYTES:
        # Only SafeTensors index candidates are read beyond the ordinary metadata budget.
        return is_plain_safetensors_index(raw)
    try:
        validate_json_structural_limits(raw, _MAX_METADATA_TOKENS, "Dataset license metadata")
    except ValueError:
        # A compact weight map can hit the generic token limit before the byte limit.
        return is_safetensors_index and is_plain_safetensors_index(raw)
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError):
        return False
    if name == "sparse_attention_config.json":
        return isinstance(data, list) and _is_sparse_attention_config(data)
    if not isinstance(data, dict) or not data:
        return False
    if name in _PROCESSOR_CONFIG_NAMES:
        return _is_transformers_processor(name, data)
    if name == "hf_quant_config.json":
        return _is_modelopt_quant_config(data)
    if is_coreml_manifest:
        return _is_coreml_package_manifest(data)
    if is_index:
        weights = data.get("weight_map")
        metadata = data.get("metadata", {})
        suffix = ".safetensors" if is_safetensors_index else ".bin"
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
