"""Utilities for handling HuggingFace model downloads."""

import json
import logging
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from glob import escape as escape_glob_pattern
from io import BytesIO
from pathlib import Path
from typing import Any

from ..helpers.disk_space import check_disk_space
from .huggingface_paths import (
    extract_model_id_from_path,
    is_huggingface_cache_path,
    is_huggingface_file_url,
    is_huggingface_url,
    parse_huggingface_file_url,
    parse_huggingface_url,
    redact_huggingface_url_for_display,
    redact_huggingface_urls_in_text,
)

logger = logging.getLogger(__name__)

_HF_CONTENT_SNIFF_BYTES = 8 * 1024
_HF_CONTENT_SNIFF_MAX_FILES = 256
_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_BYTES = b"TFL3"

__all__ = [
    "download_file_from_hf",
    "download_model",
    "extract_model_id_from_path",
    "get_model_info",
    "get_model_size",
    "is_huggingface_cache_path",
    "is_huggingface_file_url",
    "is_huggingface_url",
    "parse_huggingface_file_url",
    "parse_huggingface_url",
    "redact_huggingface_url_for_display",
    "redact_huggingface_urls_in_text",
]


@dataclass
class _HuggingFaceProbeBudget:
    remaining_bytes: int

    def reserve(self, repo_id: str, max_bytes: int) -> None:
        """Reserve a bounded remote read or fail closed before issuing it."""
        if max_bytes <= 0 or max_bytes > self.remaining_bytes:
            raise ValueError(
                "Hugging Face selective filtering incomplete: skipped file inspection byte limit exceeded "
                f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES} bytes)"
            )
        self.remaining_bytes -= max_bytes


def _get_model_extensions() -> set[str]:
    """
    Lazy-load model extensions to avoid circular imports.

    Returns all file extensions that ModelAudit can scan - dynamically loaded from scanner registry.
    This ensures we download and scan everything we have scanners for.
    """
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _read_huggingface_prefix(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    max_bytes: int,
) -> bytes:
    """Read a bounded remote prefix for selective content routing."""
    budget.reserve(repo_id, max_bytes)
    try:
        import requests
        from huggingface_hub import hf_hub_url
        from huggingface_hub.utils import build_hf_headers

        file_url = hf_hub_url(repo_id=repo_id, filename=filename, revision=revision)
        headers = build_hf_headers(
            token=None,
            headers={
                "Range": f"bytes=0-{max_bytes - 1}",
                "Accept-Encoding": "identity",
            },
        )
        with requests.get(file_url, headers=headers, stream=True, timeout=30, allow_redirects=True) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=max_bytes):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
        return b"".join(chunks)[:max_bytes]
    except Exception as exc:
        raise ValueError(
            "Hugging Face selective filtering incomplete: unable to inspect skipped file "
            f"{repo_id}/{filename}: {redact_huggingface_urls_in_text(str(exc))}"
        ) from exc


def _read_huggingface_probe(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
    max_bytes: int,
) -> bytes:
    """Return an existing or freshly expanded bounded remote prefix."""
    if len(prefix) >= max_bytes:
        return prefix[:max_bytes]
    return _read_huggingface_prefix(repo_id, filename, revision, budget, max_bytes)


def _looks_like_safetensors_prefix(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> bool:
    """Recognize bounded SafeTensors framing without requiring a local path."""
    if len(prefix) <= 8:
        return False

    header_len = struct.unpack("<Q", prefix[:8])[0]
    header_prefix = prefix[8:]
    if header_len <= 0 or not header_prefix.startswith(b"{"):
        return False

    from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES

    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        return len(prefix) >= _HF_CONTENT_SNIFF_BYTES or header_len <= len(prefix) - 8

    header_probe = _read_huggingface_prefix(repo_id, filename, revision, budget, 8 + header_len)
    if len(header_probe) != 8 + header_len or header_probe[8:9] != b"{":
        return False
    try:
        parsed_header = json.loads(header_probe[8:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed_header, dict)


def _detect_huggingface_mxnet_symbol_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded MXNet JSON route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import MXNET_SYMBOL_SIGNATURE_READ_BYTES, _detect_mxnet_symbol_prefix_route

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    if not normalized_prefix.lstrip().startswith(b"{"):
        return None

    max_probe_size = MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1
    mxnet_probe = _read_huggingface_prefix(repo_id, filename, revision, budget, max_probe_size)
    mxnet_probe = mxnet_probe[3:] if mxnet_probe.startswith(b"\xef\xbb\xbf") else mxnet_probe
    if len(mxnet_probe) > MXNET_SYMBOL_SIGNATURE_READ_BYTES:
        return _detect_mxnet_symbol_prefix_route(
            mxnet_probe[:MXNET_SYMBOL_SIGNATURE_READ_BYTES],
            fail_closed_without_hint=True,
        )
    return _detect_mxnet_symbol_prefix_route(
        mxnet_probe,
        sample_is_prefix=len(mxnet_probe) >= max_probe_size,
        fail_closed_without_hint=True,
    )


def _detect_huggingface_xml_model_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded XML model route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _XML_MODEL_SIGNATURE_READ_BYTES,
        _could_be_xml_prefix,
        _detect_xml_model_format,
    )

    if not _could_be_xml_prefix(prefix):
        return None

    xml_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, _XML_MODEL_SIGNATURE_READ_BYTES)
    detected_format = _detect_xml_model_format(
        xml_probe,
        sample_is_prefix=len(xml_probe) >= _XML_MODEL_SIGNATURE_READ_BYTES,
    )
    return None if detected_format == "unknown" else detected_format


def _detect_huggingface_jax_json_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded JAX JSON checkpoint route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _JAX_JSON_CHECKPOINT_CONTENT_ROUTE_EXCLUDED_SUFFIXES,
        JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
        _could_start_json_object,
        has_jax_json_checkpoint_structure,
    )

    if Path(filename).suffix.lower() in _JAX_JSON_CHECKPOINT_CONTENT_ROUTE_EXCLUDED_SUFFIXES:
        return None

    jax_probe = prefix
    normalized_prefix = jax_probe.lstrip()
    if normalized_prefix.startswith(b"\xef\xbb\xbf"):
        normalized_prefix = normalized_prefix[3:].lstrip()

    if not normalized_prefix:
        max_probe_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1
        jax_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size)
        normalized_prefix = jax_probe.lstrip()
        if normalized_prefix.startswith(b"\xef\xbb\xbf"):
            normalized_prefix = normalized_prefix[3:].lstrip()
        if not normalized_prefix and len(jax_probe) > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            return "jax_checkpoint"

    if not _could_start_json_object(jax_probe):
        return None

    max_probe_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1
    jax_probe = _read_huggingface_probe(repo_id, filename, revision, budget, jax_probe, max_probe_size)
    try:
        payload = json.loads(jax_probe.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        if len(jax_probe) > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            return "jax_checkpoint"
        return None
    return "jax_checkpoint" if has_jax_json_checkpoint_structure(payload) else None


def _detect_huggingface_xgboost_ubjson_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded XGBoost UBJSON route for a suffix-skipped remote file."""
    if Path(filename).suffix:
        return None

    from modelaudit.utils.file.detection import (
        _XGBOOST_UBJSON_ROUTE_READ_BYTES,
        _detect_extensionless_xgboost_ubjson_route,
    )

    xgboost_route = _detect_extensionless_xgboost_ubjson_route(prefix)
    if xgboost_route is not None:
        return xgboost_route

    normalized_prefix = prefix.lstrip(b"N")
    if not normalized_prefix.startswith(b"{"):
        return None

    xgboost_probe = _read_huggingface_probe(
        repo_id,
        filename,
        revision,
        budget,
        prefix,
        _XGBOOST_UBJSON_ROUTE_READ_BYTES,
    )
    return _detect_extensionless_xgboost_ubjson_route(xgboost_probe)


def _detect_huggingface_llamafile_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded Llamafile route for a suffix-skipped remote executable."""
    import zipfile

    from modelaudit.utils.file.detection import (
        EXECUTABLE_ZIP_POLYGLOT_FORMAT,
        LLAMAFILE_MARKER,
        LLAMAFILE_ROUTE_SCAN_BYTES,
        LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
        _is_supported_llamafile_executable_header,
    )

    if not _is_supported_llamafile_executable_header(prefix[:4]):
        return None

    max_probe_size = LLAMAFILE_ROUTE_SCAN_BYTES + 1
    probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size)
    if LLAMAFILE_MARKER in probe[:LLAMAFILE_ROUTE_SCAN_BYTES].lower():
        return "llamafile"
    if zipfile.is_zipfile(BytesIO(probe)):
        return EXECUTABLE_ZIP_POLYGLOT_FORMAT
    if len(probe) > LLAMAFILE_ROUTE_SCAN_BYTES:
        return LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT
    return None


def _detect_huggingface_torch7_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded Torch7 route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _TORCH7_SIGNATURE_READ_BYTES,
        _allows_renamed_binary_content_route,
        _is_torch7_signature,
    )

    if not _allows_renamed_binary_content_route(Path(filename)):
        return None
    probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, _TORCH7_SIGNATURE_READ_BYTES)
    return "torch7" if _is_torch7_signature(probe) else None


def _probe_huggingface_executorch_prefix(prefix: bytes, *, sample_is_prefix: bool) -> bool | None:
    """Validate bounded ExecuTorch FlatBuffers structure without a local file."""
    from modelaudit.utils.file.detection import _is_executorch_binary_signature

    if not _is_executorch_binary_signature(prefix):
        return False
    if len(prefix) < 16:
        return None if sample_is_prefix else False

    root_table_offset = struct.unpack("<I", prefix[:4])[0]
    if root_table_offset < 12:
        return False
    if root_table_offset + 4 > len(prefix):
        return None if sample_is_prefix else False

    vtable_back_offset = struct.unpack("<i", prefix[root_table_offset : root_table_offset + 4])[0]
    if vtable_back_offset <= 0 or vtable_back_offset > root_table_offset:
        return False

    vtable_offset = root_table_offset - vtable_back_offset
    if vtable_offset < 8:
        return False
    if vtable_offset + 4 > len(prefix):
        return None if sample_is_prefix else False

    vtable_size, object_size = struct.unpack("<HH", prefix[vtable_offset : vtable_offset + 4])
    if vtable_size < 4 or object_size < 4:
        return False
    return sample_is_prefix or not (
        vtable_offset + vtable_size > len(prefix) or root_table_offset + object_size > len(prefix)
    )


def _is_complete_huggingface_text_or_json(probe: bytes, *, sample_is_prefix: bool) -> bool:
    """Return whether a complete bounded probe is owned by benign text or JSON."""
    if sample_is_prefix:
        return False

    from modelaudit.utils.file.detection import _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES

    if not probe.translate(None, _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES):
        return True
    normalized = probe.lstrip()
    if normalized.startswith(b"\xef\xbb\xbf"):
        normalized = normalized[3:].lstrip()
    if not normalized.startswith((b"{", b"[")):
        return False
    try:
        return isinstance(json.loads(normalized.decode("utf-8")), (dict, list))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False


def _detect_huggingface_protobuf_model_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded TensorFlow, CoreML, ONNX, or unresolved protobuf model route."""
    from modelaudit.utils.file.detection import (
        _COREML_PROTO_SIGNATURE_READ_BYTES,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        _classify_bounded_tensorflow_protobuf_stream,
        _could_start_coreml_model_proto,
        _looks_like_coreml_model_proto_prefix,
        _looks_like_onnx_model_proto_stream,
    )

    if not _could_start_coreml_model_proto(prefix):
        return None

    max_probe_size = _COREML_PROTO_SIGNATURE_READ_BYTES
    raw_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size + 1)
    sample_is_prefix = len(raw_probe) > max_probe_size
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_or_json(probe, sample_is_prefix=sample_is_prefix):
        return None

    coreml_status = _looks_like_coreml_model_proto_prefix(probe, sample_is_prefix=sample_is_prefix)
    if coreml_status is True:
        return "coreml"

    onnx_status = _looks_like_onnx_model_proto_stream(BytesIO(probe), len(probe))
    if onnx_status is True:
        return "onnx"

    tensorflow_route = _classify_bounded_tensorflow_protobuf_stream(BytesIO(probe), len(probe))
    if tensorflow_route in {"tf_metagraph", "tf_savedmodel"}:
        return tensorflow_route
    if tensorflow_route == "oversized":
        return "tf_metagraph"
    if tensorflow_route in {"oversized_candidate", "inconclusive"}:
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    if sample_is_prefix or coreml_status is None or onnx_status is None:
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    return None


def _detect_huggingface_flax_msgpack_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded Flax MessagePack route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        FLAX_MSGPACK_STRUCTURE_READ_BYTES,
        _probe_flax_msgpack_checkpoint_stream,
    )

    if Path(filename).suffix.lower() in {".py", ".pyw"}:
        return None

    initial_probe_state = _probe_flax_msgpack_checkpoint_stream(
        BytesIO(prefix),
        len(prefix),
        sample_is_prefix=len(prefix) >= _HF_CONTENT_SNIFF_BYTES,
        incomplete_prefix_is_inconclusive=True,
    )
    if initial_probe_state is True:
        return "flax_msgpack"
    if initial_probe_state is False or len(prefix) < _HF_CONTENT_SNIFF_BYTES:
        return None

    max_probe_size = FLAX_MSGPACK_STRUCTURE_READ_BYTES
    raw_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size + 1)
    sample_is_prefix = len(raw_probe) > max_probe_size
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_or_json(probe, sample_is_prefix=sample_is_prefix):
        return None
    probe_state = _probe_flax_msgpack_checkpoint_stream(
        BytesIO(probe),
        len(probe),
        sample_is_prefix=sample_is_prefix,
        incomplete_prefix_is_inconclusive=True,
    )
    if probe_state is not False:
        return "flax_msgpack"
    return None


def _detect_huggingface_content_route_format(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
) -> str | None:
    """Return a content-routed model format for a remote file, if cheaply identifiable."""
    prefix = _read_huggingface_prefix(repo_id, filename, revision, budget, _HF_CONTENT_SNIFF_BYTES)
    if not prefix:
        return None

    from modelaudit.utils.file.detection import (
        PROTO0_1_MAX_PROBE_BYTES,
        _could_start_proto0_or_1_pickle,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _looks_like_proto0_or_1_pickle,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )

    llamafile_route = _detect_huggingface_llamafile_route(repo_id, filename, revision, budget, prefix)
    if llamafile_route is not None:
        return llamafile_route

    if _looks_like_safetensors_prefix(repo_id, filename, revision, budget, prefix):
        return "safetensors"
    if _looks_like_uncompressed_tar_header(prefix):
        return "tar"
    if _is_cntk_signature(prefix):
        return "cntk"
    if _is_content_routed_lightgbm_signature(prefix):
        return "lightgbm"

    xml_route = _detect_huggingface_xml_model_route(repo_id, filename, revision, budget, prefix)
    if xml_route is not None:
        return xml_route

    xgboost_ubjson_route = _detect_huggingface_xgboost_ubjson_route(repo_id, filename, revision, budget, prefix)
    if xgboost_ubjson_route is not None:
        return xgboost_ubjson_route

    jax_json_route = _detect_huggingface_jax_json_route(repo_id, filename, revision, budget, prefix)
    if jax_json_route is not None:
        return jax_json_route

    mxnet_route = _detect_huggingface_mxnet_symbol_route(repo_id, filename, revision, budget, prefix)
    if mxnet_route is not None:
        return mxnet_route

    if _could_start_proto0_or_1_pickle(prefix):
        pickle_probe = _read_huggingface_prefix(repo_id, filename, revision, budget, PROTO0_1_MAX_PROBE_BYTES)
        if _looks_like_proto0_or_1_pickle(
            pickle_probe,
            sample_is_prefix=len(pickle_probe) >= PROTO0_1_MAX_PROBE_BYTES,
        ):
            return "pickle"
    executorch_state = _probe_huggingface_executorch_prefix(
        prefix,
        sample_is_prefix=len(prefix) >= _HF_CONTENT_SNIFF_BYTES,
    )
    if executorch_state is not False:
        return "executorch"

    torch7_route = _detect_huggingface_torch7_route(repo_id, filename, revision, budget, prefix)
    if torch7_route is not None:
        return torch7_route

    detected_format = detect_format_from_magic_bytes(
        prefix[:4],
        prefix[:8],
        prefix[:16],
        max(len(prefix), 1),
        None,
    )
    if (
        detected_format == "unknown"
        and prefix[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + len(_TFLITE_MAGIC_BYTES)] == _TFLITE_MAGIC_BYTES
    ):
        return "tflite"
    if detected_format != "unknown":
        return detected_format

    protobuf_route = _detect_huggingface_protobuf_model_route(repo_id, filename, revision, budget, prefix)
    if protobuf_route is not None:
        return protobuf_route

    return _detect_huggingface_flax_msgpack_route(repo_id, filename, revision, budget, prefix)


def _select_huggingface_model_files(
    repo_id: str,
    repo_files: list[str],
    revision: str,
    model_extensions: set[str],
) -> list[str]:
    """Select extension-matching files plus bounded content-routed renamed model files."""
    model_files = [filename for filename in repo_files if _is_scannable_hf_file(filename, model_extensions)]
    selected_files = set(model_files)
    inspected_files = 0
    probe_budget = _HuggingFaceProbeBudget(remaining_bytes=_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES)

    for filename in repo_files:
        if filename in selected_files:
            continue
        if inspected_files >= _HF_CONTENT_SNIFF_MAX_FILES:
            raise ValueError(
                "Hugging Face selective filtering incomplete: skipped file inspection limit exceeded "
                f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_FILES} files)"
            )
        inspected_files += 1
        detected_format = _detect_huggingface_content_route_format(repo_id, filename, revision, probe_budget)
        if detected_format is None:
            continue
        model_files.append(filename)
        selected_files.add(filename)

    return model_files


def _is_scannable_hf_file(filename: str, extensions: set[str]) -> bool:
    """Return whether a listed Hugging Face file has a supported suffix."""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext.lower()) for ext in extensions if ext)


def _raise_no_scannable_hf_files(repo_id: str) -> None:
    raise Exception(
        f"Refusing to download full snapshot for {repo_id}: "
        "repository listing contains no recognized ModelAudit-scannable files"
    )


def _get_hf_cache_root() -> Path:
    """Return the HuggingFace hub cache root."""
    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        return Path(HF_HUB_CACHE)
    except Exception:
        return Path.home() / ".cache" / "huggingface" / "hub"


def _format_size(size_bytes: int) -> str:
    """Format a byte count for user-facing download budget errors."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _is_within_directory(base_dir: Path, target: Path) -> bool:
    """Return True when target resolves inside base_dir."""
    base_path = base_dir.resolve()
    target_path = target.resolve()
    if os.name == "nt":
        base_norm = os.path.normcase(os.path.normpath(str(base_path)))
        target_norm = os.path.normcase(os.path.normpath(str(target_path)))
        try:
            return os.path.commonpath([target_norm, base_norm]) == base_norm
        except ValueError:
            return False
    return target_path.is_relative_to(base_path)


def _build_huggingface_download_path(cache_dir: Path, namespace: str, repo_name: str) -> Path:
    """Build and containment-check the local HuggingFace download path."""
    cache_root = (cache_dir / "huggingface").resolve()
    download_path = cache_root / namespace
    if repo_name:
        download_path = download_path / repo_name
    resolved_download_path = download_path.resolve()
    if not _is_within_directory(cache_root, resolved_download_path):
        raise ValueError(f"HuggingFace cache path escaped cache directory: {resolved_download_path}")
    return resolved_download_path


def _is_huggingface_commit_sha(revision: object) -> bool:
    """Return whether revision is a full immutable Git commit SHA."""
    if not isinstance(revision, str) or len(revision) not in {40, 64}:
        return False
    try:
        int(revision, 16)
    except ValueError:
        return False
    return True


def _list_repo_files_with_timeout(
    repo_id: str,
    timeout_seconds: float = 30,
) -> tuple[list[str] | None, str | None, str | None]:
    """Return repository files, their immutable revision, or a failure reason."""
    from huggingface_hub import HfApi

    try:
        repo_info = HfApi().repo_info(repo_id, timeout=timeout_seconds, files_metadata=False)
    except Exception as exc:
        return None, None, str(exc)

    siblings = getattr(repo_info, "siblings", None)
    if siblings is None:
        return None, None, "repository listing unavailable"

    files: list[str] = []
    for sibling in siblings:
        if isinstance(sibling, dict):
            file_name = sibling.get("rfilename") or sibling.get("path")
        else:
            file_name = getattr(sibling, "rfilename", None) or getattr(sibling, "path", None)

        if isinstance(file_name, str) and file_name:
            files.append(file_name)

    revision = getattr(repo_info, "sha", None)
    if not _is_huggingface_commit_sha(revision):
        return files, None, "repository listing did not include an immutable commit SHA"

    return files, revision, None


def get_model_info(url: str) -> dict:
    """Get information about a HuggingFace model without downloading it.

    Args:
        url: HuggingFace model URL

    Returns:
        Dictionary with model information including size
    """
    try:
        from huggingface_hub import HfApi
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)

    api = HfApi()
    try:
        # Get model info for metadata
        model_info = api.model_info(repo_id)

        # Use list_repo_tree to get accurate file sizes
        # (model_info.siblings often returns None for size)
        total_size = 0
        files = []
        try:
            repo_files = api.list_repo_tree(repo_id, recursive=False)
            for item in repo_files:
                # Skip metadata files
                if hasattr(item, "path") and item.path not in [".gitattributes", "README.md"]:
                    file_size = getattr(item, "size", 0) or 0
                    total_size += file_size
                    files.append({"name": item.path, "size": file_size})
        except Exception as e:
            # If list_repo_tree fails, return 0 (will show as "Unknown size" in CLI)
            logger.debug(f"list_repo_tree failed for {repo_id}, falling back to unknown size: {e}")
            total_size = 0
            # Still try to get file count from siblings
            siblings = model_info.siblings or []
            for sibling in siblings:
                if sibling.rfilename not in [".gitattributes", "README.md"]:
                    files.append({"name": sibling.rfilename, "size": 0})

        return {
            "repo_id": repo_id,
            "total_size": total_size,
            "file_count": len(files),
            "files": files,
            "model_id": getattr(model_info, "modelId", repo_id),
            "author": getattr(model_info, "author", ""),
        }
    except Exception as e:
        raise Exception(f"Failed to get model info for {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e


def get_model_size(repo_id: str) -> int | None:
    """Get the total size of a HuggingFace model repository.

    Args:
        repo_id: Repository ID (e.g., "namespace/model-name")

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        from huggingface_hub import HfApi

        api = HfApi()
        model_info = api.model_info(repo_id)

        # Calculate total size from all files
        total_size = 0
        if hasattr(model_info, "siblings") and model_info.siblings:
            for file_info in model_info.siblings:
                if hasattr(file_info, "size") and file_info.size:
                    total_size += file_info.size

        return total_size if total_size > 0 else None
    except Exception:
        # If we can't get the size, return None and proceed with download
        return None


def download_model(url: str, cache_dir: Path | None = None, show_progress: bool = True) -> Path:
    """Download a model from HuggingFace.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress

    Returns:
        Path to the downloaded model directory

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)

    # Disk space check and path setup
    model_size = get_model_size(repo_id)
    download_path = None  # Will be set only if cache_dir is provided
    disk_check_path = None
    download_path_preexisting = False

    if cache_dir is not None:
        # Create a structured, containment-checked cache directory.
        download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
        download_path_preexisting = download_path.exists()
        download_path.mkdir(parents=True, exist_ok=True)
        disk_check_path = download_path

    else:
        disk_check_path = _get_hf_cache_root()
        disk_check_path.mkdir(parents=True, exist_ok=True)

    if model_size and disk_check_path is not None:
        has_space, message = check_disk_space(disk_check_path, model_size)
        if not has_space:
            raise Exception(f"Cannot download model from {display_url}: {redact_huggingface_urls_in_text(message)}")

    try:
        # Configure progress display based on environment
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Enable/disable progress bars based on parameter
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            # Force progress bar to show even in non-TTY environments
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # List files in the repository to identify model files
        repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(repo_id)
        if repo_files is None:
            raise ValueError(
                "Hugging Face selective filtering incomplete: "
                f"failed listing files in repository {repo_id}: {repo_listing_error}"
            )
        if repo_revision is None:
            raise ValueError(
                "Hugging Face selective filtering incomplete: "
                f"{repo_listing_error or 'repository listing did not include an immutable commit SHA'}"
            )

        # Find model files in the repository (using centralized model extensions)
        model_extensions = _get_model_extensions()
        model_files = _select_huggingface_model_files(repo_id, repo_files, repo_revision, model_extensions)

        # Download strategy:
        # - When cache_dir is provided: Use local_dir to place files directly there (safer)
        # - When cache_dir is None: Use HF's default caching mechanism (avoid interfering)

        download_kwargs: dict[str, Any] = {
            "repo_id": repo_id,
            "tqdm_class": None,  # Use default tqdm
        }
        download_kwargs["revision"] = repo_revision

        if cache_dir is not None:
            # User provided cache directory - use local_dir for direct placement
            download_kwargs["local_dir"] = str(download_path)
        else:
            # No cache directory provided - let HF use its default cache
            # This is safer as it doesn't risk deleting user's global cache
            pass

        # If we found specific model files, download them
        if model_files:
            download_kwargs["allow_patterns"] = [escape_glob_pattern(filename) for filename in model_files]
        else:
            _raise_no_scannable_hf_files(repo_id)

        local_path = snapshot_download(**download_kwargs)  # type: ignore[call-arg]

        # Verify we actually got model files
        downloaded_path = Path(local_path)
        downloaded_files = {
            path.relative_to(downloaded_path).as_posix() for path in downloaded_path.rglob("*") if path.is_file()
        }
        missing_model_files = set(model_files).difference(downloaded_files)
        if missing_model_files:
            raise ValueError(
                "Hugging Face selective filtering incomplete: "
                f"snapshot missing {len(missing_model_files)} selected file(s) for {repo_id}"
            )

        return Path(local_path)
    except Exception as e:
        # Clean up directory on failure only if we created a custom cache directory
        # When cache_dir is None, we use HF's default cache and shouldn't clean it up
        if (
            cache_dir is not None
            and download_path is not None
            and not download_path_preexisting
            and download_path.exists()
            and _is_within_directory(cache_dir / "huggingface", download_path)
        ):
            import shutil

            shutil.rmtree(download_path)
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_model_streaming(
    url: str, cache_dir: Path | None = None, show_progress: bool = True
) -> Iterator[tuple[Path, bool]]:
    """Download a model from HuggingFace one file at a time (streaming mode).

    This generator yields (file_path, is_last_file) tuples as each file is downloaded.
    Designed for streaming workflows to minimize disk usage.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress

    Yields:
        Tuple of (Path, bool) - (downloaded file path, is_last_file flag)

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)

    try:
        # List all files in the repository
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Configure progress display
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # List files with timeout without leaking a blocking worker thread.
        repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(repo_id)
        if repo_files is None:
            if repo_listing_error and repo_listing_error.startswith("timed out after"):
                raise Exception(f"Timeout listing files in repository {repo_id}")
            raise Exception(f"Failed listing files in repository {repo_id}: {repo_listing_error}")
        if repo_revision is None:
            raise Exception(
                f"Failed listing files in repository {repo_id}: "
                f"{repo_listing_error or 'repository listing did not include an immutable commit SHA'}"
            )

        # Filter for model files
        model_extensions = _get_model_extensions()
        model_files = _select_huggingface_model_files(repo_id, repo_files, repo_revision, model_extensions)

        if not model_files:
            _raise_no_scannable_hf_files(repo_id)

        # Setup cache directory
        download_path = None
        if cache_dir is not None:
            download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
            download_path.mkdir(parents=True, exist_ok=True)

        # Download each file one at a time
        total_files = len(model_files)
        for idx, filename in enumerate(model_files):
            is_last = idx == total_files - 1

            # Download single file
            if cache_dir is not None and download_path is not None:
                # Use specific cache dir for local placement
                local_path = hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                    revision=repo_revision,
                    cache_dir=str(cache_dir / "huggingface"),
                    local_dir=str(download_path),
                )
            else:
                # Use HF default cache
                local_path = hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                    revision=repo_revision,
                )

            yield (Path(local_path), is_last)

    except Exception as e:
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_file_from_hf(url: str, cache_dir: Path | None = None, max_size: int | None = None) -> Path:
    """Download a single file from HuggingFace using direct file URL.

    Args:
        url: Direct HuggingFace file URL (e.g., https://huggingface.co/user/repo/resolve/main/file.bin)
        cache_dir: Optional cache directory for downloads
        max_size: Optional maximum file size to download; 0 disables the limit

    Returns:
        Path to the downloaded file

    Raises:
        ValueError: If URL is invalid
        ValueError: If max_size is set and file size is unknown or exceeds it
        Exception: If download fails
    """
    try:
        from huggingface_hub import HfApi, hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    repo_id, branch, filename = parse_huggingface_file_url(url)
    display_url = redact_huggingface_url_for_display(url)

    try:
        if max_size is not None and max_size < 0:
            raise ValueError("Maximum file size must be non-negative")

        size_limit = max_size or None
        download_revision = branch
        if size_limit is not None:
            api = HfApi()
            repo_info = api.repo_info(repo_id, revision=branch)
            pinned_revision = getattr(repo_info, "sha", None)
            if not isinstance(pinned_revision, str) or not pinned_revision:
                raise ValueError(f"Unable to determine immutable revision for {display_url}; refusing capped download")

            path_info = api.get_paths_info(repo_id, filename, revision=pinned_revision)
            file_metadata = path_info[0] if path_info else None
            file_size = getattr(file_metadata, "size", None)
            if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
                raise ValueError(f"Unable to determine file size for {display_url}; refusing capped download")
            if file_size > size_limit:
                raise ValueError(
                    f"File size ({_format_size(file_size)}) exceeds maximum allowed size ({_format_size(size_limit)})"
                )
            download_revision = pinned_revision

        # Use hf_hub_download for single file downloads
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            revision=download_revision,
            cache_dir=str(cache_dir) if cache_dir else None,
        )
        downloaded_path = Path(local_path)
        if size_limit is not None:
            try:
                downloaded_size = downloaded_path.stat().st_size
            except OSError as exc:
                raise ValueError(
                    f"Unable to verify downloaded file size for {display_url}; refusing capped download"
                ) from exc
            if downloaded_size > size_limit:
                raise ValueError(
                    f"Downloaded file size ({_format_size(downloaded_size)}) "
                    f"exceeds maximum allowed size ({_format_size(size_limit)})"
                )
        return downloaded_path
    except Exception as e:
        raise Exception(f"Failed to download file from {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e
