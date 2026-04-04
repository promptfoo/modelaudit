import json
import pickletools
import re
import struct
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from ..helpers.types import FileExtension, FileFormat, FilePath, MagicBytes

# Known GGML header variants (older formats like GGMF and GGJT)
GGML_MAGIC_VARIANTS = {
    b"GGML",
    b"GGMF",
    b"GGJT",
    b"GGLA",
    b"GGSA",
}
R_WORKSPACE_HEADERS = {
    b"RDX2\n",
    b"RDX3\n",
    b"RDA2\n",
    b"RDA3\n",
}
R_SERIALIZATION_MARKERS = {
    b"X\n",
    b"A\n",
    b"B\n",
}
_CNTK_LEGACY_MAGIC = b"B\x00C\x00N\x00\x00\x00"
_CNTK_LEGACY_VERSION_MARKER = b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
_CNTK_V2_REQUIRED_MARKERS = (b"\x0a\x07version", b"\x0a\x03uid")
_CNTK_V2_STRUCTURE_MARKERS = (b"CompositeFunction", b"primitive_functions", b"PrimitiveFunction")
_CNTK_SIGNATURE_READ_BYTES = 4096
_TF_METAGRAPH_MIN_BYTES = 8
_TF_METAGRAPH_MAX_VALIDATE_BYTES = 20 * 1024 * 1024
_TORCH7_SIGNATURE_READ_BYTES = 4096
_LIGHTGBM_SIGNATURE_READ_BYTES = 8192
_LIGHTGBM_HEADER_MARKERS = (
    "version=",
    "num_class=",
    "num_tree_per_iteration=",
    "max_feature_idx=",
    "feature_names=",
    "tree_sizes=",
)
_LIGHTGBM_TREE_MARKERS = (
    "tree=",
    "num_leaves=",
    "split_feature=",
    "leaf_value=",
)
_LIGHTGBM_XGBOOST_JSON_MARKERS = ('"learner"', '"gradient_booster"', '"tree_param"')
_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
_LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"
_TORCHSERVE_MANIFEST_PATH = "MAR-INF/MANIFEST.json"
_TORCHSERVE_MANIFEST_MAX_BYTES = 1 * 1024 * 1024
_KERAS_ZIP_REQUIRED_ENTRY = "config.json"
_KERAS_ZIP_MARKERS = frozenset({"metadata.json", "model.weights.h5", "variables.h5"})
_KERAS_ZIP_CONFIG_MAX_BYTES = 4 * 1024 * 1024
_KERAS_ZIP_CONFIG_PREFIX_MAX_BYTES = 256 * 1024
_KERAS_MODEL_CONFIG_KEYS = frozenset({"layers", "input_layers", "output_layers"})
_KERAS_MODEL_TOP_LEVEL_HINTS = frozenset({"build_config", "compile_config", "module", "registered_name"})
_KERAS_CONFIG_PREFIX_CLASS_NAME_RE = re.compile(r'"class_name"\s*:\s*"[^"\\]+"')
_KERAS_CONFIG_PREFIX_CONFIG_OBJECT_RE = re.compile(r'"config"\s*:\s*\{')
_KERAS_CONFIG_PREFIX_HINT_RE = re.compile(
    r'"(?:layers|input_layers|output_layers|build_config|compile_config|module|registered_name)"\s*:'
)
_PYTORCH_ZIP_METADATA_MAX_BYTES = 64
_SKOPS_SCHEMA_ENTRIES = frozenset({"schema", "schema.json"})
_SKOPS_SCHEMA_MAX_BYTES = 4 * 1024 * 1024
_COMPRESSED_EXTENSION_CODECS = {
    ".gz": "gzip",
    ".bz2": "bzip2",
    ".xz": "xz",
    ".lz4": "lz4",
    ".zlib": "zlib",
}

# Pickle protocol 0/1 GLOBAL opcode signatures used for .bin fallback detection.
# Format: c<module>\n<name>\n
PROTOCOL0_GLOBAL_RE = re.compile(rb"^c[^\n\r]{1,64}\n[^\n\r]{1,64}\n")
MARKED_PROTOCOL0_GLOBAL_RE = re.compile(rb"^[\(\]\}]c[^\n\r]{1,64}\n[^\n\r]{1,64}\n")

# Protocol 0/1 pickles are ASCII and may not start with GLOBAL/INST.
# Use bounded opcode parsing to reduce false positives on plain text and
# still detect prefixed payloads (for example MARK/LIST/POP or BININT1/POP
# before a GLOBAL/INST opcode).
PROTO0_1_MAX_PROBE_BYTES: int = 64 * 1024
# A 64 KiB probe can contain up to 64 KiB one-byte opcodes. Keep the opcode
# budget aligned with the byte budget so trivial padding cannot hide a later
# dangerous opcode inside the sampled prefix.
PROTO0_1_MAX_PROBE_OPCODES: int = PROTO0_1_MAX_PROBE_BYTES
PROTO0_1_START_BYTES: bytes = b"()]}cilp0FGIJKLMNSTUVX"
PROTO0_1_IGNORABLE_TRAILING_BYTES: bytes = b" \t\r\n\x00"
PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES: tuple[str, ...] = (
    "pickle exhausted before seeing STOP",
    "no newline found when trying to read ",
)
PROTO0_1_TRIVIAL_LEADING_OPCODES: frozenset[str] = frozenset(
    {
        "MARK",
        "POP",
        "PUT",
        "EMPTY_TUPLE",
        "EMPTY_LIST",
        "EMPTY_DICT",
        "LIST",
        "INT",
        "BININT",
        "BININT1",
        "BININT2",
        "LONG",
        "LONG1",
        "LONG4",
        "FLOAT",
        "BINFLOAT",
        "NONE",
        "NEWTRUE",
        "NEWFALSE",
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "UNICODE",
        "BINUNICODE",
        "SHORT_BINUNICODE",
    },
)
SAFETENSORS_MAX_HEADER_BYTES: int = 100 * 1024 * 1024


def _looks_like_proto0_or_1_pickle(sample: bytes, *, sample_is_prefix: bool = False) -> bool:
    """Best-effort protocol 0/1 detection via bounded pickle opcode parsing."""
    if len(sample) < 2:
        return False

    def _matches_proto_stream(candidate: bytes) -> bool:
        # Only attempt expensive parsing for likely text-protocol starters.
        if len(candidate) < 2 or candidate[0] not in PROTO0_1_START_BYTES:
            return False

        opcode_count = 0
        has_non_trivial_opcode = False
        try:
            for opcode, _arg, _pos in pickletools.genops(candidate):
                opcode_count += 1
                if opcode.name == "STOP":
                    stop_pos = 0 if _pos is None else _pos
                    trailing = candidate[stop_pos + 1 :]
                    if not trailing or not trailing.strip(PROTO0_1_IGNORABLE_TRAILING_BYTES):
                        return opcode_count >= 2
                    # Python's unpickler ignores trailing bytes after STOP. Accept
                    # junk-suffixed streams once the parsed prefix contains any
                    # non-trivial opcode, while still rejecting scalar/container
                    # prefixes followed by plain text near-matches.
                    if has_non_trivial_opcode:
                        return opcode_count >= 2
                    stripped_trailing = trailing.lstrip(PROTO0_1_IGNORABLE_TRAILING_BYTES)
                    return bool(stripped_trailing) and _looks_like_proto0_or_1_pickle(
                        stripped_trailing,
                        sample_is_prefix=sample_is_prefix,
                    )
                if opcode.name not in PROTO0_1_TRIVIAL_LEADING_OPCODES:
                    has_non_trivial_opcode = True
                if opcode_count >= PROTO0_1_MAX_PROBE_OPCODES:
                    return False
        except ValueError as exc:
            exc_message = str(exc)
            return (
                sample_is_prefix
                and opcode_count >= 2
                and has_non_trivial_opcode
                and any(
                    exc_message.startswith(error_prefix) for error_prefix in PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES
                )
            )
        except Exception:
            return False
        # A cleanly parsed prefix without STOP at the probe boundary is only a
        # pickle indicator when a non-trivial opcode has already appeared. This
        # avoids routing large plain-text files made of scalar opcode lookalikes
        # (for example repeated ``I0\n0``) into pickle scanning.
        return sample_is_prefix and opcode_count >= 2 and has_non_trivial_opcode

    if _matches_proto_stream(sample):
        return True

    # Regression hardening: a single leading "#" token should not suppress
    # protocol 0/1 detection for otherwise valid pickle streams.
    return sample.startswith(b"#") and _matches_proto_stream(sample[1:])


def _read_pickle_probe_sample(path: Path, size: int, header16: bytes) -> bytes:
    """Read a bounded prefix for protocol 0/1 pickle probing."""
    if size <= len(header16):
        return header16
    with path.open("rb") as f:
        return f.read(min(size, PROTO0_1_MAX_PROBE_BYTES))


def _looks_like_safetensors_structure(path: Path | None, magic8: bytes, file_size: int) -> bool:
    """Validate safetensors framing: <u64 header_len><JSON header><tensor data>."""
    if file_size <= 8 or len(magic8) < 8:
        return False

    try:
        header_len = struct.unpack("<Q", magic8)[0]
    except struct.error:
        return False

    if header_len <= 0:
        return False
    if header_len >= SAFETENSORS_MAX_HEADER_BYTES:
        return False
    if header_len > file_size - 8:
        return False

    if path is None:
        return False

    try:
        with path.open("rb") as handle:
            handle.seek(8)
            header = handle.read(header_len)
    except OSError:
        return False

    if len(header) != header_len or not header.startswith(b"{"):
        return False

    try:
        parsed_header = json.loads(header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False

    return isinstance(parsed_header, dict)


def _normalize_archive_member_name(member_name: str) -> str:
    """Normalize ZIP entry names for stable path comparisons."""
    normalized = member_name.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    normalized = re.sub(r"/+", "/", normalized)
    return str(PurePosixPath(normalized))


def _read_zip_member_bounded(
    archive: zipfile.ZipFile,
    member_info: zipfile.ZipInfo,
    max_bytes: int,
) -> bytes:
    """Read a ZIP member with a strict size cap."""
    if member_info.file_size > max_bytes:
        raise ValueError("ZIP member exceeds bounded read size")

    data = bytearray()
    with archive.open(member_info, "r") as handle:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                raise ValueError("ZIP member exceeded bounded read limit")
    return bytes(data)


def _read_zip_member_prefix(
    archive: zipfile.ZipFile,
    member_info: zipfile.ZipInfo,
    max_bytes: int,
) -> bytes:
    """Read only a bounded prefix from a ZIP member."""
    with archive.open(member_info, "r") as handle:
        return handle.read(max_bytes)


def _coerce_manifest_string_list(value: object) -> list[str]:
    """Collect non-empty string values from manifest fields."""
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, list):
        collected: list[str] = []
        for item in value:
            if isinstance(item, str):
                stripped = item.strip()
                if stripped:
                    collected.append(stripped)
        return collected
    return []


def _looks_like_torchserve_manifest(manifest_data: object) -> bool:
    """Require enough manifest structure to justify TorchServe-specific routing."""
    if not isinstance(manifest_data, dict):
        return False

    model_section = manifest_data.get("model")
    model_dict = model_section if isinstance(model_section, dict) else {}

    handler_candidates: list[str] = []
    serialized_candidates: list[str] = []

    if isinstance(model_dict, dict):
        handler_candidates.extend(_coerce_manifest_string_list(model_dict.get("handler")))
        serialized_candidates.extend(_coerce_manifest_string_list(model_dict.get("serializedFile")))

    handler_candidates.extend(_coerce_manifest_string_list(manifest_data.get("handler")))
    serialized_candidates.extend(_coerce_manifest_string_list(manifest_data.get("serializedFile")))

    return bool(handler_candidates) and bool(serialized_candidates)


def _looks_like_keras_config(config_data: object) -> bool:
    """Require enough config structure to justify Keras-specific routing."""
    if not isinstance(config_data, dict):
        return False

    class_name = config_data.get("class_name")
    config = config_data.get("config")
    if not isinstance(class_name, str) or not class_name.strip() or not isinstance(config, dict):
        return False

    if any(key in config for key in _KERAS_MODEL_CONFIG_KEYS):
        return True

    return any(key in config_data for key in _KERAS_MODEL_TOP_LEVEL_HINTS)


def _looks_like_skops_schema(schema_data: object) -> bool:
    """Require enough schema structure to justify Skops-specific routing."""
    if not isinstance(schema_data, dict):
        return False

    class_name = schema_data.get("__class__")
    module_name = schema_data.get("__module__")
    loader_name = schema_data.get("__loader__")
    if not isinstance(class_name, str) or not class_name.strip():
        return False
    if not isinstance(module_name, str) or not module_name.strip():
        return False
    # Skops schema nodes are serialized as ObjectNode/ListNode/etc.
    if not isinstance(loader_name, str) or not loader_name.endswith("Node"):
        return False
    if "content" not in schema_data:
        return False

    skops_version = schema_data.get("_skops_version")
    return isinstance(skops_version, str) and bool(skops_version.strip())


def _looks_like_keras_config_prefix(config_prefix: bytes) -> bool:
    """Best-effort Keras config sniffing for oversized JSON members."""
    try:
        config_text = config_prefix.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False

    return (
        bool(_KERAS_CONFIG_PREFIX_CLASS_NAME_RE.search(config_text))
        and bool(_KERAS_CONFIG_PREFIX_CONFIG_OBJECT_RE.search(config_text))
        and bool(_KERAS_CONFIG_PREFIX_HINT_RE.search(config_text))
    )


def _read_zip_member_text(
    archive: zipfile.ZipFile,
    member_info: zipfile.ZipInfo,
    max_bytes: int,
) -> str | None:
    """Read a bounded ZIP member as UTF-8 text."""
    try:
        data = _read_zip_member_bounded(archive, member_info, max_bytes)
        return data.decode("utf-8", errors="strict").strip()
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError):
        return None


def _looks_like_pytorch_zip_metadata(archive: zipfile.ZipFile, prefix: str) -> bool:
    """Require conservative, PyTorch-specific ZIP metadata near data.pkl."""
    version_name = f"{prefix}/version" if prefix else "version"
    byteorder_name = f"{prefix}/byteorder" if prefix else "byteorder"

    version_info = archive.NameToInfo.get(version_name)
    if version_info is not None:
        version_text = _read_zip_member_text(archive, version_info, _PYTORCH_ZIP_METADATA_MAX_BYTES)
        if version_text is not None and re.fullmatch(r"\d+(?:\.\d+)?", version_text):
            return True

    byteorder_info = archive.NameToInfo.get(byteorder_name)
    if byteorder_info is not None:
        byteorder_text = _read_zip_member_text(archive, byteorder_info, _PYTORCH_ZIP_METADATA_MAX_BYTES)
        if byteorder_text in {"little", "big"}:
            return True

    return False


def is_torchserve_mar_archive(path: str) -> bool:
    """Return whether a ZIP-backed `.mar` looks like a real TorchServe archive."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            manifest_info = None
            manifest_name = _normalize_archive_member_name(_TORCHSERVE_MANIFEST_PATH)
            for info in archive.infolist():
                if _normalize_archive_member_name(info.filename) == manifest_name:
                    manifest_info = info
                    break

            if manifest_info is None:
                return False

            manifest_bytes = _read_zip_member_bounded(archive, manifest_info, _TORCHSERVE_MANIFEST_MAX_BYTES)
            manifest_data = json.loads(manifest_bytes.decode("utf-8"))
            return _looks_like_torchserve_manifest(manifest_data)
    except (
        OSError,
        RuntimeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        return False


def is_keras_zip_archive(path: str, *, allow_config_only: bool = False) -> bool:
    """Return whether a ZIP-backed file has the minimal Keras archive structure."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            member_names: set[str] = set()
            config_info: zipfile.ZipInfo | None = None
            for info in archive.infolist():
                if not info.filename or info.is_dir():
                    continue

                normalized_name = _normalize_archive_member_name(info.filename)
                member_names.add(normalized_name)
                if normalized_name == _KERAS_ZIP_REQUIRED_ENTRY:
                    config_info = info

            if _KERAS_ZIP_REQUIRED_ENTRY not in member_names:
                return False

            if allow_config_only:
                return True

            if any(marker in member_names for marker in _KERAS_ZIP_MARKERS):
                return True

            if config_info is None:
                return False

            try:
                config_data = json.loads(_read_zip_member_bounded(archive, config_info, _KERAS_ZIP_CONFIG_MAX_BYTES))
            except (RuntimeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                if config_info.file_size > _KERAS_ZIP_CONFIG_MAX_BYTES:
                    try:
                        config_prefix = _read_zip_member_prefix(
                            archive,
                            config_info,
                            _KERAS_ZIP_CONFIG_PREFIX_MAX_BYTES,
                        )
                    except (OSError, RuntimeError):
                        return False
                    return _looks_like_keras_config_prefix(config_prefix)
                return False

            return _looks_like_keras_config(config_data)
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False


def is_pytorch_zip_archive(path: str) -> bool:
    """Return whether a ZIP-backed file has a conservative PyTorch archive signature."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            member_names = {
                _normalize_archive_member_name(info.filename)
                for info in archive.infolist()
                if info.filename and not info.is_dir()
            }

            for name in member_names:
                if name == "data.pkl":
                    prefix = ""
                elif name.endswith("/data.pkl"):
                    prefix = name[: -len("/data.pkl")]
                else:
                    continue

                if _looks_like_pytorch_zip_metadata(archive, prefix):
                    return True
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False

    return False


def is_executorch_archive(path: str) -> bool:
    """Return whether a ZIP-backed file matches the mobile/ExecuTorch archive layout."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            member_names = {
                _normalize_archive_member_name(info.filename)
                for info in archive.infolist()
                if info.filename and not info.is_dir()
            }

            for name in member_names:
                if name == "bytecode.pkl":
                    prefix = ""
                elif name.endswith("/bytecode.pkl"):
                    prefix = name[: -len("/bytecode.pkl")]
                else:
                    continue

                version_name = f"{prefix}/version" if prefix else "version"
                version_info = archive.NameToInfo.get(version_name)
                if version_info is None:
                    continue

                version_text = _read_zip_member_text(archive, version_info, _PYTORCH_ZIP_METADATA_MAX_BYTES)
                if version_text is not None and re.fullmatch(r"\d+(?:\.\d+)?", version_text):
                    return True
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False

    return False


def is_skops_archive(path: str) -> bool:
    """Return whether a ZIP-backed file has a Skops schema payload.

    Oversized schema members are treated as Skops to avoid failing open on
    misnamed archives whose schema content cannot be safely parsed within the
    bounded read limit.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            for info in archive.infolist():
                if not info.filename or info.is_dir():
                    continue

                basename = PurePosixPath(_normalize_archive_member_name(info.filename)).name
                if basename not in _SKOPS_SCHEMA_ENTRIES:
                    continue
                if info.file_size > _SKOPS_SCHEMA_MAX_BYTES:
                    return True

                try:
                    schema_data = json.loads(_read_zip_member_bounded(archive, info, _SKOPS_SCHEMA_MAX_BYTES))
                except (RuntimeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                    continue

                if _looks_like_skops_schema(schema_data):
                    return True
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False

    return False


def _is_tar_archive(path: str) -> bool:
    """Return whether a path is a TAR archive, including compressed wrappers."""
    try:
        return tarfile.is_tarfile(path)
    except Exception:
        return False


def is_zipfile(path: str) -> bool:
    """Check if file is a ZIP by reading the signature."""
    file_path = Path(path)
    if not file_path.is_file():
        return False
    try:
        signature = read_magic_bytes(path, 4)
        return signature.startswith(b"PK")
    except OSError:
        return False


def read_magic_bytes(path: str, num_bytes: int = 8) -> bytes:
    with Path(path).open("rb") as f:
        return f.read(num_bytes)


def _looks_like_cntk_v2_signature(prefix: bytes) -> bool:
    return all(marker in prefix for marker in _CNTK_V2_REQUIRED_MARKERS) and any(
        marker in prefix for marker in _CNTK_V2_STRUCTURE_MARKERS
    )


def _is_cntk_signature(prefix: bytes) -> bool:
    if prefix.startswith(_CNTK_LEGACY_MAGIC):
        return _CNTK_LEGACY_VERSION_MARKER in prefix
    return _looks_like_cntk_v2_signature(prefix)


def _is_tensorflow_metagraph_file(path: str) -> bool:
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        size = file_path.stat().st_size
        if size < _TF_METAGRAPH_MIN_BYTES or size > _TF_METAGRAPH_MAX_VALIDATE_BYTES:
            return False

        # Import vendored protos module (sets up sys.path for tensorflow.* imports)
        # Order matters: modelaudit.protos must be imported first to set up sys.path
        import modelaudit.protos  # noqa: F401, I001

        from tensorflow.core.protobuf.meta_graph_pb2 import MetaGraphDef

        content = file_path.read_bytes()
        metagraph = MetaGraphDef()
        metagraph.ParseFromString(content)

        if not metagraph.HasField("graph_def"):
            return False

        graph_node_count = len(metagraph.graph_def.node)
        function_node_count = sum(len(function.node_def) for function in metagraph.graph_def.library.function)
        collection_count = len(metagraph.collection_def)
        return graph_node_count > 0 or function_node_count > 0 or collection_count > 0
    except Exception:
        return False


def _is_torch7_signature(prefix: bytes) -> bool:
    lowered = prefix.lower()
    if prefix.startswith(b"T7\x00\x00"):
        return True
    has_torch_marker = b"torch" in lowered or b"luat" in lowered
    has_structure_marker = b"nn." in lowered or b"tensor" in lowered or b"thnn" in lowered
    return has_torch_marker and has_structure_marker


def _is_lightgbm_signature(prefix: bytes) -> bool:
    preview = prefix.decode("utf-8", errors="ignore").replace("\x00", "\n").lower()
    starts_with_tree = preview.lstrip().startswith("tree")
    header_hits = sum(1 for marker in _LIGHTGBM_HEADER_MARKERS if marker in preview)
    tree_hits = sum(1 for marker in _LIGHTGBM_TREE_MARKERS if marker in preview)
    xgboost_like = all(marker in preview for marker in _LIGHTGBM_XGBOOST_JSON_MARKERS)
    return (starts_with_tree or "tree=" in preview) and header_hits >= 3 and tree_hits >= 2 and not xgboost_like


def _is_executorch_binary_signature(prefix: bytes) -> bool:
    """Recognize versioned ExecuTorch FlatBuffers binaries by their file identifier."""
    return len(prefix) >= 8 and prefix[4:6] == b"ET" and prefix[6:8].isdigit()


def _is_valid_executorch_binary(path: str | Path) -> bool:
    """Validate the minimal FlatBuffers structure for ExecuTorch binaries."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        file_size = file_path.stat().st_size
        if file_size < 16:
            return False

        with file_path.open("rb") as f:
            header = f.read(8)
            if not _is_executorch_binary_signature(header):
                return False

            root_table_offset = struct.unpack("<I", header[:4])[0]
            if root_table_offset < 12 or root_table_offset + 4 > file_size:
                return False

            f.seek(root_table_offset)
            table_header = f.read(4)
            if len(table_header) != 4:
                return False

            vtable_back_offset = struct.unpack("<i", table_header)[0]
            if vtable_back_offset <= 0 or vtable_back_offset > root_table_offset:
                return False

            vtable_offset = root_table_offset - vtable_back_offset
            if vtable_offset < 8 or vtable_offset + 4 > file_size:
                return False

            f.seek(vtable_offset)
            vtable_header = f.read(4)
            if len(vtable_header) != 4:
                return False

            vtable_size, object_size = struct.unpack("<HH", vtable_header)
            if vtable_size < 4 or object_size < 4:
                return False
            if vtable_offset + vtable_size > file_size:
                return False
            if root_table_offset + object_size > file_size:
                return False
    except (OSError, struct.error):
        return False

    return True


def _is_zlib_header(prefix: bytes) -> bool:
    if len(prefix) < 2:
        return False
    cmf = prefix[0]
    flg = prefix[1]
    if (cmf & 0x0F) != 8:
        return False
    if (cmf >> 4) > 7:
        return False
    return ((cmf << 8) + flg) % 31 == 0


def _detect_compression_format(prefix: bytes) -> str | None:
    if prefix.startswith(_GZIP_MAGIC):
        return "gzip"
    if prefix.startswith(_BZIP2_MAGIC):
        return "bzip2"
    if prefix.startswith(_XZ_MAGIC):
        return "xz"
    if prefix.startswith(_LZ4_FRAME_MAGIC):
        return "lz4"
    if _is_zlib_header(prefix[:2]):
        return "zlib"
    return None


def detect_format_from_magic_bytes(
    magic4: MagicBytes, magic8: MagicBytes, magic16: MagicBytes, file_size: int, file_path: Path | None = None
) -> FileFormat:
    """Detect file format using Python 3.10+ pattern matching on magic bytes."""
    compression_format = _detect_compression_format(magic16)
    if compression_format:
        return compression_format

    # Use pattern matching for cleaner magic byte detection
    match magic4:
        case b"CBM1":
            return "catboost"
        case b"RKNN":
            return "rknn"
        case b"T7\x00\x00":
            return "torch7"
        case b"GGUF":
            return "gguf"
        case magic if magic in GGML_MAGIC_VARIANTS:
            return "ggml"
        case magic if magic.startswith(b"PK"):
            return "zip"
        case b"\x08\x01\x12\x00":  # ONNX protobuf magic
            return "onnx"
        case _:
            pass

    # Check longer magic sequences
    match magic8:
        case magic if magic.startswith(_SEVENZIP_MAGIC):
            return "sevenzip"
        case magic if magic == _CNTK_LEGACY_MAGIC:
            return "cntk"
        case b"\x89HDF\r\n\x1a\n":  # HDF5 magic
            return "hdf5"
        case magic if magic.startswith(b"\x93NUMPY"):
            return "numpy"
        case _:
            pass

    if any(magic16.startswith(header) for header in R_WORKSPACE_HEADERS):
        return "r_serialized"
    if any(magic16.startswith(marker) for marker in R_SERIALIZATION_MARKERS):
        return "r_serialized"

    # Check pickle magic bytes using pattern matching
    match magic4[:2]:
        case b"\x80\x02" | b"\x80\x03" | b"\x80\x04" | b"\x80\x05":
            return "pickle"
        case _:
            pass
    if _looks_like_safetensors_structure(file_path, magic8, file_size):
        return "safetensors"

    # Check for patterns in first 16 bytes
    if b"onnx" in magic16:
        return "onnx"
    if b'"__metadata__"' in magic16 and _looks_like_safetensors_structure(file_path, magic8, file_size):
        return "safetensors"

    return "unknown"


def detect_file_format_from_magic(path: str) -> str:
    """Detect file format solely from magic bytes."""
    file_path = Path(path)
    if file_path.is_dir():
        if (file_path / "saved_model.pb").exists():
            return "tensorflow_directory"
        return "directory"

    if not file_path.is_file():
        return "unknown"

    try:
        size = file_path.stat().st_size
        if size < 4:
            return "unknown"

        if file_path.suffix.lower() == ".meta":
            return "tf_metagraph" if _is_tensorflow_metagraph_file(path) else "unknown"

        with file_path.open("rb") as f:
            header = f.read(16)

            # Check for TAR format by looking for the "ustar" signature
            if size >= 262:
                f.seek(257)
                if f.read(5).startswith(b"ustar"):
                    return "tar"
            # Reset to read from header for further checks
            f.seek(0)

            magic4 = header[:4]
            magic8 = header[:8]
            magic16 = header[:16]

            if _is_executorch_binary_signature(magic8) and _is_valid_executorch_binary(file_path):
                return "executorch"

            # Try the new pattern matching approach first
            format_result = detect_format_from_magic_bytes(magic4, magic8, magic16, size, file_path)
            if format_result == "zip" and file_path.suffix.lower() == ".mar" and is_torchserve_mar_archive(path):
                return "torchserve_mar"
            if format_result != "unknown":
                return format_result

            # CNTKv2 has protobuf-style serialization without a fixed first-8-byte magic.
            # Use bounded signature markers for deterministic identification.
            f.seek(0)
            cntk_prefix = f.read(_CNTK_SIGNATURE_READ_BYTES)
            if _is_cntk_signature(cntk_prefix):
                return "cntk"

            f.seek(0)
            torch7_prefix = f.read(_TORCH7_SIGNATURE_READ_BYTES)
            if _is_torch7_signature(torch7_prefix):
                return "torch7"

            f.seek(0)
            lightgbm_prefix = f.read(_LIGHTGBM_SIGNATURE_READ_BYTES)
            if _is_lightgbm_signature(lightgbm_prefix):
                return "lightgbm"
            # Protocol 0/1 pickle payloads can evade short magic-byte checks.
            # Probe a bounded prefix and require a valid opcode stream.
            pickle_probe_sample = _read_pickle_probe_sample(file_path, size, magic16)
            if _looks_like_proto0_or_1_pickle(
                pickle_probe_sample,
                sample_is_prefix=size > len(pickle_probe_sample),
            ):
                return "pickle"

            # Check for XML-based formats (OpenVINO and PMML)
            if magic16.startswith(b"<?xml"):
                # Read first 64 bytes to check for format-specific tags
                f.seek(0)
                xml_header = f.read(64)
                if b"<net" in xml_header:
                    return "openvino"
                if b"<PMML" in xml_header:
                    return "pmml"

    except OSError:
        return "unknown"

    # Fallback: use strict safetensors framing; plain JSON must not be routed as safetensors.
    magic4 = header[:4]
    magic8 = header[:8]
    magic16 = header[:16]

    if _looks_like_safetensors_structure(file_path, magic8, size):
        return "safetensors"

    if magic4 == b"\x08\x01\x12\x00" or b"onnx" in magic16:
        return "onnx"

    return "unknown"


def detect_file_format(path: str) -> str:
    """
    Attempt to identify the format:
    - TensorFlow SavedModel (directory with saved_model.pb)
    - Keras HDF5 (.h5 file with HDF5 magic bytes)
    - PyTorch ZIP (.pt/.pth file that's a ZIP)
    - Pickle (.pkl/.pickle or other files with pickle magic)
    - PyTorch binary (.bin files with various formats)
    - GGUF/GGML files with magic bytes
    - If extension indicates pickle/pt/h5/pb, etc.
    """
    file_path = Path(path)
    if file_path.is_dir():
        # We'll let the caller handle directory logic.
        # But we do a quick guess if there's a 'saved_model.pb'.
        if any(f.name == "saved_model.pb" for f in file_path.iterdir()):
            return "tensorflow_directory"
        return "directory"

    # Single file
    size = file_path.stat().st_size
    if size < 4:
        return "unknown"

    # Read first bytes for format detection using a single file handle
    with file_path.open("rb") as f:
        header = f.read(16)

    magic4 = header[:4]
    magic8 = header[:8]
    magic16 = header[:16]

    # Check first 8 bytes for HDF5 magic
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    if magic8 == hdf5_magic:
        return "hdf5"

    # Check for GGUF/GGML magic bytes
    if magic4 == b"CBM1":
        return "catboost"
    if magic4 == b"GGUF":
        return "gguf"
    if magic4 in GGML_MAGIC_VARIANTS:
        return "ggml"

    ext = file_path.suffix.lower()
    filename_lower = file_path.name.lower()

    # Compound tar wrappers should route to TAR scanner semantics.
    if filename_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "tar"

    compression_format = _detect_compression_format(header)
    if ext in _COMPRESSED_EXTENSION_CODECS:
        if _is_tar_archive(path):
            return "tar"
        expected_codec = _COMPRESSED_EXTENSION_CODECS[ext]
        if compression_format == expected_codec:
            return "compressed"
        return "unknown"
    if magic8.startswith(_SEVENZIP_MAGIC):
        return "sevenzip"
    if _is_tar_archive(path):
        return "tar"
    # Check ZIP magic first (for .pt/.pth files that are actually zips)
    if magic4.startswith(b"PK"):
        if ext == ".mar" and is_torchserve_mar_archive(path):
            return "torchserve_mar"
        return "zip"

    # Check pickle magic patterns
    pickle_magics = [
        b"\x80\x02",  # Protocol 2
        b"\x80\x03",  # Protocol 3
        b"\x80\x04",  # Protocol 4
        b"\x80\x05",  # Protocol 5
    ]
    if any(magic4.startswith(m) for m in pickle_magics):
        return "pickle"
    pickle_probe_sample = _read_pickle_probe_sample(file_path, size, magic16)
    if _looks_like_proto0_or_1_pickle(
        pickle_probe_sample,
        sample_is_prefix=size > len(pickle_probe_sample),
    ):
        return "pickle"

    # For .bin files, do more sophisticated detection
    if ext == ".bin":
        magic64 = read_magic_bytes(path, 64)
        # IMPORTANT: Check ZIP format first (PyTorch models saved with torch.save())
        if magic4.startswith(b"PK"):
            return "zip"
        # Check if it's a pickle file (protocol 2-5)
        if any(magic4.startswith(m) for m in pickle_magics):
            return "pickle"
        # CVE-2025-10155: Detect protocol 0/1 pickles that lack magic bytes.
        # Protocol 0 GLOBAL opcode: c<module>\n<name>\n
        # Use a strict shape match to avoid classifying arbitrary binaries as pickle.
        if PROTOCOL0_GLOBAL_RE.match(magic64):
            return "pickle"
        # Also detect pickle protocol 0/1 streams starting with MARK '(' (tuple/reduce
        # preamble), EMPTY_LIST ']', or EMPTY_DICT '}' opcodes.  These are valid
        # protocol 0/1 start bytes but are only treated as pickle when immediately
        # followed by a properly formed GLOBAL opcode sequence.
        if MARKED_PROTOCOL0_GLOBAL_RE.match(magic64):
            return "pickle"
        # Check for safetensors format (<u64 header_len> + JSON header).
        if _looks_like_safetensors_structure(file_path, magic8, size):
            return "safetensors"

        # Check for ONNX format (protobuf)
        if magic4 == b"\x08\x01\x12\x00" or b"onnx" in magic16:
            return "onnx"

        # Otherwise, assume raw binary format (PyTorch weights)
        return "pytorch_binary"

    # Extension-based detection for non-.bin files
    # For .pt/.pth/.ckpt files, check if they're ZIP format first
    if ext in (".pt", ".pth", ".ckpt"):
        # These files can be either ZIP or pickle format
        if magic4.startswith(b"PK"):
            return "zip"
        # If not ZIP, assume pickle format
        return "pickle"
    if ext == ".meta":
        if _is_tensorflow_metagraph_file(path):
            return "tf_metagraph"
        return "unknown"
    if ext in (".ptl", ".pte"):
        if magic4.startswith(b"PK"):
            return "executorch"
        return "executorch"
    if ext in (".pkl", ".pickle", ".dill"):
        return "pickle"
    if ext in (".dnn", ".cmf"):
        prefix = read_magic_bytes(path, _CNTK_SIGNATURE_READ_BYTES)
        if _is_cntk_signature(prefix):
            return "cntk"
        return "unknown"
    if ext in (".t7", ".th", ".net"):
        prefix = read_magic_bytes(path, _TORCH7_SIGNATURE_READ_BYTES)
        if _is_torch7_signature(prefix):
            return "torch7"
        return "unknown"
    if ext in (".lgb", ".lightgbm"):
        prefix = read_magic_bytes(path, _LIGHTGBM_SIGNATURE_READ_BYTES)
        if _is_lightgbm_signature(prefix):
            return "lightgbm"
        return "unknown"
    if ext == ".model":
        prefix = read_magic_bytes(path, _LIGHTGBM_SIGNATURE_READ_BYTES)
        if _is_lightgbm_signature(prefix):
            return "lightgbm"
    if ext == ".rknn":
        if magic4 == b"RKNN":
            return "rknn"
        return "rknn"
    if ext == ".json" and file_path.name.lower().endswith("-symbol.json"):
        return "mxnet"
    if ext == ".params":
        return "mxnet"
    if ext == ".cbm":
        return "catboost"
    if ext == ".llamafile":
        return "llamafile"
    if ext == ".h5":
        return "hdf5"
    if ext == ".pb":
        return "protobuf"
    if ext == ".tflite":
        return "tflite"
    if ext == ".mlmodel":
        return "coreml"
    if ext in (".engine", ".plan", ".trt"):
        return "tensorrt"
    if ext == ".safetensors":
        return "safetensors"
    if ext in (".pdmodel", ".pdiparams"):
        return "paddle"
    if ext == ".msgpack":
        return "flax_msgpack"
    if ext == ".onnx":
        return "onnx"
    if ext == ".nemo":
        return "nemo"
    ggml_exts = {".ggml", ".ggmf", ".ggjt", ".ggla", ".ggsa"}
    if ext in (".gguf", *ggml_exts):
        # Check magic bytes first for accuracy
        if magic4 == b"GGUF":
            return "gguf"
        if magic4 in GGML_MAGIC_VARIANTS:
            return "ggml"
        # Fall back to extension-based detection
        return "gguf" if ext == ".gguf" else "ggml"
    if ext == ".npy":
        return "numpy"
    if ext == ".npz":
        return "zip"
    if ext == ".joblib":
        if magic4.startswith(b"PK"):
            return "zip"
        return "pickle"
    if ext in (".rds", ".rda", ".rdata"):
        return "r_serialized"
    if ext in (
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz2",
        ".tar.xz",
        ".txz",
    ):
        return "tar"
    if _looks_like_safetensors_structure(file_path, magic8, size):
        return "safetensors"
    return "unknown"


def find_sharded_files(directory: str) -> list[str]:
    """
    Look for sharded model files like:
    pytorch_model-00001-of-00002.bin
    """
    dir_path = Path(directory).resolve()
    return sorted(
        [
            str(fname.resolve())
            for fname in dir_path.iterdir()
            if fname.is_file() and re.match(r"pytorch_model-\d{5}-of-\d{5}\.bin", fname.name)
        ],
    )


EXTENSION_FORMAT_MAP = {
    ".pt": "pickle",
    ".pth": "pickle",
    ".ckpt": "pickle",
    ".dnn": "cntk",
    ".cmf": "cntk",
    ".t7": "torch7",
    ".th": "torch7",
    ".net": "torch7",
    ".rknn": "rknn",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".dill": "pickle",
    ".h5": "hdf5",
    ".hdf5": "hdf5",
    ".keras": "keras",  # Keras 3.x uses ZIP, legacy Keras uses HDF5
    ".pb": "protobuf",
    ".meta": "tf_metagraph",
    ".mlmodel": "coreml",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".bin": "pytorch_binary",
    ".gz": "compressed",
    ".bz2": "compressed",
    ".xz": "compressed",
    ".lz4": "compressed",
    ".zlib": "compressed",
    ".zip": "zip",
    ".mar": "torchserve_mar",
    ".gguf": "gguf",
    ".ggml": "ggml",
    ".ggmf": "ggml",
    ".ggjt": "ggml",
    ".ggla": "ggml",
    ".ggsa": "ggml",
    ".ptl": "executorch",
    ".pte": "executorch",
    ".tar": "tar",
    ".tar.gz": "tar",
    ".tgz": "tar",
    ".tar.bz2": "tar",
    ".tbz2": "tar",
    ".tar.xz": "tar",
    ".txz": "tar",
    ".npy": "numpy",
    ".npz": "zip",
    ".joblib": "pickle",  # joblib can be either zip or pickle format
    ".skops": "skops",
    ".pdmodel": "paddle",
    ".pdiparams": "paddle",
    ".params": "mxnet",
    ".engine": "tensorrt",
    ".plan": "tensorrt",
    ".trt": "tensorrt",
    ".msgpack": "flax_msgpack",
    ".nemo": "nemo",
    ".cbm": "catboost",
    ".llamafile": "llamafile",
    ".lgb": "lightgbm",
    ".lightgbm": "lightgbm",
    ".rds": "r_serialized",
    ".rda": "r_serialized",
    ".rdata": "r_serialized",
}


def detect_format_from_extension_pattern_matching(extension: FileExtension) -> FileFormat:
    """Detect format using Python 3.10+ pattern matching for file extensions."""
    # Use pattern matching for more readable extension handling
    match extension.lower():
        # PyTorch/Pickle formats
        case ".pt" | ".pth" | ".ckpt" | ".pkl" | ".pickle" | ".dill":
            return "pickle"
        case ".dnn" | ".cmf":
            return "cntk"
        case ".t7" | ".th" | ".net":
            return "torch7"
        case ".rknn":
            return "rknn"
        # HDF5 formats
        case ".h5" | ".hdf5":
            return "hdf5"
        # Keras format: Keras 3.x uses ZIP, legacy Keras uses HDF5
        case ".keras":
            return "keras"
        # Archive formats
        case ".zip":
            return "zip"
        case ".gz" | ".bz2" | ".xz" | ".lz4" | ".zlib":
            return "compressed"
        case ".mar":
            return "torchserve_mar"
        case ".tar" | ".tar.gz" | ".tgz":
            return "tar"
        # ML model formats
        case ".onnx":
            return "onnx"
        case ".safetensors":
            return "safetensors"
        case ".bin":
            return "pytorch_binary"
        # GGML/GGUF formats
        case ".gguf":
            return "gguf"
        case ".ggml" | ".ggmf" | ".ggjt" | ".ggla" | ".ggsa":
            return "ggml"
        # ExecutorTorch formats
        case ".ptl" | ".pte":
            return "executorch"
        # Other formats
        case ".pb":
            return "protobuf"
        case ".meta":
            return "tf_metagraph"
        case ".tflite":
            return "tflite"
        case ".mlmodel":
            return "coreml"
        case ".engine" | ".plan" | ".trt":
            return "tensorrt"
        case ".pdmodel" | ".pdiparams":
            return "paddle"
        case ".params":
            return "mxnet"
        case ".xml":
            return "openvino"
        case ".pmml":
            return "pmml"
        case ".npy" | ".npz":
            return "numpy"
        case ".skops":
            return "skops"
        case ".msgpack":
            return "flax_msgpack"
        case ".nemo":
            return "nemo"
        case ".cbm":
            return "catboost"
        case ".llamafile":
            return "llamafile"
        case ".lgb" | ".lightgbm":
            return "lightgbm"
        case ".rds" | ".rda" | ".rdata":
            return "r_serialized"
        case ".7z":
            return "sevenzip"
        case _:
            return "unknown"


def detect_format_from_extension(path: FilePath) -> FileFormat:
    """Return a format string based solely on the file extension."""
    file_path = Path(path)
    if file_path.is_dir():
        if (file_path / "saved_model.pb").exists():
            return "tensorflow_directory"
        return "directory"

    filename_lower = file_path.name.lower()
    if filename_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "tar"
    if file_path.suffix.lower() == ".json" and filename_lower.endswith("-symbol.json"):
        return "mxnet"

    # Use pattern matching for modern Python 3.10+ approach
    return detect_format_from_extension_pattern_matching(file_path.suffix)


def validate_file_type(path: str) -> bool:
    """Validate that a file's magic bytes match its extension-based format."""
    try:
        header_format = detect_file_format_from_magic(path)
        ext_format = detect_format_from_extension(path)

        # If extension format is unknown, we can't validate - assume valid
        if ext_format == "unknown":
            return True

        # Small files (< 4 bytes) are always valid - can't determine magic bytes reliably
        file_path = Path(path)
        if file_path.is_file() and file_path.stat().st_size < 4:
            return True

        # Handle special cases where different formats are compatible first
        # before doing the unknown header check

        # Pickle files can be stored in various ways
        if ext_format == "pickle" and header_format in {"pickle", "zip"}:
            return True

        # PyTorch binary files are flexible in format
        if ext_format == "pytorch_binary" and header_format in {
            "pytorch_binary",
            "pickle",
            "zip",
            "unknown",  # .bin files can contain arbitrary binary data
        }:
            return True

        # TensorFlow protobuf files (.pb extension)
        if ext_format == "protobuf" and header_format in {"protobuf", "unknown"}:
            return True

        # TensorFlow MetaGraph files (.meta extension) require strict protobuf validation.
        if ext_format == "tf_metagraph":
            return _is_tensorflow_metagraph_file(path)

        # PMML files are XML-based with <PMML> tag detection
        if ext_format == "pmml" and header_format == "pmml":
            return True

        if ext_format == "torchserve_mar":
            return header_format == "torchserve_mar"

        # ZIP files can have various extensions (.zip, .pt, .pth, .ckpt, .ptl, .pte)
        if header_format == "zip" and ext_format in {
            "zip",
            "pickle",
            "pytorch_binary",
            "executorch",
        }:
            return True

        # TAR files must match
        if ext_format == "tar":
            filename_lower = Path(path).name.lower()
            if filename_lower.endswith((".tar.gz", ".tgz")):
                return header_format in {"tar", "gzip"}
            if filename_lower.endswith((".tar.bz2", ".tbz2")):
                return header_format in {"tar", "bzip2"}
            if filename_lower.endswith((".tar.xz", ".txz")):
                return header_format in {"tar", "xz"}
            return header_format == "tar"

        # Standalone compressed wrappers must match their declared codecs.
        if ext_format == "compressed":
            file_extension = Path(path).suffix.lower()
            expected_codec = _COMPRESSED_EXTENSION_CODECS.get(file_extension)
            if expected_codec is None:
                return False
            return header_format == expected_codec

        # NeMo files are TAR archives with a dedicated extension
        if ext_format == "nemo" and header_format == "tar":
            return True

        # ExecuTorch files may be ZIP archives or valid FlatBuffers binaries.
        if ext_format == "executorch":
            if header_format == "zip":
                return True
            return _is_valid_executorch_binary(path) and not zipfile.is_zipfile(path)

        # Keras files can be either ZIP (Keras 3.x) or HDF5 (legacy Keras)
        if ext_format == "keras":
            return header_format in {"zip", "hdf5"}

        # HDF5 files should always match
        if ext_format == "hdf5":
            return header_format == "hdf5"

        # SafeTensors files should always match
        if ext_format == "safetensors":
            return header_format == "safetensors"

        # GGUF/GGML files should match their format
        if ext_format in {"gguf", "ggml"}:
            return header_format == ext_format

        # ONNX files (Protocol Buffer format - difficult to detect reliably)
        if ext_format == "onnx":
            return header_format in {"onnx", "unknown"}

        # NumPy files (.npy should match, .npz is ZIP by design)
        if ext_format == "numpy":
            # .npz files are ZIP archives containing multiple .npy files
            # This is the standard NumPy compressed format, not spoofing
            # Use case-insensitive suffix check to handle MODEL.NPZ, model.Npz, etc.
            file_path = Path(path)
            if file_path.suffix.lower() == ".npz":
                return header_format in {"zip", "numpy"}
            return header_format == "numpy"

        # skops files are ZIP containers by design.
        if ext_format == "skops":
            return header_format in {"skops", "zip"}

        # PaddlePaddle files: .pdmodel files are protobuf serialised program
        # descriptors and .pdiparams files are raw binary weight tensors.
        # Neither format has distinctive magic bytes, so magic-based
        # detection legitimately returns "unknown".  Accept that.
        if ext_format == "paddle":
            return True

        # Flax msgpack files (less strict validation)
        if ext_format == "flax_msgpack":
            return True  # Hard to validate msgpack format reliably

        # TensorFlow directories are special case
        if ext_format == "tensorflow_directory":
            return header_format == "tensorflow_directory"

        # TensorFlow Lite files
        if ext_format == "tflite":
            return True  # TFLite format can be complex to validate

        if ext_format == "tensorrt":
            return True  # TensorRT engine files have complex binary format

        # CatBoost native .cbm files are expected to have CBM1 header.
        if ext_format == "catboost":
            return header_format == "catboost"

        # CNTK .dnn/.cmf signatures are marker-based and validated via bounded reads.
        if ext_format == "cntk":
            cntk_prefix = read_magic_bytes(path, _CNTK_SIGNATURE_READ_BYTES)
            return _is_cntk_signature(cntk_prefix)

        # RKNN files require RKNN signature bytes.
        if ext_format == "rknn":
            return header_format == "rknn"

        if ext_format == "torch7":
            torch7_prefix = read_magic_bytes(path, _TORCH7_SIGNATURE_READ_BYTES)
            return _is_torch7_signature(torch7_prefix)

        # LightGBM native formats are validated with strict marker heuristics.
        if ext_format == "lightgbm":
            lightgbm_prefix = read_magic_bytes(path, _LIGHTGBM_SIGNATURE_READ_BYTES)
            return _is_lightgbm_signature(lightgbm_prefix)

        # Llamafiles are executable wrappers; scanner-level checks validate markers.
        if ext_format == "llamafile":
            return True

        # MXNet params and symbol JSON artifacts rely on strict scanner-level
        # structural checks rather than magic-byte signatures.
        if ext_format == "mxnet":
            return True

        # CoreML .mlmodel files are protobuf-encoded with no stable magic bytes.
        # Structural validation is performed by the dedicated scanner.
        if ext_format == "coreml":
            return header_format in {"coreml", "unknown"}

        # R serialized workspace/data files may be uncompressed or wrapped;
        # extension-based intent is authoritative for static scanning.
        if ext_format == "r_serialized":
            if header_format == "r_serialized":
                return True
            return True

        # If header format is unknown but extension is known, this might be suspicious
        # unless the file is very small or empty (checked after format-specific rules)
        if header_format == "unknown":
            file_path = Path(path)
            return not (file_path.is_file() and file_path.stat().st_size >= 4)  # Small files are acceptable

        # Default: exact match required
        return header_format == ext_format

    except Exception:
        # If validation fails due to error, assume valid to avoid breaking scans
        return True
