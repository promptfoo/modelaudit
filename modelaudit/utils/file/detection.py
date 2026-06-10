import json
import pickletools
import posixpath
import re
import struct
import tarfile
import zipfile
from io import BytesIO, StringIO
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Literal

from ...scanner_registry_metadata import get_extension_format_map, get_registered_scanner_extensions
from ..helpers.types import FileExtension, FileFormat, FilePath, MagicBytes
from ._compression import is_zlib_header
from .hdf5 import find_hdf5_signature_offset

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
_TF_METAGRAPH_MAX_ROUTING_PAYLOAD_BYTES = _TF_METAGRAPH_MAX_VALIDATE_BYTES
_TF_METAGRAPH_MAX_ROUTING_FIELDS = 32768
_TF_METAGRAPH_MAX_ROUTING_DEPTH = 64
_CONTENT_ROUTE_PRINTABLE_TEXT_FAST_PATH_BYTES = 2 * 1024 * 1024
_CONTENT_ROUTE_PRINTABLE_TEXT_BYTES = b"\t\n\r" + bytes(range(0x20, 0x7F))
_CONTENT_ROUTE_NON_SOURCE_CONTROL_BYTES = (
    bytes(byte for byte in range(0x20) if byte not in {0x09, 0x0A, 0x0C, 0x0D}) + b"\x7f"
)
_TensorFlowProtoRoute = Literal[
    "unknown",
    "tf_metagraph",
    "tf_savedmodel",
    "oversized",
    "oversized_candidate",
    "inconclusive",
]
_TensorFlowOuterHint = Literal["unknown", "tf_metagraph", "tf_savedmodel"]
_TORCH7_SIGNATURE_READ_BYTES = 4096
_TORCH7_ASCII_HEADER_MAX_LINE_BYTES = 4096
_LIGHTGBM_SIGNATURE_READ_BYTES = 8192
_ONNX_MODEL_MAX_ROUTING_FIELDS = 4096
_ONNX_GRAPH_MAX_ROUTING_FIELDS = 4096
_ONNX_NODE_MAX_ROUTING_FIELDS = 512
_ONNX_MAX_ROUTING_TEXT_BYTES = 1024
_ONNX_MODEL_FIELD_WIRE_TYPES = {
    1: 0,
    2: 2,
    3: 2,
    4: 2,
    5: 0,
    6: 2,
    7: 2,
    8: 2,
    14: 2,
    20: 2,
    25: 2,
    26: 2,
}
_PROTO_GROUP_MAX_ROUTING_FIELDS = 512
_PROTO_GROUP_MAX_ROUTING_DEPTH = 8
_COREML_PROTO_SIGNATURE_READ_BYTES = 1024 * 1024
_COREML_PROTO_PREFIX_WIRE_TYPES = frozenset({0, 1, 2, 3, 5})
_COREML_GROUP_BUDGET_EXHAUSTED: Literal["budget_exhausted"] = "budget_exhausted"
_COREML_GROUP_INCOMPLETE: Literal["incomplete"] = "incomplete"
_COREML_GROUP_MALFORMED: Literal["malformed"] = "malformed"
_COREML_MAX_DESCRIPTION_PREFIX_FIELDS = 512
_COREML_MAX_MODEL_PREFIX_FIELDS = 4096
_COREML_MODEL_TYPE_FIELDS = frozenset(
    {
        200,
        201,
        202,
        300,
        301,
        302,
        303,
        304,
        400,
        401,
        402,
        403,
        404,
        500,
        501,
        502,
        555,
        556,
        560,
        600,
        601,
        602,
        603,
        604,
        606,
        607,
        609,
        610,
        900,
        2000,
        2001,
        2002,
        2003,
        2004,
        2005,
        2006,
        3000,
    }
)
_COREML_DESCRIPTION_FIELD_HINTS = frozenset({1, 10, 20, 21, 100})
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
_RAR4_MAGIC = b"Rar!\x1a\x07\x00"
_RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
_LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"
_ZIP_MAGIC_SIGNATURES = (
    b"PK\x03\x04",  # local file header
    b"PK\x01\x02",  # central directory file header
    b"PK\x05\x06",  # end of central directory
    b"PK\x06\x06",  # ZIP64 end of central directory
    b"PK\x06\x07",  # ZIP64 end of central directory locator
    b"PK\x07\x08",  # data descriptor
)
_TAR_BLOCK_SIZE = 512
_TAR_USTAR_OFFSET = 257
_TAR_USTAR_MAGIC_SIZE = 5
_TAR_USTAR_MIN_BYTES = _TAR_USTAR_OFFSET + _TAR_USTAR_MAGIC_SIZE
_TAR_CHECKSUM_OFFSET = 148
_TAR_CHECKSUM_SIZE = 8
_TAR_NUMERIC_FIELD_SLICES = (
    (100, 108),  # mode
    (108, 116),  # uid
    (116, 124),  # gid
    (124, 136),  # size
    (136, 148),  # mtime
)
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_SIZE = 4
_TFLITE_MIN_HEADER_SIZE = _TFLITE_MAGIC_OFFSET + _TFLITE_MAGIC_SIZE
_TFLITE_MAGIC_BYTES = b"TFL3"
LLAMAFILE_MARKER = b"llamafile"
LLAMAFILE_ROUTE_SCAN_BYTES = 8 * 1024 * 1024
LLAMAFILE_ROUTE_TAIL_SCAN_BYTES = 2 * 1024 * 1024
_LLAMAFILE_EXECUTABLE_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)
_LLAMAFILE_ROUTE_CHUNK_BYTES = 1024 * 1024
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
_NEMO_CONFIG_ENTRIES = frozenset({"model_config.yaml", "model_config.yml"})
_NEMO_ROUTE_MAX_ENTRIES = 10_000
_NEMO_ROUTE_MAX_LINK_RESOLUTION_VISITS = 100_000
_PYTORCH_ZIP_METADATA_MAX_BYTES = 64
_SKOPS_SCHEMA_ENTRIES = frozenset({"schema", "schema.json"})
_SKOPS_SCHEMA_MAX_BYTES = 4 * 1024 * 1024
_XML_MODEL_SIGNATURE_READ_BYTES = 1024 * 1024
_XML_MODEL_ROOT_FORMATS = {
    "model": "openvino",
    "net": "openvino",
    "pmml": "pmml",
}
XML_MODEL_INCONCLUSIVE_FORMAT = "xml_model_inconclusive"
PROTOBUF_MODEL_CANDIDATE_FORMAT = "protobuf_model_candidate"
JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES = 1024 * 1024
JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES = 2 * JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES
_JAX_JSON_CHECKPOINT_IDENTITY_KEYS = frozenset(
    {"framework", "library", "backend", "serialization", "format", "type", "checkpoint_type"}
)
_JAX_JSON_CHECKPOINT_MARKER_KEYS = frozenset({"orbax_version", "__orbax_metadata__"})
_JAX_JSON_CHECKPOINT_SCANNER_SUFFIXES = frozenset({".ckpt", ".checkpoint", ".orbax-checkpoint", ".pickle"})
_JAX_JSON_CHECKPOINT_CONTENT_ROUTE_EXCLUDED_SUFFIXES = frozenset({".json", ".py", ".pyw"})
_JAX_JSON_CHECKPOINT_DECLARED_SUFFIXES = frozenset(get_registered_scanner_extensions())
_JAX_JSON_CHECKPOINT_IDENTITY_RE = re.compile(
    r"(?<![a-z0-9])(?:jax|flax|haiku|orbax|jaxlib|arrayimpl|device_array)(?![a-z0-9])",
    re.IGNORECASE,
)
_STRUCTURED_JSON_TRAILING_READ_BYTES = 64 * 1024
FLAX_MSGPACK_STRUCTURE_READ_BYTES = 1024 * 1024
_FLAX_MSGPACK_ROUTING_KEYS = frozenset({"params", "opt_state", "model_state"})
_FLAX_MSGPACK_STATE_WRAPPER_KEY = "state"
_FLAX_MSGPACK_SCANNER_SUFFIXES = frozenset({".msgpack", ".flax", ".orbax", ".jax"})
_FLAX_MSGPACK_OVERLAP_SUFFIXES = frozenset({".ckpt", ".checkpoint", ".orbax-checkpoint"})
_FLAX_MSGPACK_CONTENT_ROUTE_EXCLUDED_SUFFIXES = frozenset({".py", ".pyw"})
_FLAX_MSGPACK_CONTENT_ROUTE_ALLOWED_DECLARED_SUFFIXES = frozenset(
    {".txt", ".md", ".markdown", ".rst", ".ini", ".cfg", ".toml"}
)
_FLAX_MSGPACK_DECLARED_SUFFIXES = frozenset(get_registered_scanner_extensions())
_FLAX_MSGPACK_NATIVE_SUFFIXES = _FLAX_MSGPACK_SCANNER_SUFFIXES
_FLAX_MSGPACK_PROBE_MAX_NODES = 4096
_FLAX_MSGPACK_PROBE_MAX_DEPTH = 32
_FLAX_MSGPACK_PROBE_MAX_KEY_BYTES = 64
# Keep cheap top-level padding bounded without treating ordinary 1 MiB data
# as an incomplete nested structure walk.
_FLAX_MSGPACK_PROBE_MAX_INLINE_SCALARS = FLAX_MSGPACK_STRUCTURE_READ_BYTES
_FLAX_MSGPACK_PROBE_SCALAR_SIZES = {
    0xCA: 4,
    0xCB: 8,
    0xCC: 1,
    0xCD: 2,
    0xCE: 4,
    0xCF: 8,
    0xD0: 1,
    0xD1: 2,
    0xD2: 4,
    0xD3: 8,
    0xD4: 2,
    0xD5: 3,
    0xD6: 5,
    0xD7: 9,
    0xD8: 17,
}
_FLAX_MSGPACK_PROBE_LENGTH_SIZES = {
    0xC4: (1, 0),
    0xC5: (2, 0),
    0xC6: (4, 0),
    0xC7: (1, 1),
    0xC8: (2, 1),
    0xC9: (4, 1),
    0xD9: (1, 0),
    0xDA: (2, 0),
    0xDB: (4, 0),
}
MXNET_SYMBOL_SIGNATURE_READ_BYTES = 10 * 1024 * 1024
MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT = "mxnet_symbol_routing_inconclusive"
_UTF8_BOM = b"\xef\xbb\xbf"
_JSON_NUMBER_PREFIX_RE = re.compile(rb"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_MXNET_SYMBOL_PREFIX_MAX_VALUES = 4096
_MXNET_SYMBOL_MAX_KEY_BYTES = 64
_MXNET_SYMBOL_ROOT_KEYS = frozenset({"nodes", "arg_nodes", "heads"})
_MXNET_SYMBOL_STREAM_CHUNK_BYTES = 64 * 1024
LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT = "llamafile_routing_inconclusive"
NEMO_ROUTING_INCONCLUSIVE_FORMAT = "nemo_routing_inconclusive"
XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT = "xgboost_ubjson_routing_inconclusive"
ONNX_ROUTING_INCONCLUSIVE_FORMAT = "onnx_routing_inconclusive"
TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT = "tensorflow_protobuf_routing_inconclusive"
PICKLE_ROUTING_INCONCLUSIVE_FORMAT = "pickle_routing_inconclusive"
EXECUTABLE_ZIP_POLYGLOT_FORMAT = "executable_zip_polyglot"
_XGBOOST_UBJSON_ROUTE_READ_BYTES = 256 * 1024
_COMPRESSED_EXTENSION_CODECS = {
    ".gz": "gzip",
    ".bz2": "bzip2",
    ".xz": "xz",
    ".lz4": "lz4",
    ".zlib": "zlib",
}


def _is_supported_llamafile_executable_header(header: bytes) -> bool:
    return header.startswith((b"\x7fELF", b"MZ")) or header[:4] in _LLAMAFILE_EXECUTABLE_MAGICS


def _contains_casefolded_marker_in_prefix(path: Path, marker: bytes, max_scan_bytes: int) -> bool:
    """Search for a case-insensitive marker within a bounded file prefix."""
    marker = marker.lower()
    overlap = len(marker) - 1
    remaining = min(path.stat().st_size, max_scan_bytes)
    carry = b""

    with path.open("rb") as handle:
        while remaining > 0:
            chunk = handle.read(min(_LLAMAFILE_ROUTE_CHUNK_BYTES, remaining))
            if not chunk:
                break
            haystack = carry + chunk.lower()
            if marker in haystack:
                return True
            carry = haystack[-overlap:] if overlap > 0 else b""
            remaining -= len(chunk)

    return False


def is_llamafile_executable(
    path: str | Path,
    header: bytes | None = None,
    *,
    raise_on_error: bool = False,
) -> bool:
    """Recognize an executable Llamafile using bounded content inspection."""
    file_path = Path(path)
    try:
        if header is None:
            if not file_path.is_file():
                return False
            with file_path.open("rb") as handle:
                header = handle.read(4)
        if not _is_supported_llamafile_executable_header(header):
            return False
        if _contains_casefolded_marker_in_prefix(file_path, LLAMAFILE_MARKER, LLAMAFILE_ROUTE_SCAN_BYTES):
            return True
        size = file_path.stat().st_size
        if size <= LLAMAFILE_ROUTE_SCAN_BYTES:
            return False
        with file_path.open("rb") as handle:
            handle.seek(size - LLAMAFILE_ROUTE_TAIL_SCAN_BYTES)
            return LLAMAFILE_MARKER in handle.read(LLAMAFILE_ROUTE_TAIL_SCAN_BYTES).lower()
    except OSError:
        if raise_on_error:
            raise
        return False


def _detect_llamafile_route_format(path: Path, header: bytes) -> str | None:
    """Return a Llamafile route or an explicit incomplete-routing outcome."""
    if not _is_supported_llamafile_executable_header(header):
        return None
    try:
        if is_llamafile_executable(path, header, raise_on_error=True):
            return "llamafile"
    except OSError:
        return LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT
    if zipfile.is_zipfile(path):
        return EXECUTABLE_ZIP_POLYGLOT_FORMAT
    return None


def _has_rar_magic(data: bytes) -> bool:
    """Return True for complete RAR4/RAR5 signatures."""
    return data.startswith(_RAR4_MAGIC) or data.startswith(_RAR5_MAGIC)


def _skip_xml_doctype_declaration(xml_prefix: bytes, start_offset: int) -> int | None:
    """Skip a DOCTYPE declaration without expanding entities."""
    index = start_offset + len(b"<!DOCTYPE")
    bracket_depth = 0
    quote_char: int | None = None

    while index < len(xml_prefix):
        byte = xml_prefix[index]
        if quote_char is not None:
            if byte == quote_char:
                quote_char = None
        elif byte in {ord("'"), ord('"')}:
            quote_char = byte
        elif byte == ord("["):
            bracket_depth += 1
        elif byte == ord("]") and bracket_depth > 0:
            bracket_depth -= 1
        elif byte == ord(">") and bracket_depth == 0:
            return index + 1
        index += 1
    return None


def _xml_root_tag_from_prefix(xml_prefix: bytes) -> tuple[str | None, bool]:
    """Return the normalized first XML element name and whether the probe ran out first."""
    index = 3 if xml_prefix.startswith(b"\xef\xbb\xbf") else 0
    prefix_length = len(xml_prefix)

    while index < prefix_length:
        while index < prefix_length and chr(xml_prefix[index]).isspace():
            index += 1

        if xml_prefix.startswith(b"<?", index):
            end_offset = xml_prefix.find(b"?>", index + 2)
            if end_offset == -1:
                return None, True
            index = end_offset + 2
            continue

        if xml_prefix.startswith(b"<!--", index):
            end_offset = xml_prefix.find(b"-->", index + 4)
            if end_offset == -1:
                return None, True
            index = end_offset + 3
            continue

        if xml_prefix[index : index + len(b"<!DOCTYPE")].upper() == b"<!DOCTYPE":
            next_index = _skip_xml_doctype_declaration(xml_prefix, index)
            if next_index is None:
                return None, True
            index = next_index
            continue

        break

    if index >= prefix_length:
        return None, True
    if xml_prefix[index : index + 1] != b"<":
        return None, False
    if xml_prefix[index + 1 : index + 2] in {b"/", b"!", b"?"}:
        return None, False

    tag_end = index + 1
    while tag_end < prefix_length and xml_prefix[tag_end : tag_end + 1] not in b" \t\r\n\f/>":
        tag_end += 1
    if tag_end == index + 1:
        return None, tag_end >= prefix_length
    if tag_end >= prefix_length:
        return None, True

    raw_tag = xml_prefix[index + 1 : tag_end].decode("utf-8", "ignore")
    return raw_tag.rsplit(":", 1)[-1].lower(), False


def _detect_xml_model_format(xml_prefix: bytes, *, sample_is_prefix: bool) -> str:
    """Return a model format for recognized XML roots within a bounded prefix."""
    root_tag, prefix_exhausted_before_root = _xml_root_tag_from_prefix(xml_prefix)
    if prefix_exhausted_before_root and sample_is_prefix:
        return XML_MODEL_INCONCLUSIVE_FORMAT
    if root_tag is None:
        return "unknown"
    return _XML_MODEL_ROOT_FORMATS.get(root_tag, "unknown")


def _could_be_xml_prefix(prefix: bytes) -> bool:
    """Return whether a bounded prefix plausibly begins an XML document."""
    trimmed = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    return trimmed.lstrip().startswith(b"<")


def has_mxnet_symbol_graph_structure(payload: object) -> bool:
    """Return whether decoded JSON has the minimum MXNet symbol graph contract."""
    if not isinstance(payload, dict):
        return False

    nodes = payload.get("nodes")
    arg_nodes = payload.get("arg_nodes")
    heads = payload.get("heads")
    if not isinstance(nodes, list) or not isinstance(arg_nodes, list) or not isinstance(heads, list):
        return False
    if not nodes:
        return False

    return any(
        isinstance(node, dict) and isinstance(node.get("op"), str) and isinstance(node.get("name"), str)
        for node in nodes
    )


def inspect_mxnet_symbol_root_keys(handle: BinaryIO) -> set[str]:
    """Return duplicate MXNet graph root keys using constant parser state."""
    seen: set[str] = set()
    duplicates: set[str] = set()
    started = False
    depth = 0
    in_string = False
    escaped = False
    collecting_key = False
    key_overflow = False
    raw_key = bytearray()
    expecting_key = False
    decoder = json.JSONDecoder()

    initial = handle.read(3)
    if initial != b"\xef\xbb\xbf":
        handle.seek(0)

    while chunk := handle.read(_MXNET_SYMBOL_STREAM_CHUNK_BYTES):
        for byte in chunk:
            if in_string:
                if collecting_key:
                    if len(raw_key) < _MXNET_SYMBOL_MAX_KEY_BYTES:
                        raw_key.append(byte)
                    else:
                        key_overflow = True

                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    in_string = False
                    if collecting_key:
                        if not key_overflow:
                            try:
                                key = decoder.decode(raw_key.decode("utf-8"))
                            except (UnicodeDecodeError, json.JSONDecodeError):
                                key = None
                            if key in _MXNET_SYMBOL_ROOT_KEYS:
                                if key in seen:
                                    duplicates.add(key)
                                seen.add(key)
                        collecting_key = False
                        key_overflow = False
                        expecting_key = False
                continue

            if not started:
                if byte in b" \t\r\n":
                    continue
                if byte != ord("{"):
                    return set()
                started = True
                depth = 1
                expecting_key = True
                continue

            if byte == ord('"'):
                if depth == 1 and expecting_key:
                    collecting_key = True
                    raw_key = bytearray(b'"')
                in_string = True
                escaped = False
                continue

            if byte in {ord("{"), ord("[")}:
                depth += 1
            elif byte == ord("}") and depth == 1:
                return duplicates if seen >= _MXNET_SYMBOL_ROOT_KEYS else set()
            elif byte in {ord("}"), ord("]")}:
                if depth > 1:
                    depth -= 1
                else:
                    return set()
            elif byte == ord(",") and depth == 1:
                expecting_key = True

    return duplicates if seen >= _MXNET_SYMBOL_ROOT_KEYS else set()


def _detect_mxnet_symbol_prefix_route(
    prefix: bytes,
    *,
    sample_is_prefix: bool = True,
    fail_closed_without_hint: bool = False,
    enforce_value_budget: bool = True,
) -> str | None:
    """Return a definite or bounded-inconclusive MXNet JSON route."""

    class IncompleteJSON(Exception):
        pass

    class BoundedJSON(Exception):
        pass

    class ValueBudgetExceeded(Exception):
        pass

    class InvalidJSON(Exception):
        pass

    root_array_keys: set[str] = set()
    saw_root_nodes_key = False
    saw_mxnet_heads_shape = False
    saw_direct_node_object = False
    saw_direct_node_contract = False
    parsed_values = 0

    def saw_mxnet_routing_hint() -> bool:
        visible_graph_arrays = root_array_keys & {"nodes", "arg_nodes", "heads"}
        return (
            saw_root_nodes_key
            or saw_mxnet_heads_shape
            or saw_direct_node_object
            or saw_direct_node_contract
            or len(visible_graph_arrays) >= 2
        )

    def skip_whitespace(offset: int) -> int:
        while offset < len(prefix) and prefix[offset] in b" \t\r\n":
            offset += 1
        return offset

    def skip_string(offset: int) -> int:
        if offset >= len(prefix) or prefix[offset] != ord('"'):
            raise InvalidJSON
        index = offset + 1
        while index < len(prefix):
            marker = prefix[index]
            if marker == ord('"'):
                return index + 1
            if marker == ord("\\"):
                index += 1
                if index >= len(prefix):
                    raise IncompleteJSON
            index += 1
        raise IncompleteJSON

    def read_key(offset: int) -> tuple[str | None, int]:
        end_offset = skip_string(offset)
        if end_offset - offset > _MXNET_SYMBOL_MAX_KEY_BYTES:
            return None, end_offset
        try:
            value = json.JSONDecoder().decode(prefix[offset:end_offset].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidJSON from exc
        return (value if isinstance(value, str) else None), end_offset

    def has_mxnet_heads_shape(offset: int) -> bool:
        """Recognize a visible numeric MXNet output triplet."""
        offset = skip_whitespace(offset + 1)
        if offset >= len(prefix) or prefix[offset] != ord("["):
            return False
        offset = skip_whitespace(offset + 1)
        for position in range(3):
            number_match = _JSON_NUMBER_PREFIX_RE.match(prefix, offset)
            if number_match is None:
                return False
            token = prefix[offset : number_match.end()]
            if b"." in token or b"e" in token.lower():
                return False
            offset = skip_whitespace(number_match.end())
            expected = ord("]") if position == 2 else ord(",")
            if offset >= len(prefix) or prefix[offset] != expected:
                return False
            offset = skip_whitespace(offset + 1)
        return True

    def parse_value(offset: int, depth: int, *, root_array_key: str | None = None) -> int:
        nonlocal parsed_values, saw_mxnet_heads_shape
        parsed_values += 1
        if enforce_value_budget and parsed_values > _MXNET_SYMBOL_PREFIX_MAX_VALUES:
            raise ValueBudgetExceeded
        offset = skip_whitespace(offset)
        if offset >= len(prefix):
            raise IncompleteJSON
        marker = prefix[offset]
        if marker == ord("{"):
            return parse_object(offset, depth + 1)
        if marker == ord("["):
            if root_array_key in {"nodes", "arg_nodes", "heads"}:
                root_array_keys.add(root_array_key)
            if root_array_key == "heads" and has_mxnet_heads_shape(offset):
                saw_mxnet_heads_shape = True
            return parse_array(offset, depth + 1, nodes_array=root_array_key == "nodes")
        if marker == ord('"'):
            return skip_string(offset)
        for literal in (b"true", b"false", b"null", b"NaN", b"Infinity", b"-Infinity"):
            if prefix.startswith(literal, offset):
                return offset + len(literal)
            if literal.startswith(prefix[offset:]):
                raise IncompleteJSON
        if offset + 1 == len(prefix) and prefix[offset] == ord("-"):
            raise IncompleteJSON
        number_match = _JSON_NUMBER_PREFIX_RE.match(prefix, offset)
        if number_match is None:
            raise InvalidJSON
        remainder_length = len(prefix) - number_match.end()
        if remainder_length in {1, 2} and prefix[number_match.end() :] in {
            b".",
            b"e",
            b"E",
            b"e+",
            b"e-",
            b"E+",
            b"E-",
        }:
            raise IncompleteJSON
        return number_match.end()

    def parse_array(offset: int, depth: int, *, nodes_array: bool = False) -> int:
        nonlocal saw_direct_node_object
        if depth > 64:
            raise BoundedJSON
        offset = skip_whitespace(offset + 1)
        if offset >= len(prefix):
            raise IncompleteJSON
        if prefix[offset] == ord("]"):
            return offset + 1
        while True:
            if nodes_array and prefix[offset] == ord("{"):
                saw_direct_node_object = True
                offset = parse_object(offset, depth + 1, direct_node=True)
            else:
                offset = parse_value(offset, depth + 1)
            offset = skip_whitespace(offset)
            if offset >= len(prefix):
                raise IncompleteJSON
            if prefix[offset] == ord("]"):
                return offset + 1
            if prefix[offset] != ord(","):
                raise InvalidJSON
            offset = skip_whitespace(offset + 1)
            if offset >= len(prefix):
                raise IncompleteJSON

    def parse_object(offset: int, depth: int, *, root: bool = False, direct_node: bool = False) -> int:
        nonlocal saw_direct_node_contract, saw_root_nodes_key
        if depth > 64:
            raise BoundedJSON
        direct_node_string_keys: set[str] = set()
        offset = skip_whitespace(offset + 1)
        if offset >= len(prefix):
            raise IncompleteJSON
        if prefix[offset] == ord("}"):
            return offset + 1
        while True:
            key, offset = read_key(offset)
            offset = skip_whitespace(offset)
            if offset >= len(prefix):
                raise IncompleteJSON
            if prefix[offset] != ord(":"):
                raise InvalidJSON
            if root and key == "nodes":
                saw_root_nodes_key = True
            value_offset = skip_whitespace(offset + 1)
            offset = parse_value(
                value_offset,
                depth + 1,
                root_array_key=key if root and key is not None else None,
            )
            if direct_node and key in {"op", "name"} and prefix[value_offset] == ord('"'):
                direct_node_string_keys.add(key)
                if {"op", "name"} <= direct_node_string_keys:
                    saw_direct_node_contract = True
            offset = skip_whitespace(offset)
            if offset >= len(prefix):
                raise IncompleteJSON
            if prefix[offset] == ord("}"):
                return offset + 1
            if prefix[offset] != ord(","):
                raise InvalidJSON
            offset = skip_whitespace(offset + 1)
            if offset >= len(prefix):
                raise IncompleteJSON

    try:
        root_offset = skip_whitespace(0)
        if root_offset >= len(prefix):
            return MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT if sample_is_prefix and fail_closed_without_hint else None
        if prefix[root_offset] != ord("{"):
            return None
        parse_object(root_offset, 0, root=True)
    except IncompleteJSON:
        if {"nodes", "arg_nodes", "heads"} <= root_array_keys and saw_direct_node_contract:
            return "mxnet"
        if saw_mxnet_routing_hint():
            return MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
        if not sample_is_prefix:
            return None
        return MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT if fail_closed_without_hint else None
    except ValueBudgetExceeded:
        if {"nodes", "arg_nodes", "heads"} <= root_array_keys and saw_direct_node_contract:
            return "mxnet"
        if not sample_is_prefix and not fail_closed_without_hint:
            # Resolve a graph hidden behind scalar padding with parser state only;
            # the byte and nesting limits still bound this second traversal.
            rescanned_route = _detect_mxnet_symbol_prefix_route(
                prefix,
                sample_is_prefix=False,
                fail_closed_without_hint=False,
                enforce_value_budget=False,
            )
            if rescanned_route == "mxnet" and inspect_mxnet_symbol_root_keys(BytesIO(prefix)):
                return MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
            return rescanned_route
        return (
            MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT if saw_mxnet_routing_hint() or fail_closed_without_hint else None
        )
    except BoundedJSON:
        if {"nodes", "arg_nodes", "heads"} <= root_array_keys and saw_direct_node_contract:
            return "mxnet"
        if not sample_is_prefix:
            return MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
        return (
            MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT if saw_mxnet_routing_hint() or fail_closed_without_hint else None
        )
    except InvalidJSON:
        if {"nodes", "arg_nodes", "heads"} <= root_array_keys and saw_direct_node_contract:
            return "mxnet"
        if saw_mxnet_routing_hint():
            return MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
        return None

    if {"nodes", "arg_nodes", "heads"} <= root_array_keys and saw_direct_node_contract:
        return "mxnet"
    return None


def detect_mxnet_symbol_content_route(path: str | Path) -> str | None:
    """Return a definite or bounded-inconclusive JSON MXNet symbol route.

    JSON objects with visible MXNet-specific root keys or a symbol node
    contract that do not resolve within the bounded probe remain inconclusive.
    Complete generic JSON without MXNet evidence remains with its established
    filename owner; oversized unresolved JSON cannot safely rule out a hidden
    graph and therefore fails closed.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return None

    try:
        file_size = file_path.stat().st_size
        if file_size < 4:
            return None

        read_size = min(file_size, MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1)
        with file_path.open("rb") as handle:
            prefix = handle.read(read_size)
            normalized_prefix = prefix[len(_UTF8_BOM) :] if prefix.startswith(_UTF8_BOM) else prefix
            trimmed_prefix = normalized_prefix.lstrip()
            if trimmed_prefix and not trimmed_prefix.startswith(b"{"):
                return None
    except OSError:
        return None

    is_disguised_non_json = file_path.suffix.lower() != ".json"
    prefix = prefix[len(_UTF8_BOM) :] if prefix.startswith(_UTF8_BOM) else prefix
    if file_size > MXNET_SYMBOL_SIGNATURE_READ_BYTES:
        return _detect_mxnet_symbol_prefix_route(
            prefix[:MXNET_SYMBOL_SIGNATURE_READ_BYTES],
            fail_closed_without_hint=True,
        )

    return _detect_mxnet_symbol_prefix_route(
        prefix,
        sample_is_prefix=False,
        fail_closed_without_hint=is_disguised_non_json,
    )


def is_mxnet_symbol_graph_file(path: str | Path) -> bool:
    """Return whether bounded content conclusively identifies an MXNet graph."""
    return detect_mxnet_symbol_content_route(path) == "mxnet"


def _could_be_renamed_mxnet_symbol(file_path: Path, prefix: bytes) -> bool:
    """Return whether content-based MXNet routing is needed for this path."""
    prefix = prefix[len(_UTF8_BOM) :] if prefix.startswith(_UTF8_BOM) else prefix
    trimmed_prefix = prefix.lstrip()
    return bool(file_path.name) and (trimmed_prefix.startswith(b"{") or not trimmed_prefix)


def _detect_content_routed_mxnet_symbol(file_path: Path, prefix: bytes) -> str | None:
    """Route plausible JSON symbol content or preserve bounded ambiguity."""
    if file_path.name.lower().endswith("-symbol.json"):
        # Canonical symbol names already belong to MXNetScanner; do not let a
        # discovery budget prevent its bounded fail-closed analysis from running.
        return None
    if not _could_be_renamed_mxnet_symbol(file_path, prefix):
        return None
    mxnet_route = detect_mxnet_symbol_content_route(file_path)
    if file_path.suffix.lower() != ".json":
        try:
            is_oversized_candidate = file_path.stat().st_size > MXNET_SYMBOL_SIGNATURE_READ_BYTES
        except OSError:
            return mxnet_route
        if mxnet_route != "mxnet" or is_oversized_candidate:
            return mxnet_route

    # Structurally overlapping JSON must be scanned as XGBoost so its full JSON
    # checks run; the scanner then marks MXNet overlap as incomplete coverage.
    from ...scanners.xgboost_scanner import XGBoostScanner

    xgboost_probe_bytes = None if file_path.suffix.lower() == ".json" else MXNET_SYMBOL_SIGNATURE_READ_BYTES
    if XGBoostScanner._is_xgboost_json(str(file_path), max_bytes=xgboost_probe_bytes):
        return "xgboost"
    if (
        file_path.suffix.lower() == ".json" or mxnet_route == "mxnet"
    ) and XGBoostScanner._is_probable_mxnet_overlap_candidate(str(file_path), max_bytes=xgboost_probe_bytes):
        return "xgboost"
    return mxnet_route


_MIN_BINARY_PICKLE_PROTOCOL = 1
_MAX_FORWARD_COMPAT_BINARY_PICKLE_PROTOCOL = 6

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
PROTO0_1_START_BYTES: bytes = b"()]}cilp0FGIJKLMNPSTUVX"
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
_BINARY_PICKLE_SECURITY_OPCODES: frozenset[str] = frozenset(
    {
        "BINPERSID",
        "BUILD",
        "EXT1",
        "EXT2",
        "EXT4",
        "GLOBAL",
        "INST",
        "NEWOBJ",
        "NEWOBJ_EX",
        "OBJ",
        "PERSID",
        "REDUCE",
        "STACK_GLOBAL",
    }
)
_BINARY_PICKLE_PRE_STOP_SECURITY_OPCODES: frozenset[str] = frozenset(
    {
        "BINPERSID",
        "EXT1",
        "EXT2",
        "EXT4",
        "GLOBAL",
        "INST",
        "OBJ",
        "PERSID",
        "REDUCE",
        "STACK_GLOBAL",
    }
)
_PROTOCOLLESS_BINARY_PICKLE_OPCODES: frozenset[str] = frozenset(
    {
        "ADDITEMS",
        "BINBYTES",
        "BINBYTES8",
        "BINFLOAT",
        "BINGET",
        "BININT",
        "BININT1",
        "BININT2",
        "BINPERSID",
        "BINSTRING",
        "BINUNICODE",
        "BINUNICODE8",
        "BYTEARRAY8",
        "EMPTY_SET",
        "EXT1",
        "EXT2",
        "EXT4",
        "FRAME",
        "FROZENSET",
        "LONG1",
        "LONG4",
        "LONG_BINGET",
        "LONG_BINPUT",
        "MEMOIZE",
        "NEWFALSE",
        "NEWOBJ",
        "NEWOBJ_EX",
        "NEWTRUE",
        "NEXT_BUFFER",
        "READONLY_BUFFER",
        "SHORT_BINBYTES",
        "SHORT_BINSTRING",
        "SHORT_BINUNICODE",
        "STACK_GLOBAL",
        "TUPLE1",
        "TUPLE2",
        "TUPLE3",
    }
)
_PROTOCOLLESS_BINARY_PICKLE_PRE_STOP_SECURITY_OPCODES = _BINARY_PICKLE_PRE_STOP_SECURITY_OPCODES.difference(
    {"EXT1", "EXT2", "EXT4"}
)
_PICKLE_OPCODE_BY_BYTE = {ord(opcode.code): opcode for opcode in pickletools.opcodes}
_PICKLE_LINE_PAIR_OPCODES: frozenset[str] = frozenset({"GLOBAL", "INST"})
_PICKLE_VARIABLE_LENGTH_HEADER_BYTES: dict[int, int] = {-2: 1, -3: 4, -4: 4, -5: 8}


def _read_proto_length_delimited_bounds_stream(
    stream: BinaryIO,
    end_offset: int,
) -> tuple[int, int, int] | None:
    """Return bounds for a length-delimited value without reading its payload."""
    length = _read_proto_varint_stream(stream, end_offset)
    if length is None:
        return None
    value_start = stream.tell()
    value_end = value_start + length
    if value_end > end_offset:
        return None
    return length, value_start, value_end


def _read_proto_varint(data: bytes, offset: int, end: int | None = None) -> tuple[int, int] | None:
    """Read a protobuf varint from bounded in-memory data."""
    limit = len(data) if end is None else min(end, len(data))
    value = 0
    shift = 0
    cursor = offset
    while cursor < limit and cursor - offset < 10:
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cursor
        shift += 7
    return None


def _read_length_delimited_proto_value(
    data: bytes,
    offset: int,
    end: int | None = None,
) -> tuple[int, int, int, int] | None:
    """Return length-delimited value bounds within sampled CoreML bytes."""
    limit = len(data) if end is None else min(end, len(data))
    length_result = _read_proto_varint(data, offset, limit)
    if length_result is None:
        return None
    length, value_start = length_result
    value_end = value_start + length
    if value_start > limit:
        return None
    return length, value_start, min(value_end, limit), value_end


def _skip_proto_value(data: bytes, offset: int, wire_type: int, end: int | None = None) -> int | None:
    """Skip one protobuf value, returning the next offset when the sample contains it."""
    limit = len(data) if end is None else min(end, len(data))
    if wire_type == 0:
        value_result = _read_proto_varint(data, offset, limit)
        return None if value_result is None else value_result[1]
    if wire_type == 1:
        next_offset = offset + 8
        return next_offset if next_offset <= limit else None
    if wire_type == 2:
        bounds = _read_length_delimited_proto_value(data, offset, limit)
        if bounds is None:
            return None
        _length, _value_start, _sampled_value_end, value_end = bounds
        return value_end if value_end <= limit else None
    if wire_type == 5:
        next_offset = offset + 4
        return next_offset if next_offset <= limit else None
    return None


def _skip_coreml_proto_group(
    data: bytes,
    offset: int,
    start_field_number: int,
    *,
    remaining_fields: int,
    end: int | None = None,
) -> tuple[int, int] | Literal["budget_exhausted", "incomplete", "malformed"]:
    """Skip a well-formed unknown CoreML protobuf group within a field budget."""
    limit = len(data) if end is None else min(end, len(data))
    group_stack = [start_field_number]
    fields_seen = 0

    while group_stack and offset < limit and fields_seen < remaining_fields:
        tag_result = _read_proto_varint(data, offset, limit)
        if tag_result is None:
            return _COREML_GROUP_INCOMPLETE
        tag, value_offset = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return _COREML_GROUP_MALFORMED

        fields_seen += 1
        if wire_type == 3:
            group_stack.append(field_number)
            offset = value_offset
            continue
        if wire_type == 4:
            if field_number != group_stack[-1]:
                return _COREML_GROUP_MALFORMED
            group_stack.pop()
            offset = value_offset
            continue
        if wire_type not in _COREML_PROTO_PREFIX_WIRE_TYPES:
            return _COREML_GROUP_MALFORMED

        next_offset = _skip_proto_value(data, value_offset, wire_type, limit)
        if next_offset is None:
            return _COREML_GROUP_INCOMPLETE
        offset = next_offset

    if group_stack:
        if fields_seen >= remaining_fields:
            return _COREML_GROUP_BUDGET_EXHAUSTED
        return _COREML_GROUP_INCOMPLETE
    return offset, fields_seen


def _looks_like_onnx_node_proto_stream(
    stream: BinaryIO,
    end_offset: int,
    routing_fields_remaining: list[int],
) -> bool | None:
    """Return whether a bounded message resembles an ONNX NodeProto, or is unresolved."""
    fields_seen = 0
    has_input_or_output = False
    has_op_type = False
    while stream.tell() < end_offset and fields_seen < _ONNX_NODE_MAX_ROUTING_FIELDS:
        if routing_fields_remaining[0] <= 0:
            return None
        routing_fields_remaining[0] -= 1
        tag = _read_proto_varint_stream(stream, end_offset)
        if tag is None:
            return False
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if wire_type == 2 and field_number in {1, 2, 4}:
            bounds = _read_proto_length_delimited_bounds_stream(stream, end_offset)
            if bounds is None:
                return False
            length, _value_start, value_end = bounds
            if field_number in {1, 2} and 0 < length <= _ONNX_MAX_ROUTING_TEXT_BYTES:
                has_input_or_output = True
            elif field_number == 4 and 0 < length <= _ONNX_MAX_ROUTING_TEXT_BYTES:
                op_type = stream.read(length)
                has_op_type = bool(op_type) and all(32 <= byte < 127 for byte in op_type)
            stream.seek(value_end)
        else:
            skip_status = _skip_proto_stream_value(
                stream,
                wire_type,
                end_offset,
                field_number=field_number,
                routing_fields_remaining=routing_fields_remaining,
            )
            if skip_status is None:
                return None
            if not skip_status:
                return False

        fields_seen += 1
        if has_input_or_output and has_op_type:
            return True

    if stream.tell() < end_offset:
        return None
    return False


def _looks_like_onnx_graph_proto_stream(
    stream: BinaryIO,
    end_offset: int,
    routing_fields_remaining: list[int],
) -> bool | None:
    """Return whether a bounded message resembles an ONNX GraphProto, or is unresolved."""
    fields_seen = 0
    has_node = False
    has_initializer = False
    value_info_fields: set[int] = set()

    while stream.tell() < end_offset and fields_seen < _ONNX_GRAPH_MAX_ROUTING_FIELDS:
        if routing_fields_remaining[0] <= 0:
            return None
        routing_fields_remaining[0] -= 1
        tag = _read_proto_varint_stream(stream, end_offset)
        if tag is None:
            return False
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if wire_type == 2:
            bounds = _read_proto_length_delimited_bounds_stream(stream, end_offset)
            if bounds is None:
                return False
            length, _value_start, value_end = bounds
            if field_number == 1 and length > 0:
                node_status = _looks_like_onnx_node_proto_stream(stream, value_end, routing_fields_remaining)
                if node_status is None:
                    return None
                has_node = has_node or node_status
            elif field_number == 5:
                has_initializer = True
            elif field_number in {11, 12, 13}:
                value_info_fields.add(field_number)
            stream.seek(value_end)
        else:
            skip_status = _skip_proto_stream_value(
                stream,
                wire_type,
                end_offset,
                field_number=field_number,
                routing_fields_remaining=routing_fields_remaining,
            )
            if skip_status is None:
                return None
            if not skip_status:
                return False

        fields_seen += 1
        if (has_node and value_info_fields) or len(value_info_fields) >= 2:
            return True

    if has_initializer and value_info_fields:
        return True
    if stream.tell() < end_offset:
        return None
    return False


def _looks_like_onnx_model_proto_stream(stream: BinaryIO, end_offset: int) -> bool | None:
    """Return whether a bounded message resembles an ONNX ModelProto, or is unresolved."""
    fields_seen = 0
    has_plausible_ir_version = False
    has_graph = False
    routing_fields_remaining = [_ONNX_MODEL_MAX_ROUTING_FIELDS]

    while stream.tell() < end_offset and fields_seen < _ONNX_MODEL_MAX_ROUTING_FIELDS:
        if routing_fields_remaining[0] <= 0:
            return None
        routing_fields_remaining[0] -= 1
        tag = _read_proto_varint_stream(stream, end_offset)
        if tag is None:
            return False
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if field_number == 1 and wire_type == 0:
            ir_version = _read_proto_varint_stream(stream, end_offset)
            if ir_version is None:
                return False
            has_plausible_ir_version = 0 < ir_version <= 1000
        elif field_number == 7 and wire_type == 2:
            bounds = _read_proto_length_delimited_bounds_stream(stream, end_offset)
            if bounds is None:
                return False
            length, _value_start, value_end = bounds
            if length > 0:
                graph_status = _looks_like_onnx_graph_proto_stream(stream, value_end, routing_fields_remaining)
                if graph_status is None:
                    return None
                has_graph = has_graph or graph_status
            stream.seek(value_end)
        else:
            expected_wire_type = _ONNX_MODEL_FIELD_WIRE_TYPES.get(field_number)
            if expected_wire_type is not None and wire_type != expected_wire_type:
                return False
            skip_status = _skip_proto_stream_value(
                stream,
                wire_type,
                end_offset,
                field_number=field_number,
                routing_fields_remaining=routing_fields_remaining,
            )
            if skip_status is None:
                return None
            if not skip_status:
                return False

        fields_seen += 1
        if has_plausible_ir_version and has_graph:
            return True

    if stream.tell() < end_offset:
        return None
    return False


def _looks_like_onnx_model_file(path: Path, size: int) -> bool | None:
    """Detect ONNX ModelProto structure while preserving unresolved bounded scans."""
    if size < 4:
        return False
    try:
        with path.open("rb") as stream:
            return _looks_like_onnx_model_proto_stream(stream, size)
    except OSError:
        return False


def _looks_like_proto_message_prefix(data: bytes) -> bool:
    """Return whether bytes begin with a non-empty protobuf message field."""
    if not data:
        return False
    tag_result = _read_proto_varint(data, 0)
    if tag_result is None:
        return False
    tag, _value_offset = tag_result
    return tag >> 3 > 0 and tag & 0x07 in _COREML_PROTO_PREFIX_WIRE_TYPES


def _looks_like_coreml_description_proto_prefix(data: bytes, *, sample_is_prefix: bool = False) -> bool | None:
    """Return True when a bounded prefix resembles a CoreML ModelDescription."""
    offset = 0
    fields_seen = 0
    while offset < len(data) and fields_seen < _COREML_MAX_DESCRIPTION_PREFIX_FIELDS:
        tag_result = _read_proto_varint(data, offset)
        if tag_result is None:
            return None if sample_is_prefix else False
        tag, value_offset = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if wire_type == 2 and field_number in _COREML_DESCRIPTION_FIELD_HINTS:
            return True

        if wire_type == 3:
            group_result = _skip_coreml_proto_group(
                data,
                value_offset,
                field_number,
                remaining_fields=_COREML_MAX_DESCRIPTION_PREFIX_FIELDS - fields_seen - 1,
            )
            if group_result == _COREML_GROUP_BUDGET_EXHAUSTED:
                return None
            if group_result == _COREML_GROUP_INCOMPLETE:
                return None if sample_is_prefix else False
            if group_result == _COREML_GROUP_MALFORMED:
                return False
            offset, group_fields_seen = group_result
            fields_seen += group_fields_seen
        else:
            next_offset = _skip_proto_value(data, value_offset, wire_type)
            if next_offset is None:
                return None if sample_is_prefix else False
            offset = next_offset
        fields_seen += 1

    return None if sample_is_prefix and fields_seen >= _COREML_MAX_DESCRIPTION_PREFIX_FIELDS else False


def _could_start_coreml_model_proto(data: bytes) -> bool:
    """Return whether a prefix starts with a skippable protobuf field."""
    tag_result = _read_proto_varint(data, 0)
    if tag_result is None:
        return False
    tag, _value_offset = tag_result
    return tag >> 3 > 0 and tag & 0x07 in _COREML_PROTO_PREFIX_WIRE_TYPES


def _starts_with_coreml_specification_version(data: bytes) -> bool:
    """Return whether the bounded prefix starts with a plausible CoreML identity field."""
    tag_result = _read_proto_varint(data, 0)
    if tag_result is None:
        return False
    tag, value_offset = tag_result
    if tag != (1 << 3):
        return False
    value_result = _read_proto_varint(data, value_offset)
    return value_result is not None and 0 < value_result[0] <= 10000


def _looks_like_coreml_model_proto_prefix(data: bytes, *, sample_is_prefix: bool = False) -> bool | None:
    """Return whether a bounded prefix resembles, rejects, or cannot resolve CoreML Model."""
    if not _could_start_coreml_model_proto(data):
        return False

    offset = 0
    fields_seen = 0
    has_specification_version = False
    has_description = False
    has_model_type = False
    while offset < len(data) and fields_seen < _COREML_MAX_MODEL_PREFIX_FIELDS:
        tag_result = _read_proto_varint(data, offset)
        if tag_result is None:
            return None if sample_is_prefix else False
        tag, value_offset = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False
        if field_number == 1 and wire_type != 0:
            return False
        if (field_number == 2 or field_number in _COREML_MODEL_TYPE_FIELDS) and wire_type != 2:
            return False

        if field_number == 1:
            value_result = _read_proto_varint(data, value_offset)
            if value_result is None:
                return None if sample_is_prefix else False
            specification_version, offset = value_result
            has_specification_version = 0 < specification_version <= 10000
        elif wire_type == 2:
            bounds = _read_length_delimited_proto_value(data, value_offset)
            if bounds is None:
                return None if sample_is_prefix else False
            length, value_start, value_end, actual_value_end = bounds
            if actual_value_end > len(data):
                if field_number == 2:
                    return None if sample_is_prefix and has_specification_version else False
                if field_number in _COREML_MODEL_TYPE_FIELDS and length > 0:
                    return True if has_specification_version and has_description else None
                return None if sample_is_prefix else False
            if field_number == 2:
                description_status = _looks_like_coreml_description_proto_prefix(data[value_start:value_end])
                if description_status is True:
                    has_description = True
                elif description_status is None:
                    return None
                else:
                    return False
            elif (
                field_number in _COREML_MODEL_TYPE_FIELDS
                and length > 0
                and _looks_like_proto_message_prefix(data[value_start:value_end])
            ):
                has_model_type = True
            offset = actual_value_end
        elif wire_type == 3:
            group_result = _skip_coreml_proto_group(
                data,
                value_offset,
                field_number,
                remaining_fields=_COREML_MAX_MODEL_PREFIX_FIELDS - fields_seen - 1,
            )
            if group_result == _COREML_GROUP_BUDGET_EXHAUSTED:
                return None
            if group_result == _COREML_GROUP_INCOMPLETE:
                return None if sample_is_prefix else False
            if group_result == _COREML_GROUP_MALFORMED:
                return False
            offset, group_fields_seen = group_result
            fields_seen += group_fields_seen
        else:
            next_offset = _skip_proto_value(data, value_offset, wire_type)
            if next_offset is None:
                return None if sample_is_prefix else False
            offset = next_offset

        fields_seen += 1
        if has_specification_version and has_description and has_model_type:
            return True

    if has_specification_version and has_description and has_model_type:
        return True
    if sample_is_prefix or fields_seen >= _COREML_MAX_MODEL_PREFIX_FIELDS:
        return None
    return False


def _looks_like_coreml_model_file(path: Path, size: int) -> bool | None:
    """Detect recognizable or unresolved CoreML Model structure with a bounded prefix read."""
    if size < 8:
        return False
    try:
        with path.open("rb") as handle:
            prefix = handle.read(min(size, _COREML_PROTO_SIGNATURE_READ_BYTES))
    except OSError:
        return False
    return _looks_like_coreml_model_proto_prefix(prefix, sample_is_prefix=size > len(prefix))


def _looks_like_coreml_model_candidate_file(path: Path, size: int, header: bytes) -> bool | None:
    """Return a recognized, rejected, or bounded-inconclusive CoreML route."""
    if not _could_start_coreml_model_proto(header):
        if _read_proto_varint(header, 0) is not None or len(header) >= min(size, 10):
            return False
        try:
            with path.open("rb") as handle:
                header = handle.read(min(size, 10))
        except OSError:
            return False
        if not _could_start_coreml_model_proto(header):
            return False
    return _looks_like_coreml_model_file(path, size)


def _looks_like_binary_pickle_protocol(header: bytes) -> bool:
    return (
        len(header) >= 2
        and header[0] == 0x80
        and _MIN_BINARY_PICKLE_PROTOCOL <= header[1] <= _MAX_FORWARD_COMPAT_BINARY_PICKLE_PROTOCOL
    )


SAFETENSORS_ROUTING_HEADER_PARSE_BYTES: int = 16 * 1024 * 1024


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


def _has_bounded_binary_pickle_security_signal(sample: bytes) -> bool:
    """Return whether a pickle-shaped binary prefix contains a security signal."""
    if not _looks_like_binary_pickle_protocol(sample[:4]):
        return False
    protocol_opcode_count = 0
    has_security_opcode = False
    has_pre_stop_security_opcode = False
    try:
        for opcode, _arg, position in pickletools.genops(sample):
            if opcode.name == "PROTO":
                protocol_opcode_count += 1
            if opcode.name in _BINARY_PICKLE_SECURITY_OPCODES:
                has_security_opcode = True
            if opcode.name in _BINARY_PICKLE_PRE_STOP_SECURITY_OPCODES:
                has_pre_stop_security_opcode = True
            if opcode.name == "STOP":
                stop_position = 0 if position is None else position
                try:
                    pickletools.dis(sample[: stop_position + 1], out=StringIO())
                except Exception:
                    return has_pre_stop_security_opcode
                return protocol_opcode_count > 1 or has_security_opcode
    except Exception:
        return has_pre_stop_security_opcode
    return has_pre_stop_security_opcode


def _looks_like_protocolless_binary_pickle_security_signal(
    sample: bytes,
    *,
    sample_is_prefix: bool = False,
) -> bool:
    """Return whether a PROTO-less binary pickle carries or can hide a security signal."""
    return _classify_protocolless_binary_pickle_security_signal(sample, sample_is_prefix=sample_is_prefix) is True


def _classify_protocolless_binary_pickle_security_signal(
    sample: bytes,
    *,
    sample_is_prefix: bool = False,
) -> bool | None:
    """Classify a PROTO-less binary pickle probe as security-relevant, benign, or incomplete."""
    if len(sample) < 2 or _looks_like_binary_pickle_protocol(sample[:4]) or sample[0] in PROTO0_1_START_BYTES:
        return False

    opcode_count = 0
    has_binary_opcode = False
    has_security_opcode = False
    has_pre_stop_security_opcode = False
    try:
        for opcode, _arg, position in pickletools.genops(sample):
            opcode_count += 1
            opcode_name = opcode.name
            if opcode_name == "PROTO" and opcode_count == 1:
                return False
            if opcode_name in _PROTOCOLLESS_BINARY_PICKLE_OPCODES:
                has_binary_opcode = True
            if opcode_name in _BINARY_PICKLE_SECURITY_OPCODES:
                has_security_opcode = True
            if opcode_name in _PROTOCOLLESS_BINARY_PICKLE_PRE_STOP_SECURITY_OPCODES:
                has_pre_stop_security_opcode = True
            if opcode_name == "STOP":
                if opcode_count < 2 or not has_binary_opcode or not has_security_opcode:
                    return False
                stop_position = 0 if position is None else position
                try:
                    pickletools.dis(sample[: stop_position + 1], out=StringIO())
                except Exception:
                    return has_pre_stop_security_opcode
                return True
    except ValueError:
        if opcode_count >= 2 and has_binary_opcode and has_pre_stop_security_opcode:
            return sample_is_prefix or _is_completable_pickle_prefix(sample)
        if sample_is_prefix and opcode_count >= 2 and has_binary_opcode:
            return None
        return False
    except Exception:
        if (
            opcode_count >= 2
            and has_binary_opcode
            and has_pre_stop_security_opcode
            and (sample_is_prefix or _is_completable_pickle_prefix(sample))
        ):
            return True
        if sample_is_prefix and opcode_count >= 2 and has_binary_opcode:
            return None
        return False
    if (
        opcode_count >= 2
        and has_binary_opcode
        and has_pre_stop_security_opcode
        and (sample_is_prefix or _is_completable_pickle_prefix(sample))
    ):
        return True
    if sample_is_prefix and opcode_count >= 2 and has_binary_opcode:
        return None
    return False


def _is_completable_pickle_prefix(sample: bytes) -> bool:
    """Return whether adding a bounded terminal value yields a valid pickle."""
    for suffix in (b".", b"N."):
        try:
            pickletools.dis(sample + suffix, out=StringIO())
        except Exception:
            continue
        return True
    return False


def _read_pickle_structure_bytes(
    handle: BinaryIO,
    sample: bytes,
    offset: int,
    length: int,
    file_size: int,
) -> bytes | None:
    end = offset + length
    if length < 0 or offset < 0 or end > file_size:
        return None
    if end <= len(sample):
        return sample[offset:end]
    handle.seek(offset)
    data = handle.read(length)
    return data if len(data) == length else None


def _find_pickle_line_argument_end(
    handle: BinaryIO,
    offset: int,
    file_size: int,
    line_count: int,
    max_probe_bytes: int,
) -> tuple[int | None, bool, int]:
    cursor = offset
    remaining_budget = max_probe_bytes
    consumed_bytes = 0
    for _ in range(line_count):
        while cursor < file_size and remaining_budget > 0:
            read_size = min(4096, remaining_budget, file_size - cursor)
            handle.seek(cursor)
            chunk = handle.read(read_size)
            if not chunk:
                return None, False, consumed_bytes
            newline_index = chunk.find(b"\n")
            consumed = len(chunk) if newline_index < 0 else newline_index + 1
            cursor += consumed
            remaining_budget -= consumed
            consumed_bytes += consumed
            if newline_index >= 0:
                break
        else:
            return None, cursor < file_size, consumed_bytes
    return cursor, False, consumed_bytes


def _pickle_opcode_argument_end(
    handle: BinaryIO,
    sample: bytes,
    opcode: Any,
    argument_offset: int,
    file_size: int,
    remaining_line_probe_bytes: int,
) -> tuple[int | None, bool, int]:
    argument = opcode.arg
    if argument is None:
        return argument_offset, False, 0
    argument_size = argument.n
    if argument_size > 0:
        end = argument_offset + argument_size
        return (end, False, 0) if end <= file_size else (None, False, 0)
    if argument_size == -1:
        line_count = 2 if opcode.name in _PICKLE_LINE_PAIR_OPCODES else 1
        return _find_pickle_line_argument_end(
            handle,
            argument_offset,
            file_size,
            line_count,
            remaining_line_probe_bytes,
        )

    header_size = _PICKLE_VARIABLE_LENGTH_HEADER_BYTES.get(argument_size)
    if header_size is None:
        return None, False, 0
    header = _read_pickle_structure_bytes(handle, sample, argument_offset, header_size, file_size)
    if header is None:
        return None, False, 0
    payload_size = int.from_bytes(header, "little", signed=argument_size == -3)
    if payload_size < 0:
        return None, False, 0
    end = argument_offset + header_size + payload_size
    return (end, False, 0) if end <= file_size else (None, False, 0)


def _has_bounded_protocolless_binary_pickle_security_signal(
    file_path: Path,
    file_size: int,
    sample: bytes,
) -> bool | None:
    """Structurally probe a PROTO-less pickle without loading large operands."""
    sample_is_prefix = file_size > len(sample)
    sample_state = _classify_protocolless_binary_pickle_security_signal(
        sample,
        sample_is_prefix=sample_is_prefix,
    )
    if sample_state is True:
        return True
    if not sample_is_prefix or len(sample) < 2 or _looks_like_binary_pickle_protocol(sample[:4]):
        return False

    opcode_count = 0
    offset = 0
    has_binary_opcode = False
    has_security_opcode = False
    has_pre_stop_security_opcode = False
    line_probe_bytes = 0
    try:
        with file_path.open("rb") as handle:
            while offset < file_size:
                if opcode_count >= PROTO0_1_MAX_PROBE_OPCODES:
                    return None
                opcode_byte = _read_pickle_structure_bytes(handle, sample, offset, 1, file_size)
                if opcode_byte is None:
                    return has_binary_opcode and has_pre_stop_security_opcode
                opcode = _PICKLE_OPCODE_BY_BYTE.get(opcode_byte[0])
                if opcode is None:
                    return offset >= len(sample) and has_binary_opcode and has_pre_stop_security_opcode

                opcode_count += 1
                opcode_name = opcode.name
                if opcode_name in _PROTOCOLLESS_BINARY_PICKLE_OPCODES:
                    has_binary_opcode = True
                if opcode_name in _BINARY_PICKLE_SECURITY_OPCODES:
                    has_security_opcode = True
                if opcode_name in _PROTOCOLLESS_BINARY_PICKLE_PRE_STOP_SECURITY_OPCODES:
                    has_pre_stop_security_opcode = True

                argument_end, budget_exceeded, consumed_line_bytes = _pickle_opcode_argument_end(
                    handle,
                    sample,
                    opcode,
                    offset + 1,
                    file_size,
                    PROTO0_1_MAX_PROBE_BYTES - line_probe_bytes,
                )
                line_probe_bytes += consumed_line_bytes
                if budget_exceeded:
                    return None
                if argument_end is None:
                    return offset >= len(sample) and has_binary_opcode and has_pre_stop_security_opcode
                if opcode_name == "STOP":
                    return offset >= len(sample) and opcode_count >= 2 and has_binary_opcode and has_security_opcode
                offset = argument_end
    except OSError:
        return False
    return has_binary_opcode and has_pre_stop_security_opcode


def _read_pickle_probe_sample(path: Path, size: int, header16: bytes) -> bytes:
    """Read a bounded prefix for protocol 0/1 pickle probing."""
    if size <= len(header16):
        return header16
    with path.open("rb") as f:
        return f.read(min(size, PROTO0_1_MAX_PROBE_BYTES))


def _looks_like_tflite_header(header: bytes) -> bool:
    """Return True when the FlatBuffer identifier is `TFL3` at bytes 4-7."""
    return (
        len(header) >= _TFLITE_MIN_HEADER_SIZE
        and header[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + _TFLITE_MAGIC_SIZE] == _TFLITE_MAGIC_BYTES
    )


_RENAMED_BINARY_CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset({".bin", ".meta", ".pb"})
_TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset(
    {
        ".bin",
        ".cmf",
        ".dnn",
        ".exe",
        ".lgb",
        ".lightgbm",
        ".llamafile",
        ".meta",
        ".model",
        ".net",
        ".pb",
        ".rknn",
        ".t7",
        ".th",
    }
)


def _allows_renamed_binary_content_route(file_path: Path | None) -> bool:
    return file_path is None or file_path.suffix.lower() not in _RENAMED_BINARY_CONTENT_ROUTE_BLOCKED_EXTENSIONS


def detect_pytorch_binary_supplemental_format(path: str) -> str | None:
    """Return a strict secondary scanner for a content-identified `.bin` file."""
    file_path = Path(path)
    if file_path.suffix.lower() != ".bin" or not file_path.is_file():
        return None

    try:
        size = file_path.stat().st_size
        if size < 4:
            return None
        prefix = read_magic_bytes(path, max(_TORCH7_SIGNATURE_READ_BYTES, 8))
    except OSError:
        return None

    magic4 = prefix[:4]
    magic8 = prefix[:8]
    if magic4 == b"RKNN":
        return "rknn"
    if _looks_like_renamed_r_serialized_header(prefix):
        return "r_serialized"
    if _is_torch7_signature(prefix):
        return "torch7"
    if _detect_executorch_content_route(file_path, magic8) == "executorch":
        return "executorch"
    if _looks_like_tflite_header(magic8):
        return "tflite"
    return None


def _is_safetensors_routing_candidate(path: Path | None, magic8: bytes, file_size: int) -> bool:
    """Recognize SafeTensors framing or retain oversized plausible headers."""
    if file_size <= 8 or len(magic8) < 8:
        return False

    try:
        header_len = struct.unpack("<Q", magic8)[0]
    except struct.error:
        return False

    if header_len <= 0:
        return False
    if header_len > file_size - 8:
        return False

    if path is None:
        return False

    # The scanner fails closed on headers above this bounded parse budget.
    # Retain plausible object headers without parsing attacker-sized metadata.
    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        try:
            with path.open("rb") as handle:
                handle.seek(8)
                return handle.read(1) == b"{"
        except OSError:
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
    except (RecursionError, ValueError):
        # Parsing limits are inconclusive, so retain the fail-closed scanner route.
        return True

    return isinstance(parsed_header, dict)


def should_defer_safetensors_header_limit_hash(path: str, max_header_bytes: int) -> bool:
    """Return whether recognized bounded routing will fail before full-file hashing is useful."""
    file_path = Path(path)
    try:
        file_size = file_path.stat().st_size
        if file_size <= 8:
            return False
        with file_path.open("rb") as handle:
            magic8 = handle.read(8)
        if len(magic8) != 8:
            return False
        header_len = struct.unpack("<Q", magic8)[0]
    except (OSError, struct.error):
        return False

    if header_len <= max_header_bytes or header_len > file_size - 8:
        return False
    detected_format = detect_file_format(path)
    if detected_format == "safetensors":
        return True
    return detected_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT and (
        file_path.suffix.lower() == ".safetensors" or _is_safetensors_routing_candidate(file_path, magic8, file_size)
    )


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
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError, zipfile.BadZipFile):
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


def _looks_like_pytorch_zip_storage_members(member_names: set[str], prefix: str) -> bool:
    """Detect PyTorch tensor storage members next to data.pkl."""
    storage_prefix = f"{prefix}/data/" if prefix else "data/"
    for name in member_names:
        if not name.startswith(storage_prefix):
            continue
        storage_key = name[len(storage_prefix) :]
        if "/" not in storage_key and storage_key.isascii() and storage_key.isdecimal():
            return True
    return False


def is_torchserve_mar_archive(path: str, config: dict[str, Any] | None = None) -> bool:
    """Return whether a ZIP-backed `.mar` looks like a real TorchServe archive."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    from ...scanners.zip_scanner import ZipPreflightRejected, open_preflighted_zip

    try:
        with open_preflighted_zip(file_path, config) as archive:
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
    except ZipPreflightRejected:
        if config is not None:
            raise
        return False


def _is_keras_zip_archive_content(archive: zipfile.ZipFile, *, allow_config_only: bool = False) -> bool:
    """Return whether an open ZIP has the minimal Keras archive structure."""
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


def is_keras_zip_archive(
    path: str,
    *,
    allow_config_only: bool = False,
    config: dict[str, Any] | None = None,
) -> bool:
    """Return whether a ZIP-backed file has the minimal Keras archive structure."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    from ...scanners.zip_scanner import ZipPreflightRejected, open_preflighted_zip

    try:
        with open_preflighted_zip(file_path, config) as archive:
            return _is_keras_zip_archive_content(archive, allow_config_only=allow_config_only)
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False
    except ZipPreflightRejected:
        if config is not None:
            raise
        return False


def is_pytorch_zip_archive(path: str, config: dict[str, Any] | None = None) -> bool:
    """Return whether a ZIP-backed file has a conservative PyTorch archive signature."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    from ...scanners.zip_scanner import ZipPreflightRejected, open_preflighted_zip

    try:
        with open_preflighted_zip(file_path, config) as archive:
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
                if _looks_like_pytorch_zip_storage_members(member_names, prefix):
                    return True
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False
    except ZipPreflightRejected:
        if config is not None:
            raise
        return False

    return False


def is_executorch_archive(path: str, config: dict[str, Any] | None = None) -> bool:
    """Return whether a ZIP-backed file matches the mobile/ExecuTorch archive layout."""
    file_path = Path(path)
    if not file_path.is_file():
        return False

    from ...scanners.zip_scanner import ZipPreflightRejected, open_preflighted_zip

    try:
        with open_preflighted_zip(file_path, config) as archive:
            members_by_name: dict[str, list[zipfile.ZipInfo]] = {}
            for info in archive.infolist():
                if not info.filename or info.is_dir():
                    continue
                name = _normalize_archive_member_name(info.filename).casefold()
                members_by_name.setdefault(name, []).append(info)

            for name in members_by_name:
                if name == "bytecode.pkl":
                    prefix = ""
                elif name.endswith("/bytecode.pkl"):
                    prefix = name[: -len("/bytecode.pkl")]
                else:
                    continue

                version_name = f"{prefix}/version" if prefix else "version"
                for version_info in members_by_name.get(version_name, []):
                    version_text = _read_zip_member_text(archive, version_info, _PYTORCH_ZIP_METADATA_MAX_BYTES)
                    if version_text is not None and re.fullmatch(r"\d+(?:\.\d+)?", version_text):
                        return True
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False
    except ZipPreflightRejected:
        if config is not None:
            raise
        return False

    return False


def is_skops_archive(path: str, config: dict[str, Any] | None = None) -> bool:
    """Return whether a ZIP-backed file has a Skops schema payload.

    Oversized schema members are treated as Skops to avoid failing open on
    misnamed archives whose schema content cannot be safely parsed within the
    bounded read limit.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return False

    from ...scanners.zip_scanner import ZipPreflightRejected, open_preflighted_zip

    try:
        with open_preflighted_zip(file_path, config) as archive:
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
    except ZipPreflightRejected:
        if config is not None:
            raise
        return False

    return False


def _is_nemo_root_config_member(member_name: str) -> bool:
    """Return whether a TAR member is a safe spelling of a root NeMo config."""
    normalized_name = _normalize_safe_tar_member_name(member_name)
    return normalized_name is not None and normalized_name.lower() in _NEMO_CONFIG_ENTRIES


def _normalize_safe_tar_member_name(member_name: str) -> str | None:
    """Normalize an in-archive TAR path without permitting extraction-root escape."""
    normalized_name = member_name.replace("\\", "/")
    if PurePosixPath(normalized_name).is_absolute() or re.match(r"^[A-Za-z]:/", normalized_name):
        return None

    normalized_name = posixpath.normpath(normalized_name)
    if normalized_name in {"", ".", ".."} or normalized_name.startswith("../"):
        return None
    return normalized_name


def _resolve_safe_tar_link_target_name(member: tarfile.TarInfo) -> str | None:
    """Resolve an in-archive TAR link without permitting extraction-root escape."""
    link_name = member.linkname.replace("\\", "/")
    if PurePosixPath(link_name).is_absolute() or re.match(r"^[A-Za-z]:/", link_name):
        return None

    if member.islnk():
        target_name = link_name
    else:
        member_dir = posixpath.dirname(member.name.replace("\\", "/"))
        target_name = posixpath.join(member_dir, link_name)
    if posixpath.normpath(target_name) == ".":
        return "."
    return _normalize_safe_tar_member_name(target_name)


def _resolve_safe_tar_symlink_target_at_destination(member: tarfile.TarInfo, destination_name: str) -> str | None:
    """Resolve a symlink target relative to its extracted destination."""
    link_name = member.linkname.replace("\\", "/")
    if PurePosixPath(link_name).is_absolute() or re.match(r"^[A-Za-z]:/", link_name):
        return None
    target_name = posixpath.join(posixpath.dirname(destination_name), link_name)
    if posixpath.normpath(target_name) == ".":
        return "."
    return _normalize_safe_tar_member_name(target_name)


class _NemoRouteResolutionLimitExceeded(Exception):
    """Raised when bounded NeMo TAR link routing cannot safely continue."""


def _consume_nemo_route_link_visit(member_visit_budget: list[int]) -> None:
    if member_visit_budget[0] <= 0:
        raise _NemoRouteResolutionLimitExceeded
    member_visit_budget[0] -= 1


def _consume_nemo_route_prefix_probe_budget(
    components: list[str],
    maximum_length: int,
    member_visit_budget: list[int],
) -> None:
    """Bound total prefix-string work before resolving symlink components."""
    prefix_length = 0
    probe_cost = 0
    for index, component in enumerate(components[:maximum_length]):
        prefix_length += len(component) + (1 if index else 0)
        probe_cost += prefix_length
        if probe_cost > member_visit_budget[0]:
            raise _NemoRouteResolutionLimitExceeded
    member_visit_budget[0] -= probe_cost


def _resolve_safe_tar_path_through_symlinks(
    member_name: str,
    symlink_targets: dict[str, str],
    member_visit_budget: list[int],
    *,
    follow_final_symlink: bool = True,
) -> str | None:
    """Resolve a safe extraction destination through symlinks already created."""
    current_name = _normalize_safe_tar_member_name(member_name)
    if current_name is None:
        return None
    seen: set[str] = set()
    while current_name not in seen:
        seen.add(current_name)
        if not symlink_targets:
            return current_name
        components = current_name.split("/")
        maximum_length = len(components) if follow_final_symlink else len(components) - 1
        _consume_nemo_route_prefix_probe_budget(
            components,
            maximum_length,
            member_visit_budget,
        )
        for length in range(maximum_length, 0, -1):
            prefix = "/".join(components[:length])
            target_name = symlink_targets.get(prefix)
            if target_name is None:
                continue
            suffix = "/".join(components[length:])
            redirected_name = target_name if not suffix else posixpath.join(target_name, suffix)
            if posixpath.normpath(redirected_name) == ".":
                current_name = "."
            else:
                current_name = _normalize_safe_tar_member_name(redirected_name)
                if current_name is None:
                    return None
            break
        else:
            return current_name
    return None


def _tar_member_materializes_file_content(member: tarfile.TarInfo) -> bool:
    """Mirror tarfile members extracted through makefile or makeunknown."""
    return not (
        member.isdir() or member.isfifo() or member.ischr() or member.isblk() or member.islnk() or member.issym()
    )


def _tar_links_resolve_to_regular_member(
    root_links: list[tarfile.TarInfo],
    members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
    member_visit_budget: list[int],
) -> bool:
    """Return whether a TAR link chain can materialize a regular config member."""
    pending = list(root_links)
    seen: set[tuple[str, int]] = set()
    while pending:
        member = pending.pop()
        identity = (member.name, member.offset)
        if identity in seen:
            continue
        seen.add(identity)
        if _tar_member_materializes_file_content(member):
            return True
        if not (member.issym() or member.islnk()):
            continue
        _consume_nemo_route_link_visit(member_visit_budget)
        target_member = _effective_safe_tar_link_target_member(member, members_by_normalized_name)
        if target_member is not None:
            pending.append(target_member)
    return False


def _effective_safe_tar_link_target_member(
    member: tarfile.TarInfo,
    members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
) -> tarfile.TarInfo | None:
    """Return the single target entry TAR extraction would use for a link."""
    target_name = _resolve_safe_tar_link_target_name(member)
    if target_name is None:
        return None
    target_members = members_by_normalized_name.get(target_name, [])
    if member.islnk():
        target_members = [target_member for target_member in target_members if target_member.offset < member.offset]
    return target_members[-1] if target_members else None


def _resolve_tar_hardlink_fallback_member(
    hardlink: tarfile.TarInfo,
    members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
    member_visit_budget: list[int],
) -> tarfile.TarInfo | None:
    """Resolve the member tarfile extracts after a colliding hardlink."""
    pending = hardlink
    seen: set[tuple[str, int]] = set()
    while pending.islnk():
        _consume_nemo_route_link_visit(member_visit_budget)
        identity = (pending.name, pending.offset)
        if identity in seen:
            return None
        seen.add(identity)
        target_member = _effective_safe_tar_link_target_member(pending, members_by_normalized_name)
        if target_member is None:
            return None
        if _tar_member_materializes_file_content(target_member) or target_member.issym():
            return target_member
        pending = target_member
    return None


def _detect_tar_route(path: str) -> str | None:
    """Return the safe content route for a valid TAR-backed artifact."""
    file_path = Path(path)
    if not file_path.is_file():
        return None

    try:
        with tarfile.open(file_path, "r:*") as archive:
            if file_path.suffix.lower() == ".nemo":
                return "tar"
            members_by_normalized_name: dict[str, list[tarfile.TarInfo]] = {}
            root_config_links: list[tarfile.TarInfo] = []
            symlink_targets: dict[str, str] = {}
            occupied_names: set[str] = set()
            link_resolution_budget = [_NEMO_ROUTE_MAX_LINK_RESOLUTION_VISITS]
            for entry_count, member in enumerate(archive, start=1):
                if entry_count > _NEMO_ROUTE_MAX_ENTRIES:
                    if _tar_links_resolve_to_regular_member(
                        root_config_links,
                        members_by_normalized_name,
                        link_resolution_budget,
                    ):
                        return "nemo"
                    return NEMO_ROUTING_INCONCLUSIVE_FORMAT
                normalized_member_name = _normalize_safe_tar_member_name(member.name)
                if normalized_member_name is not None:
                    members_by_normalized_name.setdefault(normalized_member_name, []).append(member)
                if _tar_member_materializes_file_content(member):
                    resolved_destination = _resolve_safe_tar_path_through_symlinks(
                        member.name,
                        symlink_targets,
                        link_resolution_budget,
                    )
                    if resolved_destination is not None and _is_nemo_root_config_member(resolved_destination):
                        return "nemo"
                    physical_destination = _resolve_safe_tar_path_through_symlinks(
                        member.name,
                        symlink_targets,
                        link_resolution_budget,
                        follow_final_symlink=False,
                    )
                    if physical_destination is not None:
                        occupied_names.add(physical_destination)
                elif member.issym():
                    destination_name = _resolve_safe_tar_path_through_symlinks(
                        member.name,
                        symlink_targets,
                        link_resolution_budget,
                        follow_final_symlink=False,
                    )
                    if destination_name is None:
                        continue
                    target_name = _resolve_safe_tar_symlink_target_at_destination(member, destination_name)
                    if target_name is None:
                        continue
                    if _is_nemo_root_config_member(destination_name):
                        return "nemo"
                    occupied_names.add(destination_name)
                    symlink_targets[destination_name] = target_name
                elif member.islnk():
                    destination_name = _resolve_safe_tar_path_through_symlinks(
                        member.name,
                        symlink_targets,
                        link_resolution_budget,
                        follow_final_symlink=False,
                    )
                    target_name = _resolve_safe_tar_link_target_name(member)
                    if (
                        destination_name is not None
                        and _is_nemo_root_config_member(destination_name)
                        and target_name is not None
                    ):
                        return "nemo"
                    if destination_name is None or target_name is None:
                        continue
                    if destination_name in occupied_names:
                        fallback_member = _resolve_tar_hardlink_fallback_member(
                            member,
                            members_by_normalized_name,
                            link_resolution_budget,
                        )
                        if fallback_member is None:
                            continue
                        if fallback_member.issym():
                            symlink_targets.pop(destination_name, None)
                            fallback_target = _resolve_safe_tar_symlink_target_at_destination(
                                fallback_member,
                                destination_name,
                            )
                            if fallback_target is not None:
                                symlink_targets[destination_name] = fallback_target
                            continue
                        resolved_write = _resolve_safe_tar_path_through_symlinks(
                            destination_name,
                            symlink_targets,
                            link_resolution_budget,
                        )
                        if resolved_write is not None and _is_nemo_root_config_member(resolved_write):
                            return "nemo"
                        continue
                    occupied_names.add(destination_name)
                    fallback_member = _resolve_tar_hardlink_fallback_member(
                        member,
                        members_by_normalized_name,
                        link_resolution_budget,
                    )
                    redirected_target = _resolve_safe_tar_path_through_symlinks(
                        target_name,
                        symlink_targets,
                        link_resolution_budget,
                    )
                    if (
                        fallback_member is not None
                        and fallback_member.issym()
                        and redirected_target is not None
                        and redirected_target not in occupied_names
                    ):
                        fallback_target = _resolve_safe_tar_symlink_target_at_destination(
                            fallback_member,
                            destination_name,
                        )
                        if fallback_target is not None:
                            symlink_targets[destination_name] = fallback_target
                    if _is_nemo_root_config_member(member.name):
                        root_config_links.append(member)
    except _NemoRouteResolutionLimitExceeded:
        return NEMO_ROUTING_INCONCLUSIVE_FORMAT
    except (EOFError, OSError, tarfile.TarError):
        return None

    try:
        return (
            "nemo"
            if _tar_links_resolve_to_regular_member(
                root_config_links,
                members_by_normalized_name,
                link_resolution_budget,
            )
            else "tar"
        )
    except _NemoRouteResolutionLimitExceeded:
        return NEMO_ROUTING_INCONCLUSIVE_FORMAT


def is_nemo_archive(path: str) -> bool:
    """Return whether a TAR-backed artifact should receive NeMo analysis."""
    return _detect_tar_route(path) == "nemo"


def _is_tar_archive(path: str) -> bool:
    """Return whether a path is a TAR archive, including compressed wrappers."""
    try:
        return tarfile.is_tarfile(path)
    except Exception:
        return False


def _tar_octal_value(field: bytes) -> int | None:
    stripped = field.split(b"\0", 1)[0].strip()
    if not stripped or any(byte < ord("0") or byte > ord("7") for byte in stripped):
        return None
    try:
        return int(stripped, 8)
    except ValueError:
        return None


def _tar_name_looks_plausible(name_field: bytes) -> bool:
    name = name_field.split(b"\0", 1)[0]
    return bool(name) and all(byte >= 0x20 and byte != 0x7F for byte in name)


def _has_tar_ustar_signature(header: bytes) -> bool:
    return len(header) >= _TAR_USTAR_MIN_BYTES and header[
        _TAR_USTAR_OFFSET : _TAR_USTAR_OFFSET + _TAR_USTAR_MAGIC_SIZE
    ].startswith(b"ustar")


def _has_valid_tar_checksum_header(header: bytes) -> bool:
    """Return whether a 512-byte TAR header block has a valid v7/POSIX checksum."""
    if len(header) < _TAR_BLOCK_SIZE:
        return False

    block = header[:_TAR_BLOCK_SIZE]
    if block == b"\0" * _TAR_BLOCK_SIZE or not _tar_name_looks_plausible(block[:100]):
        return False

    if any(_tar_octal_value(block[start:end]) is None for start, end in _TAR_NUMERIC_FIELD_SLICES):
        return False

    expected_checksum = _tar_octal_value(block[_TAR_CHECKSUM_OFFSET : _TAR_CHECKSUM_OFFSET + _TAR_CHECKSUM_SIZE])
    if expected_checksum is None:
        return False

    checksum = (
        sum(block[:_TAR_CHECKSUM_OFFSET])
        + (_TAR_CHECKSUM_SIZE * ord(" "))
        + sum(block[_TAR_CHECKSUM_OFFSET + _TAR_CHECKSUM_SIZE :])
    )
    return checksum == expected_checksum


def _looks_like_uncompressed_tar_header(header: bytes) -> bool:
    return _has_tar_ustar_signature(header) or _has_valid_tar_checksum_header(header)


def _has_zip_magic(prefix: bytes) -> bool:
    """Return whether a prefix starts with a recognized ZIP signature."""
    return prefix.startswith(_ZIP_MAGIC_SIGNATURES)


def is_zipfile(path: str) -> bool:
    """Check if file is a ZIP by reading the signature."""
    file_path = Path(path)
    if not file_path.is_file():
        return False
    try:
        signature = read_magic_bytes(path, 4)
        return _has_zip_magic(signature)
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

        graph_node_count = len(metagraph.graph_def.node)
        function_node_count = sum(len(function.node_def) for function in metagraph.graph_def.library.function)
        collection_count = len(metagraph.collection_def)
        return graph_node_count > 0 or function_node_count > 0 or collection_count > 0
    except Exception:
        return False


def _is_tensorflow_saved_model_file(path: str) -> bool:
    file_path = Path(path)
    if not file_path.is_file():
        return False

    try:
        size = file_path.stat().st_size
        if size < _TF_METAGRAPH_MIN_BYTES or size > _TF_METAGRAPH_MAX_VALIDATE_BYTES:
            return False

        import modelaudit.protos  # noqa: F401, I001

        from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

        saved_model = SavedModel()
        saved_model.ParseFromString(file_path.read_bytes())
        return any(
            len(metagraph.collection_def) > 0
            or (
                metagraph.HasField("graph_def")
                and (
                    len(metagraph.graph_def.node) > 0
                    or any(function.node_def for function in metagraph.graph_def.library.function)
                )
            )
            for metagraph in saved_model.meta_graphs
        )
    except Exception:
        return False


def _read_proto_varint_stream(stream: BinaryIO, end_offset: int | None = None) -> int | None:
    value = 0
    shift = 0
    for _ in range(10):
        if end_offset is not None and stream.tell() >= end_offset:
            return None
        raw_byte = stream.read(1)
        if not raw_byte:
            return None
        byte = raw_byte[0]
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value
        shift += 7
    return None


def _has_tensorflow_node_signal(node: Any) -> bool:
    return bool(node.name or node.op or node.input or node.attr)


def _has_tensorflow_graph_signal(graph_def: Any) -> bool:
    return any(_has_tensorflow_node_signal(node) for node in graph_def.node) or any(
        _has_tensorflow_node_signal(node) for function in graph_def.library.function for node in function.node_def
    )


def _has_tensorflow_operation_signal(graph_def: Any) -> bool:
    return any(node.op for node in graph_def.node) or any(
        node.op for function in graph_def.library.function for node in function.node_def
    )


def _classify_tensorflow_field_two_payload(
    payload: bytes,
    *,
    outer_hint: _TensorFlowOuterHint,
) -> _TensorFlowProtoRoute:
    """Classify a bounded protobuf field 2 payload from MetaGraph/SavedModel wrappers."""
    try:
        import modelaudit.protos  # noqa: F401, I001

        from google.protobuf.message import DecodeError
        from tensorflow.core.framework.graph_pb2 import GraphDef
        from tensorflow.core.protobuf.meta_graph_pb2 import MetaGraphDef
    except Exception:
        return "unknown"

    graph_signal = False
    try:
        graph_def = GraphDef()
        graph_def.ParseFromString(payload)
        graph_signal = _has_tensorflow_graph_signal(graph_def)
    except (DecodeError, ValueError, TypeError, AttributeError):
        # This field may instead hold a MetaGraphDef wrapper; inspect that next.
        pass

    saved_model_signal = False
    try:
        metagraph = MetaGraphDef()
        metagraph.ParseFromString(payload)
        saved_model_signal = len(metagraph.collection_def) > 0 or (
            metagraph.HasField("graph_def")
            and (
                _has_tensorflow_operation_signal(metagraph.graph_def)
                or (outer_hint == "tf_savedmodel" and _has_tensorflow_graph_signal(metagraph.graph_def))
            )
        )
    except (DecodeError, ValueError, TypeError, AttributeError):
        # Raw GraphDef payloads are expected here; preserve the graph signal above.
        pass

    if outer_hint == "tf_metagraph" and graph_signal:
        return "tf_metagraph"
    if outer_hint == "tf_savedmodel" and saved_model_signal:
        return "tf_savedmodel"
    if graph_signal and not saved_model_signal:
        return "tf_metagraph"
    if saved_model_signal and not graph_signal:
        return "tf_savedmodel"
    if graph_signal and saved_model_signal:
        return "inconclusive"
    return "unknown"


def _is_tensorflow_collection_payload(payload: bytes) -> bool:
    """Return whether a bounded field looks like a TensorFlow collection entry."""
    try:
        import modelaudit.protos  # noqa: F401, I001

        from tensorflow.core.protobuf.meta_graph_pb2 import MetaGraphDef
    except Exception:
        return False
    try:
        collection_entry = MetaGraphDef.CollectionDefEntry()
        collection_entry.ParseFromString(payload)
        return bool(collection_entry.key and collection_entry.value.WhichOneof("kind"))
    except Exception:
        return False


def _is_tensorflow_metainfo_payload(payload: bytes) -> bool:
    """Return whether field 1 contains recognizable MetaGraph metadata."""
    try:
        import modelaudit.protos  # noqa: F401, I001

        from tensorflow.core.protobuf.meta_graph_pb2 import MetaGraphDef
    except Exception:
        return False
    try:
        metainfo = MetaGraphDef.MetaInfoDef()
        metainfo.ParseFromString(payload)
        return bool(metainfo.meta_graph_version or metainfo.tags)
    except Exception:
        return False


def _skip_proto_stream_value(
    stream: BinaryIO,
    wire_type: int,
    end_offset: int,
    *,
    field_number: int | None = None,
    remaining_fields: list[int] | None = None,
    routing_fields_remaining: list[int] | None = None,
    group_fields_remaining: list[int] | None = None,
    group_depth: int = 0,
) -> bool | None:
    if wire_type == 0:
        return _read_proto_varint_stream(stream, end_offset) is not None
    if wire_type == 1:
        length = 8
    elif wire_type == 2:
        length_result = _read_proto_varint_stream(stream, end_offset)
        if length_result is None:
            return False
        length = length_result
    elif wire_type == 5:
        length = 4
    elif wire_type == 3:
        if field_number is None:
            return False
        max_group_depth = (
            _TF_METAGRAPH_MAX_ROUTING_DEPTH if remaining_fields is not None else _PROTO_GROUP_MAX_ROUTING_DEPTH
        )
        if group_depth >= max_group_depth:
            if remaining_fields is not None:
                remaining_fields[0] = 0
            return None

        if remaining_fields is None and group_fields_remaining is None:
            group_fields_remaining = [_PROTO_GROUP_MAX_ROUTING_FIELDS]
        while stream.tell() < end_offset:
            if group_fields_remaining is not None:
                if group_fields_remaining[0] <= 0:
                    return None
                group_fields_remaining[0] -= 1
            if routing_fields_remaining is not None:
                if routing_fields_remaining[0] <= 0:
                    return None
                routing_fields_remaining[0] -= 1
            if remaining_fields is not None:
                if remaining_fields[0] <= 0:
                    return None
                remaining_fields[0] -= 1
            nested_tag = _read_proto_varint_stream(stream, end_offset)
            if nested_tag is None:
                return False
            nested_field_number = nested_tag >> 3
            nested_wire_type = nested_tag & 0x07
            if nested_field_number == 0:
                return False
            if nested_wire_type == 4:
                return nested_field_number == field_number
            nested_status = _skip_proto_stream_value(
                stream,
                nested_wire_type,
                end_offset,
                field_number=nested_field_number,
                remaining_fields=remaining_fields,
                routing_fields_remaining=routing_fields_remaining,
                group_fields_remaining=group_fields_remaining,
                group_depth=group_depth + 1,
            )
            if nested_status is not True:
                return nested_status
        return False
    else:
        return False

    if stream.tell() + length > end_offset:
        return False
    stream.seek(length, 1)
    return True


def _classify_bounded_tensorflow_protobuf_stream(stream: BinaryIO, file_size: int) -> _TensorFlowProtoRoute:
    """Seek past top-level protobuf values while looking for TensorFlow graph content."""
    remaining_fields = [_TF_METAGRAPH_MAX_ROUTING_FIELDS]
    parsed_payload_bytes = 0
    outer_hint: _TensorFlowOuterHint = "unknown"
    saw_tensorflow_wrapper_hint = False
    saw_tensorflow_candidate = False
    saw_structured_unknown = False
    while remaining_fields[0] > 0:
        remaining_fields[0] -= 1
        if stream.tell() >= file_size:
            return "unknown"
        tag = _read_proto_varint_stream(stream)
        if tag is None:
            return "unknown"
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return "unknown"
        if wire_type in {2, 3}:
            saw_structured_unknown = True
        if field_number == 1 and wire_type == 0:
            if _read_proto_varint_stream(stream) is None:
                return "unknown"
            # SavedModel stores its version here, but field 1 varints
            # are common in unrelated protobuf messages. Keep this as
            # an interpretation hint until a TensorFlow structure is seen.
            saw_tensorflow_wrapper_hint = True
            outer_hint = "tf_savedmodel"
            continue
        if field_number == 1 and wire_type == 2:
            length = _read_proto_varint_stream(stream)
            if length is None or stream.tell() + length > file_size:
                return "unknown"
            if length > _TF_METAGRAPH_MAX_VALIDATE_BYTES:
                return "oversized" if saw_tensorflow_candidate else "inconclusive"
            payload = stream.read(length)
            if len(payload) != length:
                return "unknown"
            if _is_tensorflow_metainfo_payload(payload):
                saw_tensorflow_wrapper_hint = True
                saw_tensorflow_candidate = True
                outer_hint = "tf_metagraph"
            continue
        if field_number == 2 and wire_type == 2:
            length = _read_proto_varint_stream(stream)
            if length is None or stream.tell() + length > file_size:
                return "unknown"
            if length > _TF_METAGRAPH_MAX_VALIDATE_BYTES:
                # Field 2 is graph_def on MetaGraphDef and meta_graphs on SavedModel.
                return "oversized" if saw_tensorflow_candidate else "oversized_candidate"
            if parsed_payload_bytes + length > _TF_METAGRAPH_MAX_ROUTING_PAYLOAD_BYTES:
                return "inconclusive"
            parsed_payload_bytes += length
            payload = stream.read(length)
            if len(payload) != length:
                return "unknown"
            payload_route = _classify_tensorflow_field_two_payload(payload, outer_hint=outer_hint)
            if payload_route != "unknown":
                return payload_route
            continue
        if field_number == 4 and wire_type == 2:
            length = _read_proto_varint_stream(stream)
            if length is None or stream.tell() + length > file_size:
                return "unknown"
            if length > _TF_METAGRAPH_MAX_VALIDATE_BYTES:
                return "oversized" if saw_tensorflow_candidate else "oversized_candidate"
            if parsed_payload_bytes + length > _TF_METAGRAPH_MAX_ROUTING_PAYLOAD_BYTES:
                return "inconclusive"
            parsed_payload_bytes += length
            payload = stream.read(length)
            if len(payload) != length:
                return "unknown"
            if _is_tensorflow_collection_payload(payload):
                return "tf_metagraph"
            continue
        if not _skip_proto_stream_value(
            stream,
            wire_type,
            file_size,
            field_number=field_number,
            remaining_fields=remaining_fields,
        ):
            if remaining_fields[0] <= 0:
                return (
                    "inconclusive"
                    if saw_tensorflow_wrapper_hint or saw_tensorflow_candidate or saw_structured_unknown
                    else "unknown"
                )
            return "unknown"
    return (
        "inconclusive"
        if saw_tensorflow_wrapper_hint or saw_tensorflow_candidate or saw_structured_unknown
        else "unknown"
    )


def _classify_bounded_tensorflow_protobuf(path: Path, file_size: int) -> _TensorFlowProtoRoute:
    """Classify bounded TensorFlow protobuf structure from a local file."""
    try:
        with path.open("rb") as stream:
            return _classify_bounded_tensorflow_protobuf_stream(stream, file_size)
    except OSError:
        return "unknown"


def _has_bounded_non_source_control_signal(file_path: Path, file_size: int) -> bool:
    """Return whether a bounded prefix contains bytes invalid in ordinary source text."""
    try:
        payload = read_magic_bytes(str(file_path), min(file_size, _CONTENT_ROUTE_PRINTABLE_TEXT_FAST_PATH_BYTES))
    except OSError:
        return False
    return any(byte in _CONTENT_ROUTE_NON_SOURCE_CONTROL_BYTES for byte in payload)


def _detect_renamed_tensorflow_protobuf(
    file_path: Path,
    file_size: int,
    *,
    fail_closed_on_inconclusive: bool = True,
) -> str:
    """Recognize renamed MetaGraph/SavedModel protobufs after bounded field discovery."""
    suffix = file_path.suffix.lower()
    if _is_complete_bounded_printable_text(file_path, file_size):
        return "unknown"
    route = _classify_bounded_tensorflow_protobuf(file_path, file_size)
    if (
        suffix in {".py", ".pyw"}
        and route not in {"tf_metagraph", "tf_savedmodel"}
        and not _has_bounded_non_source_control_signal(file_path, file_size)
    ):
        return "unknown"
    if route == "unknown":
        return "unknown"
    if route == "oversized":
        return "tf_metagraph" if fail_closed_on_inconclusive else route
    if route == "oversized_candidate":
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT if fail_closed_on_inconclusive else route
    if route == "inconclusive":
        if _is_complete_structured_json_content_owner(file_path, file_size):
            return "unknown"
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT if fail_closed_on_inconclusive else route
    return route


def _resolve_inconclusive_tensorflow_flax_overlap(file_path: Path, file_size: int) -> str:
    """Use bounded strict parsing when an ambiguous protobuf also routes as Flax."""
    if file_size > _TF_METAGRAPH_MAX_VALIDATE_BYTES:
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    is_metagraph = _is_tensorflow_metagraph_file(str(file_path))
    is_saved_model = _is_tensorflow_saved_model_file(str(file_path))
    if is_metagraph and is_saved_model:
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    if is_metagraph:
        return "tf_metagraph"
    if is_saved_model:
        return "tf_savedmodel"
    return "flax_msgpack"


def _read_torch7_ascii_header_fields(prefix: bytes, offset: int) -> list[bytes] | None:
    """Read the first six Torch7 ASCII header fields without splitting the suffix."""
    fields: list[bytes] = []
    position = offset
    while len(fields) < 6 and position < len(prefix):
        line_limit = min(len(prefix), position + _TORCH7_ASCII_HEADER_MAX_LINE_BYTES + 1)
        newline = prefix.find(b"\n", position, line_limit)
        carriage_return = prefix.find(b"\r", position, line_limit)
        line_end_candidates = [index for index in (newline, carriage_return) if index != -1]
        if not line_end_candidates:
            if line_limit < len(prefix):
                return None
            fields.append(prefix[position:line_limit])
            break

        line_end = min(line_end_candidates)
        fields.append(prefix[position:line_end])
        position = line_end + 2 if prefix[line_end : line_end + 2] == b"\r\n" else line_end + 1

    return fields if len(fields) >= 6 else None


def _find_torch7_ascii_object_signature_offset(prefix: bytes) -> int | None:
    """Return the offset of a Torch7 ASCII serialized Torch object header."""
    for match in re.finditer(rb"4(?:\r\n|[\r\n])", prefix):
        fields = _read_torch7_ascii_header_fields(prefix, match.start())
        if fields is None:
            continue
        try:
            object_index = int(fields[1])
            version_length = int(fields[2])
            class_name_length = int(fields[4])
        except ValueError:
            continue

        version = fields[3]
        class_name = fields[5]
        if object_index <= 0 or version_length != len(version) or class_name_length != len(class_name):
            continue
        if re.fullmatch(rb"V [+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", version) is None:
            continue
        if class_name.startswith((b"torch.", b"nn.", b"cunn.", b"cutorch.")):
            return match.start()
    return None


def _has_torch7_ascii_object_signature(prefix: bytes) -> bool:
    """Return whether text contains a Torch7 ASCII serialized Torch object header."""
    return _find_torch7_ascii_object_signature_offset(prefix) is not None


def _has_torch7_binary_object_structure(prefix: bytes, offset: int = 0) -> bool:
    """Return whether binary Torch7 magic has nearby serialized Torch structure."""
    if len(prefix) - offset < 8 or not prefix.startswith(b"T7\x00\x00", offset):
        return False
    next_marker = prefix.find(b"T7\x00\x00", offset + len(b"T7\x00\x00"))
    window_end = offset + _TORCH7_SIGNATURE_READ_BYTES if next_marker == -1 else next_marker
    window = prefix[offset:window_end]
    lowered = window.lower()
    has_torch_marker = b"torch" in lowered or b"luat" in lowered
    has_structure_marker = b"nn." in lowered or b"tensor" in lowered or b"thnn" in lowered
    return has_torch_marker and has_structure_marker


def _find_torch7_binary_object_signature_offset(prefix: bytes) -> int | None:
    """Return the offset of a binary Torch7 candidate payload."""
    search_offset = 0
    while True:
        match_offset = prefix.find(b"T7\x00\x00", search_offset)
        if match_offset == -1:
            return None
        if _has_torch7_binary_object_structure(prefix, match_offset):
            return match_offset
        search_offset = match_offset + 1


def _find_torch7_binary_candidate_offset(prefix: bytes) -> int | None:
    """Return the offset of a binary Torch7 candidate worth secondary analysis."""
    search_offset = 0
    while True:
        match_offset = prefix.find(b"T7\x00\x00", search_offset)
        if match_offset == -1:
            return None
        if len(prefix) - match_offset >= 8:
            return match_offset
        search_offset = match_offset + 1


def _is_torch7_signature(prefix: bytes) -> bool:
    lowered = prefix.lower()
    if prefix.startswith(b"T7\x00\x00"):
        return True
    if _has_torch7_ascii_object_signature(prefix):
        return True
    # Marker-only matches must still look serialized. PyTorch source commonly
    # mentions both ``torch`` and ``nn.`` and must not route as Torch7.
    if b"\x00" not in prefix:
        return False
    has_torch_marker = b"torch" in lowered or b"luat" in lowered
    has_structure_marker = b"nn." in lowered or b"tensor" in lowered or b"thnn" in lowered
    return has_torch_marker and has_structure_marker


def find_structural_torch7_offset(payload: bytes) -> int | None:
    """Return the earliest explicit serialized Torch7 signature offset in bytes."""
    binary_offset = _find_torch7_binary_object_signature_offset(payload)
    ascii_offset = _find_torch7_ascii_object_signature_offset(payload)
    offsets = [offset for offset in (binary_offset, ascii_offset) if offset is not None and offset >= 0]
    return min(offsets) if offsets else None


def find_torch7_candidate_offset(payload: bytes) -> int | None:
    """Return the earliest Torch7 candidate with structure or nearby Lua risk signal."""
    binary_offset = _find_torch7_binary_candidate_offset(payload)
    ascii_offset = _find_torch7_ascii_object_signature_offset(payload)
    offsets = [offset for offset in (binary_offset, ascii_offset) if offset is not None and offset >= 0]
    return min(offsets) if offsets else None


def is_torch7_suffix_override_candidate(path: str) -> bool:
    """Return whether suffix dispatch may be safely overridden by Torch7."""
    try:
        prefix = read_magic_bytes(path, _TORCH7_SIGNATURE_READ_BYTES)
    except OSError:
        return False
    if not _is_torch7_signature(prefix):
        return False

    content_format = detect_file_format_from_magic(path)
    if content_format == "torch7":
        return True
    return content_format == "onnx" and (prefix.startswith(b"T7\x00\x00") or _has_torch7_ascii_object_signature(prefix))


def _is_lightgbm_signature(prefix: bytes) -> bool:
    preview = prefix.decode("utf-8", errors="ignore").replace("\x00", "\n").lower()
    starts_with_tree = preview.lstrip().startswith("tree")
    header_hits = sum(1 for marker in _LIGHTGBM_HEADER_MARKERS if marker in preview)
    tree_hits = sum(1 for marker in _LIGHTGBM_TREE_MARKERS if marker in preview)
    xgboost_like = all(marker in preview for marker in _LIGHTGBM_XGBOOST_JSON_MARKERS)
    return (starts_with_tree or "tree=" in preview) and header_hits >= 3 and tree_hits >= 2 and not xgboost_like


def _is_lightgbm_native_tree_record(line: str) -> bool:
    if line == "tree":
        return True
    if not line.startswith("tree="):
        return False
    return line.removeprefix("tree=").strip().isdigit()


def _is_content_routed_lightgbm_signature(prefix: bytes) -> bool:
    """Require native tree framing before routing a misleading suffix as LightGBM."""
    preview = prefix.decode("utf-8", errors="ignore").replace("\x00", "\n").lower()
    native_lines = [line.strip() for line in preview.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not native_lines:
        return False

    nul_offset = prefix.find(b"\x00")
    binary_payload_lines: list[str] = []
    if nul_offset >= 0:
        binary_payload_preview = prefix[nul_offset + 1 :].decode("utf-8", errors="ignore").replace("\x00", "\n").lower()
        binary_payload_lines = [
            line.strip()
            for line in binary_payload_preview.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    has_tree_record = _is_lightgbm_native_tree_record(native_lines[0]) or any(
        _is_lightgbm_native_tree_record(line) for line in binary_payload_lines
    )
    return has_tree_record and _is_lightgbm_signature(prefix)


def _is_executorch_binary_signature(prefix: bytes) -> bool:
    """Recognize versioned ExecuTorch FlatBuffers binaries by their file identifier."""
    return len(prefix) >= 8 and prefix[4:6] == b"ET" and prefix[6:8].isdigit()


def _is_valid_executorch_binary(path: str | Path, *, propagate_io_errors: bool = False) -> bool:
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
    except OSError:
        if propagate_io_errors:
            raise
        return False
    except struct.error:
        return False

    return True


def _detect_executorch_content_route(file_path: Path, magic8: bytes) -> str | None:
    """Preserve signature-valid candidates when structure probing cannot complete."""
    if not _is_executorch_binary_signature(magic8):
        return None
    try:
        if _is_valid_executorch_binary(file_path, propagate_io_errors=True):
            return "executorch"
    except OSError:
        return "executorch"
    return None


def _detect_compression_format(prefix: bytes) -> str | None:
    if prefix.startswith(_GZIP_MAGIC):
        return "gzip"
    if prefix.startswith(_BZIP2_MAGIC):
        return "bzip2"
    if prefix.startswith(_XZ_MAGIC):
        return "xz"
    if prefix.startswith(_LZ4_FRAME_MAGIC):
        return "lz4"
    if is_zlib_header(prefix[:2]):
        return "zlib"
    return None


def _looks_like_renamed_r_serialized_header(prefix: bytes) -> bool:
    """Require a complete R workspace serialization prefix for renamed artifacts."""
    return any(
        prefix.startswith(workspace_header + marker)
        for workspace_header in R_WORKSPACE_HEADERS
        for marker in R_SERIALIZATION_MARKERS
    )


def _could_start_json_object(prefix: bytes) -> bool:
    """Return True when a bounded prefix begins a JSON object after whitespace/BOM."""
    normalized_prefix = prefix.lstrip()
    if normalized_prefix.startswith(b"\xef\xbb\xbf"):
        normalized_prefix = normalized_prefix[3:].lstrip()
    return normalized_prefix.startswith(b"{")


def has_jax_json_checkpoint_structure(payload: object) -> bool:
    """Return whether parsed metadata explicitly identifies a JAX-family checkpoint."""
    if not isinstance(payload, dict):
        return False

    if _JAX_JSON_CHECKPOINT_MARKER_KEYS & payload.keys():
        return True

    for key in _JAX_JSON_CHECKPOINT_IDENTITY_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and _JAX_JSON_CHECKPOINT_IDENTITY_RE.search(value):
            return True
    return False


def _probe_jax_json_checkpoint_file(file_path: Path) -> bool | None:
    """Return True for JAX JSON, None for bounded ambiguity, else False."""
    try:
        if not file_path.is_file():
            return False
        file_size = file_path.stat().st_size
        with file_path.open("rb") as stream:
            prefix = stream.read(min(file_size, JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1))
    except OSError:
        return None

    if not _could_start_json_object(prefix):
        normalized_prefix = prefix.lstrip()
        if normalized_prefix.startswith(b"\xef\xbb\xbf"):
            normalized_prefix = normalized_prefix[3:].lstrip()
        if file_size > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES and not normalized_prefix:
            return None
        return False

    try:
        payload = json.loads(prefix.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        if file_size > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            # A visible non-JAX value cannot prove the unseen tail has no later
            # JAX identity field; preserve bounded ambiguity instead of skipping.
            return None
        return False
    return has_jax_json_checkpoint_structure(payload)


def is_jax_json_checkpoint_file(path: str | Path) -> bool:
    """Preserve confirmed and bounded-inconclusive JAX JSON candidates for scanning."""
    return _probe_jax_json_checkpoint_file(Path(path)) is not False


def _probe_content_routed_jax_json_checkpoint(file_path: Path) -> bool | None:
    """Return the bounded JAX JSON probe state for content-routable suffixes."""
    ext = file_path.suffix.lower()
    if ext in _JAX_JSON_CHECKPOINT_CONTENT_ROUTE_EXCLUDED_SUFFIXES:
        return False
    if not (ext in _JAX_JSON_CHECKPOINT_SCANNER_SUFFIXES or ext not in _JAX_JSON_CHECKPOINT_DECLARED_SUFFIXES):
        return False
    return _probe_jax_json_checkpoint_file(file_path)


def _is_confirmed_content_routed_jax_json_checkpoint(file_path: Path) -> bool:
    """Return whether bounded routing positively identifies JAX JSON metadata."""
    return _probe_content_routed_jax_json_checkpoint(file_path) is True


def _could_be_content_routed_jax_json_checkpoint(file_path: Path) -> bool:
    """Route JAX-owned or renamed JSON candidates without claiming foreign suffixes."""
    return _probe_content_routed_jax_json_checkpoint(file_path) is not False


class _MsgpackProbeInvalid(ValueError):
    """Raised when bounded MessagePack structure probing sees invalid data."""


class _MsgpackProbeIncomplete(_MsgpackProbeInvalid):
    """Raised when a bounded MessagePack prefix ends inside a valid value."""


class _MsgpackProbeLimit(ValueError):
    """Raised when bounded MessagePack structure probing cannot finish safely."""


def _read_msgpack_probe_bytes(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise _MsgpackProbeIncomplete
    return data


def _read_msgpack_probe_uint(stream: BinaryIO, size: int) -> int:
    return int.from_bytes(_read_msgpack_probe_bytes(stream, size), "big")


def _skip_msgpack_probe_bytes(stream: BinaryIO, size: int, file_size: int) -> None:
    if size < 0 or stream.tell() + size > file_size:
        raise _MsgpackProbeIncomplete
    stream.seek(size, 1)


def _consume_msgpack_probe_node(remaining_nodes: list[int]) -> None:
    remaining_nodes[0] -= 1
    if remaining_nodes[0] < 0:
        raise _MsgpackProbeLimit


def _skip_msgpack_probe_value(
    stream: BinaryIO,
    file_size: int,
    remaining_nodes: list[int],
    depth: int,
) -> None:
    marker = _read_msgpack_probe_bytes(stream, 1)[0]
    _consume_msgpack_probe_node(remaining_nodes)
    _skip_msgpack_probe_value_after_marker(stream, marker, file_size, remaining_nodes, depth)


def _skip_msgpack_probe_value_after_marker(
    stream: BinaryIO,
    marker: int,
    file_size: int,
    remaining_nodes: list[int],
    depth: int,
) -> None:
    if marker <= 0x7F or marker >= 0xE0 or marker in {0xC0, 0xC2, 0xC3}:
        return
    if 0xA0 <= marker <= 0xBF:
        _skip_msgpack_probe_bytes(stream, marker & 0x1F, file_size)
        return

    if marker in _FLAX_MSGPACK_PROBE_SCALAR_SIZES:
        _skip_msgpack_probe_bytes(stream, _FLAX_MSGPACK_PROBE_SCALAR_SIZES[marker], file_size)
        return

    if marker in _FLAX_MSGPACK_PROBE_LENGTH_SIZES:
        length_size, type_size = _FLAX_MSGPACK_PROBE_LENGTH_SIZES[marker]
        _skip_msgpack_probe_bytes(stream, _read_msgpack_probe_uint(stream, length_size) + type_size, file_size)
        return

    if depth >= _FLAX_MSGPACK_PROBE_MAX_DEPTH:
        raise _MsgpackProbeLimit

    if 0x90 <= marker <= 0x9F:
        child_count = marker & 0x0F
    elif marker == 0xDC:
        child_count = _read_msgpack_probe_uint(stream, 2)
    elif marker == 0xDD:
        child_count = _read_msgpack_probe_uint(stream, 4)
    elif 0x80 <= marker <= 0x8F:
        child_count = (marker & 0x0F) * 2
    elif marker == 0xDE:
        child_count = _read_msgpack_probe_uint(stream, 2) * 2
    elif marker == 0xDF:
        child_count = _read_msgpack_probe_uint(stream, 4) * 2
    else:
        raise _MsgpackProbeInvalid

    for _ in range(child_count):
        _skip_msgpack_probe_value(stream, file_size, remaining_nodes, depth + 1)


def _is_inline_msgpack_probe_scalar(marker: int) -> bool:
    """Return whether a marker is a complete single-byte scalar value."""
    return marker <= 0x7F or marker >= 0xE0 or marker in {0xC0, 0xC2, 0xC3}


def _read_msgpack_probe_map_count_after_marker(stream: BinaryIO, marker: int) -> int | None:
    if 0x80 <= marker <= 0x8F:
        return marker & 0x0F
    if marker == 0xDE:
        return _read_msgpack_probe_uint(stream, 2)
    if marker == 0xDF:
        return _read_msgpack_probe_uint(stream, 4)
    return None


def _read_msgpack_probe_key(
    stream: BinaryIO,
    file_size: int,
    remaining_nodes: list[int],
) -> str | None:
    marker = _read_msgpack_probe_bytes(stream, 1)[0]
    _consume_msgpack_probe_node(remaining_nodes)
    if 0xA0 <= marker <= 0xBF:
        length = marker & 0x1F
    elif marker in {0xD9, 0xC4}:
        length = _read_msgpack_probe_uint(stream, 1)
    elif marker in {0xDA, 0xC5}:
        length = _read_msgpack_probe_uint(stream, 2)
    elif marker in {0xDB, 0xC6}:
        length = _read_msgpack_probe_uint(stream, 4)
    else:
        _skip_msgpack_probe_value_after_marker(stream, marker, file_size, remaining_nodes, 1)
        return None

    if length > _FLAX_MSGPACK_PROBE_MAX_KEY_BYTES:
        _skip_msgpack_probe_bytes(stream, length, file_size)
        return None
    try:
        return _read_msgpack_probe_bytes(stream, length).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _has_bounded_flax_msgpack_state_root(
    stream: BinaryIO,
    file_size: int,
    remaining_nodes: list[int],
    recognized_checkpoint_root: list[bool],
) -> bool:
    """Recognize a standard state wrapper without accepting generic state maps."""
    marker = _read_msgpack_probe_bytes(stream, 1)[0]
    _consume_msgpack_probe_node(remaining_nodes)
    map_count = _read_msgpack_probe_map_count_after_marker(stream, marker)
    if map_count is None:
        _skip_msgpack_probe_value_after_marker(stream, marker, file_size, remaining_nodes, 1)
        return False

    has_checkpoint_root = False
    for _ in range(map_count):
        if _read_msgpack_probe_key(stream, file_size, remaining_nodes) in _FLAX_MSGPACK_ROUTING_KEYS:
            recognized_checkpoint_root[0] = True
            _skip_msgpack_probe_value(stream, file_size, remaining_nodes, 2)
            has_checkpoint_root = True
        else:
            _skip_msgpack_probe_value(stream, file_size, remaining_nodes, 2)
    return has_checkpoint_root


def _probe_flax_msgpack_checkpoint_stream(
    stream: BinaryIO,
    file_size: int,
    *,
    sample_is_prefix: bool = False,
    incomplete_prefix_is_inconclusive: bool = False,
) -> bool | None:
    """Inspect streamed maps, preserving recognized roots in truncated prefixes."""
    remaining_nodes = [_FLAX_MSGPACK_PROBE_MAX_NODES]
    inline_scalars_seen = 0
    recognized_checkpoint_root = [False]
    try:
        while stream.tell() < file_size:
            marker = _read_msgpack_probe_bytes(stream, 1)[0]
            map_count = _read_msgpack_probe_map_count_after_marker(stream, marker)
            if map_count is None and _is_inline_msgpack_probe_scalar(marker):
                inline_scalars_seen += 1
                if inline_scalars_seen > _FLAX_MSGPACK_PROBE_MAX_INLINE_SCALARS:
                    raise _MsgpackProbeLimit
                continue

            _consume_msgpack_probe_node(remaining_nodes)
            if map_count is None:
                _skip_msgpack_probe_value_after_marker(stream, marker, file_size, remaining_nodes, 0)
                continue
            has_checkpoint_root = False
            for _ in range(map_count):
                key = _read_msgpack_probe_key(stream, file_size, remaining_nodes)
                if key in _FLAX_MSGPACK_ROUTING_KEYS:
                    recognized_checkpoint_root[0] = True
                    _skip_msgpack_probe_value(stream, file_size, remaining_nodes, 1)
                    has_checkpoint_root = True
                if key == _FLAX_MSGPACK_STATE_WRAPPER_KEY:
                    if _has_bounded_flax_msgpack_state_root(
                        stream,
                        file_size,
                        remaining_nodes,
                        recognized_checkpoint_root,
                    ):
                        has_checkpoint_root = True
                elif key not in _FLAX_MSGPACK_ROUTING_KEYS:
                    _skip_msgpack_probe_value(stream, file_size, remaining_nodes, 1)
            if has_checkpoint_root:
                return True
    except _MsgpackProbeLimit:
        # Once a root is recognized, run the scanner so it can analyze sibling
        # security fields even if routing validation exhausts its budget.
        return True if recognized_checkpoint_root[0] else None
    except OSError:
        return None
    except _MsgpackProbeIncomplete:
        if incomplete_prefix_is_inconclusive:
            return None if sample_is_prefix else False
        return sample_is_prefix and recognized_checkpoint_root[0]
    except _MsgpackProbeInvalid:
        return False
    return False


def _has_bounded_flax_msgpack_routing_key(path: Path, file_size: int) -> bool | None:
    """Inspect streamed maps, returning None when safe routing cannot complete."""
    try:
        with path.open("rb") as stream:
            return _probe_flax_msgpack_checkpoint_stream(stream, file_size)
    except OSError:
        return None


def _probe_flax_msgpack_checkpoint_file(file_path: Path) -> bool | None:
    """Return True for Flax structure, None for incomplete inspection, else False."""
    try:
        if not file_path.is_file():
            return False
        file_size = file_path.stat().st_size
        if file_size < 2:
            return False
    except OSError:
        return None

    return _has_bounded_flax_msgpack_routing_key(file_path, file_size)


def is_flax_msgpack_checkpoint_file(path: str | Path) -> bool:
    """Preserve recognized and inconclusive Flax candidates for scanning."""
    return _probe_flax_msgpack_checkpoint_file(Path(path)) is not False


def has_inconclusive_renamed_flax_msgpack_routing(path: str | Path) -> bool:
    """Return whether renamed MessagePack routing could not complete safely."""
    file_path = Path(path)
    if file_path.suffix.lower() in _FLAX_MSGPACK_NATIVE_SUFFIXES:
        return False
    try:
        if _probe_complete_structured_json_document(file_path, file_path.stat().st_size) is None:
            return True
    except OSError:
        return True
    return _probe_flax_msgpack_checkpoint_file(file_path) is None


def _probe_complete_structured_json_document(file_path: Path, file_size: int) -> bool | None:
    """Return whether bounded inspection proves a renamed JSON document complete."""
    read_size = min(file_size, MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1)
    prefix = read_magic_bytes(str(file_path), read_size)
    normalized_prefix = prefix[len(_UTF8_BOM) :] if prefix.startswith(_UTF8_BOM) else prefix
    try:
        decoded_prefix = normalized_prefix.decode("utf-8")
    except UnicodeDecodeError:
        return False

    stripped_prefix = decoded_prefix.lstrip()
    if not stripped_prefix.startswith(("{", "[")):
        return False
    try:
        _, end_offset = json.JSONDecoder().raw_decode(stripped_prefix)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return False
    if stripped_prefix[end_offset:].strip():
        return False
    if read_size == file_size:
        return True

    try:
        with file_path.open("rb") as stream:
            stream.seek(read_size)
            trailing_read_size = min(file_size - read_size, _STRUCTURED_JSON_TRAILING_READ_BYTES)
            trailing_bytes = stream.read(trailing_read_size)
    except OSError:
        return None
    if len(trailing_bytes) != trailing_read_size:
        return None
    if trailing_bytes.strip(b" \t\r\n"):
        return False
    return True if read_size + trailing_read_size == file_size else None


def _is_deep_scalar_array_json_document(payload: str) -> bool:
    """Recognize deeply nested JSON arrays without recursive decoder traversal."""
    stripped = payload.strip()
    depth = 0
    while depth < len(stripped) and stripped[depth] == "[":
        depth += 1
    if depth == 0 or len(stripped) < depth * 2:
        return False
    closing_start = len(stripped) - depth
    if stripped[closing_start:] != "]" * depth:
        return False
    scalar_payload = stripped[depth:closing_start].strip()
    if not scalar_payload:
        return False
    try:
        scalar = json.loads(scalar_payload)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return False
    return not isinstance(scalar, (dict, list))


def _is_complete_structured_json_content_owner(file_path: Path, file_size: int) -> bool:
    """Return whether bounded parsing proves that JSON, not a binary route, owns a file."""
    json_document_probe = _probe_complete_structured_json_document(file_path, file_size)
    if json_document_probe is True:
        return True
    if json_document_probe is None or file_size > MXNET_SYMBOL_SIGNATURE_READ_BYTES:
        return False
    try:
        payload = read_magic_bytes(str(file_path), file_size).decode("utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return False
    return _is_deep_scalar_array_json_document(payload)


def _is_complete_bounded_printable_text(file_path: Path, file_size: int) -> bool:
    """Return whether a small complete file cannot contain binary structure tags."""
    if file_size > _CONTENT_ROUTE_PRINTABLE_TEXT_FAST_PATH_BYTES:
        return False
    try:
        payload = read_magic_bytes(str(file_path), file_size)
    except OSError:
        return False
    return not payload.translate(None, _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES)


def _preserve_inconclusive_protobuf_model_routing(file_path: Path, file_size: int) -> bool:
    """Keep ambiguous binary model protobufs scannable without claiming proven text."""
    if file_path.suffix.lower() in {".py", ".pyw"} and not _has_bounded_non_source_control_signal(file_path, file_size):
        return False
    return not _is_complete_structured_json_content_owner(
        file_path, file_size
    ) and not _is_complete_bounded_printable_text(file_path, file_size)


def _could_be_content_routed_flax_msgpack(file_path: Path) -> bool:
    """Route declared Flax formats and renamed candidates without claiming overlaps."""
    ext = file_path.suffix.lower()
    if ext in _FLAX_MSGPACK_CONTENT_ROUTE_EXCLUDED_SUFFIXES:
        return False
    try:
        size = file_path.stat().st_size
    except OSError:
        return False
    if ext not in _FLAX_MSGPACK_SCANNER_SUFFIXES:
        json_document_probe = _probe_complete_structured_json_document(file_path, size)
        if json_document_probe is True:
            return False
        if json_document_probe is None and ext not in _FLAX_MSGPACK_CONTENT_ROUTE_ALLOWED_DECLARED_SUFFIXES:
            return True
        if _is_complete_bounded_printable_text(file_path, size):
            return False
    if ext == "":
        xgboost_route = _detect_extensionless_xgboost_ubjson_route(
            read_magic_bytes(str(file_path), min(size, _XGBOOST_UBJSON_ROUTE_READ_BYTES))
        )
        if xgboost_route is not None:
            return False
    content_routable = (
        ext in _FLAX_MSGPACK_SCANNER_SUFFIXES
        or ext in _FLAX_MSGPACK_OVERLAP_SUFFIXES
        or ext not in _FLAX_MSGPACK_DECLARED_SUFFIXES
        or ext in _FLAX_MSGPACK_CONTENT_ROUTE_ALLOWED_DECLARED_SUFFIXES
    )
    if not content_routable:
        return False
    probe_state = _probe_flax_msgpack_checkpoint_file(file_path)
    # An oversized document-suffix scalar stream is indistinguishable from a
    # delayed Flax root within the bounded probe, so preserve it fail closed.
    return probe_state is not False


def detect_flax_msgpack_overlap_routes(path: str, *, include_unvalidated_pickle: bool = False) -> tuple[str, ...]:
    """Return trusted foreign content routes that also occur in a Flax candidate."""
    file_path = Path(path)
    try:
        if not file_path.is_file() or not is_flax_msgpack_checkpoint_file(file_path):
            return ()
        size = file_path.stat().st_size
    except OSError:
        return ()

    return _detect_trusted_flax_foreign_content_routes(
        file_path,
        size,
        include_unvalidated_pickle=include_unvalidated_pickle,
    )


def _detect_trusted_flax_foreign_content_routes(
    file_path: Path,
    file_size: int,
    *,
    include_unvalidated_pickle: bool = False,
) -> tuple[str, ...]:
    """Return strict foreign content routes that can safely override or supplement Flax suffixes."""
    prefix = read_magic_bytes(
        str(file_path),
        min(
            file_size,
            max(_TORCH7_SIGNATURE_READ_BYTES, _CNTK_SIGNATURE_READ_BYTES, _LIGHTGBM_SIGNATURE_READ_BYTES),
        ),
    )
    routes: list[str] = []
    pickle_probe_sample = _read_pickle_probe_sample(file_path, file_size, prefix[:16])
    if (
        (include_unvalidated_pickle and _looks_like_binary_pickle_protocol(prefix[:4]))
        or _has_bounded_binary_pickle_security_signal(pickle_probe_sample)
        or _has_bounded_protocolless_binary_pickle_security_signal(
            file_path,
            file_size,
            pickle_probe_sample,
        )
        or _looks_like_proto0_or_1_pickle(
            pickle_probe_sample,
            sample_is_prefix=file_size > len(pickle_probe_sample),
        )
    ):
        routes.append("pickle")
    if _allows_renamed_binary_content_route(file_path) and prefix[:4] == b"RKNN":
        routes.append("rknn")
    if _is_torch7_signature(prefix[:_TORCH7_SIGNATURE_READ_BYTES]):
        routes.append("torch7")
    if file_path.suffix.lower() != ".model" and _is_cntk_signature(prefix[:_CNTK_SIGNATURE_READ_BYTES]):
        routes.append("cntk")
    if _is_content_routed_lightgbm_signature(prefix[:_LIGHTGBM_SIGNATURE_READ_BYTES]):
        routes.append("lightgbm")
    return tuple(routes)


def _resolve_inconclusive_flax_foreign_overlap(file_path: Path) -> str | None:
    """Prefer a proven foreign owner when Flax ownership is not structurally confirmed."""
    probe_state = _probe_flax_msgpack_checkpoint_file(file_path)
    if probe_state is True:
        return None
    if probe_state is False and file_path.suffix.lower() not in _FLAX_MSGPACK_NATIVE_SUFFIXES:
        return None
    try:
        if not file_path.is_file():
            return None
        size = file_path.stat().st_size
    except OSError:
        return None
    return next(iter(_detect_trusted_flax_foreign_content_routes(file_path, size)), None)


def detect_format_from_magic_bytes(
    magic4: MagicBytes,
    magic8: MagicBytes,
    magic16: MagicBytes,
    file_size: int,
    file_path: Path | None = None,
    *,
    include_onnx_structure: bool = True,
    pickle_probe_sample: bytes | None = None,
    pickle_probe_is_prefix: bool | None = None,
) -> FileFormat:
    """Detect file format using Python 3.10+ pattern matching on magic bytes."""
    compression_format = _detect_compression_format(magic16)
    if compression_format:
        if _is_safetensors_routing_candidate(file_path, magic8, file_size):
            return "safetensors"
        return compression_format

    # Use pattern matching for cleaner magic byte detection
    match magic4:
        case b"CBM1":
            return "catboost"
        case b"RKNN" if _allows_renamed_binary_content_route(file_path):
            return "rknn"
        case b"T7\x00\x00" if _allows_renamed_binary_content_route(file_path):
            return "torch7"
        case b"GGUF":
            return "gguf"
        case magic if magic in GGML_MAGIC_VARIANTS:
            return "ggml"
        case magic if _has_zip_magic(magic):
            return "zip"
        case _:
            pass

    coreml_route_status: bool | None = False
    if file_path is not None:
        coreml_route_status = _looks_like_coreml_model_candidate_file(file_path, file_size, magic4)
        if coreml_route_status is True:
            return "coreml"

    # Check longer magic sequences
    match magic8:
        case magic if magic.startswith(_SEVENZIP_MAGIC):
            return "sevenzip"
        case magic if _has_rar_magic(magic):
            return "rar"
        case magic if magic == _CNTK_LEGACY_MAGIC and (file_path is None or file_path.suffix.lower() != ".model"):
            return "cntk"
        case b"\x89HDF\r\n\x1a\n":  # HDF5 magic
            return "hdf5"
        case magic if magic.startswith(b"\x93NUMPY"):
            return "numpy"
        case _:
            pass

    if _looks_like_renamed_r_serialized_header(magic16):
        return "r_serialized"

    onnx_route_status: bool | None = False
    if file_path is not None:
        mxnet_route = _detect_content_routed_mxnet_symbol(file_path, magic16)
        if mxnet_route is not None:
            return mxnet_route
        if include_onnx_structure:
            onnx_route_status = _looks_like_onnx_model_file(file_path, file_size)
            if onnx_route_status is True:
                return "onnx"

    if _is_safetensors_routing_candidate(file_path, magic8, file_size):
        return "safetensors"
    if _looks_like_binary_pickle_protocol(magic4) and (
        file_path is None or not _could_be_content_routed_flax_msgpack(file_path)
    ):
        return "pickle"

    if file_path is None:
        protocol_less_sample = magic16 if pickle_probe_sample is None else pickle_probe_sample
        sample_is_prefix = (
            file_size > len(protocol_less_sample) if pickle_probe_is_prefix is None else pickle_probe_is_prefix
        )
        protocol_less_state = _classify_protocolless_binary_pickle_security_signal(
            protocol_less_sample,
            sample_is_prefix=sample_is_prefix,
        )
        if protocol_less_state is True:
            return "pickle"
        if protocol_less_state is None:
            return PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    if file_path is not None:
        pickle_probe_sample = _read_pickle_probe_sample(file_path, file_size, magic16)
        protocol_less_state = _has_bounded_protocolless_binary_pickle_security_signal(
            file_path,
            file_size,
            pickle_probe_sample,
        )
        if protocol_less_state is True and not _could_be_content_routed_flax_msgpack(file_path):
            return "pickle"
        if protocol_less_state is None and (
            not _could_be_content_routed_flax_msgpack(file_path)
            or _probe_flax_msgpack_checkpoint_file(file_path) is not True
        ):
            return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        if _looks_like_proto0_or_1_pickle(
            pickle_probe_sample,
            sample_is_prefix=file_size > len(pickle_probe_sample),
        ) and not _could_be_content_routed_flax_msgpack(file_path):
            return "pickle"

    if file_path is not None and _is_confirmed_content_routed_jax_json_checkpoint(file_path):
        return "jax_checkpoint"

    if file_path is not None and not file_path.suffix:
        xgboost_route = _detect_extensionless_xgboost_ubjson_route(
            read_magic_bytes(str(file_path), min(file_size, _XGBOOST_UBJSON_ROUTE_READ_BYTES))
        )
        if xgboost_route is not None:
            return xgboost_route

    renamed_tensorflow_format = "unknown"
    if file_path is not None:
        renamed_tensorflow_format = _detect_renamed_tensorflow_protobuf(
            file_path,
            file_size,
            fail_closed_on_inconclusive=False,
        )
        if renamed_tensorflow_format == "oversized":
            return "tf_metagraph"
        if renamed_tensorflow_format == "oversized_candidate":
            return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
        if renamed_tensorflow_format not in {"unknown", "inconclusive"}:
            return renamed_tensorflow_format

    if file_path is not None and not _could_be_xml_prefix(magic16) and _could_be_content_routed_flax_msgpack(file_path):
        foreign_overlap_format = _resolve_inconclusive_flax_foreign_overlap(file_path)
        if foreign_overlap_format is not None:
            return foreign_overlap_format
        if renamed_tensorflow_format == "inconclusive":
            return _resolve_inconclusive_tensorflow_flax_overlap(file_path, file_size)
        if (
            coreml_route_status is None
            and _starts_with_coreml_specification_version(magic16)
            and _preserve_inconclusive_protobuf_model_routing(file_path, file_size)
            and _probe_flax_msgpack_checkpoint_file(file_path) is not True
        ):
            return PROTOBUF_MODEL_CANDIDATE_FORMAT
        return "flax_msgpack"

    if file_path is not None and _could_be_content_routed_jax_json_checkpoint(file_path):
        return "jax_checkpoint"

    if renamed_tensorflow_format == "inconclusive":
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT

    if file_path is not None and file_path.suffix.lower() == ".mlmodel" and coreml_route_status is None:
        return "coreml"

    if (
        coreml_route_status is None
        and file_path is not None
        and _preserve_inconclusive_protobuf_model_routing(file_path, file_size)
    ):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT

    if (
        file_path is not None
        and onnx_route_status is None
        and _preserve_inconclusive_protobuf_model_routing(file_path, file_size)
    ):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT

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
            if _is_tensorflow_metagraph_file(path):
                return "tf_metagraph"
            mxnet_route = _detect_content_routed_mxnet_symbol(file_path, b"{")
            if mxnet_route is not None:
                return mxnet_route
            return _detect_renamed_tensorflow_protobuf(file_path, size)

        with file_path.open("rb") as f:
            header = f.read(min(size, _TAR_BLOCK_SIZE))

            if _looks_like_uncompressed_tar_header(header):
                return _detect_tar_route(path) or "tar"

            magic4 = header[:4]
            magic8 = header[:8]
            magic16 = header[:16]

            if get_extension_format_map().get(file_path.suffix.lower()) == "r_serialized" and (
                any(magic16.startswith(marker) for marker in R_SERIALIZATION_MARKERS)
                or any(magic16.startswith(header) for header in R_WORKSPACE_HEADERS)
            ):
                return "r_serialized"

            llamafile_format = _detect_llamafile_route_format(file_path, magic4)
            if llamafile_format is not None:
                return llamafile_format

            # Try the new pattern matching approach first
            format_result = detect_format_from_magic_bytes(
                magic4,
                magic8,
                magic16,
                size,
                file_path,
            )
            if format_result == "zip" and file_path.suffix.lower() == ".mar" and is_torchserve_mar_archive(path):
                return "torchserve_mar"
            if format_result in {"gzip", "bzip2", "xz"}:
                tar_route = _detect_tar_route(path)
                if tar_route in {"nemo", NEMO_ROUTING_INCONCLUSIVE_FORMAT}:
                    return tar_route
            if format_result != "unknown":
                return format_result

            # Protocol 0/1 pickle payloads can evade short magic-byte checks.
            # Probe a bounded prefix and require a valid opcode stream.
            pickle_probe_sample = _read_pickle_probe_sample(file_path, size, magic16)
            if _looks_like_proto0_or_1_pickle(
                pickle_probe_sample,
                sample_is_prefix=size > len(pickle_probe_sample),
            ):
                return "pickle"

            f.seek(0)
            torch7_prefix = f.read(_TORCH7_SIGNATURE_READ_BYTES)
            if _allows_renamed_binary_content_route(file_path) and _is_torch7_signature(torch7_prefix):
                return "torch7"

            # CNTKv2 has protobuf-style serialization without a fixed first-8-byte magic.
            # Use bounded signature markers for deterministic identification after serialized formats.
            f.seek(0)
            cntk_prefix = f.read(_CNTK_SIGNATURE_READ_BYTES)
            if file_path.suffix.lower() != ".model" and _is_cntk_signature(cntk_prefix):
                return "cntk"

            f.seek(0)
            lightgbm_prefix = f.read(_LIGHTGBM_SIGNATURE_READ_BYTES)
            if _is_content_routed_lightgbm_signature(lightgbm_prefix):
                return "lightgbm"

            if not file_path.suffix:
                f.seek(0)
                xgboost_route = _detect_extensionless_xgboost_ubjson_route(
                    f.read(min(size, _XGBOOST_UBJSON_ROUTE_READ_BYTES))
                )
                if xgboost_route is not None:
                    return xgboost_route

            if (
                _allows_renamed_binary_content_route(file_path)
                and _detect_executorch_content_route(file_path, magic8) == "executorch"
            ):
                return "executorch"
            if file_path.suffix.lower() not in _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS and _looks_like_tflite_header(
                magic8
            ):
                return "tflite"

            # Check for XML-based formats (OpenVINO and PMML) using the first
            # structural root tag rather than a short raw-byte substring.
            if _could_be_xml_prefix(header):
                f.seek(0)
                xml_prefix = f.read(min(size, _XML_MODEL_SIGNATURE_READ_BYTES))
                xml_format = _detect_xml_model_format(
                    xml_prefix,
                    sample_is_prefix=size > len(xml_prefix),
                )
                if xml_format != "unknown":
                    return xml_format
            if _could_be_content_routed_flax_msgpack(file_path):
                return "flax_msgpack"

            renamed_tensorflow_format = _detect_renamed_tensorflow_protobuf(file_path, size)
            if renamed_tensorflow_format != "unknown":
                return renamed_tensorflow_format

    except OSError:
        return "unknown"

    # Fallback: use strict safetensors framing; plain JSON must not be routed as safetensors.
    magic4 = header[:4]
    magic8 = header[:8]

    if _is_safetensors_routing_candidate(file_path, magic8, size):
        return "safetensors"

    coreml_route_status = _looks_like_coreml_model_candidate_file(file_path, size, magic4)
    if coreml_route_status is True:
        return "coreml"
    if coreml_route_status is None and _preserve_inconclusive_protobuf_model_routing(file_path, size):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    if file_path.suffix.lower() not in _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS and _looks_like_tflite_header(magic8):
        return "tflite"
    if _looks_like_onnx_model_file(file_path, size) is None and _preserve_inconclusive_protobuf_model_routing(
        file_path, size
    ):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT

    return "unknown"


def _could_start_proto0_or_1_pickle(sample: bytes) -> bool:
    if not sample:
        return False
    if sample[0] in PROTO0_1_START_BYTES:
        return True
    return len(sample) >= 2 and sample[0] == ord("#") and sample[1] in PROTO0_1_START_BYTES


def _detect_extensionless_xgboost_ubjson_route(prefix: bytes) -> str | None:
    """Return a definite or bounded-inconclusive extensionless XGBoost route."""
    from ...scanners.xgboost_scanner import XGBoostScanner

    probe_state = XGBoostScanner._classify_extensionless_ubjson_probe(prefix)
    if probe_state == "xgboost":
        return "xgboost"
    if probe_state == "inconclusive":
        return XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    return None


def detect_xgboost_ubjson_content_route(path: str) -> str | None:
    """Content-route a bounded UBJSON XGBoost candidate regardless of suffix."""
    file_path = Path(path)
    try:
        if not file_path.is_file():
            return None
        size = file_path.stat().st_size
        if size < 4:
            return None
        return _detect_extensionless_xgboost_ubjson_route(
            read_magic_bytes(path, min(size, _XGBOOST_UBJSON_ROUTE_READ_BYTES))
        )
    except OSError:
        return None


def detect_file_format_for_skip_filter(path: str) -> str:
    """Cheap content detection for skipped-extension preservation.

    This intentionally recognizes only content-derived format signals. It avoids
    extension-based routing and uses bounded content probes so disguised payloads
    reach full scans without unbounded prefilter reads.
    """
    file_path = Path(path)
    if file_path.is_dir():
        if (file_path / "saved_model.pb").exists():
            return "tensorflow_directory"
        return "directory"
    if not file_path.is_file():
        return "unknown"

    size = file_path.stat().st_size
    if size < 4:
        return "unknown"

    initial_read_size = min(size, max(64, _TAR_BLOCK_SIZE))
    with file_path.open("rb") as f:
        prefix = f.read(initial_read_size)

        header = prefix[:16]
        magic4 = header[:4]
        magic8 = header[:8]
        magic16 = header[:16]

        if _looks_like_uncompressed_tar_header(prefix):
            return _detect_tar_route(path) or "tar"

        llamafile_format = _detect_llamafile_route_format(file_path, magic4)
        if llamafile_format is not None:
            return llamafile_format
        format_result = detect_format_from_magic_bytes(
            magic4,
            magic8,
            magic16,
            size,
            file_path,
        )
        if format_result == "zip":
            return "zip"
        if format_result in {"gzip", "bzip2", "xz", "lz4", "zlib"}:
            tar_route = _detect_tar_route(path)
            if tar_route is not None:
                return tar_route
            return format_result
        if format_result != "unknown":
            return format_result

        if _could_start_proto0_or_1_pickle(prefix):
            max_probe_size = min(size, PROTO0_1_MAX_PROBE_BYTES)
            if len(prefix) < max_probe_size:
                prefix += f.read(max_probe_size - len(prefix))
            if _looks_like_proto0_or_1_pickle(
                prefix[:PROTO0_1_MAX_PROBE_BYTES],
                sample_is_prefix=size > min(size, PROTO0_1_MAX_PROBE_BYTES),
            ):
                return "pickle"

        torch7_probe_size = min(size, _TORCH7_SIGNATURE_READ_BYTES)
        if len(prefix) < torch7_probe_size:
            prefix += f.read(torch7_probe_size - len(prefix))
        if _allows_renamed_binary_content_route(file_path) and _is_torch7_signature(prefix):
            return "torch7"

        cntk_probe_size = min(size, _CNTK_SIGNATURE_READ_BYTES)
        if len(prefix) < cntk_probe_size:
            prefix += f.read(cntk_probe_size - len(prefix))
        if file_path.suffix.lower() != ".model" and _is_cntk_signature(prefix[:cntk_probe_size]):
            return "cntk"

        lightgbm_probe_size = min(size, _LIGHTGBM_SIGNATURE_READ_BYTES)
        if len(prefix) < lightgbm_probe_size:
            prefix += f.read(lightgbm_probe_size - len(prefix))
        if _is_content_routed_lightgbm_signature(prefix[:lightgbm_probe_size]):
            return "lightgbm"

        if not file_path.suffix:
            xgboost_probe_size = min(size, _XGBOOST_UBJSON_ROUTE_READ_BYTES)
            if len(prefix) < xgboost_probe_size:
                prefix += f.read(xgboost_probe_size - len(prefix))
            xgboost_route = _detect_extensionless_xgboost_ubjson_route(prefix[:xgboost_probe_size])
            if xgboost_route is not None:
                return xgboost_route

        if (
            _allows_renamed_binary_content_route(file_path)
            and _detect_executorch_content_route(file_path, magic8) == "executorch"
        ):
            return "executorch"
        if file_path.suffix.lower() not in _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS and _looks_like_tflite_header(
            magic8
        ):
            return "tflite"

        if _could_be_xml_prefix(prefix):
            xml_probe_size = min(size, _XML_MODEL_SIGNATURE_READ_BYTES)
            if len(prefix) < xml_probe_size:
                prefix += f.read(xml_probe_size - len(prefix))
            xml_format = _detect_xml_model_format(
                prefix,
                sample_is_prefix=size > len(prefix),
            )
            if xml_format != "unknown":
                return xml_format
        if _could_be_content_routed_flax_msgpack(file_path):
            return "flax_msgpack"

    renamed_tensorflow_format = _detect_renamed_tensorflow_protobuf(file_path, size)
    if renamed_tensorflow_format != "unknown":
        return renamed_tensorflow_format
    coreml_route_status = _looks_like_coreml_model_candidate_file(file_path, size, magic4)
    if coreml_route_status is True:
        return "coreml"
    if coreml_route_status is None and _preserve_inconclusive_protobuf_model_routing(file_path, size):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    if _looks_like_onnx_model_file(file_path, size) is None and _preserve_inconclusive_protobuf_model_routing(
        file_path, size
    ):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
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
        header = f.read(min(size, _TAR_BLOCK_SIZE))

    magic4 = header[:4]
    magic8 = header[:8]
    magic16 = header[:16]
    ext = file_path.suffix.lower()
    filename_lower = file_path.name.lower()

    if magic8.startswith(b"\x93NUMPY"):
        return "numpy"
    mxnet_route = _detect_content_routed_mxnet_symbol(file_path, header)
    if mxnet_route is not None:
        return mxnet_route
    coreml_route_status = _looks_like_coreml_model_candidate_file(file_path, size, magic4)
    if coreml_route_status is True:
        return "coreml"

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
    if ext != ".bin" and _looks_like_renamed_r_serialized_header(magic16):
        return "r_serialized"
    llamafile_format = _detect_llamafile_route_format(file_path, magic4)
    if llamafile_format is not None:
        return llamafile_format

    compression_format = _detect_compression_format(header)
    if compression_format and _is_safetensors_routing_candidate(file_path, magic8, size):
        return "safetensors"
    has_known_container_magic = (
        _has_zip_magic(magic4)
        or magic8.startswith(_SEVENZIP_MAGIC)
        or _has_rar_magic(magic8)
        or _looks_like_uncompressed_tar_header(header)
    )
    if compression_format is None and not has_known_container_magic:
        could_be_flax = _could_be_content_routed_flax_msgpack(file_path)
        if (
            _looks_like_binary_pickle_protocol(magic4)
            and not could_be_flax
            and not _is_safetensors_routing_candidate(file_path, magic8, size)
        ):
            return "pickle"
        pickle_probe_sample = _read_pickle_probe_sample(file_path, size, magic16)
        protocol_less_state = _has_bounded_protocolless_binary_pickle_security_signal(
            file_path,
            size,
            pickle_probe_sample,
        )
        if protocol_less_state is True and not could_be_flax:
            return "pickle"
        if protocol_less_state is None and (
            not could_be_flax or _probe_flax_msgpack_checkpoint_file(file_path) is not True
        ):
            return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        if (
            _looks_like_proto0_or_1_pickle(
                pickle_probe_sample,
                sample_is_prefix=size > len(pickle_probe_sample),
            )
            and not could_be_flax
        ):
            return "pickle"

    # Compound tar wrappers should route to TAR scanner semantics.
    if filename_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        tar_route = _detect_tar_route(path)
        if tar_route is not None:
            return tar_route
        if _detect_compression_format(header) is not None:
            return "tar"
        torch7_prefix = read_magic_bytes(path, _TORCH7_SIGNATURE_READ_BYTES)
        if _is_torch7_signature(torch7_prefix):
            return "torch7"
        return "tar"

    if ext in _COMPRESSED_EXTENSION_CODECS:
        tar_route = _detect_tar_route(path)
        if tar_route is not None:
            return tar_route
        expected_codec = _COMPRESSED_EXTENSION_CODECS[ext]
        if compression_format == expected_codec:
            return "compressed"
        torch7_prefix = read_magic_bytes(path, _TORCH7_SIGNATURE_READ_BYTES)
        if _is_torch7_signature(torch7_prefix):
            return "torch7"
        return "unknown"
    if magic8.startswith(_SEVENZIP_MAGIC):
        return "sevenzip"
    if _has_rar_magic(magic8):
        return "rar"
    if _looks_like_uncompressed_tar_header(header):
        return _detect_tar_route(path) or "tar"
    if compression_format:
        tar_route = _detect_tar_route(path)
        if tar_route is not None:
            return tar_route
        return compression_format
    # Check ZIP magic first (for .pt/.pth files that are actually zips)
    if _has_zip_magic(magic4):
        if ext == ".mar" and is_torchserve_mar_archive(path):
            return "torchserve_mar"
        return "zip"

    onnx_route_status = _looks_like_onnx_model_file(file_path, size)
    if onnx_route_status is True:
        return "onnx"

    if _could_be_xml_prefix(header):
        xml_prefix = read_magic_bytes(path, _XML_MODEL_SIGNATURE_READ_BYTES)
        xml_format = _detect_xml_model_format(
            xml_prefix,
            sample_is_prefix=size > len(xml_prefix),
        )
        if xml_format != "unknown":
            return xml_format

    if ext == "":
        xgboost_route = _detect_extensionless_xgboost_ubjson_route(
            read_magic_bytes(path, min(size, _XGBOOST_UBJSON_ROUTE_READ_BYTES))
        )
        if xgboost_route is not None:
            return xgboost_route

    renamed_tensorflow_format = _detect_renamed_tensorflow_protobuf(
        file_path,
        size,
        fail_closed_on_inconclusive=False,
    )
    if renamed_tensorflow_format == "oversized":
        return "tf_metagraph"
    if renamed_tensorflow_format == "oversized_candidate":
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    if renamed_tensorflow_format not in {"unknown", "inconclusive"}:
        return renamed_tensorflow_format

    if _is_safetensors_routing_candidate(file_path, magic8, size):
        if renamed_tensorflow_format == "inconclusive":
            return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
        return "safetensors"

    if _is_confirmed_content_routed_jax_json_checkpoint(file_path):
        return "jax_checkpoint"

    if ext in _FLAX_MSGPACK_SCANNER_SUFFIXES or _could_be_content_routed_flax_msgpack(file_path):
        foreign_overlap_format = _resolve_inconclusive_flax_foreign_overlap(file_path)
        if foreign_overlap_format is not None:
            return foreign_overlap_format
        if renamed_tensorflow_format == "inconclusive":
            return _resolve_inconclusive_tensorflow_flax_overlap(file_path, size)
        if (
            coreml_route_status is None
            and _starts_with_coreml_specification_version(magic16)
            and _preserve_inconclusive_protobuf_model_routing(file_path, size)
            and _probe_flax_msgpack_checkpoint_file(file_path) is not True
        ):
            return PROTOBUF_MODEL_CANDIDATE_FORMAT
        return "flax_msgpack"

    if _could_be_content_routed_jax_json_checkpoint(file_path):
        return "jax_checkpoint"

    torch7_prefix = read_magic_bytes(path, _TORCH7_SIGNATURE_READ_BYTES)
    if _allows_renamed_binary_content_route(file_path) and _is_torch7_signature(torch7_prefix):
        return "torch7"

    signature_prefix = read_magic_bytes(path, max(_CNTK_SIGNATURE_READ_BYTES, _LIGHTGBM_SIGNATURE_READ_BYTES))
    if ext != ".model" and _is_cntk_signature(signature_prefix[:_CNTK_SIGNATURE_READ_BYTES]):
        return "cntk"
    if _is_content_routed_lightgbm_signature(signature_prefix[:_LIGHTGBM_SIGNATURE_READ_BYTES]):
        return "lightgbm"

    if ext == "":
        xgboost_route = _detect_extensionless_xgboost_ubjson_route(
            read_magic_bytes(path, min(size, _XGBOOST_UBJSON_ROUTE_READ_BYTES))
        )
        if xgboost_route is not None:
            return xgboost_route
    # For .bin files, do more sophisticated detection
    if ext == ".bin":
        magic64 = read_magic_bytes(path, 64)
        # IMPORTANT: Check ZIP format first (PyTorch models saved with torch.save())
        if _has_zip_magic(magic4):
            return "zip"
        if _looks_like_binary_pickle_protocol(magic4):
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
        if _is_safetensors_routing_candidate(file_path, magic8, size):
            return "safetensors"

        if renamed_tensorflow_format == "oversized":
            return "tf_metagraph"
        if renamed_tensorflow_format in {"oversized_candidate", "inconclusive"}:
            return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
        if onnx_route_status is None and _preserve_inconclusive_protobuf_model_routing(file_path, size):
            return PROTOBUF_MODEL_CANDIDATE_FORMAT

        # Otherwise, assume raw binary format (PyTorch weights)
        return "pytorch_binary"

    if (
        _allows_renamed_binary_content_route(file_path)
        and _detect_executorch_content_route(file_path, magic8) == "executorch"
    ):
        return "executorch"
    if _allows_renamed_binary_content_route(file_path) and magic4 == b"RKNN":
        return "rknn"
    if ext not in _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS and _looks_like_tflite_header(magic8):
        return "tflite"

    if renamed_tensorflow_format == "oversized":
        return "tf_metagraph"
    if renamed_tensorflow_format in {"oversized_candidate", "inconclusive"}:
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    if ext == ".mlmodel":
        return "coreml"
    if ext == ".onnx":
        return "onnx"
    if coreml_route_status is None and _preserve_inconclusive_protobuf_model_routing(file_path, size):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    if onnx_route_status is None and _preserve_inconclusive_protobuf_model_routing(file_path, size):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT

    # Extension-based detection for non-.bin files
    # For .pt/.pth/.ckpt files, check if they're ZIP format first
    if ext in (".pt", ".pth", ".ckpt"):
        # These files can be either ZIP or pickle format
        if _has_zip_magic(magic4):
            return "zip"
        # If not ZIP, assume pickle format
        return "pickle"
    if ext == ".meta" and _is_tensorflow_metagraph_file(path):
        return "tf_metagraph"
    if ext in (".ptl", ".pte"):
        if _has_zip_magic(magic4):
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
    if ext in (".engine", ".plan", ".trt"):
        return "tensorrt"
    if ext == ".safetensors":
        return "safetensors"
    if ext in (".pdmodel", ".pdiparams"):
        return "paddle"
    if ext == ".msgpack":
        return "flax_msgpack"
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
        if _has_zip_magic(magic4):
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
    if _is_safetensors_routing_candidate(file_path, magic8, size):
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


_EXTENSION_FORMAT_MAP = get_extension_format_map()


def detect_format_from_extension_pattern_matching(extension: FileExtension) -> FileFormat:
    """Detect format from the descriptor-owned extension-format policy."""
    return _EXTENSION_FORMAT_MAP.get(extension.lower(), "unknown")


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

    # Remaining extension-only policy is centralized with scanner metadata.
    return detect_format_from_extension_pattern_matching(file_path.suffix)


def validate_file_type_with_formats(path: str, header_format: str, ext_format: str) -> bool:
    """Validate file type using precomputed magic/header and extension formats."""
    try:
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
        if ext_format == "pickle" and header_format in {"pickle", "zip", "jax_checkpoint"}:
            return True

        # PyTorch binary files are flexible in format
        if ext_format == "pytorch_binary" and header_format in {
            "pytorch_binary",
            "pickle",
            "r_serialized",
            "zip",
            "unknown",  # .bin files can contain arbitrary binary data
        }:
            return True

        # TensorFlow protobuf files (.pb extension)
        if ext_format == "protobuf" and header_format in {
            "protobuf",
            "unknown",
            "onnx",
            PROTOBUF_MODEL_CANDIDATE_FORMAT,
            "tf_metagraph",
            "tf_savedmodel",
        }:
            return True

        # TensorFlow MetaGraph files (.meta extension) require strict protobuf validation.
        if ext_format == "tf_metagraph":
            if header_format == "tf_savedmodel":
                return True
            return _is_tensorflow_metagraph_file(path)

        # PMML files are XML-based with <PMML> tag detection
        if ext_format == "pmml" and header_format == "pmml":
            return True

        # OpenVINO IR XML can be identified structurally by the dedicated scanner
        # even when bounded magic-byte detection returns unknown for normal XML.
        if ext_format == "openvino":
            return header_format in {"openvino", "unknown"}

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

        # TAR-backed NeMo artifacts remain valid under either declared container suffix.
        if ext_format == "tar":
            filename_lower = Path(path).name.lower()
            if filename_lower.endswith((".tar.gz", ".tgz")):
                return header_format in {"tar", "gzip", "nemo"}
            if filename_lower.endswith((".tar.bz2", ".tbz2")):
                return header_format in {"tar", "bzip2", "nemo"}
            if filename_lower.endswith((".tar.xz", ".txz")):
                return header_format in {"tar", "xz", "nemo"}
            return header_format in {"tar", "nemo"}

        # Standalone compressed wrappers must match their declared codecs.
        if ext_format == "compressed":
            file_extension = Path(path).suffix.lower()
            expected_codec = _COMPRESSED_EXTENSION_CODECS.get(file_extension)
            if expected_codec is None:
                return False
            return header_format == expected_codec

        # NeMo files are TAR archives with a dedicated or structurally recognized route.
        if ext_format == "nemo" and header_format in {"tar", "nemo"}:
            return True

        # ExecuTorch files may be ZIP archives or valid FlatBuffers binaries.
        if ext_format == "executorch":
            if header_format == "zip":
                return True
            return _is_valid_executorch_binary(path) and not zipfile.is_zipfile(path)

        # Keras files can be either ZIP (Keras 3.x) or HDF5 (legacy Keras)
        if ext_format == "keras":
            return header_format in {"zip", "hdf5"} or find_hdf5_signature_offset(path) is not None

        # HDF5 files should always match
        if ext_format == "hdf5":
            return header_format == "hdf5" or find_hdf5_signature_offset(path) is not None

        # SafeTensors files should always match
        if ext_format == "safetensors":
            return header_format == "safetensors"

        # GGUF/GGML files should match their format
        if ext_format in {"gguf", "ggml"}:
            return header_format == ext_format

        # ONNX files (Protocol Buffer format - difficult to detect reliably)
        if ext_format == "onnx":
            return header_format in {"onnx", "unknown", PROTOBUF_MODEL_CANDIDATE_FORMAT}

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
            return header_format in {"coreml", "unknown", PROTOBUF_MODEL_CANDIDATE_FORMAT}

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


def validate_file_type(path: str) -> bool:
    """Validate that a file's magic bytes match its extension-based format."""
    header_format = detect_file_format_from_magic(path)
    ext_format = detect_format_from_extension(path)
    return validate_file_type_with_formats(path, header_format, ext_format)
