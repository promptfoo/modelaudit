import json
import pickletools
import re
import struct
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from ...scanner_registry_metadata import get_extension_format_map
from ..helpers.types import FileExtension, FileFormat, FilePath, MagicBytes
from ._compression import is_zlib_header

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
_ONNX_PROTO_SIGNATURE_READ_BYTES = 1024 * 1024
_ONNX_MODEL_TOP_LEVEL_TAG_START_BYTES = frozenset(
    {
        0x08,  # ir_version
        0x12,  # producer_name
        0x1A,  # producer_version
        0x22,  # domain
        0x28,  # model_version
        0x32,  # doc_string
        0x3A,  # graph
        0x42,  # opset_import
        0x72,  # metadata_props
    }
)
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
_XML_MODEL_SIGNATURE_READ_BYTES = 1024 * 1024
_XML_MODEL_ROOT_FORMATS = {
    "model": "openvino",
    "net": "openvino",
    "pmml": "pmml",
}
XML_MODEL_INCONCLUSIVE_FORMAT = "xml_model_inconclusive"
_JINJA2_SUSPICIOUS_TEMPLATE_CHUNK_BYTES = 8192
_JINJA2_TEMPLATE_SYNTAX_MARKERS = (b"{{", b"{%", b"{#")
_JINJA2_SUSPICIOUS_TEMPLATE_MARKERS = (
    b"__globals__",
    b"__builtins__",
    b"__subclasses__",
    b"__mro__",
    b"__import__",
    b"os.system",
    b"os.popen",
    b"subprocess.",
    b"pty.spawn",
)
_JINJA2_NATIVE_SUFFIXES = frozenset({".gguf", ".json", ".yaml", ".yml", ".jinja", ".j2", ".template"})
_COMPRESSED_EXTENSION_CODECS = {
    ".gz": "gzip",
    ".bz2": "bzip2",
    ".xz": "xz",
    ".lz4": "lz4",
    ".zlib": "zlib",
}


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


def _read_proto_varint(data: bytes, offset: int, end: int | None = None) -> tuple[int, int] | None:
    """Read a protobuf varint from bounded data."""
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


def _has_onnx_model_tag_start(data: bytes) -> bool:
    """Return True when data starts with a plausible ONNX ModelProto field tag."""
    return bool(data) and data[0] in _ONNX_MODEL_TOP_LEVEL_TAG_START_BYTES


def _read_length_delimited_proto_value(
    data: bytes,
    offset: int,
    end: int | None = None,
) -> tuple[int, int, int, int] | None:
    """Return protobuf length-delimited value bounds within the sampled prefix."""
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


def _looks_like_onnx_node_proto_prefix(data: bytes) -> bool:
    """Return True when a bounded prefix resembles an ONNX NodeProto."""
    offset = 0
    fields_seen = 0
    has_input_or_output = False
    has_op_type = False
    while offset < len(data) and fields_seen < 128:
        tag_result = _read_proto_varint(data, offset)
        if tag_result is None:
            break
        tag, value_offset = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if wire_type == 2 and field_number in {1, 2, 4}:
            bounds = _read_length_delimited_proto_value(data, value_offset)
            if bounds is None:
                break
            length, value_start, value_end, actual_value_end = bounds
            if field_number in {1, 2} and 0 < length <= 1024:
                has_input_or_output = True
            elif field_number == 4 and 0 < length <= 1024:
                op_type = data[value_start:value_end]
                has_op_type = bool(op_type) and all(32 <= byte < 127 for byte in op_type)
            offset = actual_value_end
        else:
            next_offset = _skip_proto_value(data, value_offset, wire_type)
            if next_offset is None:
                break
            offset = next_offset

        fields_seen += 1
        if has_input_or_output and has_op_type:
            return True

    return False


def _looks_like_onnx_graph_proto_prefix(data: bytes) -> bool:
    """Return True when a bounded prefix resembles an ONNX GraphProto."""
    offset = 0
    fields_seen = 0
    has_node = False
    has_initializer = False
    value_info_fields: set[int] = set()

    while offset < len(data) and fields_seen < 512:
        tag_result = _read_proto_varint(data, offset)
        if tag_result is None:
            break
        tag, value_offset = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if wire_type == 2:
            bounds = _read_length_delimited_proto_value(data, value_offset)
            if bounds is None:
                break
            _length, value_start, value_end, actual_value_end = bounds
            if field_number == 1 and _looks_like_onnx_node_proto_prefix(data[value_start:value_end]):
                has_node = True
            elif field_number == 5:
                has_initializer = True
            elif field_number in {11, 12, 13}:
                value_info_fields.add(field_number)
            offset = actual_value_end
        else:
            next_offset = _skip_proto_value(data, value_offset, wire_type)
            if next_offset is None:
                break
            offset = next_offset

        fields_seen += 1
        if (has_node and value_info_fields) or len(value_info_fields) >= 2:
            return True

    return has_initializer and bool(value_info_fields)


def _looks_like_onnx_model_proto_prefix(data: bytes) -> bool:
    """Return True when a bounded prefix resembles an ONNX ModelProto."""
    if not _has_onnx_model_tag_start(data):
        return False

    offset = 0
    fields_seen = 0
    has_plausible_ir_version = False
    has_graph = False

    while offset < len(data) and fields_seen < 512:
        tag_result = _read_proto_varint(data, offset)
        if tag_result is None:
            break
        tag, value_offset = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return False

        if field_number == 1 and wire_type == 0:
            value_result = _read_proto_varint(data, value_offset)
            if value_result is None:
                break
            ir_version, offset = value_result
            has_plausible_ir_version = 0 < ir_version <= 1000
        elif field_number == 7 and wire_type == 2:
            bounds = _read_length_delimited_proto_value(data, value_offset)
            if bounds is None:
                break
            length, value_start, value_end, actual_value_end = bounds
            if length > 0 and _looks_like_onnx_graph_proto_prefix(data[value_start:value_end]):
                has_graph = True
            offset = actual_value_end
        else:
            next_offset = _skip_proto_value(data, value_offset, wire_type)
            if next_offset is None:
                break
            offset = next_offset

        fields_seen += 1
        if has_plausible_ir_version and has_graph:
            return True

    return False


def _looks_like_onnx_model_file(path: Path, size: int) -> bool:
    """Detect real ONNX ModelProto structure with a bounded prefix read."""
    if size < 4:
        return False
    try:
        with path.open("rb") as handle:
            prefix = handle.read(min(size, _ONNX_PROTO_SIGNATURE_READ_BYTES))
    except OSError:
        return False
    return _looks_like_onnx_model_proto_prefix(prefix)


def _looks_like_onnx_model_candidate_file(path: Path, size: int, header: bytes) -> bool:
    """Run the bounded ONNX parser only for plausible protobuf tag starts."""
    return _has_onnx_model_tag_start(header) and _looks_like_onnx_model_file(path, size)


def _looks_like_binary_pickle_protocol(header: bytes) -> bool:
    return (
        len(header) >= 2
        and header[0] == 0x80
        and _MIN_BINARY_PICKLE_PROTOCOL <= header[1] <= _MAX_FORWARD_COMPAT_BINARY_PICKLE_PROTOCOL
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


def _looks_like_tflite_header(header: bytes) -> bool:
    """Return True when the FlatBuffer identifier is `TFL3` at bytes 4-7."""
    return (
        len(header) >= _TFLITE_MIN_HEADER_SIZE
        and header[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + _TFLITE_MAGIC_SIZE] == _TFLITE_MAGIC_BYTES
    )


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
                if _looks_like_pytorch_zip_storage_members(member_names, prefix):
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

        if not metagraph.HasField("graph_def"):
            return False

        graph_node_count = len(metagraph.graph_def.node)
        function_node_count = sum(len(function.node_def) for function in metagraph.graph_def.library.function)
        collection_count = len(metagraph.collection_def)
        return graph_node_count > 0 or function_node_count > 0 or collection_count > 0
    except Exception:
        return False


def _has_torch7_ascii_object_signature(prefix: bytes) -> bool:
    """Return whether text contains a Torch7 ASCII serialized Torch object header."""
    fields = prefix.splitlines()
    for offset in range(len(fields) - 5):
        if fields[offset] != b"4":
            continue
        try:
            object_index = int(fields[offset + 1])
            version_length = int(fields[offset + 2])
            class_name_length = int(fields[offset + 4])
        except ValueError:
            continue

        version = fields[offset + 3]
        class_name = fields[offset + 5]
        if object_index <= 0 or version_length != len(version) or class_name_length != len(class_name):
            continue
        if re.fullmatch(rb"V [+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", version) is None:
            continue
        if class_name.startswith((b"torch.", b"nn.", b"cunn.", b"cutorch.")):
            return True
    return False


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


def is_suspicious_jinja2_template_file(path: str | Path) -> bool:
    """Recognize high-signal SSTI content with bounded-memory streaming."""
    file_path = Path(path)
    max_marker_length = max(
        *(len(marker) for marker in _JINJA2_TEMPLATE_SYNTAX_MARKERS),
        *(len(marker) for marker in _JINJA2_SUSPICIOUS_TEMPLATE_MARKERS),
    )
    overlap = b""
    syntax_found = False
    suspicious_marker_found = False
    try:
        if not file_path.is_file():
            return False
        with file_path.open("rb") as f:
            while chunk := f.read(_JINJA2_SUSPICIOUS_TEMPLATE_CHUNK_BYTES):
                sample = overlap + chunk
                lowered_sample = sample.lower()
                syntax_found = syntax_found or any(marker in sample for marker in _JINJA2_TEMPLATE_SYNTAX_MARKERS)
                suspicious_marker_found = suspicious_marker_found or any(
                    marker in lowered_sample for marker in _JINJA2_SUSPICIOUS_TEMPLATE_MARKERS
                )
                if syntax_found and suspicious_marker_found:
                    return True
                overlap = sample[-(max_marker_length - 1) :]
    except OSError:
        return False

    return False


def _could_be_renamed_suspicious_jinja2_template(file_path: Path) -> bool:
    """Route non-native suffixes only after streamed high-signal SSTI inspection."""
    return file_path.suffix.lower() not in _JINJA2_NATIVE_SUFFIXES and is_suspicious_jinja2_template_file(file_path)


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
        case magic if _has_zip_magic(magic):
            return "zip"
        case _:
            pass

    if file_path is not None and _looks_like_onnx_model_candidate_file(file_path, file_size, magic4):
        return "onnx"

    # Check longer magic sequences
    match magic8:
        case magic if magic.startswith(_SEVENZIP_MAGIC):
            return "sevenzip"
        case magic if _has_rar_magic(magic):
            return "rar"
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

    if _looks_like_binary_pickle_protocol(magic4):
        return "pickle"
    if _looks_like_safetensors_structure(file_path, magic8, file_size):
        return "safetensors"

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
            header = f.read(min(size, _TAR_BLOCK_SIZE))

            if _looks_like_uncompressed_tar_header(header):
                return "tar"

            magic4 = header[:4]
            magic8 = header[:8]
            magic16 = header[:16]

            if _looks_like_tflite_header(magic8):
                return "tflite"

            if _is_executorch_binary_signature(magic8) and _is_valid_executorch_binary(file_path):
                return "executorch"

            # Try the new pattern matching approach first
            format_result = detect_format_from_magic_bytes(magic4, magic8, magic16, size, file_path)
            if format_result == "zip" and file_path.suffix.lower() == ".mar" and is_torchserve_mar_archive(path):
                return "torchserve_mar"
            if format_result != "unknown":
                return format_result

            if _could_be_renamed_suspicious_jinja2_template(file_path):
                return "jinja2_template"

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

    except OSError:
        return "unknown"

    # Fallback: use strict safetensors framing; plain JSON must not be routed as safetensors.
    magic4 = header[:4]
    magic8 = header[:8]

    if _looks_like_tflite_header(magic8):
        return "tflite"

    if _looks_like_safetensors_structure(file_path, magic8, size):
        return "safetensors"

    if _looks_like_onnx_model_candidate_file(file_path, size, magic4):
        return "onnx"

    return "unknown"


def _could_start_proto0_or_1_pickle(sample: bytes) -> bool:
    if not sample:
        return False
    if sample[0] in PROTO0_1_START_BYTES:
        return True
    return len(sample) >= 2 and sample[0] == ord("#") and sample[1] in PROTO0_1_START_BYTES


def detect_file_format_for_skip_filter(path: str) -> str:
    """Cheap content detection for skipped-extension preservation.

    This intentionally recognizes only content-derived format signals. It avoids
    extension-based routing and uses one bounded prefix read for common skipped
    files, while still preserving disguised model/archive payloads for full scans.
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
            return "tar"

        if _looks_like_tflite_header(magic8):
            return "tflite"
        if _is_executorch_binary_signature(magic8) and _is_valid_executorch_binary(file_path):
            return "executorch"

        format_result = detect_format_from_magic_bytes(magic4, magic8, magic16, size, file_path)
        if format_result == "zip":
            return "zip"
        if format_result in {"gzip", "bzip2", "xz", "lz4", "zlib"}:
            if _is_tar_archive(path):
                return "tar"
            return format_result
        if format_result != "unknown":
            return format_result

        if _could_be_renamed_suspicious_jinja2_template(file_path):
            return "jinja2_template"

        lightgbm_probe_size = min(size, _LIGHTGBM_SIGNATURE_READ_BYTES)
        if len(prefix) < lightgbm_probe_size:
            prefix += f.read(lightgbm_probe_size - len(prefix))
        if _is_lightgbm_signature(prefix):
            return "lightgbm"

        if _could_start_proto0_or_1_pickle(prefix):
            max_probe_size = min(size, PROTO0_1_MAX_PROBE_BYTES)
            if len(prefix) < max_probe_size:
                prefix += f.read(max_probe_size - len(prefix))
            if _looks_like_proto0_or_1_pickle(
                prefix[:PROTO0_1_MAX_PROBE_BYTES],
                sample_is_prefix=size > min(size, PROTO0_1_MAX_PROBE_BYTES),
            ):
                return "pickle"

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

    if magic8.startswith(b"\x93NUMPY"):
        return "numpy"
    if _looks_like_onnx_model_candidate_file(file_path, size, magic4):
        return "onnx"

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
    if _has_rar_magic(magic8):
        return "rar"
    if _looks_like_uncompressed_tar_header(header):
        return "tar"
    if compression_format:
        if _is_tar_archive(path):
            return "tar"
        return compression_format
    # Check ZIP magic first (for .pt/.pth files that are actually zips)
    if _has_zip_magic(magic4):
        if ext == ".mar" and is_torchserve_mar_archive(path):
            return "torchserve_mar"
        return "zip"

    if _looks_like_binary_pickle_protocol(magic4):
        return "pickle"
    pickle_probe_sample = _read_pickle_probe_sample(file_path, size, magic16)
    if _looks_like_proto0_or_1_pickle(
        pickle_probe_sample,
        sample_is_prefix=size > len(pickle_probe_sample),
    ):
        return "pickle"
    if _could_be_xml_prefix(header):
        xml_prefix = read_magic_bytes(path, _XML_MODEL_SIGNATURE_READ_BYTES)
        xml_format = _detect_xml_model_format(
            xml_prefix,
            sample_is_prefix=size > len(xml_prefix),
        )
        if xml_format != "unknown":
            return xml_format

    if _could_be_renamed_suspicious_jinja2_template(file_path):
        return "jinja2_template"

    # For .bin files, do more sophisticated detection
    if ext == ".bin":
        magic64 = read_magic_bytes(path, 64)
        if _looks_like_tflite_header(magic8):
            return "tflite"
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
        if _looks_like_safetensors_structure(file_path, magic8, size):
            return "safetensors"

        # Check for ONNX format (protobuf)
        if _looks_like_onnx_model_candidate_file(file_path, size, magic4):
            return "onnx"

        # Otherwise, assume raw binary format (PyTorch weights)
        return "pytorch_binary"

    # Extension-based detection for non-.bin files
    # For .pt/.pth/.ckpt files, check if they're ZIP format first
    if ext in (".pt", ".pth", ".ckpt"):
        # These files can be either ZIP or pickle format
        if _has_zip_magic(magic4):
            return "zip"
        # If not ZIP, assume pickle format
        return "pickle"
    if ext == ".meta":
        if _is_tensorflow_metagraph_file(path):
            return "tf_metagraph"
        return "unknown"
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
        if ext_format == "pickle" and header_format in {"pickle", "zip"}:
            return True

        # PyTorch binary files are flexible in format
        if ext_format == "pytorch_binary" and header_format in {
            "pytorch_binary",
            "pickle",
            "tflite",
            "zip",
            "unknown",  # .bin files can contain arbitrary binary data
        }:
            return True

        # TensorFlow protobuf files (.pb extension)
        if ext_format == "protobuf" and header_format in {"protobuf", "unknown", "onnx"}:
            return True

        # TensorFlow MetaGraph files (.meta extension) require strict protobuf validation.
        if ext_format == "tf_metagraph":
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


def validate_file_type(path: str) -> bool:
    """Validate that a file's magic bytes match its extension-based format."""
    header_format = detect_file_format_from_magic(path)
    ext_format = detect_format_from_extension(path)
    return validate_file_type_with_formats(path, header_format, ext_format)
