"""
Common file creation utilities for tests.

These utilities create various model file formats for testing purposes.
All functions accept a Path and create the file at that location.
"""

import base64
import json
import pickle
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

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


def _encode_proto_varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _coreml_field_varint(field_number: int, value: int) -> bytes:
    return _encode_proto_varint(field_number << 3) + _encode_proto_varint(value)


def _coreml_field_bytes(field_number: int, value: bytes) -> bytes:
    return _encode_proto_varint((field_number << 3) | 2) + _encode_proto_varint(len(value)) + value


def create_mock_coreml(
    path: Path,
    *,
    custom_class: str | None = None,
    custom_parameter: tuple[str, str] | None = None,
    model_type_first: bool = False,
    model_type_padding: int = 0,
) -> Path:
    """Create a minimal structurally valid CoreML model fixture."""
    metadata = _coreml_field_bytes(1, b"Mock CoreML model")
    description = _coreml_field_bytes(100, metadata)
    layer = _coreml_field_bytes(1, b"layer_1")
    if custom_class is not None:
        custom = _coreml_field_bytes(10, custom_class.encode("utf-8"))
        if custom_parameter is not None:
            key, value = custom_parameter
            parameter_value = _coreml_field_bytes(20, value.encode("utf-8"))
            parameter = _coreml_field_bytes(1, key.encode("utf-8")) + _coreml_field_bytes(2, parameter_value)
            custom += _coreml_field_bytes(30, parameter)
        layer += _coreml_field_bytes(500, custom)
    neural_network = _coreml_field_bytes(1, layer) + (b"\x00" * model_type_padding)
    fields = [_coreml_field_varint(1, 8), _coreml_field_bytes(2, description), _coreml_field_bytes(500, neural_network)]
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
                class MaliciousClass:
                    def __reduce__(self):
                        return (eval, ("print('malicious code')",))

                data["malicious"] = MaliciousClass()

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


def create_resource_limited_safetensors_index(
    path: Path,
    weight_map: dict[str, str],
    *,
    max_bytes: int | None = None,
    max_tokens: int | None = None,
) -> Path:
    """Create a valid index just beyond one production parser resource limit."""
    if (max_bytes is None) == (max_tokens is None):
        raise ValueError("exactly one SafeTensors index resource limit is required")
    weight_map_json = json.dumps(weight_map, separators=(",", ":"))
    if max_bytes is not None:
        prefix = '{"metadata":{"padding":"'
        suffix = f'"}},"weight_map":{weight_map_json}}}'
        padding_size = max(max_bytes + 1 - len(prefix.encode()) - len(suffix.encode()), 0)
        payload = prefix + ("x" * padding_size) + suffix
    else:
        assert max_tokens is not None
        payload = f'{{"metadata":[{"0," * max_tokens}0],"weight_map":{weight_map_json}}}'
    path.write_text(payload, encoding="utf-8")
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
