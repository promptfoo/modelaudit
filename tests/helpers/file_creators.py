"""
Common file creation utilities for tests.

These utilities create various model file formats for testing purposes.
All functions accept a Path and create the file at that location.
"""

import json
import pickle
import struct
import zipfile
from pathlib import Path
from typing import Any


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


def create_mock_gguf(path: Path, *, version: int = 3) -> Path:
    """Create a mock GGUF file for testing.

    Args:
        path: Where to create the file
        version: GGUF version number

    Returns:
        Path to created file
    """
    # GGUF magic: "GGUF" + version (little-endian uint32)
    magic = b"GGUF"
    version_bytes = struct.pack("<I", version)
    # Minimal header: tensor_count=0, metadata_kv_count=0
    tensor_count = struct.pack("<Q", 0)
    metadata_count = struct.pack("<Q", 0)

    path.write_bytes(magic + version_bytes + tensor_count + metadata_count)
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
