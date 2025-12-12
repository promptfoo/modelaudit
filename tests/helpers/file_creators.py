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
) -> Path:
    """Create a mock PyTorch ZIP model file.

    Args:
        path: Where to create the file
        with_pickle: Whether to include a pickle file inside
        malicious: Whether to include malicious code (for testing detection)
        data: Optional custom data dict to pickle

    Returns:
        Path to created file
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("version", "3")
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
            zf.writestr("data.pkl", pickled_data)

        # Add a model config file
        zf.writestr("model.json", '{"name": "test_model"}')
    return path


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
