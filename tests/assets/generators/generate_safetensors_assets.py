#!/usr/bin/env python3
"""
Generate SafeTensors test assets for security testing.

This script creates the small committed SafeTensors fixtures used by the
regression corpus. Scanner-specific metadata cases should usually live in
typed pytest tests that build temporary fixtures.
"""

import json
import struct
from pathlib import Path

import numpy as np

_DTYPE_CODES = {
    np.dtype("float32"): "F32",
}


def _write_safetensors(path: Path, tensors: dict[str, np.ndarray], metadata: dict[str, str]) -> None:
    """Write a tiny deterministic SafeTensors file for committed fixtures."""
    header: dict[str, object] = {"__metadata__": dict(sorted(metadata.items()))}
    data_chunks: list[bytes] = []
    offset = 0

    for name, tensor in sorted(tensors.items()):
        array = np.ascontiguousarray(tensor)
        dtype_code = _DTYPE_CODES.get(array.dtype)
        if dtype_code is None:
            raise ValueError(f"Unsupported fixture tensor dtype for {name}: {array.dtype}")

        tensor_data = array.tobytes(order="C")
        next_offset = offset + len(tensor_data)
        header[name] = {
            "dtype": dtype_code,
            "shape": list(array.shape),
            "data_offsets": [offset, next_offset],
        }
        data_chunks.append(tensor_data)
        offset = next_offset

    header_bytes = json.dumps(header, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header_padding = (8 - (len(header_bytes) % 8)) % 8
    header_bytes += b" " * header_padding

    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + b"".join(data_chunks))


def generate_safetensors_assets(assets_dir: Path | None = None) -> None:
    """Generate the committed SafeTensors regression assets."""
    if assets_dir is None:
        assets_dir = Path(__file__).parent.parent / "samples" / "safetensors"
    assets_dir.mkdir(exist_ok=True)

    print("Generating SafeTensors regression assets...")

    base_data = {
        "embeddings": np.arange(8, dtype=np.float32).reshape(2, 4),
        "bias": np.zeros(4, dtype=np.float32),
    }

    safe_metadata: dict[str, str] = {
        "model_name": "transformer-small",
        "author": "Safe ML Team",
        "version": "1.2.3",
        "description": "A small transformer model for text classification",
        "license": "MIT",
    }

    safe_path = assets_dir / "safe_model.safetensors"
    _write_safetensors(safe_path, base_data, safe_metadata)
    print(f"Generated: {safe_path.name} (safe baseline)")

    malicious_path = assets_dir / "malicious_import.safetensors"
    malicious_metadata = {
        "model_info": "import os; os.system('echo pwned')",
        "description": "Legitimate looking model with malicious import statement",
    }
    _write_safetensors(malicious_path, base_data, malicious_metadata)
    print(f"Generated: {malicious_path.name} (malicious metadata baseline)")

    print(f"\nSafeTensors assets location: {assets_dir}")
    print("SafeTensors regression assets generated successfully.")


if __name__ == "__main__":
    generate_safetensors_assets()
