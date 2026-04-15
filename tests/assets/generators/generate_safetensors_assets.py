#!/usr/bin/env python3
"""
Generate SafeTensors test assets for security testing.

This script creates the small committed SafeTensors fixtures used by the
regression corpus. Scanner-specific metadata cases should usually live in
typed pytest tests that build temporary fixtures.
"""

from pathlib import Path

import numpy as np
from safetensors.numpy import save_file


def generate_safetensors_assets() -> None:
    """Generate the committed SafeTensors regression assets."""
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
    save_file(base_data, str(safe_path), metadata=safe_metadata)
    print(f"Generated: {safe_path.name} (safe baseline)")

    malicious_path = assets_dir / "malicious_import.safetensors"
    malicious_metadata = {
        "model_info": "import os; os.system('echo pwned')",
        "description": "Legitimate looking model with malicious import statement",
    }
    save_file(base_data, str(malicious_path), metadata=malicious_metadata)
    print(f"Generated: {malicious_path.name} (malicious metadata baseline)")

    print(f"\nSafeTensors assets location: {assets_dir}")
    print("SafeTensors regression assets generated successfully.")


if __name__ == "__main__":
    generate_safetensors_assets()
