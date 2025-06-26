#!/usr/bin/env python3
"""
Generator for safe assets that might look like nested pickles but are legitimate.

This script creates assets that could trigger false positives to test the
robustness of our nested pickle detection.
"""

import base64
import pickle
from pathlib import Path


def generate_safe_nested_assets():
    """Generate safe assets that could trigger false positives."""

    # Ensure output directory exists
    output_dir = Path(__file__).parent.parent / "samples" / "pickles"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating safe nested-like assets in {output_dir}")

    # 1. Legitimate model with base64-like config strings
    print("Creating safe_model_with_tokens.pkl...")
    safe_model_with_tokens = {
        "model_name": "legitimate-gpt2",
        "config": {
            "hidden_size": 768,
            "num_attention_heads": 12,
        },
        # JWT token - legitimate use case for base64-like strings in model configs
        "auth_token": (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
        "metadata": {
            "training_time": "2024-01-15T10:30:00Z",
            "dataset_checksum": "1234567890abcdef" * 8,  # Hex string but not nested pickle
            "description": (
                "This is a legitimate model with some base64-like strings that should not trigger false positives"
            ),
        },
    }

    with open(output_dir / "safe_model_with_tokens.pkl", "wb") as f:
        pickle.dump(safe_model_with_tokens, f)

    # 2. Model with embedded non-pickle binary data
    print("Creating safe_model_with_binary.pkl...")

    # Create some binary data that is NOT a pickle
    fake_tensor_data = b"\x00\x01\x02\x03" * 256  # Binary data but not pickle
    compressed_data = b"\x1f\x8b\x08\x00" + b"fake gzip data" * 50  # Looks like gzip

    safe_model_with_binary = {
        "model_type": "cnn",
        "layers": ["conv1", "pool1", "conv2", "pool2", "fc1", "fc2"],
        "weights_binary": fake_tensor_data,  # Binary but not pickle
        "compressed_config": compressed_data,  # Binary but not pickle
        "tensor_metadata": {"shape": [224, 224, 3], "dtype": "float32", "serialization_format": "custom_binary_v2"},
    }

    with open(output_dir / "safe_model_with_binary.pkl", "wb") as f:
        pickle.dump(safe_model_with_binary, f)

    # 3. Model with legitimate encoded data
    print("Creating safe_model_with_encoding.pkl...")

    # Legitimate use cases for encoding in models
    legitimate_json_config = '{"hidden_size": 768, "num_layers": 12}'
    legitimate_yaml_config = "model:\n  type: transformer\n  layers: 12"

    safe_model_with_encoding = {
        "model_name": "safe-transformer",
        "config_json_b64": base64.b64encode(legitimate_json_config.encode()).decode(),
        "config_yaml_b64": base64.b64encode(legitimate_yaml_config.encode()).decode(),
        "license_text": base64.b64encode(b"MIT License\nCopyright (c) 2024").decode(),
        # Hex-encoded but legitimate data
        "model_signature": "deadbeef" * 32,  # Hex but not nested pickle
        "weights": {"embedding": "placeholder_tensor_data", "attention": "placeholder_tensor_data"},
    }

    with open(output_dir / "safe_model_with_encoding.pkl", "wb") as f:
        pickle.dump(safe_model_with_encoding, f)

    # 4. Large model with repeating patterns (should not trigger detection)
    print("Creating safe_large_model.pkl...")

    # Create data that might look suspicious due to patterns
    repeating_pattern = "ABCD1234" * 100  # Repeating pattern
    large_config = "=" * 200  # Many equals (could look like base64 padding)

    safe_large_model = {
        "model_architecture": "very-large-transformer",
        "config": {
            "pattern_data": repeating_pattern,
            "padding_config": large_config,
            "layer_configs": ["layer_" + str(i) for i in range(1000)],  # Large list
        },
        "weights": {f"layer_{i}": [0.1] * 1000 for i in range(50)},  # Large nested structure
        "optimizer_state": {
            "momentum": [0.9] * 10000,
            "learning_rate_schedule": [0.001 * (0.95**i) for i in range(1000)],
        },
    }

    with open(output_dir / "safe_large_model.pkl", "wb") as f:
        pickle.dump(safe_large_model, f)

    # 5. Model with legitimate nested structures
    print("Creating safe_nested_structure.pkl...")

    # Legitimate nested data structures that aren't nested pickles
    nested_config = {
        "level1": {"level2": {"level3": {"model_params": {"hidden_size": 768, "intermediate_size": 3072}}}}
    }

    safe_nested_structure = {
        "model_name": "nested-config-model",
        "deep_config": nested_config,
        "serialized_metadata": str(nested_config),  # String representation
        "binary_placeholder": b"not a pickle just binary data" * 10,
        "weights": {
            "encoder": {"layers": {f"layer_{i}": {"weight": [0.1] * 100, "bias": [0.0] * 100} for i in range(12)}}
        },
    }

    with open(output_dir / "safe_nested_structure.pkl", "wb") as f:
        pickle.dump(safe_nested_structure, f)

    print("✅ All safe nested-like assets generated successfully!")
    print("Generated safe files:")
    for pkl_file in output_dir.glob("safe_*.pkl"):
        print(f"  - {pkl_file.name}")


if __name__ == "__main__":
    generate_safe_nested_assets()
