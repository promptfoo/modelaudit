#!/usr/bin/env python3
"""
Generator for malicious nested pickle assets for security testing.

This script creates various types of nested pickle attacks to test the
enhanced nested pickle detection capabilities.
"""

import base64
import pickle
from pathlib import Path


class MaliciousInnerPayload:
    """A malicious class that executes code when unpickled."""

    def __reduce__(self):
        # Simulated malicious payload (safe for testing)
        return (print, ("MALICIOUS: Nested pickle executed!",))


def generate_nested_pickle_assets():
    """Generate various nested pickle attack samples."""

    # Ensure output directory exists
    output_dir = Path(__file__).parent.parent / "samples" / "pickles"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating nested pickle assets in {output_dir}")

    # 1. Raw nested pickle attack
    print("Creating nested_pickle_raw.pkl...")
    inner_obj = MaliciousInnerPayload()
    inner_bytes = pickle.dumps(inner_obj)

    raw_attack_data = {
        "legitimate_data": {"weights": [1, 2, 3]},
        "hidden_payload": inner_bytes,  # Raw nested pickle bytes
    }

    with open(output_dir / "nested_pickle_raw.pkl", "wb") as f:
        pickle.dump(raw_attack_data, f)

    # 2. Base64-encoded nested pickle (stored as string)
    print("Creating nested_pickle_base64.pkl...")
    inner_obj = MaliciousInnerPayload()
    inner_bytes = pickle.dumps(inner_obj)
    b64_encoded = base64.b64encode(inner_bytes).decode("ascii")

    b64_attack_data = {
        "model_config": "ResNet50",
        "encoded_weights": b64_encoded,  # This will be stored as a STRING opcode
        "metadata": {"version": "1.0", "description": "A model with base64-encoded malicious payload"},
    }

    with open(output_dir / "nested_pickle_base64.pkl", "wb") as f:
        pickle.dump(b64_attack_data, f)

    # 3. Hex-encoded nested pickle (stored as string)
    print("Creating nested_pickle_hex.pkl...")
    inner_obj = MaliciousInnerPayload()
    inner_bytes = pickle.dumps(inner_obj)
    hex_encoded = inner_bytes.hex()

    hex_attack_data = {
        "architecture": "transformer",
        "hex_data": hex_encoded,  # This will be stored as a STRING opcode
        "config": {"hidden_size": 768, "num_layers": 12},
    }

    with open(output_dir / "nested_pickle_hex.pkl", "wb") as f:
        pickle.dump(hex_attack_data, f)

    # 4. Multi-stage nested attack
    print("Creating nested_pickle_multistage.pkl...")
    inner_obj = MaliciousInnerPayload()
    stage2_bytes = pickle.dumps(inner_obj)
    stage1_bytes = pickle.dumps({"stage2": stage2_bytes})

    multi_attack_data = {
        "model_metadata": {"version": "1.0"},
        "stage1_payload": stage1_bytes,  # Raw nested
        "stage1_encoded": base64.b64encode(stage1_bytes).decode("ascii"),  # Encoded nested
    }

    with open(output_dir / "nested_pickle_multistage.pkl", "wb") as f:
        pickle.dump(multi_attack_data, f)

    # 5. Complex realistic model with hidden payload
    print("Creating malicious_model_realistic.pkl...")

    # Create a realistic-looking model structure
    inner_malicious = MaliciousInnerPayload()
    inner_bytes = pickle.dumps(inner_malicious)

    realistic_model = {
        "model_name": "bert-base-uncased",
        "model_type": "transformer",
        "config": {"hidden_size": 768, "num_attention_heads": 12, "num_hidden_layers": 12, "vocab_size": 30522},
        "state_dict": {
            "embeddings.weight": "placeholder_tensor_data",
            "encoder.layer.0.attention.self.query.weight": "placeholder_tensor_data",
            "encoder.layer.0.attention.self.key.weight": "placeholder_tensor_data",
        },
        "optimizer_state": "placeholder_optimizer_data",
        # Hidden malicious payload disguised as model metadata
        "training_metadata": inner_bytes,  # Raw nested pickle
        "tokenizer_config": base64.b64encode(inner_bytes).decode("ascii"),  # Base64 nested
    }

    with open(output_dir / "malicious_model_realistic.pkl", "wb") as f:
        pickle.dump(realistic_model, f)

    # 6. Decode-exec chain attack (simulate manually)
    print("Creating decode_exec_chain.pkl...")

    # Create a more direct approach - store base64 strings that decode to suspicious content
    malicious_code = "os.system('echo ATTACK')"
    encoded_code = base64.b64encode(malicious_code.encode()).decode("ascii")

    # Also create a nested pickle encoded in base64
    inner_malicious = MaliciousInnerPayload()
    inner_bytes = pickle.dumps(inner_malicious)
    encoded_pickle = base64.b64encode(inner_bytes).decode("ascii")

    decode_exec_payload = {
        "model_version": "1.0",
        "legitimate_field": "normal_data",
        # These will trigger different detection patterns
        "suspicious_code": encoded_code,  # Base64-encoded malicious code
        "suspicious_payload": encoded_pickle,  # Base64-encoded nested pickle
        "_internal_config": malicious_code,  # Direct code string
    }

    with open(output_dir / "decode_exec_chain.pkl", "wb") as f:
        pickle.dump(decode_exec_payload, f)

    # 7. Simple direct nested pickle (for easier testing)
    print("Creating simple_nested.pkl...")
    inner_simple = {"malicious": "data"}
    inner_simple_bytes = pickle.dumps(inner_simple)

    simple_nested = {"outer_data": "legitimate", "inner_pickle": inner_simple_bytes}

    with open(output_dir / "simple_nested.pkl", "wb") as f:
        pickle.dump(simple_nested, f)

    print("✅ All nested pickle assets generated successfully!")
    print("Generated files:")
    for pkl_file in sorted(output_dir.glob("nested_pickle_*.pkl")):
        print(f"  - {pkl_file.name}")
    for pkl_file in sorted(output_dir.glob("malicious_*.pkl")):
        print(f"  - {pkl_file.name}")
    for pkl_file in sorted(output_dir.glob("decode_exec_*.pkl")):
        print(f"  - {pkl_file.name}")
    for pkl_file in sorted(output_dir.glob("simple_*.pkl")):
        print(f"  - {pkl_file.name}")


if __name__ == "__main__":
    generate_nested_pickle_assets()
