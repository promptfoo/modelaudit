#!/usr/bin/env python3
"""
JAX/Flax Model Scanning Demo

This script demonstrates the enhanced JAX and Flax model scanning capabilities
in ModelAudit, including support for:
- Msgpack-based Flax checkpoints
- Orbax checkpoint format
- JAX-specific security threat detection
- Architecture analysis and metadata extraction
"""

import json
import os
import pickle
import tempfile

import msgpack

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("Warning: NumPy not available, some demos will be skipped")

from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner


def create_sample_flax_checkpoint(path: str):
    """Create a sample Flax checkpoint with transformer architecture."""
    if not HAS_NUMPY:
        print("Skipping Flax checkpoint creation - NumPy not available")
        return False

    # Simulate a transformer model checkpoint
    checkpoint_data = {
        "params": {
            "transformer": {
                "embeddings": {
                    "token_embedding": np.random.randn(50257, 768).astype(np.float32).tobytes(),
                    "position_embedding": np.random.randn(1024, 768).astype(np.float32).tobytes(),
                },
                "encoder": {
                    "layer_0": {
                        "attention": {
                            "query": np.random.randn(768, 768).astype(np.float32).tobytes(),
                            "key": np.random.randn(768, 768).astype(np.float32).tobytes(),
                            "value": np.random.randn(768, 768).astype(np.float32).tobytes(),
                        },
                        "feed_forward": {
                            "dense": np.random.randn(768, 3072).astype(np.float32).tobytes(),
                            "output": np.random.randn(3072, 768).astype(np.float32).tobytes(),
                        },
                        "layer_norm": {
                            "scale": np.ones(768).astype(np.float32).tobytes(),
                            "bias": np.zeros(768).astype(np.float32).tobytes(),
                        },
                    }
                },
            }
        },
        "opt_state": {"step": 10000, "learning_rate": 1e-4, "adam": {"beta1": 0.9, "beta2": 0.999, "eps": 1e-8}},
        "metadata": {
            "model_type": "transformer",
            "layers": 12,
            "hidden_size": 768,
            "vocab_size": 50257,
            "jax_version": "0.4.23",
            "flax_version": "0.7.5",
        },
    }

    with open(path, "wb") as f:
        msgpack.pack(checkpoint_data, f, use_bin_type=True)

    return True


def create_suspicious_jax_checkpoint(path: str):
    """Create a JAX checkpoint with security threats."""
    suspicious_data = {
        "params": {"layer": np.random.randn(10, 10).tobytes() if HAS_NUMPY else b"\x00" * 400},
        # JAX-specific threats
        "__jax_array__": "malicious_array_metadata",
        "custom_transform": "jax.experimental.host_callback.call(malicious_function)",
        "eval_code": "exec(open('/tmp/malicious.py').read())",
        # Invalid tensor shapes
        "tensor_info": {
            "shape": [-1, 100, -50],  # Negative dimensions
            "dtype": "malicious_dtype",
        },
        # Orbax-specific threats
        "__orbax_metadata__": {
            "restore_fn": "eval(user_input)",
            "custom_serializer": "subprocess.run(['rm', '-rf', '/'])",
        },
    }

    with open(path, "wb") as f:
        msgpack.pack(suspicious_data, f, use_bin_type=True)


def create_orbax_checkpoint_directory(dir_path: str):
    """Create an Orbax checkpoint directory structure."""
    os.makedirs(dir_path, exist_ok=True)

    # Create metadata
    metadata = {
        "version": "0.1.0",
        "type": "orbax_checkpoint",
        "format": "flax",
        "save_args": {"step": 5000, "timestamp": "2024-01-15T10:30:00Z"},
    }

    with open(os.path.join(dir_path, "orbax_checkpoint_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    # Create checkpoint files
    if HAS_NUMPY:
        params_data = {
            "model": {
                "dense_layers": {
                    "layer_0": np.random.randn(128, 64).astype(np.float32),
                    "layer_1": np.random.randn(64, 32).astype(np.float32),
                    "output": np.random.randn(32, 10).astype(np.float32),
                }
            }
        }
    else:
        params_data = {"model": {"dense_layers": {"layer_0": [1.0] * 100, "layer_1": [0.5] * 50, "output": [0.1] * 10}}}

    with open(os.path.join(dir_path, "checkpoint"), "wb") as f:
        pickle.dump(params_data, f)


def demo_flax_msgpack_scanning():
    """Demonstrate Flax msgpack scanning capabilities."""
    print("\n" + "=" * 60)
    print("🔬 FLAX MSGPACK SCANNER DEMO")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Test 1: Legitimate Flax checkpoint
        print("\n📁 Test 1: Scanning legitimate Flax checkpoint")
        flax_path = os.path.join(tmp_dir, "transformer_model.msgpack")
        if create_sample_flax_checkpoint(flax_path):
            scanner = FlaxMsgpackScanner()
            result = scanner.scan(flax_path)

            print(f"  ✅ Scan completed: {result.success}")
            print(f"  📊 Issues found: {len(result.issues)}")
            print(f"  🏗️  Model architecture: {result.metadata.get('model_architecture', 'unknown')}")
            print(f"  🧮 Estimated parameters: {result.metadata.get('estimated_parameters', 0):,}")
            print(f"  📈 Layer count: {result.metadata.get('layer_count', 0)}")

            # Show JAX-specific metadata
            jax_metadata = result.metadata.get("jax_metadata", {})
            print(f"  🎯 ML confidence: {jax_metadata.get('confidence', 0):.2f}")
            print(f"  🔧 Has optimizer: {jax_metadata.get('has_optimizer_state', False)}")

        # Test 2: Suspicious JAX checkpoint
        print("\n📁 Test 2: Scanning suspicious JAX checkpoint")
        suspicious_path = os.path.join(tmp_dir, "suspicious_model.jax")
        create_suspicious_jax_checkpoint(suspicious_path)

        scanner = FlaxMsgpackScanner()
        result = scanner.scan(suspicious_path)

        print(f"  ⚠️  Scan completed: {result.success}")
        print(f"  🚨 Issues found: {len(result.issues)}")

        # Show critical issues
        critical_issues = [issue for issue in result.issues if issue.severity == "critical"]
        if critical_issues:
            print("  🔴 Critical security issues:")
            for i, issue in enumerate(critical_issues[:3], 1):  # Show first 3
                print(f"    {i}. {issue.message}")

        # Test 3: File extension support
        print("\n📁 Test 3: Testing file extension support")
        extensions = [".msgpack", ".flax", ".orbax", ".jax"]
        for ext in extensions:
            test_path = os.path.join(tmp_dir, f"test{ext}")
            with open(test_path, "wb") as f:
                msgpack.pack({"test": "data"}, f)

            can_handle = FlaxMsgpackScanner.can_handle(test_path)
            print(f"  {ext}: {'✅' if can_handle else '❌'}")


def demo_jax_checkpoint_scanning():
    """Demonstrate JAX checkpoint scanning capabilities."""
    print("\n" + "=" * 60)
    print("🔬 JAX CHECKPOINT SCANNER DEMO")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Test 1: Orbax checkpoint directory
        print("\n📁 Test 1: Scanning Orbax checkpoint directory")
        orbax_dir = os.path.join(tmp_dir, "orbax_checkpoint")
        create_orbax_checkpoint_directory(orbax_dir)

        scanner = JaxCheckpointScanner()
        result = scanner.scan(orbax_dir)

        print(f"  ✅ Scan completed: {result.success}")
        print(f"  📊 Issues found: {len(result.issues)}")
        print(f"  📁 Checkpoint type: {result.metadata.get('checkpoint_type', 'unknown')}")
        print(f"  💾 Total size: {result.metadata.get('total_size', 0):,} bytes")
        print(f"  🔍 Orbax version: {result.metadata.get('orbax_version', 'N/A')}")

        # Test 2: Directory detection
        print("\n📁 Test 2: Testing checkpoint directory detection")
        test_dirs = [("orbax_checkpoint", True), ("regular_directory", False), ("pytorch_checkpoint", False)]

        for dir_name, should_handle in test_dirs:
            test_dir = os.path.join(tmp_dir, dir_name)
            os.makedirs(test_dir, exist_ok=True)

            if dir_name == "orbax_checkpoint":
                # Already created above
                pass
            elif dir_name == "pytorch_checkpoint":
                # Create PyTorch-style checkpoint
                with open(os.path.join(test_dir, "model.pth"), "w") as f:
                    f.write("pytorch model")

            can_handle = JaxCheckpointScanner.can_handle(test_dir)
            status = "✅" if can_handle == should_handle else "❌"
            print(f"  {dir_name}: {status} (expected: {should_handle}, got: {can_handle})")


def demo_security_threat_detection():
    """Demonstrate security threat detection in JAX/Flax models."""
    print("\n" + "=" * 60)
    print("🛡️  SECURITY THREAT DETECTION DEMO")
    print("=" * 60)

    threats = [
        {
            "name": "JAX Host Callback Exploit",
            "data": {
                "params": {"weights": b"\x00" * 100},
                "malicious_code": "jax.experimental.host_callback.call(os.system, 'rm -rf /')",
            },
        },
        {
            "name": "Orbax Restore Function Injection",
            "data": {
                "__orbax_metadata__": {"restore_fn": "eval(user_controlled_input)"},
                "params": {"layer": b"\x00" * 50},
            },
        },
        {
            "name": "Invalid Tensor Dimensions",
            "data": {
                "params": {"tensor": b"\x00" * 100},
                "shape_info": {
                    "shape": [-1, -100, 1000000000],  # Negative and extremely large dims
                    "dtype": "float32",
                },
            },
        },
        {
            "name": "Fake JAX Array Metadata",
            "data": {
                "__jax_array__": "malicious_array_impl",
                "__tree_flatten__": "custom_flatten_function",
                "params": {"data": b"\x00" * 100},
            },
        },
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        scanner = FlaxMsgpackScanner()

        for i, threat in enumerate(threats, 1):
            print(f"\n🔍 Test {i}: {threat['name']}")

            threat_path = os.path.join(tmp_dir, f"threat_{i}.msgpack")
            with open(threat_path, "wb") as f:
                msgpack.pack(threat["data"], f, use_bin_type=True)

            result = scanner.scan(threat_path)

            critical_issues = [issue for issue in result.issues if issue.severity == "critical"]
            warning_issues = [issue for issue in result.issues if issue.severity == "warning"]

            if critical_issues or warning_issues:
                print(f"  🚨 Threats detected: {len(critical_issues)} critical, {len(warning_issues)} warnings")
                if critical_issues:
                    print(f"    🔴 {critical_issues[0].message}")
            else:
                print("  ❌ No threats detected (potential false negative)")


def main():
    """Run all JAX/Flax scanning demos."""
    print("🚀 ModelAudit JAX/Flax Enhanced Scanning Demo")
    print("=" * 60)
    print("This demo showcases the enhanced JAX and Flax model scanning capabilities:")
    print("• Flax msgpack checkpoint analysis")
    print("• Orbax checkpoint format support")
    print("• JAX-specific security threat detection")
    print("• Model architecture and metadata extraction")

    try:
        demo_flax_msgpack_scanning()
        demo_jax_checkpoint_scanning()
        demo_security_threat_detection()

        print("\n" + "=" * 60)
        print("✅ Demo completed successfully!")
        print("=" * 60)
        print("\nKey features demonstrated:")
        print("• Support for .msgpack, .flax, .orbax, .jax file extensions")
        print("• Orbax checkpoint directory scanning")
        print("• JAX-specific security pattern detection")
        print("• ML model architecture analysis")
        print("• Enhanced metadata extraction")
        print("• Large model support (up to 500MB+ embeddings)")
        print("\nFor production use:")
        print("• Install with: pip install modelaudit[flax,msgpack]")
        print("• Scan models: modelaudit scan your_model.flax")
        print("• Use --verbose for detailed analysis")

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        print("Please ensure you have the required dependencies installed:")
        print("  pip install msgpack numpy")


if __name__ == "__main__":
    main()
