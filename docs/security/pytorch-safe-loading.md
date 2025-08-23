# PyTorch Safe Loading Practices

Secure techniques for loading PyTorch models to prevent code execution attacks.

## ✅ Recommended Approaches

### 1. Use SafeTensors Format (Best)

```python
from safetensors.torch import load_file, save_file
import torch
import torch.nn as nn

# Save model safely
model = MyModel()
save_file(model.state_dict(), "model.safetensors")

# Load model safely
state_dict = load_file("model.safetensors")
model = MyModel()
model.load_state_dict(state_dict)
```

### 2. Updated PyTorch with Validation

```python
import torch
import hashlib
import os

def safe_load_pytorch_model(model_path, expected_hash=None, trusted_source=False):
    """Safely load PyTorch model with validation"""

    # 1. Verify file hash if provided
    if expected_hash:
        with open(model_path, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"Model hash mismatch: {actual_hash} != {expected_hash}")

    # 2. Check PyTorch version
    torch_version = torch.__version__
    if not trusted_source and torch_version <= "2.5.1":
        raise ValueError(f"PyTorch {torch_version} vulnerable to CVE-2025-32434")

    # 3. Load with weights_only (but don't rely on it for security)
    try:
        return torch.load(model_path, weights_only=True, map_location='cpu')
    except Exception as e:
        raise ValueError(f"Model loading failed: {e}")

# Usage
model_dict = safe_load_pytorch_model(
    "model.pt",
    expected_hash="abc123...",
    trusted_source=True
)
```

### 3. Sandboxed Loading

```python
import subprocess
import tempfile
import json

def load_model_in_sandbox(model_path):
    """Load model in isolated process"""

    # Create sandbox script
    sandbox_script = '''
import torch
import sys
import json

try:
    model = torch.load(sys.argv[1], weights_only=True, map_location='cpu')
    # Extract only safe data
    result = {
        "success": True,
        "state_dict_keys": list(model.keys()) if isinstance(model, dict) else [],
        "model_type": str(type(model))
    }
    print(json.dumps(result))
except Exception as e:
    result = {"success": False, "error": str(e)}
    print(json.dumps(result))
    '''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(sandbox_script)
        script_path = f.name

    try:
        # Run in isolated process
        result = subprocess.run([
            'python', script_path, model_path
        ], capture_output=True, text=True, timeout=30)

        return json.loads(result.stdout)
    finally:
        os.unlink(script_path)
```

## ❌ Dangerous Practices to Avoid

```python
# ❌ NEVER: Loading untrusted models without validation
model = torch.load('untrusted_model.pt')  # Can execute arbitrary code

# ❌ NEVER: Relying on weights_only=True for security
model = torch.load('untrusted_model.pt', weights_only=True)  # CVE-2025-32434

# ❌ NEVER: Loading models over HTTP without validation
import urllib.request
urllib.request.urlretrieve('http://evil.com/model.pt', 'model.pt')
model = torch.load('model.pt')

# ❌ NEVER: Ignoring model source validation
def load_any_model(url):
    # Download and load without any validation
    return torch.load(download_model(url))
```

## Best Practices Summary

1. **Always verify model source and integrity**
2. **Use SafeTensors format when possible**
3. **Keep PyTorch updated to latest version**
4. **Implement hash verification for model files**
5. **Consider sandboxed loading for untrusted models**
6. **Never rely solely on `weights_only=True` for security**

## Related Guides

- [PyTorch Security Overview](pytorch-overview.md) - Understanding threat vectors
- [Supply Chain Security](pytorch-supply-chain.md) - Model source validation
- [Security Checklist](pytorch-checklist.md) - Complete security checklist
