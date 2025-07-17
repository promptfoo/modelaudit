# ModelAudit

**Secure your AI models before deployment.** Detects malicious code, backdoors, and security vulnerabilities in ML model files.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Tests](https://github.com/promptfoo/modelaudit/actions/workflows/test.yml/badge.svg)](https://github.com/promptfoo/modelaudit/actions/workflows/test.yml)
[![Code Style: ruff](https://img.shields.io/badge/code%20style-ruff-005cd7.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/github/license/promptfoo/promptfoo)](https://github.com/promptfoo/promptfoo/blob/main/LICENSE)

<img width="989" alt="image" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

📖 **[Full Documentation](https://www.promptfoo.dev/docs/model-audit/)** | 🎯 **[Usage Examples](https://www.promptfoo.dev/docs/model-audit/usage/)** | 🔍 **[Supported Formats](https://www.promptfoo.dev/docs/model-audit/scanners/)**

## 🚀 Quick Start

**Install and scan in 30 seconds:**

```bash
# Install ModelAudit with all ML framework support
pip install modelaudit[all]

# Scan a model file
modelaudit model.pkl

# Scan a directory
modelaudit ./models/

# Export results for CI/CD
modelaudit model.pkl --format json --output results.json
```

**Example output:**

```bash
$ modelaudit suspicious_model.pkl

✓ Scanning suspicious_model.pkl
Files scanned: 1 | Issues found: 2 critical, 1 warning

1. suspicious_model.pkl (pos 28): [CRITICAL] Malicious code execution attempt
   Why: Contains os.system() call that could run arbitrary commands

2. suspicious_model.pkl (pos 52): [WARNING] Dangerous pickle deserialization
   Why: Could execute code when the model loads

✗ Security issues found - DO NOT deploy this model
```

## 🛡️ What Problems It Solves

### **Prevents Code Execution Attacks**

Stops malicious models that run arbitrary commands when loaded (common in PyTorch .pt files)

### **Detects Model Backdoors**

Identifies trojaned models with hidden functionality or suspicious weight patterns

### **Ensures Supply Chain Security**

Validates model integrity and prevents tampering in your ML pipeline

### **Enforces License Compliance**

Checks for license violations that could expose your company to legal risk

## 📊 Supported Model Formats

ModelAudit scans **all major ML model formats** with specialized security analysis for each:

| Format          | Extensions                 | Risk Level | Notes                                        |
| --------------- | -------------------------- | ---------- | -------------------------------------------- |
| **PyTorch**     | `.pt`, `.pth`              | 🔴 HIGH    | Contains pickle serialization - always scan  |
| **Pickle**      | `.pkl`, `.pickle`, `.dill` | 🔴 HIGH    | Avoid in production - convert to SafeTensors |
| **SafeTensors** | `.safetensors`             | 🟢 SAFE    | Preferred secure format                      |
| **GGUF/GGML**   | `.gguf`, `.ggml`           | 🟢 SAFE    | LLM standard, binary format                  |
| **ONNX**        | `.onnx`                    | 🟢 SAFE    | Industry standard, good interoperability     |
| **TensorFlow**  | `.pb`, SavedModel          | 🟠 MEDIUM  | Scan for dangerous operations                |
| **Keras**       | `.h5`, `.keras`            | 🟠 MEDIUM  | Check for executable layers                  |
| **JAX/Flax**    | `.msgpack`, `.orbax`       | 🟡 LOW     | Validate transforms                          |

[View complete format documentation →](https://www.promptfoo.dev/docs/model-audit/scanners/)

## 🎯 Common Use Cases

### **Pre-Deployment Security Checks**

```bash
modelaudit production_model.safetensors --format json --output security_report.json
```

### **CI/CD Pipeline Integration**

```bash
modelaudit models/ --exit-code-on-issues --timeout 300
```

### **Third-Party Model Validation**

```bash
# Scan models from HuggingFace or cloud storage
modelaudit https://huggingface.co/gpt2
modelaudit s3://my-bucket/downloaded-model.pt
```

### **Compliance & Audit Reporting**

```bash
modelaudit model_package.zip --sbom compliance_report.json --verbose
```

[View advanced usage examples →](https://www.promptfoo.dev/docs/model-audit/usage/)

## ⚙️ Installation Options

**Basic installation (recommended for most users):**

```bash
pip install modelaudit[all]
```

**Minimal installation with specific formats:**

```bash
# Basic installation
pip install modelaudit

# Add specific format support as needed
pip install modelaudit[tensorflow]  # TensorFlow SavedModel
pip install modelaudit[pytorch]     # PyTorch models
pip install modelaudit[onnx]        # ONNX models
```

**NumPy compatibility:**

```bash
# For full compatibility with all ML frameworks
pip install modelaudit[numpy1]

# Check scanner compatibility status
modelaudit doctor --show-failed
```

**Docker installation:**

```bash
docker pull ghcr.io/promptfoo/modelaudit:latest
docker run --rm -v $(pwd):/data ghcr.io/promptfoo/modelaudit:latest model.pkl
```

## 📋 Output Formats

**Human-readable output (default):**

```bash
$ modelaudit model.pkl

✓ Scanning model.pkl
Files scanned: 1 | Issues found: 1 critical

1. model.pkl (pos 28): [CRITICAL] Malicious code execution attempt
   Why: Contains os.system() call that could run arbitrary commands
```

**JSON output for automation:**

```json
{
  "files_scanned": 1,
  "issues": [
    {
      "message": "Malicious code execution attempt",
      "severity": "critical",
      "location": "model.pkl (pos 28)"
    }
  ]
}
```

## 🔧 Getting Help

- **Documentation**: [promptfoo.dev/docs/model-audit/](https://www.promptfoo.dev/docs/model-audit/)
- **Troubleshooting**: [promptfoo.dev/docs/model-audit/troubleshooting/](https://www.promptfoo.dev/docs/model-audit/troubleshooting/)
- **Issues**: [github.com/promptfoo/modelaudit/issues](https://github.com/promptfoo/modelaudit/issues)

For scanner compatibility issues:

```bash
modelaudit doctor --show-failed
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.