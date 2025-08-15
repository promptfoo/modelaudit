# ModelAudit

**Secure your AI models before deployment.** Detects malicious code, backdoors, and security vulnerabilities in ML model files.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit.svg)](https://pypi.org/project/modelaudit/)
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

| Format          | Extensions                            | Risk Level | Notes                                        |
| --------------- | ------------------------------------- | ---------- | -------------------------------------------- |
| **PyTorch**     | `.pt`, `.pth`, `.ckpt`, `.bin`        | 🔴 HIGH    | Contains pickle serialization - always scan  |
| **Pickle**      | `.pkl`, `.pickle`, `.dill`            | 🔴 HIGH    | Avoid in production - convert to SafeTensors |
| **Joblib**      | `.joblib`                             | 🔴 HIGH    | Can contain pickled objects                  |
| **SafeTensors** | `.safetensors`                        | 🟢 SAFE    | Preferred secure format                      |
| **GGUF/GGML**   | `.gguf`, `.ggml`                      | 🟢 SAFE    | LLM standard, binary format                  |
| **ONNX**        | `.onnx`                               | 🟢 SAFE    | Industry standard, good interoperability     |
| **TensorFlow**  | `.pb`, SavedModel                     | 🟠 MEDIUM  | Scan for dangerous operations                |
| **Keras**       | `.h5`, `.keras`, `.hdf5`              | 🟠 MEDIUM  | Check for executable layers                  |
| **JAX/Flax**    | `.msgpack`, `.flax`, `.orbax`, `.jax` | 🟡 LOW     | Validate transforms                          |

Plus 10+ additional formats including ExecuTorch, TensorFlow Lite, Core ML, and more.

[View complete format documentation →](https://www.promptfoo.dev/docs/model-audit/scanners/)

## 🎯 Common Use Cases

### **Pre-Deployment Security Checks**

```bash
modelaudit production_model.safetensors --format json --output security_report.json
```

### **CI/CD Pipeline Integration**

ModelAudit automatically detects CI environments and adjusts output accordingly:

```bash
# Recommended: Use JSON format for machine-readable output
modelaudit models/ --format json --output results.json

# Text output automatically adapts to CI (no spinners, plain text)
modelaudit models/ --timeout 300

# Disable colors explicitly with NO_COLOR environment variable
NO_COLOR=1 modelaudit models/
```

**CI-Friendly Features:**

- 🚫 Spinners automatically disabled when output is piped or in CI
- 🎨 Colors disabled when `NO_COLOR` environment variable is set
- 📊 JSON output recommended for parsing in CI pipelines
- 🔍 Exit codes: 0 (clean), 1 (issues found), 2 (errors)

### **Third-Party Model Validation**

```bash
# Scan models from HuggingFace, PyTorch Hub, or cloud storage
modelaudit https://huggingface.co/gpt2
modelaudit https://pytorch.org/hub/pytorch_vision_resnet/
modelaudit s3://my-bucket/downloaded-model.pt
modelaudit https://company.jfrog.io/artifactory/repo/model.pt \
    --jfrog-api-token YOUR_TOKEN
```

### **Compliance & Audit Reporting**

```bash
modelaudit model_package.zip --sbom compliance_report.json --verbose
```

[View advanced usage examples →](https://www.promptfoo.dev/docs/model-audit/usage/)

### Static Scanning vs. Promptfoo Redteaming

ModelAudit performs **static** analysis only. It examines model files for risky patterns
without ever loading or executing them. Promptfoo's redteaming module is
**dynamic**—it loads the model (locally or via API) and sends crafted prompts to
probe runtime behavior. Use ModelAudit first to verify the model file itself,
then run redteaming if you need to test how the model responds when invoked.

## ⚙️ Installation Options

**Basic installation (recommended for most users):**

### Quick Install Decision Guide

**🚀 Just want everything to work?**

```bash
pip install modelaudit[all]
```

**💡 Know what formats you need?**

```bash
# Basic installation (pickle, joblib, numpy, zip/tar archives)
pip install modelaudit

# Add only what you need
pip install modelaudit[tensorflow]  # TensorFlow SavedModel (.pb)
pip install modelaudit[pytorch]     # PyTorch models (.pt, .pth)
pip install modelaudit[h5]          # Keras/H5 models (.h5, .keras)
pip install modelaudit[onnx]        # ONNX models (.onnx)
pip install modelaudit[safetensors] # SafeTensors (.safetensors)

# Multiple formats
pip install modelaudit[tensorflow,pytorch,h5]
```

**☁️ Need cloud storage support?**

```bash
pip install modelaudit[cloud]  # S3, GCS, and Azure support
```

**⚠️ Having NumPy compatibility issues?**

```bash
# Some ML frameworks require NumPy < 2.0
pip install modelaudit[numpy1]

# Check what's working
modelaudit doctor --show-failed
```

**Docker installation:**

```bash
docker pull ghcr.io/promptfoo/modelaudit:latest
docker run --rm -v $(pwd):/data ghcr.io/promptfoo/modelaudit:latest model.pkl
```

### 📦 Dependency Reference

<details>
<summary><b>View all available extras and what they include</b></summary>

| Extra           | Includes                      | Use When                                |
| --------------- | ----------------------------- | --------------------------------------- |
| `[tensorflow]`  | TensorFlow framework          | Scanning `.pb` SavedModel files         |
| `[pytorch]`     | PyTorch framework             | Scanning `.pt`, `.pth` files            |
| `[h5]`          | h5py library                  | Scanning `.h5`, `.keras`, `.hdf5` files |
| `[onnx]`        | ONNX runtime                  | Scanning `.onnx` model files            |
| `[safetensors]` | SafeTensors library           | Scanning `.safetensors` files           |
| `[flax]`        | msgpack for JAX/Flax          | Scanning `.msgpack`, `.flax` files      |
| `[cloud]`       | fsspec, s3fs, gcsfs           | Scanning from S3, GCS, Azure            |
| `[mlflow]`      | MLflow library                | Scanning MLflow model registry          |
| `[all]`         | All ML frameworks             | Maximum compatibility                   |
| `[numpy1]`      | All ML frameworks + NumPy<2.0 | When facing NumPy conflicts             |

</details>

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

### 🔍 Troubleshooting Common Issues

**Scanner not working?**

```bash
# Check which scanners are available
modelaudit doctor --show-failed
```

**NumPy compatibility errors?**

```bash
# Option 1: Use the numpy1 compatibility mode
pip install modelaudit[numpy1]

# Option 2: Manually downgrade NumPy
pip install "numpy<2.0" --force-reinstall
pip install --force-reinstall tensorflow torch h5py  # Reinstall ML frameworks
```

**Missing scanner for your format?**

```bash
# ModelAudit will tell you exactly what to install
modelaudit your-model.onnx
# Output: "onnx not installed, cannot scan ONNX files. Install with 'pip install modelaudit[onnx]'"
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
