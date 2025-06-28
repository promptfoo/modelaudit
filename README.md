# ModelAudit

**Secure your AI models before deployment.** Detects malicious code, backdoors, and security vulnerabilities in ML model files.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Tests](https://github.com/promptfoo/modelaudit/actions/workflows/test.yml/badge.svg)](https://github.com/promptfoo/modelaudit/actions/workflows/test.yml)
[![Code Style: ruff](https://img.shields.io/badge/code%20style-ruff-005cd7.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/github/license/promptfoo/promptfoo)](https://github.com/promptfoo/promptfoo/blob/main/LICENSE)

<img width="989" alt="image" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

## 🚀 Quick Start

**Install and scan in 30 seconds:**

```bash
# Install ModelAudit
pip install modelaudit[all]

# Scan a model file
modelaudit scan model.pkl

# Scan a directory
modelaudit scan ./models/

# Export results for CI/CD
modelaudit scan model.pkl --format json --output results.json
```

**Example output:**

```bash
$ modelaudit scan suspicious_model.pkl

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

## Table of Contents

- [ModelAudit](#modelaudit)
  - [🚀 Quick Start](#-quick-start)
  - [🛡️ What Problems It Solves](#️-what-problems-it-solves)
    - [**Prevents Code Execution Attacks**](#prevents-code-execution-attacks)
    - [**Detects Model Backdoors**](#detects-model-backdoors)
    - [**Ensures Supply Chain Security**](#ensures-supply-chain-security)
    - [**Enforces License Compliance**](#enforces-license-compliance)
  - [Table of Contents](#table-of-contents)
  - [📊 Supported Model Formats](#-supported-model-formats)
  - [🎯 Common Use Cases](#-common-use-cases)
    - [**🔒 Pre-Deployment Security Checks**](#-pre-deployment-security-checks)
    - [**🏭 CI/CD Pipeline Integration**](#-cicd-pipeline-integration)
    - [**📦 Third-Party Model Validation**](#-third-party-model-validation)
    - [**📋 Compliance \& Audit Reporting**](#-compliance--audit-reporting)
  - [⚙️ Advanced Usage](#️-advanced-usage)
    - [Installation Options](#installation-options)
    - [Cloud Storage Scanning](#cloud-storage-scanning)
    - [CI/CD Integration](#cicd-integration)
    - [Command Line Options](#command-line-options)
  - [📋 Output Formats](#-output-formats)
  - [🔧 Troubleshooting](#-troubleshooting)
  - [📝 License](#-license)

## 📊 Supported Model Formats

ModelAudit scans **all major ML model formats** with specialized security analysis for each:

| Format                                     | Extensions                    | Security Assessment                                                            |
| ------------------------------------------ | ----------------------------- | ------------------------------------------------------------------------------ |
| **PyTorch** (PyTorch)                      | `.pt`, `.pth` (ZIP)           | 🔴 **HIGH RISK** - ⛔ **Always scan** - Contains pickle serialization          |
| **SafeTensors** (Hugging Face - universal) | `.safetensors`                | 🟢 **SAFE** - 🏆 **Preferred choice** - Purpose-built for security             |
| **GGUF/GGML** (llama.cpp, Ollama)          | `.gguf`, `.ggml`              | 🟢 **SAFE** - 🏆 **LLM standard** - Binary format, optimized for inference     |
| **TensorFlow SavedModel** (TensorFlow)     | `.pb`, directories            | 🟠 **MEDIUM RISK** - ⚠️ **Use with caution** - Scan for dangerous operations   |
| **ONNX** (Cross-framework)                 | `.onnx`                       | 🟢 **SAFE** - ✅ **Recommended** - Industry standard, good interoperability    |
| **PyTorch Binary** (PyTorch/Transformers)  | `.bin` (HuggingFace)          | 🟡 **LOW RISK** - ✅ **Generally safe** - Simple tensor storage                |
| **Keras H5** (Keras/TensorFlow)            | `.h5`, `.hdf5`, `.keras`      | 🟠 **MEDIUM RISK** - ⚠️ **Use with caution** - Check for executable layers     |
| **Core ML** (Apple Core ML)                | `.mlmodel`                    | 🟢 **SAFE** - ✅ **Apple ecosystem** - Compiled format, sandboxed execution    |
| **TensorFlow Lite** (TensorFlow)           | `.tflite`                     | 🟢 **SAFE** - ✅ **Mobile standard** - Compiled format, limited attack surface |
| **Pickle** (Python/scikit-learn)           | `.pkl`, `.pickle`, `.dill`    | 🔴 **HIGH RISK** - ⛔ **Avoid in production** - Convert to SafeTensors         |
| **JAX/Flax** (JAX/Flax)                    | `.msgpack`, `.flax`, `.orbax` | 🟡 **LOW RISK** - ✅ **Generally safe** - Validate transforms                  |
| **NumPy** (NumPy - universal)              | `.npy`, `.npz`                | 🟡 **LOW RISK** - ✅ **Data format** - Watch for object arrays                 |
| **Joblib** (scikit-learn)                  | `.joblib`                     | 🟡 **VARIABLE RISK** - ⚠️ **Scan carefully** - May contain pickle              |
| **Model Configs** (Universal)              | `.json`, `.yaml`, `.toml`     | 🟡 **LOW RISK** - ✅ **Config only** - No code execution                       |
| **Archives** (Various)                     | `.zip`, `.tar`, `.gz`         | 🟡 **VARIABLE RISK** - ⚠️ **Depends on contents** - Scan internal files        |
| **PMML** (Enterprise/Legacy)               | `.pmml`                       | 🟢 **SAFE** - ✅ **Enterprise standard** - Declarative XML format              |

## 🎯 Common Use Cases

### **🔒 Pre-Deployment Security Checks**

```bash
# Validate models before production deployment
modelaudit scan production_model.safetensors --format json --output security_report.json
```

### **🏭 CI/CD Pipeline Integration**

```bash
# Automatic scanning in your build pipeline
modelaudit scan models/ --exit-code-on-issues --timeout 300
```

### **📦 Third-Party Model Validation**

```bash
# Scan models from HuggingFace, cloud storage, or repositories
modelaudit scan https://huggingface.co/gpt2
modelaudit scan s3://my-bucket/downloaded-model.pt
```

### **📋 Compliance & Audit Reporting**

```bash
# Generate comprehensive audit reports with license compliance
modelaudit scan model_package.zip --sbom compliance_report.json --verbose
```

## ⚙️ Advanced Usage

### Installation Options

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
pip install modelaudit[cloud]       # S3/GCS/R2 support
pip install modelaudit[mlflow]      # MLflow integration
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
# Pull and run with Docker
docker pull ghcr.io/promptfoo/modelaudit:latest
docker run --rm -v $(pwd):/data ghcr.io/promptfoo/modelaudit:latest scan /data/model.pkl
```

**Development installation:**

```bash
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit
rye sync --features all
```

### Cloud Storage Scanning

ModelAudit can scan models directly from cloud storage with automatic authentication.

**Amazon S3:**

```bash
# Set credentials via environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Scan from S3
modelaudit scan s3://my-bucket/model.pkl
```

**Google Cloud Storage:**

```bash
# Authenticate with service account
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Scan from GCS
modelaudit scan gs://my-bucket/model.pt
```

**Cloudflare R2:**

```bash
# R2 uses S3-compatible authentication
export AWS_ACCESS_KEY_ID="your-r2-access-key"
export AWS_SECRET_ACCESS_KEY="your-r2-secret-key"
export AWS_ENDPOINT_URL="https://your-account.r2.cloudflarestorage.com"

# Scan from R2
modelaudit scan r2://my-bucket/model.safetensors
```

**HuggingFace Hub & Repositories:**

```bash
# Scan models from HuggingFace
modelaudit scan https://huggingface.co/gpt2
modelaudit scan hf://distilbert-base-uncased

# Scan from JFrog Artifactory
export JFROG_API_TOKEN=your_token_here
modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt

# Scan from MLflow registry
modelaudit scan models:/MyModel/Staging --registry-uri http://mlflow.example.com
```

### CI/CD Integration

**Exit codes for automation:**

- `0`: Success - No security issues found
- `1`: Security issues found (scan completed successfully)
- `2`: Errors occurred during scanning

**GitHub Actions example:**

```yaml
- name: Scan ML Models
  run: |
    pip install modelaudit[all]
    modelaudit scan models/ --format json --output security-report.json

- name: Upload Security Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: security-report.json
```

**Jenkins pipeline example:**

```groovy
stage('Model Security Scan') {
    steps {
        sh 'pip install modelaudit[all]'
        sh 'modelaudit scan models/ --exit-code-on-issues'
    }
}
```

### Command Line Options

```bash
# Resource limits
modelaudit scan model.pkl --max-file-size 1073741824    # 1GB limit
modelaudit scan models/ --max-total-size 5368709120     # 5GB total
modelaudit scan large_model.pkl --timeout 300           # 5 minute timeout

# Custom security policies
modelaudit scan model.pkl --blacklist "unsafe_pattern" --blacklist "malicious_func"

# Output options
modelaudit scan model.pkl --format json --output results.json
modelaudit scan model.pkl --sbom sbom.json              # Generate SBOM
modelaudit scan model.pkl --verbose                     # Detailed output

# Advanced scanning
modelaudit scan models/ --exit-code-on-issues          # Fail CI on issues
modelaudit scan model.pkl --why                        # Explain findings
```

## 📋 Output Formats

**Human-readable output (default):**

```bash
$ modelaudit scan model.pkl

✓ Scanning model.pkl
Files scanned: 1 | Issues found: 1 critical

1. model.pkl (pos 28): [CRITICAL] Malicious code execution attempt
   Why: Contains os.system() call that could run arbitrary commands
```

**JSON output for automation:**

```bash
modelaudit scan model.pkl --format json
```

```json
{
  "files_scanned": 1,
  "bytes_scanned": 156,
  "issues": [
    {
      "message": "Malicious code execution attempt",
      "severity": "critical",
      "location": "model.pkl (pos 28)",
      "details": {
        "module": "os",
        "function": "system",
        "position": 28
      }
    }
  ]
}
```

**SBOM (Software Bill of Materials):**

```bash
modelaudit scan model.pkl --sbom sbom.json
```

Generates CycloneDX-compliant SBOM with license compliance information.

## 🔧 Troubleshooting

**Scanner compatibility issues:**

```bash
# Check which scanners failed to load
modelaudit doctor --show-failed

# Install missing dependencies
pip install modelaudit[tensorflow,pytorch,onnx]
```

**Large file timeouts:**

```bash
# Increase timeout for large models
modelaudit scan large_model.pt --timeout 600
```

**Memory issues:**

```bash
# Set file size limits
modelaudit scan models/ --max-file-size 2147483648  # 2GB limit
```

**Cloud authentication errors:**

```bash
# Verify credentials are set
echo $AWS_ACCESS_KEY_ID
echo $GOOGLE_APPLICATION_CREDENTIALS

# Test cloud access
modelaudit scan s3://my-bucket/test.pkl --verbose
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
