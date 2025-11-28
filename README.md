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

## 📁 Project Structure

ModelAudit is organized by conceptual purpose for clarity and maintainability:

```
modelaudit/
├── scanners/         # 29 specialized file format scanners
│   ├── pickle_scanner.py, pytorch_*.py, onnx_scanner.py, etc.
│   └── base.py - BaseScanner class with shared functionality
│
├── detectors/        # Security threat detection modules
│   ├── cve_patterns.py - Known CVE patterns (CVE-2025-32434, etc.)
│   ├── secrets.py - API keys, tokens, credentials
│   ├── jit_script.py - JIT/TorchScript malicious code
│   ├── network_comm.py - URLs, IPs, sockets
│   └── suspicious_symbols.py - Dangerous function calls
│
├── integrations/     # External system integrations
│   ├── jfrog.py - JFrog Artifactory support
│   ├── mlflow.py - MLflow registry support
│   ├── sbom_generator.py - CycloneDX SBOM generation
│   ├── sarif_formatter.py - SARIF output format
│   └── license_checker.py - License compliance
│
├── analysis/         # Advanced analysis algorithms
│   ├── anomaly_detector.py, entropy_analyzer.py
│   └── ml_context_analyzer.py - Context-aware analysis
│
├── utils/
│   ├── file/         # File handling (detection, filtering, streaming)
│   ├── sources/      # Model sources (HuggingFace, cloud, JFrog, DVC)
│   └── helpers/      # Generic utilities (retry, caching, etc.)
│
├── cache/            # Caching system for scan results
├── auth/             # Authentication for remote sources
├── progress/         # Progress tracking and UI
│
├── core.py           # Main scanning orchestration
└── cli.py            # Command-line interface
```

**Navigation guide**:

- **"What formats can we scan?"** → `scanners/`
- **"What threats do we detect?"** → `detectors/`
- **"What systems do we integrate with?"** → `integrations/`
- **"Where can models come from?"** → `utils/sources/`

[View detailed refactoring plan →](docs/REFACTORING_PLAN.md)

## 🛡️ What Problems It Solves

### **Prevents Code Execution Attacks**

Stops malicious models that run arbitrary commands when loaded (common in PyTorch .pt files)

### **Detects Model Backdoors**

Identifies trojaned models with hidden functionality or suspicious weight patterns

### **Ensures Supply Chain Security**

Validates model integrity and prevents tampering in your ML pipeline

### **Enforces License Compliance**

Checks for license violations that could expose your company to legal risk

### **Finds Embedded Secrets**

Detects API keys, tokens, and other credentials hidden in model weights or metadata

### **Flags Network Communication**

Identifies URLs, IPs, and socket usage that could enable data exfiltration or C2 channels

### **Detects Hidden JIT/Script Execution**

Scans TorchScript, ONNX, and other JIT-compiled code for dangerous operations

### **Smart Whitelist System (Reduces False Positives)**

Automatically downgrades findings for 7,440+ trusted models from popular downloads and verified organizations (Meta, Google, Microsoft, NVIDIA, etc.) - [Learn more](#-whitelist-system)

## 📊 Supported Model Formats

ModelAudit supports **29 specialized file format scanners** with comprehensive security analysis:

### 🔴 High Risk Formats (Pickle-based serialization)

| Format             | Extensions                        | Security Focus                    |
| ------------------ | --------------------------------- | --------------------------------- |
| **Pickle**         | `.pkl`, `.pickle`, `.dill`        | Dangerous opcodes, code execution |
| **PyTorch**        | `.pt`, `.pth`, `.ckpt`, `.bin`    | Pickle payloads, embedded malware |
| **Joblib**         | `.joblib`                         | Pickled scikit-learn objects      |
| **NumPy**          | `.npy`, `.npz`                    | Array metadata, pickle objects    |
| **JAX Checkpoint** | `.ckpt`, `.checkpoint`, `.pickle` | Serialized transforms             |

### 🟠 Medium Risk Formats (Complex with custom operations)

| Format              | Extensions               | Security Focus                |
| ------------------- | ------------------------ | ----------------------------- |
| **TensorFlow**      | `.pb`, SavedModel dirs   | PyFunc operations, custom ops |
| **Keras H5**        | `.h5`, `.hdf5`           | Unsafe Lambda layers          |
| **Keras ZIP**       | `.keras`                 | ZIP-based Keras archives      |
| **ONNX**            | `.onnx`                  | Custom operators, metadata    |
| **TensorFlow Lite** | `.tflite`                | Mobile model validation       |
| **PaddlePaddle**    | `.pdmodel`, `.pdiparams` | Custom operations             |
| **XGBoost**         | `.bst`, `.model`, `.ubj` | Serialized boosting models    |
| **Core ML**         | `.mlmodel`               | Apple custom layers           |

### 🟡 Lower Risk Formats (Safer serialization)

| Format               | Extensions                            | Security Focus                  |
| -------------------- | ------------------------------------- | ------------------------------- |
| **SafeTensors**      | `.safetensors`                        | Header validation (recommended) |
| **GGUF/GGML**        | `.gguf`, `.ggml`                      | LLM standard format             |
| **JAX/Flax Msgpack** | `.msgpack`, `.flax`, `.orbax`, `.jax` | Msgpack serialization           |
| **ExecuTorch**       | `.ptl`, `.pte`                        | PyTorch mobile archives         |
| **TensorRT**         | `.engine`, `.plan`                    | NVIDIA inference engines        |
| **OpenVINO**         | `.xml`                                | Intel IR format                 |
| **PMML**             | `.pmml`                               | XML predictive models           |
| **OCI Layers**       | `.manifest`                           | Container layer analysis        |

### 📦 Archive & Container Formats

| Format    | Extensions                                                        | Security Focus                  |
| --------- | ----------------------------------------------------------------- | ------------------------------- |
| **ZIP**   | `.zip`                                                            | Path traversal, malicious files |
| **TAR**   | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz` | Archive exploits                |
| **7-Zip** | `.7z`                                                             | Archive security                |

### 📄 Configuration & Metadata Formats

| Format               | Extensions                                        | Security Focus            |
| -------------------- | ------------------------------------------------- | ------------------------- |
| **Metadata**         | `.json`, `.md`, `.yml`, `.yaml`, `.rst`           | Embedded secrets, URLs    |
| **Manifest**         | `.json`, `.yaml`, `.xml`, `.toml`, `.ini`, `.cfg` | Config vulnerabilities    |
| **Text**             | `.txt`, `.md`, `.markdown`, `.rst`                | ML-related text analysis  |
| **Jinja2 Templates** | `.jinja`, `.j2`, `.template`                      | Template injection (SSTI) |

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
# Scan models from HuggingFace, PyTorch Hub, MLflow, JFrog, or cloud storage
modelaudit https://huggingface.co/gpt2
modelaudit https://pytorch.org/hub/pytorch_vision_resnet/
modelaudit models:/MyModel/Production
modelaudit model.dvc
modelaudit s3://my-bucket/downloaded-model.pt

# JFrog Artifactory - now supports both files AND folders
# Auth: export JFROG_API_TOKEN=... (or JFROG_ACCESS_TOKEN)
modelaudit https://company.jfrog.io/artifactory/repo/model.pt
# Or with explicit flag:
modelaudit https://company.jfrog.io/artifactory/repo/model.pt --api-token "$JFROG_API_TOKEN"
modelaudit https://company.jfrog.io/artifactory/repo/models/  # Scan entire folder!
```

### **Compliance & Audit Reporting**

```bash
modelaudit model_package.zip --sbom compliance_report.json --strict --verbose
```

### 🧠 Smart Detection Examples

ModelAudit automatically adapts to your input - **no configuration needed for most cases:**

```bash
# Local file - fast scan, no progress bars
modelaudit model.pkl

# Cloud directory - auto enables caching + progress bars
modelaudit s3://my-bucket/models/

# HuggingFace model - selective download + caching
modelaudit hf://microsoft/DialoGPT-medium

# Large local file - enables progress + optimizations
modelaudit 15GB-model.bin

# CI environment - auto detects and uses JSON output
CI=true modelaudit model.pkl
```

**Override smart detection when needed:**

```bash
# Force strict mode for security-critical scans
modelaudit model.pkl --strict --format json --output report.json

# Override size limits for huge models
modelaudit huge-model.pt --max-size 50GB --timeout 7200

# Preview mode without downloading
modelaudit s3://bucket/model.pt --dry-run
```

[View advanced usage examples →](https://www.promptfoo.dev/docs/model-audit/usage/)

### ⚙️ Smart Detection & CLI Options

ModelAudit uses **smart detection** to automatically configure optimal settings based on your input:

**✨ Smart Detection Features:**

- **Input type** (local/cloud/registry) → optimal download & caching strategies
- **File size** (>1GB) → large model optimizations + progress bars
- **Terminal type** (TTY/CI) → appropriate UI (progress vs quiet mode)
- **Cloud operations** → automatic caching, size limits, timeouts

**🎛️ Override Controls (13 focused flags):**

- `--strict` – scan all file types, strict license validation, fail on warnings
- `--max-size SIZE` – unified size limit (e.g., `10GB`, `500MB`)
- `--timeout SECONDS` – override auto-detected timeout
- `--dry-run` – preview what would be scanned/downloaded
- `--progress` – force enable progress reporting
- `--no-cache` – disable caching (overrides smart detection)
- `--format json` / `--output file.json` – structured output for CI/CD
- `--sbom file.json` – generate CycloneDX v1.6 SBOM with enhanced ML-BOM support
- `--verbose` / `--quiet` – control output detail level
- `--blacklist PATTERN` – additional security patterns

**🔐 Authentication (via environment variables):**

- Set `JFROG_API_TOKEN` or `JFROG_ACCESS_TOKEN` for JFrog Artifactory
- Set `MLFLOW_TRACKING_URI` for MLflow registry access

### 🚀 Large Model Support (Up to 1 TB)

ModelAudit automatically optimizes scanning strategies for different model sizes:

- **< 100 GB**: Full in-memory analysis for comprehensive scanning
- **100 GB - 1 TB**: Chunked processing with 50 GB chunks for memory efficiency
- **1 TB - 5 TB**: Streaming analysis with intelligent sampling
- **> 5 TB**: Advanced distributed scanning techniques

Large models are supported with automatic timeout increases and memory-optimized processing.

### Static Scanning vs. Promptfoo Redteaming

ModelAudit performs **static** analysis only. It examines model files for risky patterns
without ever loading or executing them. Promptfoo's redteaming module is
**dynamic**—it loads the model (locally or via API) and sends crafted prompts to
probe runtime behavior. Use ModelAudit first to verify the model file itself,
then run redteaming if you need to test how the model responds when invoked.

## ⚙️ Installation Options

**Requirements:**

- Python 3.10 or higher
- Compatible with Python 3.10, 3.11, 3.12, and 3.13

**Basic installation (recommended for most users):**

### Quick Install Decision Guide

**🚀 Just want everything to work?**

```bash
pip install modelaudit[all]
```

**Basic installation:**

```bash
# Core functionality only (pickle, numpy, archives)
pip install modelaudit
```

**Specific frameworks:**

```bash
pip install modelaudit[tensorflow]  # TensorFlow (.pb)
pip install modelaudit[pytorch]     # PyTorch (.pt, .pth)
pip install modelaudit[h5]          # Keras (.h5, .keras)
pip install modelaudit[onnx]        # ONNX (.onnx)
pip install modelaudit[safetensors] # SafeTensors (.safetensors)

# Multiple frameworks
pip install modelaudit[tensorflow,pytorch,h5]
```

**Additional features:**

```bash
pip install modelaudit[coreml]      # Apple Core ML
pip install modelaudit[flax]        # JAX/Flax models
pip install modelaudit[mlflow]      # MLflow registry
pip install modelaudit[huggingface] # Hugging Face integration
```

**Compatibility:**

```bash
# NumPy 1.x compatibility (some frameworks require NumPy < 2.0)
pip install modelaudit[numpy1]

# For CI/CD environments (omits dependencies like TensorRT that may not be available)
pip install modelaudit[all-ci]
```

**Docker:**

```bash
docker pull ghcr.io/promptfoo/modelaudit:latest
# Linux/macOS
docker run --rm -v "$(pwd)":/app ghcr.io/promptfoo/modelaudit:latest model.pkl
# Windows
docker run --rm -v "%cd%":/app ghcr.io/promptfoo/modelaudit:latest model.pkl
```

## Security Checks

### Code Execution Detection

- Dangerous Python modules: `os`, `sys`, `subprocess`, `eval`, `exec`
- Pickle opcodes: `REDUCE`, `GLOBAL`, `INST`, `OBJ`, `NEWOBJ`, `STACK_GLOBAL`, `BUILD`, `NEWOBJ_EX`
- Embedded executable file detection

### Embedded Data Extraction

- API keys, tokens, and credentials in model weights/metadata
- URLs, IP addresses, and network endpoints
- Suspicious configuration properties

### Archive Security

- Path traversal attacks in ZIP/TAR archives
- Executable files within model packages
- Malicious filenames and directory structures

### ML Framework Analysis

- TensorFlow operations: `PyFunc`, `PyFuncStateless`
- Keras unsafe layers and custom objects
- Template injection in model configurations

### Context-Aware Analysis

- Intelligently distinguishes between legitimate ML framework patterns and genuine threats to reduce false positives in complex model files

## Supported Formats

ModelAudit includes **29 specialized file format scanners** ([see complete list](https://www.promptfoo.dev/docs/model-audit/scanners/)):

### Model Formats

| Format              | Extensions                            | Risk Level | Security Focus                    |
| ------------------- | ------------------------------------- | ---------- | --------------------------------- |
| **Pickle**          | `.pkl`, `.pickle`, `.dill`            | 🔴 HIGH    | Code execution, dangerous opcodes |
| **PyTorch**         | `.pt`, `.pth`, `.ckpt`, `.bin`        | 🔴 HIGH    | Pickle payloads, embedded malware |
| **Joblib**          | `.joblib`                             | 🔴 HIGH    | Pickled scikit-learn objects      |
| **NumPy**           | `.npy`, `.npz`                        | 🔴 HIGH    | Array metadata, pickle objects    |
| **TensorFlow**      | `.pb`, SavedModel directories         | 🟠 MEDIUM  | PyFunc operations, custom ops     |
| **Keras**           | `.h5`, `.hdf5`, `.keras`              | 🟠 MEDIUM  | Unsafe layers, custom objects     |
| **ONNX**            | `.onnx`                               | 🟠 MEDIUM  | Custom operators, metadata        |
| **XGBoost**         | `.bst`, `.model`, `.ubj`              | 🟠 MEDIUM  | Serialized boosting models        |
| **SafeTensors**     | `.safetensors`                        | 🟢 SAFE    | Header validation (recommended)   |
| **GGUF/GGML**       | `.gguf`, `.ggml`                      | 🟢 SAFE    | LLM standard format               |
| **JAX/Flax**        | `.msgpack`, `.flax`, `.orbax`, `.jax` | 🟡 LOW     | Msgpack serialization             |
| **JAX Checkpoint**  | `.ckpt`, `.checkpoint`, `.pickle`     | 🟡 LOW     | JAX checkpoint formats            |
| **TensorFlow Lite** | `.tflite`                             | 🟡 LOW     | Mobile model validation           |
| **ExecuTorch**      | `.ptl`, `.pte`                        | 🟡 LOW     | PyTorch mobile archives           |
| **Core ML**         | `.mlmodel`                            | 🟡 LOW     | Apple custom layers               |
| **TensorRT**        | `.engine`, `.plan`                    | 🟡 LOW     | NVIDIA inference engines          |
| **PaddlePaddle**    | `.pdmodel`, `.pdiparams`              | 🟡 LOW     | Custom operations                 |
| **OpenVINO**        | `.xml`                                | 🟡 LOW     | Intel IR format                   |
| **PMML**            | `.pmml`                               | 🟡 LOW     | XML predictive models             |

### Archive & Configuration Formats

| Format               | Extensions                                  | Security Focus                  |
| -------------------- | ------------------------------------------- | ------------------------------- |
| **ZIP**              | `.zip`                                      | Path traversal, malicious files |
| **TAR**              | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, etc. | Archive exploits                |
| **7-Zip**            | `.7z`                                       | Archive security                |
| **OCI Layers**       | `.manifest`                                 | Container layer analysis        |
| **Metadata**         | `.json`, `.md`, `.yml`, `.yaml`, `.rst`     | Embedded secrets, URLs          |
| **Manifest**         | `.json`, `.yaml`, `.xml`, `.toml`, `.ini`   | Configuration vulnerabilities   |
| **Text**             | `.txt`, `.md`, `.markdown`, `.rst`          | ML-related text analysis        |
| **Jinja2 Templates** | `.jinja`, `.j2`, `.template`                | Template injection (SSTI)       |

[Complete format documentation →](https://www.promptfoo.dev/docs/model-audit/scanners/)

## Usage Examples

### Basic Scanning

```bash
# Scan single file
modelaudit model.pkl

# Scan directory
modelaudit ./models/

# Strict mode (fail on warnings)
modelaudit model.pkl --strict
```

### CI/CD Integration

```bash
# JSON output for automation
modelaudit models/ --format json --output results.json

# Generate SBOM report
modelaudit model.pkl --sbom compliance_report.json

# Disable colors in CI
NO_COLOR=1 modelaudit models/
```

### Remote Sources

```bash
# Hugging Face models (via direct URL or hf:// scheme)
modelaudit https://huggingface.co/gpt2
modelaudit hf://microsoft/DialoGPT-medium

# Cloud storage
modelaudit s3://bucket/model.pt
modelaudit gs://bucket/models/
modelaudit https://account.blob.core.windows.net/container/model.pt

# MLflow registry
modelaudit models:/MyModel/Production

# JFrog Artifactory (files and folders)
modelaudit https://company.jfrog.io/artifactory/repo/model.pt      # Single file
modelaudit https://company.jfrog.io/artifactory/repo/models/       # Entire folder
```

### Command Options

- **`--format`** - Output format: text, json, sarif
- **`--output`** - Write results to file
- **`--verbose`** - Detailed output
- **`--quiet`** - Minimal output
- **`--strict`** - Fail on warnings, scan all files
- **`--timeout`** - Override scan timeout
- **`--max-size`** - Set size limits (e.g., 10 GB)
- **`--dry-run`** - Preview without scanning
- **`--progress`** - Force progress display
- **`--sbom`** - Generate CycloneDX SBOM
- **`--blacklist`** - Additional patterns to flag
- **`--no-cache`** - Disable result caching
- **`--stream`** - Stream scan: download files one-by-one, scan immediately, then delete to save disk space

[Advanced usage examples →](https://www.promptfoo.dev/docs/model-audit/usage/)

### 💾 Disk Space Optimization

For large models or environments with limited disk space, use the `--stream` flag to minimize storage usage:

```bash
# Scan large models without filling disk
modelaudit hf://meta-llama/Llama-3.2-90B --stream

# Works with all sources
modelaudit s3://bucket/large-model.pkl --stream
modelaudit gs://bucket/model/ --stream
modelaudit ./local-models/ --stream
```

**How it works:**

- Files are downloaded one at a time (not all at once)
- Each file is scanned immediately after download
- Files are deleted after scanning to free up space
- Ideal for CI/CD pipelines or constrained environments
- Computes SHA256 hash and aggregate content hash for deduplication

## 🛡️ Whitelist System

ModelAudit includes a smart whitelist system that **reduces false positives** for trusted models while maintaining security:

### What's Whitelisted

- **7,440+ models** from two trusted sources:
  1. **Popular models** (540 models) - Top downloaded models from HuggingFace
  2. **Trusted organizations** (6,900 models) - Models from 18 verified organizations:
     - Meta/Facebook, Google, Microsoft, NVIDIA
     - OpenAI, Hugging Face, Stability AI
     - EleutherAI, BigScience, BigCode
     - Mistral AI, Sentence Transformers
     - And more...

### How It Works

- **Automatic detection**: Model IDs are extracted from URLs, cache paths, and metadata
- **Smart downgrading**: Security findings are downgraded from WARNING/CRITICAL → INFO
- **Enabled by default**: Works transparently with no configuration needed
- **User control**: Disable via config if needed: `{"use_hf_whitelist": False}`

### Example

```bash
# Scanning a whitelisted model
$ modelaudit facebook/bart-large-cnn

✓ Scanning facebook/bart-large-cnn
Files scanned: 3 | Issues found: 0 critical, 0 warning, 2 info

# Issues are downgraded to INFO for trusted models
1. model.safetensors: [INFO] Contains pickle import (whitelisted model)
   Original severity: WARNING
```

### Updating the Whitelist

**For maintainers**: Update periodically to include new popular models and releases:

```bash
# Update popular models (top downloads)
python scripts/fetch_hf_top_models.py --count 2000

# Update organization models (trusted orgs)
python scripts/fetch_hf_org_models.py

# Commit the updated files in modelaudit/whitelists/
```

**Recommended update frequency**: Monthly or before major releases

## Output Formats

### Text (default)

```text
$ modelaudit model.pkl

✓ Scanning model.pkl
Files scanned: 1 | Issues found: 1 critical

1. model.pkl (pos 28): [CRITICAL] Malicious code execution attempt
   Why: Contains os.system() call that could run arbitrary commands
```

### JSON (for automation)

```bash
modelaudit model.pkl --format json
```

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

### SARIF (for security tools)

```bash
modelaudit model.pkl --format sarif --output results.sarif
```

## Troubleshooting

### Check scanner availability

```bash
modelaudit doctor --show-failed
```

### NumPy compatibility issues

```bash
# Use NumPy 1.x compatibility mode
pip install modelaudit[numpy1]
```

### Missing dependencies

```bash
# ModelAudit shows exactly what to install
modelaudit your-model.onnx
# Output: "Install with 'pip install modelaudit[onnx]'"
```

### Exit Codes

- `0` - No security issues found
- `1` - Security issues detected
- `2` - Scan errors occurred

### Authentication

ModelAudit uses environment variables for authenticating to remote services:

```bash
# JFrog Artifactory
export JFROG_API_TOKEN=your_token

# MLflow
export MLFLOW_TRACKING_URI=http://localhost:5000

# AWS, Google Cloud, and Azure
# Authentication is handled automatically by the respective client libraries
# (e.g., via IAM roles, `aws configure`, `gcloud auth login`, or environment variables).
# For specific env var setup, refer to the library's documentation.
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Hugging Face
export HF_TOKEN=your_token
```

## Documentation

- **Documentation**: [promptfoo.dev/docs/model-audit/](https://www.promptfoo.dev/docs/model-audit/)
- **Usage Examples**: [promptfoo.dev/docs/model-audit/usage/](https://www.promptfoo.dev/docs/model-audit/usage/)
- **Report Issues**: Contact support at [promptfoo.dev](https://www.promptfoo.dev/)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
