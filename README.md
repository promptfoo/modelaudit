# ModelAudit

A security scanner for AI models. Quickly check your AIML models for potential security risks before deployment.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Tests](https://github.com/promptfoo/modelaudit/actions/workflows/test.yml/badge.svg)](https://github.com/promptfoo/modelaudit/actions/workflows/test.yml)
[![Code Style: ruff](https://img.shields.io/badge/code%20style-ruff-005cd7.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/github/license/promptfoo/promptfoo)](https://github.com/promptfoo/promptfoo/blob/main/LICENSE)

<img width="989" alt="image" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

## Table of Contents

- [ModelAudit](#modelaudit)
  - [Table of Contents](#table-of-contents)
  - [🔍 What It Does](#-what-it-does)
  - [🚀 Quick Start](#-quick-start)
    - [Installation](#installation)
    - [Basic Usage](#basic-usage)
    - [Cloud Storage Authentication](#cloud-storage-authentication)
      - [Amazon S3](#amazon-s3)
      - [Google Cloud Storage (GCS)](#google-cloud-storage-gcs)
      - [Cloudflare R2](#cloudflare-r2)
  - [✨ Features](#-features)
    - [Core Capabilities](#core-capabilities)
    - [Reporting \& Integration](#reporting--integration)
    - [Security Detection](#security-detection)
  - [🛡️ Supported Model Formats](#️-supported-model-formats)
    - [Weight Analysis](#weight-analysis)
  - [⚙️ Advanced Usage](#️-advanced-usage)
    - [Command Line Options](#command-line-options)
    - [Exit Codes](#exit-codes)
  - [📋 JSON Output Format](#-json-output-format)
  - [🔄 CI/CD Integration](#-cicd-integration)
    - [Basic Integration](#basic-integration)
    - [Platform Examples](#platform-examples)
  - [🔧 Troubleshooting](#-troubleshooting)
    - [Common Issues](#common-issues)
  - [⚠️ Limitations](#️-limitations)
  - [📝 License](#-license)

## 🔍 What It Does

ModelAudit scans ML model files for:

- **Malicious code execution** (e.g., `os.system` calls in pickled models)
- **Suspicious TensorFlow operations** (PyFunc, file I/O operations)
- **Potentially unsafe Keras Lambda layers** with arbitrary code execution
- **Dangerous pickle opcodes** (REDUCE, INST, OBJ, STACK_GLOBAL)
- **Nested pickle payloads** and multi-stage serialization attacks
- **Custom ONNX operators** and external data integrity issues
- **Encoded payloads** and suspicious string patterns
- **Risky configurations** in model architectures
- **Suspicious patterns** in model manifests and configuration files
- **Models with blacklisted names** or content patterns
- **Malicious content in ZIP archives** including nested archives and zip bombs
- **Container-delivered models** in OCI/Docker layers and manifest files
- **GGUF/GGML file integrity** and tensor alignment validation
- **Anomalous weight patterns** that may indicate trojaned models (statistical analysis)
- **License compliance issues** including commercial use restrictions and AGPL obligations
- **Enhanced joblib/dill security** (format validation, compression bombs, embedded pickle analysis, bypass prevention)
- **NumPy array integrity issues** (malformed headers, dangerous dtypes)

## 🚀 Quick Start

### Installation

ModelAudit is available on [PyPI](https://pypi.org/project/modelaudit/) and requires **Python 3.9 or higher**.

**Basic installation:**

```bash
pip install modelaudit
```

**With optional dependencies for specific model formats:**

```bash
# For TensorFlow SavedModel scanning
pip install modelaudit[tensorflow]

# For Keras H5 model scanning
pip install modelaudit[h5]

# For PyTorch model scanning
pip install modelaudit[pytorch]

# For ONNX model scanning
pip install modelaudit[onnx]

# For TensorFlow Lite model scanning
pip install modelaudit[tflite]

# For YAML manifest scanning
pip install modelaudit[yaml]

# For SafeTensors model scanning
pip install modelaudit[safetensors]

# For enhanced pickle support (dill serialization with security validation)
pip install modelaudit[dill]

# For Joblib model scanning (includes scikit-learn integration)
pip install modelaudit[joblib]

# For Flax msgpack scanning
pip install modelaudit[flax]

# For S3/GCS/R2 cloud storage support
pip install modelaudit[cloud]

# For scanning models stored in MLflow registries
pip install modelaudit[mlflow]

# Install all optional dependencies
pip install modelaudit[all]

# For NumPy 1.x compatibility (if you need all ML frameworks to work)
pip install modelaudit[numpy1]
```

**NumPy Compatibility:**

ModelAudit supports both NumPy 1.x and 2.x, with automatic graceful fallback when ML frameworks have compatibility issues:

```bash
# Default installation (works with NumPy 2.x, some ML framework scanners may not load)
pip install modelaudit[all]

# Full NumPy 1.x compatibility mode (ensures all ML frameworks work)
pip install modelaudit[numpy1]

# Check scanner compatibility status
modelaudit doctor --show-failed
```

**Development installation:**

```bash
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Using Rye (recommended)
rye sync --features all

# Or using pip
pip install -e .[all]
```

**Docker installation:**

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/promptfoo/modelaudit:latest

# Use specific variants
docker pull ghcr.io/promptfoo/modelaudit:latest-full        # All ML frameworks
docker pull ghcr.io/promptfoo/modelaudit:latest-tensorflow  # TensorFlow only

# Run with Docker
docker run --rm -v $(pwd):/data ghcr.io/promptfoo/modelaudit:latest scan /data/model.pkl
```

### Basic Usage

```bash
# Scan a single model
modelaudit scan model.pkl

# Scan an ONNX model
modelaudit scan model.onnx

# Scan multiple models (including enhanced dill/joblib support and JAX/Flax)
modelaudit scan model1.pkl model2.h5 model3.pt llama-model.gguf model4.joblib model5.dill model6.npy flax-model.msgpack jax-checkpoint.orbax

# Scan a directory
modelaudit scan ./models/

# Scan a model stored in the MLflow registry
modelaudit scan models:/MyModel/1

# Scan a model from HuggingFace Hub
modelaudit scan https://huggingface.co/gpt2
modelaudit scan hf://distilbert-base-uncased

# Scan models from cloud storage
modelaudit scan s3://my-bucket/models/
modelaudit scan gs://my-bucket/model.pt

# Scan a model from JFrog Artifactory
modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt

# With API token authentication (recommended)
modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt --jfrog-api-token YOUR_API_TOKEN

# With access token authentication
modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt --jfrog-access-token YOUR_ACCESS_TOKEN

# Using environment variables (recommended for CI/CD)
export JFROG_API_TOKEN=your_token_here
modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt

# Using .env file (create a .env file in your project root)
echo "JFROG_API_TOKEN=your_token_here" > .env
modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt

# Export results to JSON
modelaudit scan model.pkl --format json --output results.json

# Generate Software Bill of Materials (SBOM) with license information
modelaudit scan model.pkl --sbom sbom.json
```

### Cloud Storage Authentication

ModelAudit supports scanning models directly from cloud storage. Authentication is handled automatically using standard cloud provider credentials.

#### Amazon S3

**Environment Variables:**

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"  # Optional

# Then scan
modelaudit scan s3://my-bucket/model.pkl
```

**AWS Credentials File (`~/.aws/credentials`):**

```ini
[default]
aws_access_key_id = your-access-key
aws_secret_access_key = your-secret-key
region = us-east-1
```

**IAM Roles:** Automatically detected when running on EC2 instances or other AWS services.

#### Google Cloud Storage (GCS)

**Service Account Key:**

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Then scan
modelaudit scan gs://my-bucket/model.pt
```

**Application Default Credentials (ADC):**

```bash
# Authenticate with gcloud (for development)
gcloud auth application-default login

# Or use service account (for production)
gcloud auth activate-service-account --key-file=/path/to/key.json
```

#### Cloudflare R2

R2 uses S3-compatible authentication:

```bash
export AWS_ACCESS_KEY_ID="your-r2-access-key"
export AWS_SECRET_ACCESS_KEY="your-r2-secret-key"
export AWS_ENDPOINT_URL="https://your-account.r2.cloudflarestorage.com"

# Then scan
modelaudit scan r2://my-bucket/model.safetensors
```

**Example output:**

```bash
$ modelaudit scan suspicious_model.pkl

────────────────────────────────────────────────────────────────────────────────
ModelAudit Security Scanner
Scanning for potential security issues in ML model files
────────────────────────────────────────────────────────────────────────────────
Paths to scan: suspicious_model.pkl
────────────────────────────────────────────────────────────────────────────────

✓ Scanning suspicious_model.pkl

Active Scanner: pickle
Scan completed in 0.02 seconds
Files scanned: 1
Scanned 156 bytes
Issues found: 2 critical, 1 warnings

1. suspicious_model.pkl (pos 28): [CRITICAL] Suspicious module reference found: posix.system
2. suspicious_model.pkl (pos 52): [WARNING] Found REDUCE opcode - potential __reduce__ method execution

────────────────────────────────────────────────────────────────────────────────
✗ Scan completed with findings
```

Some issues will also show a short **Why** paragraph explaining the security
risk:

```bash
1. suspicious_model.pkl (pos 28): [CRITICAL] Suspicious module reference found: posix.system
   Why: The 'os' module provides direct access to operating system functions.
```

## ✨ Features

### Core Capabilities

- **Automatic Format Detection**: Identifies model formats automatically
- **Deep Security Analysis**: Examines model internals, not just metadata
- **Multiple Format Support**: PyTorch (.pt, .pth, .bin), TensorFlow (SavedModel, .pb), Keras (.h5, .hdf5, .keras), SafeTensors (.safetensors), GGUF/GGML (.gguf, .ggml), Pickle (.pkl, .pickle, .ckpt), Joblib (.joblib), NumPy (.npy, .npz), PMML (.pmml), OpenVINO (.xml, .bin), ZIP archives (.zip), Manifests (.json, .yaml, .xml, etc.), Flax (.msgpack, .ckpt)
- **Recursive Archive Scanning**: Scans contents of ZIP files and nested archives
- **Batch Processing**: Scan multiple files and directories efficiently
- **Configurable Scanning**: Set timeouts, file size limits, custom blacklists
- **DVC Integration**: Automatically scan files referenced in `.dvc` pointer files

### Reporting & Integration

- **Multiple Output Formats**: Human-readable text and machine-readable JSON
- **SBOM Generation**: CycloneDX Software Bill of Materials with license metadata
- **Detailed Reporting**: Scan duration, files processed, bytes scanned, issue severity
- **Severity Levels**: CRITICAL, WARNING, INFO, DEBUG for flexible filtering
- **CI/CD Integration**: Clear exit codes for automated pipeline integration
- **MLflow Support**: Scan models directly from the MLflow model registry

### Security Detection

- **Code Execution**: Detects embedded Python code, eval/exec calls, system commands
- **Pickle Security**: Analyzes dangerous opcodes, suspicious imports, encoded payloads
- **Enhanced Dill/Joblib Analysis**: ML-aware scanning with format validation and bypass prevention
- **Model Integrity**: Checks for unexpected files, suspicious configurations
- **Archive Security**: Automatic Zip-Slip protection against directory traversal, zip bombs, malicious nested files
- **License Compliance**: Identifies commercial use restrictions, AGPL network obligations, unlicensed datasets
- **Pattern Matching**: Custom blacklist patterns for organizational policies

## 🛡️ Supported Model Formats

ModelAudit provides specialized security scanners for different model formats:

| Format              | File Extensions                                                                                          | What We Check                                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Pickle**          | `.pkl`, `.pickle`, `.dill`, `.bin`, `.pt`, `.pth`, `.ckpt`                                               | Malicious code execution, dangerous opcodes, suspicious imports, nested pickle detection, decode-exec chains       |
| **PyTorch Zip**     | `.pt`, `.pth`                                                                                            | Embedded pickle analysis, suspicious files, custom patterns                                                        |
| **PyTorch Binary**  | `.bin`                                                                                                   | Binary tensor data analysis, embedded content                                                                      |
| **TensorFlow Lite** | `.tflite`                                                                                                | Extreme tensor shapes, custom ops, FlatBuffer integrity                                                            |
| **TensorFlow**      | SavedModel dirs, `.pb`                                                                                   | Suspicious operations, file I/O, Python execution                                                                  |
| **Keras**           | `.h5`, `.hdf5`, `.keras`                                                                                 | Lambda layers, custom objects, dangerous configurations                                                            |
| **ONNX**            | `.onnx`                                                                                                  | Custom operators, external data validation, tensor integrity                                                       |
| **OpenVINO**        | `.xml`, `.bin`                                         
                                                | Suspicious layers, external library references                            |
| **SafeTensors**     | `.safetensors`                                                                                           | Metadata integrity, tensor validation                                                                              |
| **Flax/JAX**        | `.msgpack`, `.flax`, `.orbax`, `.jax`                                                                   | Enhanced msgpack integrity, JAX-specific threat detection, Orbax checkpoint support, ML architecture analysis, decompression bomb prevention |
| **GGUF/GGML**       | `.gguf`, `.ggml`                                                                                         | Header validation, tensor integrity, metadata security checks                                                      |
| **Joblib**          | `.joblib`                                                                                                | File format validation, compression bomb detection, embedded pickle analysis, ML-aware security filtering          |
| **NumPy**           | `.npy`, `.npz`                                                                                           | Array integrity, dangerous dtypes, dimension validation                                                            |
| **PMML**            | `.pmml`                                                                                                  | XML well-formedness, external entity checks, suspicious extensions                                                 |
| **ZIP Archives**    | `.zip`                                                                                                   | Recursive content scanning, zip bombs, directory traversal                                                         |
| **Manifests**       | `.json`, `.yaml`, `.yml`, `.xml`, `.toml`, `.ini`, `.cfg`, `.config`, `.manifest`, `.model`, `.metadata` | Suspicious keys, credential exposure, blacklisted patterns                                                         |

### Weight Analysis

ModelAudit can detect anomalous weight patterns that may indicate trojaned models using statistical analysis. This feature is disabled by default for large language models to avoid false positives.

## ⚙️ Advanced Usage

### Command Line Options

```bash
# Set maximum file size to scan (1GB limit)
modelaudit scan model.pkl --max-file-size 1073741824

# Stop scanning after a total of 5GB has been processed
modelaudit scan models/ --max-total-size 5368709120

# Add custom blacklist patterns
modelaudit scan model.pkl --blacklist "unsafe_model" --blacklist "malicious_net"

# Set scan timeout (5 minutes)
modelaudit scan large_model.pkl --timeout 300

# Generate SBOM with license information
modelaudit scan model.pkl --sbom sbom.json

# Verbose output for debugging
modelaudit scan model.pkl --verbose

# Scan a model from the MLflow registry
modelaudit scan models:/MyModel/Staging --registry-uri http://mlflow.example.com
```

### Exit Codes

ModelAudit uses different exit codes to indicate scan results:

- **0**: Success - No security issues found
- **1**: Security issues found (scan completed successfully)
- **2**: Errors occurred during scanning (e.g., file not found, scan failures)

## 📋 JSON Output Format

When using `--format json`, ModelAudit outputs structured results:

```json
{
  "scanner_names": ["pickle"],
  "start_time": 1750168822.481906,
  "bytes_scanned": 74,
  "issues": [
    {
      "message": "Found REDUCE opcode - potential __reduce__ method execution",
      "severity": "warning",
      "location": "evil.pickle (pos 71)",
      "details": {
        "position": 71,
        "opcode": "REDUCE",
        "ml_context_confidence": 0.0
      },
      "timestamp": 1750168822.482304
    },
    {
      "message": "Suspicious module reference found: posix.system",
      "severity": "critical",
      "location": "evil.pickle (pos 28)",
      "details": {
        "module": "posix",
        "function": "system",
        "position": 28,
        "opcode": "STACK_GLOBAL",
        "ml_context_confidence": 0.0
      },
      "timestamp": 1750168822.482378
    }
  ],
  "has_errors": false,
  "files_scanned": 1,
  "duration": 0.0005328655242919922,
  "assets": [
    {
      "path": "model.safetensors",
      "type": "safetensors",
      "tensors": ["embedding.weight", "decoder.weight"]
    }
  ]
}
```

Some issues also include a `why` field explaining **why** the finding is a
problem:

```json
{
  "message": "Dangerous import: os.system",
  "severity": "critical",
  "location": "test.pkl",
  "why": "The 'os' module provides direct access to operating system functions."
}
```

Each issue includes a `message`, `severity` level (`critical`, `warning`, `info`, `debug`), `location`, and scanner-specific `details`.
The `assets` array lists every file and component encountered during the scan, including nested archive members and tensor names.

## 🔄 CI/CD Integration

ModelAudit is designed to integrate seamlessly into CI/CD pipelines with clear exit codes:

- **Exit Code 0**: No security issues found
- **Exit Code 1**: Security issues found (fails the build)
- **Exit Code 2**: Scan errors occurred (fails the build)

### Basic Integration

```bash
# Install ModelAudit
pip install modelaudit[all]

# Scan models and fail build if issues found
modelaudit scan models/ --format json --output scan-results.json

# Optional: Upload scan-results.json as build artifact
```

### Platform Examples

**GitHub Actions:**

```yaml
- name: Scan models
  run: |
    rye run modelaudit scan models/ --format json --output scan-results.json
    if [ $? -eq 1 ]; then
      echo "Security issues found in models!"
      exit 1
    fi
```

**GitLab CI:**

```yaml
model-security-scan:
  script:
    - pip install modelaudit[all]
    - modelaudit scan models/ --format json --output results.json
  artifacts:
    paths: [results.json]
```

**Jenkins:**

```groovy
sh 'pip install modelaudit[all]'
sh 'modelaudit scan models/ --format json --output results.json'
```

## 🔧 Troubleshooting

### Common Issues

**Installation Problems:**

```bash
# If you get dependency conflicts
pip install --upgrade pip setuptools wheel
pip install modelaudit[all] --no-cache-dir

# Install with Rye (recommended)
rye sync --features all

# Or with pip
pip install -e .[all]

# If optional dependencies fail, install base package first
pip install modelaudit
pip install tensorflow h5py torch pyyaml safetensors onnx joblib  # Add what you need
```

**Large Models:**

```bash
# Increase file size limit and timeout for large models
modelaudit scan large_model.pt --max-file-size 5000000000 --timeout 600 --max-total-size 10000000000
```

**Cloud Storage Authentication:**

```bash
# Check AWS credentials
aws sts get-caller-identity

# Check GCS authentication
gcloud auth list

# Test S3 access
aws s3 ls s3://your-bucket/

# Test GCS access
gsutil ls gs://your-bucket/

# Common authentication errors:
# - "NoCredentialsError": Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
# - "DefaultCredentialsError": Set GOOGLE_APPLICATION_CREDENTIALS or run gcloud auth
# - "Access Denied": Check bucket permissions and IAM roles
```

**Testing:**

```bash
# Run all tests
rye run pytest

# Run with coverage
rye run pytest --cov=modelaudit

# Run specific test categories
rye run pytest tests/test_pickle_scanner.py -v
rye run pytest tests/test_integration.py -v

# Run tests with all optional dependencies
rye sync --features all
rye run pytest

# Run comprehensive migration test (tests everything including Docker)
./test_migration.sh
```

**Debug Mode:**

```bash
# Enable verbose output for troubleshooting
modelaudit scan model.pkl --verbose
```

**Development Commands:**

```bash
# Run linting and formatting with Ruff
rye run ruff check modelaudit/          # Check for linting issues
rye run ruff check --fix modelaudit/    # Fix auto-fixable issues
rye run ruff format modelaudit/         # Format code

# Type checking
rye run mypy modelaudit/

# Build package
rye build

# Publish (maintainers only)
rye publish
```

**Getting Help:**

- Use `--verbose` for detailed output
- Use `--format json` to see all details
- Check file permissions and format support
- Report issues on the [promptfoo GitHub repository](https://github.com/promptfoo/promptfoo/issues)

## ⚠️ Limitations

ModelAudit is designed to find **obvious security risks** in model files, including direct code execution attempts, known dangerous patterns, malicious archive structures, and suspicious configurations.

**What it cannot detect:**

- Advanced adversarial attacks or subtle weight manipulation
- Heavily encoded/encrypted malicious payloads
- Runtime behavior that only triggers under specific conditions
- Model poisoning through careful data manipulation
- All possible license types or complex license arrangements

**Recommendations:**

- Use ModelAudit as one layer of your security strategy
- Review flagged issues manually - not all warnings indicate malicious intent
- Combine with other security practices like sandboxed execution and runtime monitoring
- Consult legal counsel for license compliance requirements beyond technical detection
- Implement automated scanning in CI/CD pipelines

## 📝 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - see the [LICENSE](LICENSE) file for details.
