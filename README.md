# ModelAudit

A security scanner for AI models. Quickly check your AIML models for potential security risks before deployment.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/release/python-390/)

<img width="989" alt="image" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

## Table of Contents

- [ModelAudit](#modelaudit)
  - [Table of Contents](#table-of-contents)
  - [🔍 What It Does](#-what-it-does)
  - [🚀 Quick Start](#-quick-start)
    - [Installation](#installation)
    - [Basic Usage](#basic-usage)
  - [✨ Features](#-features)
    - [Core Capabilities](#core-capabilities)
    - [Reporting \& Integration](#reporting--integration)
    - [Security Detection](#security-detection)
    - [Advanced Security Protections](#advanced-security-protections)
  - [🛡️ Supported Model Formats](#️-supported-model-formats)
    - [Weight Analysis](#weight-analysis)
    - [ONNX Scanner](#onnx-scanner)
  - [🛠️ Security Scanners](#️-security-scanners)
    - [Pickle Scanner](#pickle-scanner)
    - [TensorFlow Scanner](#tensorflow-scanner)
    - [Keras Scanner](#keras-scanner)
    - [PyTorch Scanner](#pytorch-scanner)
    - [Joblib Scanner](#joblib-scanner)
    - [NumPy Scanner](#numpy-scanner)
    - [SafeTensors Scanner](#safetensors-scanner)
    - [GGUF/GGML Scanner](#ggufggml-scanner)
    - [Manifest Scanner](#manifest-scanner)
    - [ZIP Scanner](#zip-scanner)
    - [Weight Distribution Scanner](#weight-distribution-scanner)
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
- **Custom ONNX operators** and external data integrity issues
- **Encoded payloads** and suspicious string patterns
- **Risky configurations** in model architectures
- **Suspicious patterns** in model manifests and configuration files
- **Models with blacklisted names** or content patterns
- **Malicious content in ZIP archives** including nested archives and zip bombs
- **Anomalous weight patterns** that may indicate trojaned models (statistical analysis)
- **Compressed archive vulnerabilities** (compression bombs, memory exhaustion)
- **NumPy array integrity issues** (malformed headers, dangerous dtypes)
- **Joblib serialization risks** (embedded pickle content, decompression attacks)

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

# For YAML manifest scanning
pip install modelaudit[yaml]

# For SafeTensors model scanning
pip install modelaudit[safetensors]

# For Joblib model scanning
pip install modelaudit[joblib]

# Install all optional dependencies
pip install modelaudit[all]
```

### Basic Usage

```bash
# Scan a single model
modelaudit scan model.pkl

# Scan an ONNX model
modelaudit scan model.onnx

# Scan multiple models of different formats
modelaudit scan model1.pkl model2.h5 model3.pt model4.joblib model5.npy

# Scan a directory
modelaudit scan ./models/

# Export results to JSON
modelaudit scan model.pkl --format json --output results.json
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

## ✨ Features

### Core Capabilities

- **Multiple Format Support**: PyTorch (.pt, .pth, .bin), TensorFlow (SavedModel, .pb), Keras (.h5, .hdf5, .keras), SafeTensors (.safetensors), GGUF/GGML (.gguf, .ggml), Pickle (.pkl, .pickle, .ckpt), Joblib (.joblib), NumPy (.npy, .npz), ZIP archives (.zip), Manifests (.json, .yaml, .xml, etc.)
- **Automatic Format Detection**: Identifies model formats automatically
- **Deep Security Analysis**: Examines model internals, not just metadata
- **Recursive Archive Scanning**: Scans contents of ZIP files and nested archives
- **Batch Processing**: Scan multiple files and directories efficiently
- **Configurable Scanning**: Set timeouts, file size limits, custom blacklists

### Reporting & Integration

- **Multiple Output Formats**: Human-readable text and machine-readable JSON
- **Detailed Reporting**: Scan duration, files processed, bytes scanned, issue severity
- **Severity Levels**: CRITICAL, WARNING, INFO, DEBUG for flexible filtering
- **CI/CD Integration**: Clear exit codes for automated pipeline integration

### Security Detection

- **Code Execution**: Detects embedded Python code, eval/exec calls, system commands
- **Pickle Security**: Analyzes dangerous opcodes, suspicious imports, encoded payloads
- **Model Integrity**: Checks for unexpected files, suspicious configurations
- **Archive Security**: Automatic Zip-Slip protection against directory traversal, zip bombs, malicious nested files
- **Pattern Matching**: Custom blacklist patterns for organizational policies

### Advanced Security Protections

- **Compression Bomb Detection**: Prevents decompression attacks with configurable ratio limits (>100x compression flagged)
- **Memory Exhaustion Protection**: Configurable limits on file sizes, array dimensions, and memory usage
- **Integer Overflow Prevention**: Safe arithmetic prevents malicious array size calculations from causing crashes
- **Resource Limits**: Configurable timeouts, file size limits, and memory constraints prevent DoS attacks
- **Attack Scenario Testing**: Comprehensive test suite validates protection against real-world attack vectors

## 🛡️ Supported Model Formats

ModelAudit provides specialized security scanners for different model formats:

| Format             | File Extensions                                                                                          | What We Check                                                   |
| ------------------ | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Pickle**         | `.pkl`, `.pickle`, `.bin`, `.pt`, `.pth`, `.ckpt`                                                        | Malicious code execution, dangerous opcodes, suspicious imports |
| **PyTorch Zip**    | `.pt`, `.pth`                                                                                            | Embedded pickle analysis, suspicious files, custom patterns     |
| **PyTorch Binary** | `.bin`                                                                                                   | Binary tensor data analysis, embedded content                   |
| **TensorFlow**     | SavedModel dirs, `.pb`                                                                                   | Suspicious operations, file I/O, Python execution               |
| **Keras**          | `.h5`, `.hdf5`, `.keras`                                                                                 | Lambda layers, custom objects, dangerous configurations         |
| **ONNX**           | `.onnx`                                                                                                  | Custom operators, external data validation, tensor integrity    |
| **SafeTensors**    | `.safetensors`                                                                                           | Metadata integrity, tensor validation                           |
| **GGUF/GGML**      | `.gguf`, `.ggml`                                                                                         | Header validation, metadata integrity, suspicious patterns      |
| **Joblib**         | `.joblib`                                                                                                | Compression bombs, embedded pickle analysis, decompression safety |
| **NumPy**          | `.npy`, `.npz`                                                                                           | Array integrity, dangerous dtypes, dimension validation         |
| **ZIP Archives**   | `.zip`                                                                                                   | Recursive content scanning, zip bombs, directory traversal      |
| **Manifests**      | `.json`, `.yaml`, `.yml`, `.xml`, `.toml`, `.ini`, `.cfg`, `.config`, `.manifest`, `.model`, `.metadata` | Suspicious keys, credential exposure, blacklisted patterns      |

### Weight Analysis

ModelAudit can detect anomalous weight patterns that may indicate trojaned models using statistical analysis. This feature is disabled by default for large language models to avoid false positives.

### ONNX Scanner

**Inspects ONNX models for security risks and integrity issues:**

- **Custom Operators**: Flags non-standard operator domains that could contain malicious code
- **External Data Validation**: Verifies external weight files exist and have correct sizes
- **Tensor Integrity**: Checks for truncated or corrupted tensor data
- **Path Traversal Protection**: Ensures external data files stay within model directory
- **Model Structure Analysis**: Validates ONNX model format and metadata

## 🛠️ Security Scanners

### Pickle Scanner

**Detects malicious code in Python pickle files:**

- Dangerous opcodes: `REDUCE`, `INST`, `OBJ`, `STACK_GLOBAL`
- Suspicious imports: `os`, `subprocess`, `eval`, `exec`
- Encoded payloads and obfuscated code
- `__reduce__` method exploits

### TensorFlow Scanner

**Analyzes TensorFlow SavedModel for suspicious operations:**

- File I/O operations: `ReadFile`, `WriteFile`
- Python execution: `PyFunc`, `PyCall`
- System operations: `ShellExecute`, `SystemConfig`
- Checks SavedModel directory structure

### Keras Scanner

**Examines Keras H5 models for security risks:**

- Dangerous layer types: `Lambda`, `TFOpLambda`
- Suspicious configurations containing code execution
- Custom objects and metrics with arbitrary code
- Model architecture analysis

### PyTorch Scanner

**Scans PyTorch models (ZIP-based format):**

- Embedded pickle file analysis
- Missing standard files (data.pkl warnings)
- Suspicious additional files (Python scripts, executables)
- Custom blacklist pattern matching

### Joblib Scanner

**Analyzes Joblib serialized files for security risks:**

- **Compression Bomb Protection**: Detects suspicious compression ratios (>100x) that could cause memory exhaustion
- **Memory Limits**: Configurable limits on decompressed file sizes and memory usage
- **Format Validation**: Supports zlib, lzma, and ZIP-compressed joblib files
- **Embedded Pickle Analysis**: Scans decompressed pickle content using the full pickle scanner security checks
- **Safe Decompression**: Chunked reading and size validation prevent resource exhaustion attacks

### NumPy Scanner

**Examines NumPy binary files for integrity and security:**

- **Array Validation**: Comprehensive validation of array dimensions, data types, and memory requirements
- **Overflow Protection**: Prevents integer overflow in size calculations that could bypass security checks
- **Memory Limits**: Configurable limits on total array size (default: 1GB) and individual dimensions
- **Dangerous Type Detection**: Blocks potentially unsafe dtypes like 'object' and 'void' that could contain arbitrary Python objects
- **File Integrity**: Validates NumPy file format, magic signatures, and header consistency

### SafeTensors Scanner

**Validates SafeTensors model files for integrity:**

- Parses header metadata and verifies tensor offsets
- Checks dtype and shape sizes against byte ranges
- Flags suspicious or malformed metadata entries

### GGUF/GGML Scanner

**Validates GGUF and GGML model files:**

- Header validation and metadata integrity
- Suspicious patterns and configurations
- Format compliance checking

### Manifest Scanner

**Analyzes configuration and manifest files:**

- Suspicious keys: network access, file paths, execution commands
- Credential exposure: passwords, API keys, secrets
- Blacklisted model names and patterns
- Supports JSON, YAML, XML, TOML formats

### ZIP Scanner

**Scans ZIP archives and their contents:**

- **Recursive scanning**: Analyzes files within ZIP archives using appropriate scanners
- **Security checks**: Detects directory traversal attempts, zip bombs, suspicious compression ratios
- **Nested archive support**: Scans ZIP files within ZIP files up to configurable depth
- **Content analysis**: Each file in the archive is scanned with its appropriate scanner
- **Resource limits**: Configurable max depth, max entries, and max file size protections

### Weight Distribution Scanner

**Detects anomalous weight patterns that may indicate trojaned models:**

- **Outlier detection**: Uses Z-score analysis to find neurons with abnormal weight magnitudes
- **Dissimilarity analysis**: Identifies weight vectors that are significantly different from others using cosine similarity
- **Extreme value detection**: Flags neurons with unusually large weight values
- **Multi-format support**: Works with PyTorch, Keras/TensorFlow H5, ONNX, and SafeTensors models
- **Focus on classification models**: Designed for models with <10k output classes

**Note**: This scanner is disabled by default for LLMs (models with >10k vocabulary size) as the detection methods are not effective for large language models. To enable experimental LLM scanning, use `--config '{"enable_llm_checks": true}'`.

## ⚙️ Advanced Usage

### Command Line Options

```bash
# Set maximum file size to scan (1GB limit)
modelaudit scan model.pkl --max-file-size 1073741824

# Add custom blacklist patterns
modelaudit scan model.pkl --blacklist "unsafe_model" --blacklist "malicious_net"

# Set scan timeout (5 minutes)
modelaudit scan large_model.pkl --timeout 300

# Verbose output for debugging
modelaudit scan model.pkl --verbose

# Custom security configuration
modelaudit scan model.pkl --config '{
    "max_decompression_ratio": 50.0,
    "max_decompressed_size": 50000000,
    "max_array_bytes": 500000000,
    "max_dimensions": 16,
    "timeout": 120
}'
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
  "duration": 0.0005328655242919922
}
```

Each issue includes a `message`, `severity` level (`critical`, `warning`, `info`, `debug`), `location`, and scanner-specific `details`.

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
    pip install modelaudit[all]
    modelaudit scan models/ --format json --output results.json
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

# If optional dependencies fail, install base package first
pip install modelaudit
pip install tensorflow h5py torch pyyaml safetensors onnx joblib  # Add what you need
```

**Large Models:**
```bash
# Increase file size limit and timeout for large models
modelaudit scan large_model.pt --max-file-size 5000000000 --timeout 600
```

**Debug Mode:**
```bash
# Enable verbose output for troubleshooting
modelaudit scan model.pkl --verbose

# Create test files for scanning
python -c "import pickle; pickle.dump({'test': 'data'}, open('test_model.pkl', 'wb'))"
python -c "import joblib; joblib.dump({'test': 'data'}, 'test_model.joblib')"
python -c "import numpy as np; np.save('test_model.npy', np.array([1, 2, 3]))"

# Test scanning them
modelaudit scan test_model.pkl test_model.joblib test_model.npy
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

**Recommendations:**
- Use ModelAudit as one layer of your security strategy
- Review flagged issues manually - not all warnings indicate malicious intent
- Combine with other security practices like sandboxed execution and runtime monitoring
- Implement automated scanning in CI/CD pipelines

## 📝 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - see the [LICENSE](LICENSE) file for details.
