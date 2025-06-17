# ModelAudit

A security scanner for AI models. Quickly check your AIML models for potential security risks before deployment.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/release/python-390/)

<img width="989" alt="image" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

## Table of Contents

- [What It Does](#-what-it-does)
- [Quick Start](#-quick-start)
- [Features](#-features)
- [Supported Model Formats](#️-supported-model-formats)
- [Advanced Usage](#-advanced-usage)
- [JSON Output Format](#-json-output-format)
- [CI/CD Integration](#-cicd-integration)
- [Troubleshooting](#-troubleshooting)
- [Limitations](#-limitations)
- [Development](#️-development)
- [License](#-license)

## 🔍 What It Does

ModelAudit scans ML model files for:

- **Malicious code execution** (e.g., `os.system` calls in pickled models)
- **Suspicious TensorFlow operations** (PyFunc, file I/O operations)
- **Potentially unsafe Keras Lambda layers** with arbitrary code execution
- **Dangerous pickle opcodes** (REDUCE, INST, OBJ, STACK_GLOBAL)
- **Encoded payloads** and suspicious string patterns
- **Risky configurations** in model architectures
- **Suspicious patterns** in model manifests and configuration files
- **Models with blacklisted names** or content patterns
- **Malicious content in ZIP archives** including nested archives and zip bombs

## 🚀 Quick Start

### Installation

ModelAudit is available on [PyPI](https://pypi.org/project/modelaudit/).

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

# For YAML manifest scanning
pip install modelaudit[yaml]

# Install all optional dependencies
pip install modelaudit[all]
```

### Basic Usage

```bash
# Scan a single model
modelaudit scan model.pkl

# Scan multiple models
modelaudit scan model1.pkl model2.h5 model3.pt

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
Issues found: 2 errors, 1 warnings

1. suspicious_model.pkl (pos 28): [CRITICAL] Suspicious module reference found: posix.system
2. suspicious_model.pkl (pos 52): [WARNING] Found REDUCE opcode - potential __reduce__ method execution

────────────────────────────────────────────────────────────────────────────────
✗ Scan completed with findings
```

## ✨ Features

### Core Capabilities

- **Multiple Format Support**: PyTorch (.pt, .pth), TensorFlow (SavedModel), Keras (.h5, .keras), SafeTensors (.safetensors), Pickle (.pkl), ZIP archives (.zip)
- **Automatic Format Detection**: Identifies model formats automatically
- **Deep Security Analysis**: Examines model internals, not just metadata
- **Recursive Archive Scanning**: Scans contents of ZIP files and nested archives
- **Batch Processing**: Scan multiple files and directories efficiently
- **Configurable Scanning**: Set timeouts, file size limits, custom blacklists

### Reporting & Integration

- **Detailed Reporting**: Scan duration, files processed, bytes scanned, issue severity
- **Multiple Output Formats**: Human-readable text and machine-readable JSON
- **Severity Levels**: ERROR, WARNING, INFO, DEBUG for flexible filtering
- **CI/CD Ready**: Clear exit codes for automated pipeline integration

### Security Detection

- **Code Execution**: Detects embedded Python code, eval/exec calls, system commands
- **Pickle Security**: Analyzes dangerous opcodes, suspicious imports, encoded payloads
- **Model Integrity**: Checks for unexpected files, suspicious configurations
- **Archive Security**: Directory traversal attacks, zip bombs, malicious nested files
- **Pattern Matching**: Custom blacklist patterns for organizational policies

## 🛡️ Supported Model Formats

ModelAudit provides specialized security scanners for different model formats:

| Format           | File Extensions          | What We Check                                                   |
| ---------------- | ------------------------ | --------------------------------------------------------------- |
| **Pickle**       | `.pkl`, `.joblib`        | Malicious code execution, dangerous opcodes, suspicious imports |
| **PyTorch**      | `.pt`, `.pth`            | Embedded pickle analysis, suspicious files, custom patterns     |
| **TensorFlow**   | SavedModel dirs          | Suspicious operations, file I/O, Python execution               |
| **Keras**        | `.h5`, `.keras`          | Lambda layers, custom objects, dangerous configurations         |
| **SafeTensors**  | `.safetensors`           | Metadata integrity, tensor validation                           |
| **ZIP Archives** | `.zip`                   | Recursive content scanning, zip bombs, directory traversal      |
| **Manifests**    | `.json`, `.yaml`, `.xml` | Suspicious keys, credential exposure, blacklisted patterns      |

### Weight Analysis

For classification models, ModelAudit can also detect anomalous weight patterns that may indicate trojaned models using statistical analysis (disabled by default for large language models).

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
```

### Exit Codes

ModelAudit uses different exit codes to indicate scan results:

- **0**: Success - No security issues found
- **1**: Security issues found (scan completed successfully)
- **2**: Errors occurred during scanning (e.g., file not found, scan failures)

## 📋 JSON Output Format

When using `--format json`, ModelAudit outputs:

```json
{
  "scanner_names": ["pickle"],
  "start_time": 1750135672.0367858,
  "bytes_scanned": 74,
  "issues": [
    {
      "message": "Suspicious module reference found: posix.system",
      "severity": "critical",
      "location": "evil.pickle (pos 28)",
      "details": {
        "module": "posix",
        "function": "system",
        "position": 28,
        "opcode": "STACK_GLOBAL"
      },
      "timestamp": 1750135692.850314
    }
  ],
  "has_errors": false,
  "files_scanned": 1,
  "duration": 0.0007040500640869141
}
```

### JSON Schema

| Field           | Type    | Description                           |
| --------------- | ------- | ------------------------------------- |
| `scanner_names` | array   | List of scanners used during the scan |
| `start_time`    | number  | Unix timestamp when scan started      |
| `bytes_scanned` | number  | Total bytes processed                 |
| `issues`        | array   | List of security issues found         |
| `has_errors`    | boolean | Whether operational errors occurred   |
| `files_scanned` | number  | Number of files processed             |
| `duration`      | number  | Scan duration in seconds              |

### Issue Object

| Field       | Type   | Description                                       |
| ----------- | ------ | ------------------------------------------------- |
| `message`   | string | Human-readable issue description                  |
| `severity`  | string | `"critical"`, `"warning"`, `"info"`, or `"debug"` |
| `location`  | string | File location (e.g., "file.pkl (pos 123)")        |
| `details`   | object | Scanner-specific additional information           |
| `timestamp` | number | Unix timestamp when issue was found               |

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Model Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.9"

      - name: Install ModelAudit
        run: pip install modelaudit[all]

      - name: Scan models
        run: |
          modelaudit scan models/ --format json --output scan-results.json
          # Upload results as artifact even if scan fails
          echo "SCAN_EXIT_CODE=$?" >> $GITHUB_ENV
        continue-on-error: true

      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan-results.json

      - name: Check scan results
        run: |
          if [ "$SCAN_EXIT_CODE" -eq 1 ]; then
            echo "❌ Security issues found in models!"
            cat scan-results.json
            exit 1
          elif [ "$SCAN_EXIT_CODE" -eq 2 ]; then
            echo "⚠️ Scan errors occurred"
            exit 1
          else
            echo "✅ No security issues found"
          fi
```

### GitLab CI

```yaml
stages:
  - security

model-security-scan:
  stage: security
  image: python:3.9
  before_script:
    - pip install modelaudit[all]
  script:
    - modelaudit scan models/ --format json --output scan-results.json
  artifacts:
    when: always
    reports:
      junit: scan-results.json
    paths:
      - scan-results.json
  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Model Security Scan') {
            steps {
                sh 'pip install modelaudit[all]'
                script {
                    def exitCode = sh(
                        script: 'modelaudit scan models/ --format json --output scan-results.json',
                        returnStatus: true
                    )
                    if (exitCode == 1) {
                        error("Security issues found in models!")
                    } else if (exitCode == 2) {
                        error("Scan errors occurred")
                    }
                }
            }
            post {
                always {
                    archiveArtifacts 'scan-results.json'
                }
            }
        }
    }
}
```

## 🔧 Troubleshooting

### Common Issues

**Installation Problems:**

```bash
# If you get dependency conflicts
pip install --upgrade pip setuptools wheel
pip install modelaudit[all] --no-cache-dir

# For Apple Silicon Macs with TensorFlow issues
pip install tensorflow-macos tensorflow-metal
pip install modelaudit[all]

# If optional dependencies fail
pip install modelaudit  # Install base package first
pip install tensorflow h5py torch pyyaml  # Then add what you need
```

**Memory Issues:**

```bash
# For large models, increase file size limit and use timeout
modelaudit scan large_model.pt --max-file-size 5000000000 --timeout 600

# Scan files individually instead of directories
for file in models/*.pt; do
    modelaudit scan "$file"
done
```

**Permission Errors:**

```bash
# If scanning fails due to permissions
sudo modelaudit scan /protected/path/model.pkl

# Or copy models to accessible location
cp /protected/models/* ./temp_models/
modelaudit scan ./temp_models/
```

**False Positives:**

```bash
# Use blacklist patterns to reduce noise
modelaudit scan model.pkl --blacklist "known_safe_pattern"

# Or scan with less verbose output (hides debug-level issues)
modelaudit scan model.pkl
```

### Debug Mode

```bash
# Enable verbose logging
modelaudit scan model.pkl --verbose

# Get detailed scanner information in JSON format
modelaudit scan model.pkl --verbose --format json | jq '.issues[].details'
```

### Getting Help

- **Check exit codes**: Use the exit code reference above
- **Enable verbose mode**: Add `--verbose` for detailed output
- **Review JSON output**: Use `--format json` to see all details
- **Check file permissions**: Ensure ModelAudit can read your files
- **Verify file format**: Confirm the file is a supported model format

For additional help:

- Check the [GitHub Issues](https://github.com/promptfoo/modelaudit/issues) for known problems
- Visit the [GitHub Repository](https://github.com/promptfoo/modelaudit) for source code and development information

## ⚠️ Limitations

### What ModelAudit Detects

ModelAudit is designed to find **obvious security risks** in model files, including:

- Direct code execution attempts
- Known dangerous patterns
- Malicious archive structures
- Suspicious configurations

### What It Cannot Detect

**Advanced Adversarial Attacks:**

- Subtle weight manipulation that doesn't change model architecture
- Model poisoning attacks that use normal training procedures
- Backdoors inserted through careful data poisoning

**Encrypted or Obfuscated Payloads:**

- Heavily encoded malicious code that doesn't match known patterns
- Custom serialization formats
- Encrypted sections of model files

**Runtime Behavior:**

- Code that only executes maliciously under specific conditions
- Time-based attacks or environment-specific exploits
- Network-based attacks that trigger after deployment

### False Positives

ModelAudit may flag legitimate models in these cases:

**Custom Layer Types:**

```python
# This might trigger warnings even if legitimate
model.add(Lambda(lambda x: tf.py_function(my_custom_op, [x], tf.float32)))
```

**Development Models:**

```python
# Debug code or development artifacts might trigger alerts
pickle.dump({'debug': True, 'os': __import__('os')}, file)
```

**Research Models:**

- Models with experimental architectures
- Models using custom operators or functions
- Models with debugging information embedded

### Recommendations

1. **Use ModelAudit as one layer** of your security strategy
2. **Review flagged issues manually** - not all warnings indicate malicious intent
3. **Maintain an allowlist** of known-good models and patterns
4. **Combine with other security practices**:

   - Model provenance tracking
   - Sandboxed execution environments
   - Runtime monitoring
   - Regular security audits

5. **For production environments**:
   - Scan models before deployment
   - Use configuration management to reduce false positives
   - Implement automated scanning in CI/CD pipelines
   - Monitor model behavior after deployment

## 🛠️ Development

### Installing from Source

If you want to install the latest development version from source:

```bash
# Clone repository
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install with Poetry (recommended)
poetry install --all-extras

# Or with pip
pip install -e .[all]
```

### Contributing

Interested in contributing? Visit the [GitHub Repository](https://github.com/promptfoo/modelaudit) to get started with development, view source code, and submit pull requests.

## 📝 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - see the [LICENSE](LICENSE) file for details.
