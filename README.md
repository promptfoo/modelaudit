# ModelAudit

A security scanner for machine learning models. Quickly check your AIML models for potential security risks before deployment.

## 🔍 What It Does

ModelAudit scans ML model files for:

- Malicious code (e.g., `os.system` calls in pickled models)
- Suspicious TensorFlow operations
- Potentially unsafe Keras Lambda layers
- Models with blacklisted names
- Dangerous pickle opcodes and serialization patterns
- Suspicious string patterns that might indicate encoded payloads
- Risky configurations in model architectures
- Suspicious patterns in model manifests and configuration files

## 🚀 Quick Start

### Installation

```bash
# Using pip
pip install modelaudit

# Or with optional dependencies for specific model formats
pip install modelaudit[tensorflow,h5,pytorch]

# For YAML manifest scanning support
pip install modelaudit[yaml]

# For all dependencies
pip install modelaudit[all]
```

### Basic Usage

```bash
# Scan one or more models or directories
modelaudit scan model.pkl model2.h5 models_directory

# Export results to JSON
modelaudit scan model.pkl --format json --output results.json

# Set maximum file size to scan
modelaudit scan model.pkl --max-file-size 1073741824  # 1GB limit

# Add custom blacklist patterns
modelaudit scan model.pkl --blacklist "unsafe_model" --blacklist "malicious_net"
```

## ✨ Features

- **Multiple Format Support**: Scans PyTorch, TensorFlow, Keras, and pickle models
- **Automatic Format Detection**: Identifies model formats automatically
- **Comprehensive Scanning**: Checks for various security issues with severity levels
- **Batch Processing**: Scan multiple files and directories at once
- **Configurable Timeouts**: Set scan timeouts for large models
- **Detailed Reporting**: Get information about scan duration, files scanned, and bytes processed
- **Structured Output**: Export results as JSON for integration with other tools
- **Name Blacklisting**: Block models with names matching suspicious patterns
- **Manifest Scanning**: Detect suspicious patterns in model configuration files

## 🛡️ Scanners

ModelAudit includes specialized scanners for different model formats:

- **Pickle Scanner**: Detects malicious code and encoded payloads in pickle files
- **TensorFlow Scanner**: Identifies suspicious operations in SavedModel format
- **Keras Scanner**: Checks for unsafe Lambda layers and risky configurations
- **PyTorch Scanner**: Examines PyTorch models for security issues
- **Manifest Scanner**: Analyzes model manifests and configuration files for suspicious patterns and blacklisted names

## 🛠️ Development

### Using Poetry

```bash
# Clone the repository
git clone https://github.com/ianxwebster/modelaudit.git
cd modelaudit

# Install dependencies
poetry install

# Install with extras
poetry install --extras "all"
```

## 📝 License

This project is licensed under the MIT License.
