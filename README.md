# ModelAudit

**Secure your AI models before deployment.** Static scanner that detects malicious code, backdoors, and security vulnerabilities in ML model files — without ever loading or executing them.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Code Style: ruff](https://img.shields.io/badge/code%20style-ruff-005cd7.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/github/license/promptfoo/modelaudit)](https://github.com/promptfoo/modelaudit/blob/main/LICENSE)

<img width="989" alt="ModelAudit scan results" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

**[Full Documentation](https://www.promptfoo.dev/docs/model-audit/)** | **[Usage Examples](https://www.promptfoo.dev/docs/model-audit/usage/)** | **[Supported Formats](https://www.promptfoo.dev/docs/model-audit/scanners/)**

## Quick Start

**Requires Python 3.10+**

```bash
pip install modelaudit[all]

# Scan a file or directory
modelaudit model.pkl
modelaudit ./models/

# Export results for CI/CD
modelaudit model.pkl --format json --output results.json
```

```
$ modelaudit suspicious_model.pkl

Files scanned: 1 | Issues found: 2 critical, 1 warning

1. suspicious_model.pkl (pos 28): [CRITICAL] Malicious code execution attempt
   Why: Contains os.system() call that could run arbitrary commands

2. suspicious_model.pkl (pos 52): [WARNING] Dangerous pickle deserialization
   Why: Could execute code when the model loads
```

## What It Detects

- **Code execution attacks** in Pickle, PyTorch, NumPy, and Joblib files
- **Model backdoors** with hidden functionality or suspicious weight patterns
- **Embedded secrets** — API keys, tokens, and credentials in model weights or metadata
- **Network indicators** — URLs, IPs, and socket usage that could enable data exfiltration
- **Archive exploits** — path traversal, symlink attacks in ZIP/TAR/7z files
- **Unsafe ML operations** — Lambda layers, custom ops, TorchScript/JIT, template injection
- **Supply chain risks** — tampering, license violations, suspicious configurations

## Supported Formats

ModelAudit includes **30 specialized scanners** covering model, archive, and configuration formats:

| Format           | Extensions                            | Risk   |
| ---------------- | ------------------------------------- | ------ |
| **Pickle**       | `.pkl`, `.pickle`, `.dill`            | HIGH   |
| **PyTorch**      | `.pt`, `.pth`, `.ckpt`, `.bin`        | HIGH   |
| **Joblib**       | `.joblib`                             | HIGH   |
| **NumPy**        | `.npy`, `.npz`                        | HIGH   |
| **TensorFlow**   | `.pb`, SavedModel dirs                | MEDIUM |
| **Keras**        | `.h5`, `.hdf5`, `.keras`              | MEDIUM |
| **ONNX**         | `.onnx`                               | MEDIUM |
| **XGBoost**      | `.bst`, `.model`, `.ubj`              | MEDIUM |
| **SafeTensors**  | `.safetensors`                        | LOW    |
| **GGUF/GGML**    | `.gguf`, `.ggml`                      | LOW    |
| **JAX/Flax**     | `.msgpack`, `.flax`, `.orbax`, `.jax` | LOW    |
| **TFLite**       | `.tflite`                             | LOW    |
| **ExecuTorch**   | `.ptl`, `.pte`                        | LOW    |
| **TensorRT**     | `.engine`, `.plan`                    | LOW    |
| **PaddlePaddle** | `.pdmodel`, `.pdiparams`              | LOW    |
| **OpenVINO**     | `.xml`                                | LOW    |
| **PMML**         | `.pmml`                               | LOW    |

Plus scanners for ZIP, TAR, 7-Zip, OCI layers, Jinja2 templates, JSON/YAML metadata, manifests, and text files.

[View complete format documentation](https://www.promptfoo.dev/docs/model-audit/scanners/)

## Remote Sources

Scan models directly from remote registries and cloud storage:

```bash
# Hugging Face
modelaudit https://huggingface.co/gpt2
modelaudit hf://microsoft/DialoGPT-medium

# Cloud storage
modelaudit s3://bucket/model.pt
modelaudit gs://bucket/models/

# MLflow registry
modelaudit models:/MyModel/Production

# JFrog Artifactory (files and folders)
# Auth: export JFROG_API_TOKEN=...
modelaudit https://company.jfrog.io/artifactory/repo/model.pt
modelaudit https://company.jfrog.io/artifactory/repo/models/

# DVC-tracked models
modelaudit model.dvc
```

## Installation

```bash
# Everything (recommended)
pip install modelaudit[all]

# Core only (pickle, numpy, archives)
pip install modelaudit

# Specific frameworks
pip install modelaudit[tensorflow,pytorch,h5,onnx,safetensors]

# CI/CD environments
pip install modelaudit[all-ci]

# Docker
docker run --rm -v "$(pwd)":/app ghcr.io/promptfoo/modelaudit:latest model.pkl
```

## CLI Options

```
--format {text,json,sarif}   Output format (default: text)
--output FILE                Write results to file
--strict                     Fail on warnings, scan all file types
--sbom FILE                  Generate CycloneDX SBOM
--stream                     Download, scan, and delete files one-by-one (saves disk)
--max-size SIZE              Size limit (e.g., 10GB)
--timeout SECONDS            Override scan timeout
--dry-run                    Preview what would be scanned
--verbose / --quiet          Control output detail
--blacklist PATTERN          Additional patterns to flag
--no-cache                   Disable result caching
--progress                   Force progress display
```

Exit codes: `0` clean, `1` issues found, `2` errors.

## Documentation

- **[Full docs](https://www.promptfoo.dev/docs/model-audit/)** — setup, configuration, and advanced usage
- **[Usage examples](https://www.promptfoo.dev/docs/model-audit/usage/)** — CI/CD integration, remote scanning, SBOM generation
- **[Supported formats](https://www.promptfoo.dev/docs/model-audit/scanners/)** — detailed scanner documentation
- **Troubleshooting** — run `modelaudit doctor --show-failed` to check scanner availability

## License

MIT License — see [LICENSE](LICENSE) for details.
