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

ModelAudit includes specialized scanners covering model, archive, and configuration formats:

| Format                  | Extensions                            | Risk   |
| ----------------------- | ------------------------------------- | ------ |
| **Pickle**              | `.pkl`, `.pickle`, `.dill`            | HIGH   |
| **PyTorch**             | `.pt`, `.pth`, `.ckpt`, `.bin`        | HIGH   |
| **Joblib**              | `.joblib`                             | HIGH   |
| **NumPy**               | `.npy`, `.npz`                        | HIGH   |
| **R Serialized**        | `.rds`, `.rda`, `.rdata`              | HIGH   |
| **TensorFlow**          | `.pb`, `.meta`, SavedModel dirs       | MEDIUM |
| **Keras**               | `.h5`, `.hdf5`, `.keras`              | MEDIUM |
| **ONNX**                | `.onnx`                               | MEDIUM |
| **CoreML**              | `.mlmodel`                            | LOW    |
| **MXNet**               | `*-symbol.json`, `*-NNNN.params`      | LOW    |
| **NeMo**                | `.nemo`                               | MEDIUM |
| **CNTK**                | `.dnn`, `.cmf`                        | MEDIUM |
| **RKNN**                | `.rknn`                               | MEDIUM |
| **Torch7**              | `.t7`, `.th`, `.net`                  | HIGH   |
| **CatBoost**            | `.cbm`                                | MEDIUM |
| **XGBoost**             | `.bst`, `.model`, `.ubj`              | MEDIUM |
| **LightGBM**            | `.lgb`, `.lightgbm`, `.model`         | MEDIUM |
| **Llamafile**           | `.llamafile`, extensionless, `.exe`   | MEDIUM |
| **TorchServe**          | `.mar`                                | HIGH   |
| **SafeTensors**         | `.safetensors`                        | LOW    |
| **GGUF/GGML**           | `.gguf`, `.ggml`                      | LOW    |
| **JAX/Flax**            | `.msgpack`, `.flax`, `.orbax`, `.jax` | LOW    |
| **TFLite**              | `.tflite`                             | LOW    |
| **ExecuTorch**          | `.ptl`, `.pte`                        | LOW    |
| **TensorRT**            | `.engine`, `.plan`                    | LOW    |
| **PaddlePaddle**        | `.pdmodel`, `.pdiparams`              | LOW    |
| **OpenVINO**            | `.xml`                                | LOW    |
| **Skops**               | `.skops`                              | HIGH   |
| **PMML**                | `.pmml`                               | LOW    |
| **Compressed Wrappers** | `.gz`, `.bz2`, `.xz`, `.lz4`, `.zlib` | MEDIUM |

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

### Authentication Environment Variables

- `HF_TOKEN` for private Hugging Face repositories
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and optional `AWS_SESSION_TOKEN`) for S3
- `GOOGLE_APPLICATION_CREDENTIALS` for GCS
- `MLFLOW_TRACKING_URI` for MLflow registry access
- `JFROG_API_TOKEN` or `JFROG_ACCESS_TOKEN` for JFrog Artifactory
- Store credentials in environment variables or a secrets manager, and never commit tokens/keys.

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

Primary commands:

```bash
modelaudit [PATHS...]                           # Default scan command
modelaudit scan [OPTIONS] PATHS...              # Explicit scan command
modelaudit metadata [OPTIONS] PATH              # Extract model metadata safely (no deserialization by default)
modelaudit doctor [--show-failed]               # Diagnose scanner/dependency availability
modelaudit debug [--json] [--verbose]           # Environment and configuration diagnostics
modelaudit cache [stats|clear|cleanup] [OPTIONS]
```

Common scan options:

```text
--format {text,json,sarif}   Output format (default: auto-detected)
--output FILE                Write results to file
--strict                     Fail on warnings, scan all file types, strict license validation
--sbom FILE                  Generate CycloneDX SBOM
--stream                     Download, scan, and delete files one-by-one (saves disk)
--max-size SIZE              Size limit (e.g., 10GB)
--timeout SECONDS            Override scan timeout
--dry-run                    Preview what would be scanned
--verbose / --quiet          Control output detail
--blacklist PATTERN          Additional patterns to flag
--no-cache                   Disable result caching
--cache-dir DIR              Set cache directory for downloads and scan results
--progress                   Force progress display
```

## Metadata Extraction

```bash
# Human-readable summary (safe default: no model deserialization)
modelaudit metadata model.safetensors

# Machine-readable output
modelaudit metadata ./models --format json --output metadata.json

# Focus only on security-relevant metadata fields
modelaudit metadata model.onnx --security-only
```

`--trust-loaders` enables scanner metadata loaders that may deserialize model content. Only use this on trusted artifacts in isolated environments.

## Exit Codes

- `0`: No security issues detected
- `1`: Security issues detected
- `2`: Scan errors

## Telemetry and Privacy

ModelAudit includes telemetry for product reliability and usage analytics.

- Collected metadata can include command usage, scan timing, scanner/file-type usage, issue severity/type aggregates, and model path or URL identifiers.
- Model files are scanned locally and ModelAudit does not upload model binary contents as telemetry events.
- Telemetry is disabled automatically in CI/test environments and in editable development installs by default.

Opt out explicitly with either environment variable:

```bash
export PROMPTFOO_DISABLE_TELEMETRY=1
# or
export NO_ANALYTICS=1
```

To opt in during editable/development installs:

```bash
export MODELAUDIT_TELEMETRY_DEV=1
```

## Output Examples

```bash
# JSON for CI/CD pipelines
modelaudit model.pkl --format json --output results.json

# SARIF for code scanning platforms
modelaudit model.pkl --format sarif --output results.sarif
```

## Troubleshooting

- Run `modelaudit doctor --show-failed` to list unavailable scanners and missing optional deps.
- Run `modelaudit debug --json` to collect environment/config diagnostics for bug reports.
- Use `modelaudit cache cleanup --max-age 30` to remove stale cache entries safely.
- If `pip` installs an older release, verify Python is `3.10+` (`python --version`).
- For additional troubleshooting and cloud auth guidance, see:
  - https://www.promptfoo.dev/docs/model-audit/
  - https://www.promptfoo.dev/docs/model-audit/usage/

## Documentation

- **[Full docs](https://www.promptfoo.dev/docs/model-audit/)** — setup, configuration, and advanced usage
- **[Usage examples](https://www.promptfoo.dev/docs/model-audit/usage/)** — CI/CD integration, remote scanning, SBOM generation
- **[Supported formats](https://www.promptfoo.dev/docs/model-audit/scanners/)** — detailed scanner documentation
- **[Support policy](SUPPORT.md)** — supported Python/OS versions and maintenance policy
- **[Security model and limitations](docs/user/security-model.md)** — what ModelAudit does and does not guarantee
- **[Compatibility matrix](docs/user/compatibility-matrix.md)** — file formats vs optional dependencies
- **[Metadata extraction guide](docs/user/metadata-extraction.md)** — safe metadata workflows and `--trust-loaders` guidance
- **[Offline/air-gapped guide](docs/user/offline-air-gapped.md)** — secure operation without internet access
- **[Scanner contributor quickstart](docs/agents/new-scanner-quickstart.md)** — safe workflow for new scanner development
- **Troubleshooting** — run `modelaudit doctor --show-failed` to check scanner availability

## License

MIT License — see [LICENSE](LICENSE) for details.
