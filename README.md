# ModelAudit

**Secure your AI models before deployment.** Static scanner that detects malicious code, potential backdoor indicators, and security vulnerabilities in ML model files — without ever loading or executing them.

[![PyPI version](https://badge.fury.io/py/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Python versions](https://img.shields.io/pypi/pyversions/modelaudit.svg)](https://pypi.org/project/modelaudit/)
[![Code Style: ruff](https://img.shields.io/badge/code%20style-ruff-005cd7.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/github/license/promptfoo/modelaudit)](https://github.com/promptfoo/modelaudit/blob/main/LICENSE)
[![Security policy](https://img.shields.io/badge/security-policy-brightgreen.svg)](https://github.com/promptfoo/modelaudit/security/policy)

<img width="989" alt="ModelAudit scan results" src="https://www.promptfoo.dev/img/docs/modelaudit/modelaudit-result.png" />

**[Full Documentation](https://www.promptfoo.dev/docs/model-audit/)** | **[Usage Examples](https://www.promptfoo.dev/docs/model-audit/usage/)** | **[Supported Formats](https://www.promptfoo.dev/docs/model-audit/scanners/)**

## Why ModelAudit

Models download from untrusted registries, pass through CI, and end up running in production. Traditional SAST tools do not look at pickle opcodes, HDF5 group layouts, ONNX proto graphs, or TensorFlow SavedModel signatures — ModelAudit does:

- **Scan statically.** No model is ever loaded, unpickled, or executed.
- **Cover the formats you actually ship.** 40+ scanners spanning pickle, PyTorch, SafeTensors, ONNX, TensorFlow, Keras, GGUF, archives, and configs.
- **Fit into CI.** Machine-readable output (JSON, SARIF), strict mode, exit codes, and [selectable scanners](https://github.com/promptfoo/modelaudit/blob/main/docs/user/scanner-selection.md).
- **Surface coverage limits.** Recognized scanners report bounded-analysis gaps such as truncated reads or exhausted budgets instead of presenting them as fully covered results.

Comparable tools: [`picklescan`](https://github.com/mmaitre314/picklescan) (pickle only, Python-based), [`fickling`](https://github.com/trailofbits/fickling) (pickle only, AST-based), [`modelscan`](https://github.com/protectai/modelscan) (pickle + TensorFlow + Keras subset). ModelAudit is broader in coverage and ships a native Rust pickle engine via its companion package [`modelaudit-picklescan`](https://pypi.org/project/modelaudit-picklescan/).

## Quick Start

**Requires Python 3.10-3.13**

```bash
pip install "modelaudit[all]"

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
- **Potential backdoor indicators** — suspicious weight patterns, anomalous tensors, or hidden-code signals
- **Embedded secrets** — API keys, tokens, and credentials in model weights or metadata
- **Network indicators** — URLs, IPs, and socket usage that could enable data exfiltration
- **Archive exploits** — path traversal, symlink attacks in ZIP/TAR/7z files
- **Unsafe ML operations** — Lambda layers, custom ops, TorchScript/JIT, template injection
- **Supply chain risks** — tampering, license violations, suspicious configurations

## Supported Formats

ModelAudit includes 45 registered scanners covering model, archive, and configuration formats:

| Format                  | Extensions                                                                                  | Risk   |
| ----------------------- | ------------------------------------------------------------------------------------------- | ------ |
| **Pickle**              | `.pkl`, `.pickle`, `.dill`                                                                  | HIGH   |
| **PyTorch**             | `.pt`, `.pth`, `.ckpt`, `.bin`                                                              | HIGH   |
| **Joblib**              | `.joblib`                                                                                   | HIGH   |
| **NumPy**               | `.npy`, `.npz`                                                                              | HIGH   |
| **R Serialized**        | `.rds`, `.rda`, `.rdata`, signature-valid renamed workspace artifacts                       | HIGH   |
| **TensorFlow**          | `.pb`, `.meta`, SavedModel dirs                                                             | MEDIUM |
| **Keras**               | `.h5`, `.hdf5`, `.keras`                                                                    | MEDIUM |
| **ONNX**                | `.onnx`                                                                                     | MEDIUM |
| **CoreML**              | `.mlmodel`, structurally valid renamed artifacts                                            | LOW    |
| **MXNet**               | `*-symbol.json`, `*-NNNN.params`, structurally valid renamed symbol JSON                    | LOW    |
| **NeMo**                | `.nemo`, renamed archives with root config                                                  | MEDIUM |
| **CNTK**                | `.dnn`, `.cmf`, signature-valid renamed artifacts                                           | MEDIUM |
| **RKNN**                | `.rknn`, signature-valid artifacts under non-conflicting renamed suffixes                   | MEDIUM |
| **Torch7**              | Serialized artifacts (`.t7`, `.th`, `.net` or renamed)                                      | HIGH   |
| **CatBoost**            | `.cbm`                                                                                      | MEDIUM |
| **XGBoost**             | `.bst`, `.model`, `.json`, `.ubj`, extensionless UBJSON                                     | MEDIUM |
| **LightGBM**            | `.lgb`, `.lightgbm`, `.model`, signature-valid renamed artifacts                            | MEDIUM |
| **Llamafile**           | Executable wrappers (`.llamafile`, `.exe`, extensionless or renamed)                        | MEDIUM |
| **TorchServe**          | `.mar`                                                                                      | HIGH   |
| **SafeTensors**         | `.safetensors`                                                                              | LOW    |
| **GGUF/GGML**           | `.gguf`, `.ggml`, `.ggmf`, `.ggjt`, `.ggla`, `.ggsa`, signature-valid renamed artifacts     | LOW    |
| **JAX/Flax**            | `.msgpack`, `.flax`, `.orbax`, `.jax`, `.checkpoint`, `.orbax-checkpoint`                   | LOW    |
| **TFLite**              | `.tflite`, signature-valid artifacts under non-conflicting renamed suffixes                 | LOW    |
| **ExecuTorch**          | `.ptl`, `.pte`, signature-valid standalone artifacts under non-conflicting renamed suffixes | LOW    |
| **TensorRT**            | `.engine`, `.plan`, `.trt`                                                                  | LOW    |
| **PaddlePaddle**        | `.pdmodel`, `.pdiparams`                                                                    | LOW    |
| **OpenVINO**            | `.xml`                                                                                      | LOW    |
| **Skops**               | `.skops`                                                                                    | HIGH   |
| **PMML**                | `.pmml`                                                                                     | LOW    |
| **Compressed Wrappers** | `.gz`, `.bz2`, `.xz`, `.lz4`, `.zlib`                                                       | MEDIUM |

Plus scanners for ZIP, TAR, 7-Zip, OCI layers, Jinja2 templates, JSON/YAML metadata, manifests, model cards, text files, and RAR recognition. RAR archives are reported as unsupported/fail-closed instead of being skipped.

Structurally valid TensorFlow SavedModel and MetaGraph protobufs are also recognized when renamed to non-model suffixes.
CoreML models can also be recognized when renamed, with incomplete coverage reported explicitly.
SafeTensors files with oversized but plausible framing are retained for bounded, inconclusive analysis under
otherwise unclaimed suffixes such as `.jpg`.
Structurally plausible Flax/JAX MessagePack checkpoints are also recognized when renamed to non-model suffixes;
renamed structures that cannot be fully classified are reported as incomplete coverage.
Structured JAX/Orbax JSON checkpoint metadata is likewise recognized when renamed; oversized ambiguous
candidates are reported as incomplete coverage; observable security patterns in the bounded inspected prefix may
still be reported conservatively.

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
# Non-local artifact stores: export MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS=s3://trusted-bucket/models
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
- `MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS` for non-local MLflow artifact roots (comma-separated URI prefixes)
- Use concrete backend roots such as `s3://bucket/prefix`; logical `models:/` or `runs:/` URIs and percent-encoded remote paths are refused.
- `JFROG_API_TOKEN` or `JFROG_ACCESS_TOKEN` for JFrog Artifactory
- `MODELAUDIT_JFROG_ALLOWED_HOSTS` for comma-separated custom JFrog hostnames that may receive credentials
- `MODELAUDIT_JFROG_ALLOWED_REDIRECT_HOSTS` for comma-separated external redirect hostnames that may be downloaded without credentials
- Store credentials in environment variables or a secrets manager, and never commit tokens/keys.

## Installation

```bash
# Broad scanner coverage (recommended; excludes the TensorFlow runtime and platform-specific TensorRT)
pip install "modelaudit[all]"

# Core only (static scanners, pickle, NumPy, archives, manifests, metadata)
pip install modelaudit

# Specific frameworks (TensorFlow installs on Python 3.11-3.12; ONNX installs on Python 3.10-3.12)
pip install "modelaudit[tensorflow,pytorch,h5,onnx,safetensors]"

# CI/CD environments
pip install "modelaudit[all-ci]"

# On Python 3.11-3.12, add TensorFlow only when you need runtime-dependent checkpoint or weight analysis
pip install "modelaudit[all,tensorflow]"

# Docker
docker run --rm -v "$(pwd)":/app ghcr.io/promptfoo/modelaudit:latest model.pkl
```

The ONNX extra, including the ONNX portion of `modelaudit[all]`, is packaged for Python 3.10-3.12.
PyTorch-containing extras require Python 3.10-3.12 or standard (GIL-enabled) CPython 3.13; the patched PyTorch 2.13
wheels do not support free-threaded CPython 3.13t. On Apple Silicon, they also require macOS 14 or newer because the
wheels target `macosx_14_0_arm64`. The core-only installation remains available for static scanning on macOS 11-13 and
CPython 3.13t.

## CLI Options

Primary commands:

```bash
modelaudit [PATHS...]                           # Default scan command
modelaudit scan [OPTIONS] PATHS...              # Explicit scan command
modelaudit scan --list-scanners                 # List scanner IDs for targeted scans
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
--stream                     Process files one-by-one; remote downloads are deleted after scanning
--assume-shard-family        Treat explicitly listed cross-directory shards as one model family
--max-size SIZE              Size limit (e.g., 10GB)
--timeout SECONDS            Override scan timeout
--dry-run                    Preview what would be scanned
--verbose / --quiet          Control output detail
--blacklist PATTERN          Additional patterns to flag
--no-cache                   Disable result caching
--cache-dir DIR              Set cache directory for downloads and scan results
--progress                   Force progress display
--scanners LIST              Only run selected scanners (IDs/classes; comma-separated or repeated)
--exclude-scanner NAME       Exclude a scanner from the active set (comma-separated or repeated)
--list-scanners              List scanner IDs, class names, extensions, and dependencies
```

Targeted scanner selection:

```bash
# Discover scanner IDs and class names
modelaudit scan --list-scanners
modelaudit scan --list-scanners --format json

# Run only selected scanners
modelaudit scan ./models --scanners pickle,tf_savedmodel
modelaudit scan ./model.pkl --scanners PickleScanner

# Run the default scanner set except a noisy or slow scanner
modelaudit scan ./models --exclude-scanner weight_distribution

# For container formats, include both the container scanner and nested scanner
modelaudit scan ./archive.zip --scanners zip,pickle
```

`--scanners` starts from an explicit allowlist. `--exclude-scanner` subtracts scanners from either that allowlist or the default scanner set. Scanner selection is reflected in JSON output under `scanner_selection`.

For remote folders, ModelAudit narrows downloads by selected scanner extensions when safe. Content-based renamed-wrapper routing applies after acquisition; scan a direct file URL when repository filenames may be intentionally misleading.

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

- Collected metadata can include command and feature usage, scan and download timing or size metadata, scanner/file-type usage, stable rule or CVE identifiers, severity aggregates, registered file extensions, coarse source or provider categories, and runtime version, platform, and CI metadata.
- Telemetry does not include raw local paths, filenames, model IDs or names, repository or artifact identifiers, bucket or object keys, remote URL paths, free-form issue or error text, URL userinfo, query strings, fragments, or model binary contents.
- Packaged installs enable telemetry by default. Telemetry is disabled automatically when `CI=true` is set or `IS_TESTING=true` is set, and in editable development installs unless `MODELAUDIT_TELEMETRY_DEV=1`. Events that are sent from other CI providers (TeamCity, CodeBuild, Bitbucket Pipelines, Jenkins) are tagged with `isRunningInCi=true` so they can be filtered downstream.
- A persistent pseudonymous user identifier is stored in `~/.promptfoo/promptfoo.yaml` for cross-tool correlation with [Promptfoo](https://www.promptfoo.dev/), and each telemetry session uses a new session identifier. Existing IDs from `~/.modelaudit/user_config.json` are migrated on first run after upgrade. A legacy email value in that file, if present, may be attached to the analytics user profile.

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
- If `pip` installs an older release, verify Python is supported (`python --version`; ModelAudit supports Python 3.10-3.13).
- For additional troubleshooting and cloud auth guidance, see:
  - https://www.promptfoo.dev/docs/model-audit/
  - https://www.promptfoo.dev/docs/model-audit/usage/

## Documentation

- **[Full docs](https://www.promptfoo.dev/docs/model-audit/)** — setup, configuration, and advanced usage
- **[Usage examples](https://www.promptfoo.dev/docs/model-audit/usage/)** — CI/CD integration, remote scanning, SBOM generation
- **[Supported formats](https://www.promptfoo.dev/docs/model-audit/scanners/)** — detailed scanner documentation
- **[Support policy](https://github.com/promptfoo/modelaudit/blob/main/SUPPORT.md)** — supported Python/OS versions and maintenance policy
- **[Security model and limitations](https://github.com/promptfoo/modelaudit/blob/main/docs/user/security-model.md)** — what ModelAudit does and does not guarantee
- **[Compatibility matrix](https://github.com/promptfoo/modelaudit/blob/main/docs/user/compatibility-matrix.md)** — file formats vs optional dependencies
- **[Scanner selection](https://github.com/promptfoo/modelaudit/blob/main/docs/user/scanner-selection.md)** — targeted scanner allowlists and exclusions
- **[Metadata extraction guide](https://github.com/promptfoo/modelaudit/blob/main/docs/user/metadata-extraction.md)** — safe metadata workflows and `--trust-loaders` guidance
- **[Offline/air-gapped guide](https://github.com/promptfoo/modelaudit/blob/main/docs/user/offline-air-gapped.md)** — secure operation without internet access
- **Troubleshooting** — run `modelaudit doctor --show-failed` to check scanner availability

## Related Packages

- **[`modelaudit-picklescan`](https://pypi.org/project/modelaudit-picklescan/)** — the standalone Rust-backed pickle scanner used by ModelAudit's pickle, PyTorch, ExecuTorch, and PyTorch-ZIP scanners. Install it directly if you only need pickle analysis (as a library, not a CLI) and do not want the full scanner bundle.

## Reporting Vulnerabilities

Do not open public issues for suspected vulnerabilities. See [SECURITY.md](https://github.com/promptfoo/modelaudit/blob/main/SECURITY.md) for coordinated disclosure.

## Contributing

Issues, feature requests, and PRs are welcome. See [CONTRIBUTING.md](https://github.com/promptfoo/modelaudit/blob/main/CONTRIBUTING.md).

## License

MIT License — see [LICENSE](https://github.com/promptfoo/modelaudit/blob/main/LICENSE) for details.
