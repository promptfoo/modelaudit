# Compatibility Matrix (Formats vs Optional Dependencies)

This page shows which model formats work in base install and which require optional dependencies.

## Installation profiles

- Broad portable coverage: `pip install "modelaudit[all]"` (ONNX installs on Python 3.10-3.12; on Python 3.11-3.12, add `tensorflow` only for TensorFlow-dependent checkpoint/weight analysis)
- Minimal base install: `pip install modelaudit`
- Targeted extras: install only the extras you need (examples below)

## Matrix

| Format family                   | Common extensions                                                 | Base install                                              | Optional dependency / extra                                                                      |
| ------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Pickle family                   | `.pkl`, `.pickle`, `.dill`                                        | Yes                                                       | `modelaudit[dill]` for broader dill compatibility                                                |
| PyTorch archive/binary          | `.pt`, `.pth`, `.ckpt`, `.bin`                                    | Yes (static archive/pickle checks)                        | `modelaudit[pytorch]` optional for broader Torch ecosystem tooling                               |
| NumPy                           | `.npy`, `.npz`                                                    | Yes                                                       | None                                                                                             |
| R serialized                    | `.rds`, `.rda`, `.rdata`                                          | Yes (static analysis only)                                | None                                                                                             |
| TensorFlow SavedModel/MetaGraph | `.pb`, `.meta`, SavedModel directories                            | Yes (vendored protos)                                     | `modelaudit[tensorflow]` on Python 3.11-3.12 for TensorFlow-dependent checkpoint/weight analysis |
| Keras H5                        | `.h5`, `.hdf5`                                                    | No                                                        | `modelaudit[h5]` (required)                                                                      |
| ONNX                            | `.onnx`                                                           | No                                                        | `modelaudit[onnx]` on Python 3.10-3.12 (required)                                                |
| CoreML                          | `.mlmodel`                                                        | Yes (static protobuf/metadata checks)                     | None                                                                                             |
| NeMo                            | `.nemo`                                                           | Yes (static tar/config analysis, Hydra `_target_` checks) | None                                                                                             |
| CNTK native                     | `.dnn`, `.cmf`                                                    | Yes (static signature and string analysis)                | None                                                                                             |
| RKNN models                     | `.rknn`                                                           | Yes (static bounded metadata checks)                      | None                                                                                             |
| Torch7 serialized               | `.t7`, `.th`, `.net`                                              | Yes (static string/structure checks)                      | None                                                                                             |
| CatBoost native                 | `.cbm`                                                            | Yes (static bounded metadata inspection)                  | None                                                                                             |
| LightGBM native                 | `.lgb`, `.lightgbm`, signature-validated `.model`                 | Yes (static native-text/binary checks)                    | None                                                                                             |
| Llamafile binaries              | `.llamafile`, extensionless, `.exe`                               | Yes (executable + embedded GGUF checks)                   | None required                                                                                    |
| TorchServe archives             | `.mar`                                                            | Yes                                                       | None                                                                                             |
| SafeTensors                     | `.safetensors`                                                    | Yes                                                       | None required                                                                                    |
| GGUF/GGML                       | `.gguf`, `.ggml`, `.ggmf`, `.ggjt`, `.ggla`, `.ggsa`              | Yes                                                       | None required                                                                                    |
| Flax/JAX msgpack                | `.msgpack`, `.flax`, `.orbax`, `.jax`                             | Yes                                                       | None (`modelaudit[flax]` is a compatibility alias)                                               |
| JAX checkpoints                 | `.ckpt`, `.checkpoint`, `.orbax-checkpoint`                       | Yes                                                       | None                                                                                             |
| TFLite                          | `.tflite`                                                         | No                                                        | `modelaudit[tflite]` (required)                                                                  |
| XGBoost                         | `.bst`, `.model`, `.json`, `.ubj`                                 | Yes for static checks on common formats                   | `modelaudit[xgboost]` recommended for UBJ/full validation paths                                  |
| TensorRT                        | `.engine`, `.plan`, `.trt`                                        | Yes                                                       | None required                                                                                    |
| PaddlePaddle                    | `.pdmodel`, `.pdiparams`                                          | Yes (static byte-pattern checks)                          | None required                                                                                    |
| MXNet                           | `*-symbol.json`, `*-NNNN.params`                                  | Yes (static graph + params checks)                        | None required                                                                                    |
| Standalone compressed wrappers  | `.gz`, `.bz2`, `.xz`, `.lz4`, `.zlib`                             | Yes (safe bounded decompression + inner scan routing)     | `lz4` package optional only for `.lz4` payload decompression                                     |
| 7-Zip archives                  | `.7z`                                                             | No                                                        | `modelaudit[sevenzip]` (required)                                                                |
| RAR archives                    | `.rar`                                                            | Yes (recognized and failed closed as unsupported)         | None                                                                                             |
| Archives/config/text            | `.zip`, `.tar*`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`, `.txt` | Yes                                                       | None                                                                                             |

## Notes

- Scanner selection is extension- and content-aware; overlapping extensions may be dispatched to different scanners based on file content.
- Runtime scanner selection is available with `modelaudit scan --scanners ...` and `--exclude-scanner ...`; use `modelaudit scan --list-scanners` to discover scanner IDs.
- Compressed wrappers enforce limits via `compressed_max_decompressed_bytes`, `compressed_max_decompression_ratio`, and `compressed_max_depth`.
- R serialized (`.rds/.rda/.rdata`) support is static-only: ModelAudit does not execute R code or evaluate objects in an R runtime.
- CNTK scanner scope in v1 is `.dnn`/`.cmf`; `.model` remains owned by XGBoost overlap handling.
- Llamafile wrappers are executable by design: executable presence is reported at `INFO`, and severity escalates only when suspicious runtime indicators or malformed embedded payloads are found.
- RAR archives are recognized so they do not disappear from directory scans; ModelAudit reports them as unsupported coverage with a non-clean result.
- Standalone Jinja2 templates exceeding the configured template-analysis size limit or failing UTF-8 text decoding are reported as incomplete coverage instead of clean results.
- `modelaudit doctor --show-failed` shows unavailable scanners and missing dependencies in your environment.
- If you need predictable CI behavior across many formats, prefer `modelaudit[all]`; ONNX is included on Python 3.10-3.12, and TensorFlow runtime-dependent paths require adding `modelaudit[tensorflow]` on Python 3.11-3.12.
