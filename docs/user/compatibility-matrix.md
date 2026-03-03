# Compatibility Matrix (Formats vs Optional Dependencies)

This page shows which model formats work in base install and which require optional dependencies.

## Installation profiles

- Broadest coverage: `pip install modelaudit[all]`
- Minimal base install: `pip install modelaudit`
- Targeted extras: install only the extras you need (examples below)

## Matrix

| Format family                   | Common extensions                                                 | Base install                            | Optional dependency / extra                                                  |
| ------------------------------- | ----------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------- |
| Pickle family                   | `.pkl`, `.pickle`, `.dill`                                        | Yes                                     | `modelaudit[dill]` for broader dill compatibility                            |
| PyTorch archive/binary          | `.pt`, `.pth`, `.ckpt`, `.bin`                                    | Yes (static archive/pickle checks)      | `modelaudit[pytorch]` optional for broader Torch ecosystem tooling           |
| NumPy                           | `.npy`, `.npz`                                                    | Yes                                     | None                                                                         |
| TensorFlow SavedModel structure | `.pb`, SavedModel directories                                     | Yes (vendored protos)                   | `modelaudit[tensorflow]` for TensorFlow-dependent checkpoint/weight analysis |
| Keras H5                        | `.h5`, `.hdf5`                                                    | No                                      | `modelaudit[h5]` (required)                                                  |
| ONNX                            | `.onnx`                                                           | No                                      | `modelaudit[onnx]` (required)                                                |
| SafeTensors                     | `.safetensors`                                                    | Yes                                     | None required                                                                |
| Flax/JAX msgpack                | `.msgpack`, `.flax`, `.orbax`, `.jax`                             | No                                      | `modelaudit[flax]` (required)                                                |
| JAX checkpoints                 | `.ckpt`, `.checkpoint`, `.orbax-checkpoint`                       | Yes                                     | None                                                                         |
| TFLite                          | `.tflite`                                                         | No                                      | `modelaudit[tflite]` (required)                                              |
| XGBoost                         | `.bst`, `.model`, `.json`, `.ubj`                                 | Yes for static checks on common formats | `modelaudit[xgboost]` recommended for UBJ/full validation paths              |
| TensorRT                        | `.engine`, `.plan`                                                | Yes                                     | None required                                                                |
| PaddlePaddle                    | `.pdmodel`, `.pdiparams`                                          | Yes (static byte-pattern checks)        | None required                                                                |
| 7-Zip archives                  | `.7z`                                                             | No                                      | `modelaudit[sevenzip]` (required)                                            |
| Archives/config/text            | `.zip`, `.tar*`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`, `.txt` | Yes                                     | None                                                                         |

## Notes

- Scanner selection is extension- and content-aware; overlapping extensions may be dispatched to different scanners based on file content.
- `modelaudit doctor --show-failed` shows unavailable scanners and missing dependencies in your environment.
- If you need predictable CI behavior across many formats, prefer `modelaudit[all]`.
