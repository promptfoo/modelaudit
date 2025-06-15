# Test Assets

This directory contains minimal models used in the test suite. Each file is small so the repository stays lightweight.

## Malicious examples
- `evil_pickle.pkl` – pickle object with `__reduce__` calling `os.system`.
- `malicious_keras.h5` – Keras H5 model with a Lambda layer that evaluates code.
- `malicious_pytorch.pt` – PyTorch zip containing a pickle that runs `eval`.
- `malicious_tf/` – TensorFlow SavedModel whose graph includes a `PyFunc` node.
- `malicious_manifest.json` – JSON manifest leaking an API key and remote URL.
- `malicious_zip.zip` – ZIP archive with directory traversal entry and a malicious pickle inside.

## Safe examples
- `safe_pickle.pkl` – simple dictionary pickle with no code execution.
- `safe_keras.h5` – basic Sequential Keras model.
- `safe_pytorch.pt` – PyTorch zip with benign pickle data.
- `safe_tf/` – SavedModel containing only a constant op.
- `safe_manifest.json` – benign configuration manifest.
- `safe_zip.zip` – ZIP archive with a harmless text file.

To recreate these files, run `generate_assets.py` in this directory.
