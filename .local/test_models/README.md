# ModelAudit Test Dataset

Comprehensive collection of legitimate model file examples for all formats supported by ModelAudit.

## 📋 Format Categories

### Pickle Formats (7 files)
- `simple_model.pkl` - Standard Python pickle
- `simple_model.pickle` - Alternative pickle extension
- `simple_model.dill` - Dill serialization format
- `pytorch_model.pt` - PyTorch model format
- `pytorch_weights.pth` - PyTorch weights format
- `checkpoint.ckpt` - Model checkpoint format
- `sklearn_model.joblib` - Joblib serialization

### HDF5 Formats (3 files)
- `keras_model.h5` - Keras HDF5 model
- `keras_model.hdf5` - HDF5 format model
- `keras_model.keras` - Keras native format

### NumPy Formats (2 files)
- `weights.npy` - NumPy array file
- `model_weights.npz` - Compressed NumPy arrays

### ONNX Format (1 file)
- `simple_model.onnx` - Open Neural Network Exchange format

### SafeTensors Format (1 file)
- `model.safetensors` - Hugging Face SafeTensors format

### TensorFlow Formats (3 items)
- `frozen_model.pb` - TensorFlow frozen graph (protobuf)
- `mobile_model.tflite` - TensorFlow Lite model
- `saved_model/` - TensorFlow SavedModel directory

### OpenVINO Format (1 file)
- `openvino_model.xml` - Intel OpenVINO IR model

### PMML Format (1 file)
- `regression_model.pmml` - Predictive Model Markup Language

### GGUF/GGML Formats (4 files)
- `llama_model.gguf` - GGUF quantized model (new format)
- `legacy_model.ggml` - Legacy GGML format
- `legacy_model.ggmf` - GGMF variant
- `legacy_model.ggjt` - GGJT variant

### Archive Formats (3 files)
- `model_archive.zip` - ZIP archive with model files
- `model_archive.tar` - TAR archive with model files
- `model_archive.tar.gz` - Gzip compressed TAR archive

### PyTorch Binary Format (2 files)
- `pytorch_model.bin` - PyTorch binary (ZIP-based)
- `raw_weights.bin` - Raw binary weights

### ExecuTorch Format (2 files)
- `mobile_model.pte` - ExecuTorch model
- `mobile_model.ptl` - ExecuTorch legacy format

### Specialized Formats (6 files)
- `optimized_model.engine` - TensorRT engine (stub)
- `optimized_model.plan` - TensorRT plan (stub)
- `paddle_model.pdmodel` - Baidu PaddlePaddle model (stub)
- `paddle_model.pdiparams` - PaddlePaddle parameters (stub)
- `jax_model.msgpack` - Flax/JAX MessagePack format
- `jax_model.flax` - Flax model file

## 📊 Statistics

- **Total Files**: 36 model files + 1 directory
- **Format Categories**: 13 categories
- **Extensions Covered**: 30+ unique extensions

## 🚀 Usage

### Scan All Models
```bash
rye run modelaudit .local/test_models/
```

### Scan Specific Format
```bash
rye run modelaudit .local/test_models/simple_model.pkl
```

### Scan with JSON Output
```bash
rye run modelaudit --format json --output results.json .local/test_models/
```

## 🔧 Regenerate Dataset

To regenerate all examples:
```bash
cd .local/test_models
python3 generate_all_formats.py
```

## 📝 Notes

- All files are **legitimate, minimal examples** designed for testing
- Some specialized formats (TensorRT, PaddlePaddle) are minimal stubs due to framework dependencies
- Files contain no actual trained models or sensitive data
- All examples use simple synthetic data for testing purposes

## 🎯 Purpose

This dataset serves multiple purposes:
1. **Format Detection Testing** - Verify ModelAudit correctly identifies all formats
2. **Scanner Coverage** - Ensure all format-specific scanners work
3. **Validation Testing** - Test that legitimate files don't trigger false positives
4. **Documentation** - Provide reference examples for each supported format

## 🔍 Format Detection

All files have correct magic bytes and structure for their format:
- Binary formats use proper magic byte headers
- XML formats (OpenVINO, PMML) have correct XML structure
- Archive formats are valid ZIP/TAR files
- Pickle formats use standard Python pickle protocol 4

## ⚠️ Security Note

These are **test files only**. They:
- Contain no executable code
- Use minimal synthetic data
- Are safe to scan and analyze
- Should not be used in production systems
