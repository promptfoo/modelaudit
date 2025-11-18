# Test Dataset Scan Results

## Summary

Generated **37 test files** covering all supported ModelAudit formats. Initial scan revealed some scanner bugs and validation issues.

## ✅ Successfully Scanned Formats

These formats scan without errors:

### Pickle Formats (7 files)
- ✓ `simple_model.pkl`
- ✓ `simple_model.pickle`
- ✓ `simple_model.dill`
- ✓ `pytorch_model.pt`
- ✓ `pytorch_weights.pth`
- ✓ `checkpoint.ckpt`
- ✓ `sklearn_model.joblib`

### HDF5 Formats (3 files)
- ✓ `keras_model.h5`
- ✓ `keras_model.hdf5`
- ✓ `keras_model.keras`

### NumPy Formats (1 file)
- ✓ `weights.npy`

### SafeTensors (1 file)
- ✓ `model.safetensors`

### TensorFlow (2 files)
- ✓ `frozen_model.pb`
- ✓ `saved_model/` directory

### OpenVINO (1 file)
- ✓ `openvino_model.xml` (with companion `openvino_model.bin`)

### GGUF/GGML (4 files)
- ✓ `llama_model.gguf`
- ✓ `legacy_model.ggml`
- ✓ `legacy_model.ggmf`
- ✓ `legacy_model.ggjt`

### Archives (3 files)
- ✓ `model_archive.zip`
- ✓ `model_archive.tar`
- ✓ `model_archive.tar.gz`

### PyTorch Binary (2 files)
- ✓ `pytorch_model.bin`
- ✓ `raw_weights.bin`

### ExecuTorch (2 files)
- ✓ `mobile_model.pte`
- ✓ `mobile_model.ptl`

### Specialized (6 files)
- ✓ `optimized_model.engine`
- ✓ `optimized_model.plan`
- ✓ `paddle_model.pdmodel`
- ✓ `paddle_model.pdiparams`
- ✓ `jax_model.msgpack`
- ✓ `jax_model.flax`

## ⚠️ Issues Found

### 1. NumPy .npz Validation Issue
**File**: `model_weights.npz`
**Issue**: False positive - file type validation fails
**Root Cause**: `.npz` files are ZIP archives by design (NumPy's compressed format), but validation expects "numpy" magic bytes
**Status**: 🐛 Scanner bug - validation rule should accept ZIP for .npz extension
**Fix Needed**: Update `validate_file_type()` to allow `header_format="zip"` for `ext_format="numpy"` when extension is `.npz`

### 2. TFLite Scanner Crash
**File**: `mobile_model.tflite`
**Issue**: Scanner crashes with buffer overflow error
**Error**: `unpack_from requires a buffer of at least 860636760 bytes`
**Root Cause**: TFLite scanner doesn't validate file size before reading
**Status**: 🐛 Critical scanner bug - causes process crash
**Fix Needed**: Add file size validation in TFLite scanner before unpacking

### 3. PMML Root Element Warning
**File**: `regression_model.pmml`
**Issue**: Scanner reports "Root element is not <PMML>"
**Status**: 🔍 Need investigation - XML appears valid
**Note**: May be whitespace/encoding issue or scanner XML parsing bug

### 4. ONNX Parsing (Previously Fixed)
**File**: `simple_model.onnx`
**Status**: ✅ Fixed with improved protobuf structure

## 📊 Statistics

- **Total Files**: 37 files + 1 directory
- **Successfully Scanned**: ~34 files (91.9%)
- **Scanner Bugs Found**: 2 critical issues
- **Validation Issues**: 1 false positive

## 🔧 Recommended Fixes

### Priority 1: TFLite Scanner Crash
```python
# Add in TFLite scanner before unpacking:
if file_size < required_size:
    logger.warning(f"File too small for TFLite format: {file_size} < {required_size}")
    return ScanResult(...)
```

### Priority 2: .npz Validation
```python
# In validate_file_type(), add:
if ext_format == "numpy" and path.endswith(".npz"):
    return header_format in {"zip", "numpy"}
```

### Priority 3: PMML XML Parsing
Investigate XML parser in PMML scanner - may need to handle different encodings or whitespace.

## 🎯 Test Coverage

This dataset provides comprehensive coverage for:
- ✅ Format detection (magic bytes)
- ✅ Extension mapping
- ✅ Scanner compatibility
- ✅ Validation rules
- ✅ Edge cases (archives, variants)

## 💡 Usage for Development

### Test Individual Format
```bash
rye run modelaudit .local/test_models/simple_model.pkl
```

### Test Specific Category
```bash
rye run modelaudit .local/test_models/*.onnx
```

### Skip Problematic Files
```bash
# Exclude TFLite until scanner is fixed
find .local/test_models -type f ! -name "*.tflite" -exec rye run modelaudit {} \;
```

## 📝 Notes

- All files are minimal legitimate examples
- No actual trained models or sensitive data
- Files designed to test detection, not inference
- Some specialized formats (TensorRT, Paddle) are minimal stubs due to complexity
