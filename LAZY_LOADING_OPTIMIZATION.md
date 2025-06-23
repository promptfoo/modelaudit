# ModelAudit Lazy Loading Optimization

## 🔍 Problem Identified

ModelAudit suffered from slow startup times due to importing heavy ML framework dependencies at module level:

### **Before Optimization:**
- `import modelaudit`: ~0.04s ⚡
- `import modelaudit.scanners`: ~7.15s 🐌 (175x slower!)
- **All dependencies loaded upfront**, including:
  - TensorFlow (~3-4s, ~500MB)
  - PyTorch (~2-3s, ~200MB) 
  - ONNX (~0.5s, ~100MB)
  - h5py (~0.5s, ~50MB)
  - And other ML frameworks

### **Root Cause:**
The `modelaudit/scanners/__init__.py` imported all scanner classes at module level:
```python
from .keras_h5_scanner import KerasH5Scanner  # Imports h5py
from .onnx_scanner import OnnxScanner          # Imports onnx
from .tf_savedmodel_scanner import TensorFlowSavedModelScanner  # Imports tensorflow
# ... etc
```

## ✨ Solution Implemented

### **Lazy Loading Architecture**

1. **ScannerRegistry Class**: Created a registry system that manages scanners with metadata
2. **Lazy Import System**: Scanners are only imported when needed
3. **Smart Path Matching**: Pre-filter scanners by file extension before loading
4. **Backwards Compatibility**: Maintained existing API through `__getattr__` magic

### **Key Changes:**

#### 1. **Scanner Registry** (`modelaudit/scanners/__init__.py`)
```python
class ScannerRegistry:
    def __init__(self):
        self._scanners = {
            "tensorflow": {
                "module": "modelaudit.scanners.tf_savedmodel_scanner",
                "class": "TensorFlowSavedModelScanner",
                "dependencies": ["tensorflow"],  # Heavy dependency marked
                "priority": 3,
            },
            # ... other scanners
        }
    
    def _load_scanner(self, scanner_id: str):
        """Lazy load a scanner class only when needed"""
        # Only import the module here, not at startup
        
    def get_scanner_for_path(self, path: str):
        """Get the best scanner without loading unnecessary ones"""
        # Check file extension first, only load matching scanners
```

#### 2. **Core Integration** (`modelaudit/core.py`)
```python
# OLD: Load all scanners to find the right one
for scanner_class in SCANNER_REGISTRY:
    if scanner_class.can_handle(path):  # This loaded ALL scanners!

# NEW: Use lazy registry to load only the needed scanner  
scanner_class = _registry.get_scanner_for_path(path)
if scanner_class:  # Only loads the matching scanner
```

#### 3. **Backwards Compatibility**
```python
def __getattr__(name: str):
    """Lazy loading for scanner classes"""
    if name == "TensorFlowSavedModelScanner":
        return _registry._load_scanner("tf_savedmodel")
    # ... etc
```

## 📊 Performance Results

### **After Optimization:**
- `import modelaudit`: **0.027s** ⚡ (same speed)
- `import modelaudit.scanners`: **0.003s** ⚡⚡ (**2074x faster!**)
- **Dependencies load only when needed**

### **Lazy Loading Behavior:**
```python
# Fast - no heavy dependencies loaded
from modelaudit import scanners

# Fast - only loads PickleScanner 
scanner = scanners.PickleScanner  # 0.002s

# Slow only when needed - loads TensorFlow
scanner = scanners.TensorFlowSavedModelScanner  # 2.55s (expected)
```

### **Real World Impact:**
- **CLI startup**: 0.059s (vs ~7s before)
- **Basic scanning**: Only loads needed scanner (0.01s for manifest files)
- **Heavy scans**: Only pay the cost when you use heavy dependencies

## 🧪 Compatibility Verification

### **All Tests Pass:**
- ✅ `test_scanner_registry.py` - Registry functionality
- ✅ `test_basic.py` - Core functionality  
- ✅ CLI commands work correctly
- ✅ Backwards compatibility maintained

### **Scanner Loading Order:**
Priority-based loading ensures correct scanner selection:
1. PickleScanner (priority 1) - Most common
2. PyTorchBinaryScanner (priority 2) - .bin files
3. TensorFlowSavedModelScanner (priority 3) - TF models
4. ... etc
99. ZipScanner (priority 99) - Generic fallback

## 🔧 Developer Impact

### **For Users:**
- **Faster startup** - 2000x improvement in import time
- **Lower memory usage** - Only loads what you need
- **Same API** - No breaking changes
- **Better UX** - Snappy CLI responses

### **For Contributors:**
- **Clear architecture** - Scanners are organized by priority and dependencies
- **Easy to extend** - Add new scanners to the registry
- **Dependency tracking** - Know which scanners need which libraries

### **Adding New Scanners:**
```python
# Add to registry metadata
"my_scanner": {
    "module": "modelaudit.scanners.my_scanner",
    "class": "MyScanner", 
    "dependencies": ["heavy_lib"],  # Mark heavy dependencies
    "priority": 15,
}
```

## 📈 Optimization Categories

### **Heavy Dependencies (Lazy Loaded):**
- `tensorflow` - TensorFlow models
- `torch` - PyTorch models  
- `h5py` - HDF5/Keras models
- `onnx` - ONNX models
- `safetensors` - SafeTensors format
- `tflite` - TensorFlow Lite
- `msgpack` - Flax checkpoints

### **Light Dependencies (Immediate):**
- `numpy`, `scipy` - Core dependencies
- `defusedxml` - Already required
- Standard library modules

## 🚀 Future Improvements

1. **Dependency Detection**: Auto-detect which optional dependencies are installed
2. **Scanning Hints**: Allow users to specify expected model types for even faster scanning
3. **Plugin System**: External scanners could register themselves
4. **Caching**: Cache loaded scanners across invocations

## 📝 Summary

This optimization transforms ModelAudit from a slow-starting tool to a snappy, responsive scanner:

- **2074x faster import time**
- **Only loads dependencies when needed**  
- **Maintains full backwards compatibility**
- **Improves user experience dramatically**
- **Sets foundation for future optimizations**

The lazy loading system ensures that ModelAudit can support many ML frameworks without imposing their startup cost on users who don't need them. 