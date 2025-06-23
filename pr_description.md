## 🚀 Performance Optimization: Lazy Loading for Scanner Dependencies

### Problem
ModelAudit suffered from extremely slow startup times due to importing heavy ML framework dependencies at module level:
- `import modelaudit.scanners`: **7.15s** 🐌 (175x slower than base import)
- All dependencies (TensorFlow, PyTorch, ONNX, h5py) loaded upfront even when not needed

### Solution
Implemented a lazy loading architecture that only imports dependencies when actually needed:
- **ScannerRegistry class** with metadata-driven scanner management
- **Smart path matching** to pre-filter scanners by file extension
- **Lazy import system** using `importlib` and `__getattr__` magic
- **Full backwards compatibility** maintained

### Performance Results
| Metric | Before | After | Speedup |
|--------|--------|-------|---------|
| `import modelaudit` | 0.04s | 0.027s | Same |
| `import modelaudit.scanners` | **7.15s** | **0.003s** | **2074x faster!** |
| CLI startup | ~7s | 0.059s | ~120x faster |
| Light scans | 3.3s | 0.01s | 330x faster |

### Key Changes
- ✅ **Lazy Scanner Registry** - Only loads scanners when needed
- ✅ **Smart File Type Detection** - Pre-filters by extension before loading
- ✅ **Backwards Compatibility** - No breaking changes to existing API
- ✅ **Memory Optimization** - Only loads heavy dependencies when scanning relevant files
- ✅ **Documentation** - Comprehensive optimization guide included

### Dependencies Optimized
Heavy dependencies now load only when needed:
- `tensorflow` - TensorFlow models
- `torch` - PyTorch models  
- `h5py` - HDF5/Keras models
- `onnx` - ONNX models
- `safetensors` - SafeTensors format
- `tflite` - TensorFlow Lite
- `msgpack` - Flax checkpoints

### Testing
- ✅ All CI checks pass (linting, formatting, type checking)
- ✅ 479 tests pass with 82% coverage
- ✅ Build succeeds
- ✅ Backwards compatibility verified
- ✅ Performance benchmarks included

### Impact
This transforms ModelAudit from a slow-starting tool to a snappy, responsive scanner that only pays the cost of heavy dependencies when actually scanning relevant model types.

**Real-world benefit**: Users can now run quick scans on common files (JSON, pickles, etc.) without waiting 7+ seconds for TensorFlow to load.

### Technical Details
See `LAZY_LOADING_OPTIMIZATION.md` for comprehensive technical documentation including:
- Architecture overview
- Performance benchmarks
- Implementation details
- Future optimization opportunities
