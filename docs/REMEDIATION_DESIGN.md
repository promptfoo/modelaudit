# Model Remediation & Safe Conversion Tool - Design Document

## Overview

The Model Remediation tool will allow users to convert unsafe model formats to secure alternatives while preserving model functionality. This addresses the critical gap where users identify security issues but have no automated way to fix them.

## Core Features (MVP - Phase 1)

### 1. Pickle to SafeTensors Conversion
**Priority: CRITICAL** - This is the most common and dangerous format

```bash
# Basic conversion
modelaudit convert model.pkl --to safetensors

# With validation
modelaudit convert model.pkl --to safetensors --validate

# Batch conversion
modelaudit convert ./models/*.pkl --to safetensors --output-dir ./safe_models/
```

**Implementation Details:**
- Extract weights and architecture from pickle files
- Handle PyTorch state_dicts, full models, and checkpoints
- Preserve all tensor data, metadata, and model configuration
- Validate numerical accuracy (< 1e-6 difference)

### 2. Dangerous Operation Removal
**Priority: HIGH** - Make models safe without full conversion

```bash
# Remove dangerous ops while keeping format
modelaudit remediate model.pkl --remove-dangerous-ops

# Interactive mode
modelaudit remediate model.pkl --interactive
```

**Operations to Remove/Replace:**
- `eval()`, `exec()`, `__import__`
- `os.system()`, `subprocess` calls
- Network operations
- File system access
- Lambda layers in Keras models

### 3. Safety Validation
**Priority: HIGH** - Ensure conversions maintain model integrity

```bash
# Validate conversion maintains outputs
modelaudit validate model.pkl converted.safetensors --samples 1000

# Check for numerical drift
modelaudit validate model.pkl converted.safetensors --tolerance 1e-6
```

## Architecture

```
modelaudit/
├── remediation/
│   ├── __init__.py
│   ├── base.py              # BaseConverter class
│   ├── converters/
│   │   ├── __init__.py
│   │   ├── pickle_to_safetensors.py
│   │   ├── joblib_to_onnx.py
│   │   ├── keras_to_tensorflow.py
│   │   └── pytorch_to_onnx.py
│   ├── validators/
│   │   ├── __init__.py
│   │   ├── numerical.py     # Numerical accuracy validation
│   │   ├── functional.py    # Functional equivalence testing
│   │   └── security.py      # Post-conversion security scan
│   └── remediators/
│       ├── __init__.py
│       ├── pickle_cleaner.py
│       └── keras_lambda_remover.py
```

## CLI Command Structure

### New Commands

```bash
# Convert between formats
modelaudit convert <input> --to <format> [options]
  Options:
    --output, -o          Output file path
    --validate            Validate conversion accuracy
    --backup              Create backup before conversion
    --force               Overwrite existing files
    --batch               Process multiple files
    --preserve-metadata   Keep all metadata

# Remediate security issues in-place
modelaudit remediate <input> [options]
  Options:
    --remove-dangerous-ops    Remove dangerous operations
    --remove-lambdas         Remove lambda layers (Keras)
    --interactive, -i        Interactive remediation mode
    --dry-run               Show what would be changed
    --backup                Create backup first

# Validate conversion accuracy
modelaudit validate <original> <converted> [options]
  Options:
    --samples, -n        Number of test samples (default: 100)
    --tolerance          Numerical tolerance (default: 1e-6)
    --seed               Random seed for reproducibility
    --report             Generate detailed report
```

## Implementation Phases

### Phase 1: MVP (Week 1-2)
1. **Pickle → SafeTensors converter**
   - Support PyTorch state_dict format
   - Basic weight extraction
   - Metadata preservation
   - Simple validation

2. **Basic dangerous op removal**
   - Pickle opcode filtering
   - Remove GLOBAL opcodes for dangerous modules
   - Backup functionality

3. **CLI integration**
   - `convert` command
   - Progress bars
   - Basic error handling

### Phase 2: Enhanced Safety (Week 3-4)
1. **Advanced conversions**
   - Full PyTorch model → SafeTensors
   - Joblib → ONNX
   - Keras H5 → SavedModel

2. **Intelligent remediation**
   - Pattern-based dangerous code detection
   - Lambda layer analysis and removal
   - Custom layer handling

3. **Validation suite**
   - Automated test generation
   - Performance benchmarking
   - Accuracy reports

### Phase 3: Production Features (Week 5-6)
1. **Batch operations**
   - Directory scanning
   - Parallel processing
   - Progress tracking

2. **Integration features**
   - Pre-commit hooks
   - CI/CD templates
   - Python API

3. **Advanced formats**
   - TensorFlow → ONNX
   - Custom format plugins
   - Format auto-detection

## Technical Considerations

### 1. Weight Extraction Challenges
- **Problem**: Pickle files can contain arbitrary Python objects
- **Solution**: Use restricted unpickler that only allows safe types
- **Fallback**: Use pickle scanner to identify weight tensors

### 2. Metadata Preservation
- **Problem**: Different formats store metadata differently
- **Solution**: Common metadata schema that maps between formats
- **Example**: Training config, optimizer state, epoch info

### 3. Large File Handling
- **Problem**: Models can be many GBs
- **Solution**: Streaming conversion, memory-mapped files
- **Progress**: Show progress bars with ETA

### 4. Format Limitations
- **Problem**: Not all conversions are possible
- **Solution**: Clear compatibility matrix
- **Example**: Can't convert custom PyTorch modules to ONNX

## User Experience

### Success Flow
```
$ modelaudit convert suspicious_model.pkl --to safetensors --validate

🔍 Analyzing suspicious_model.pkl...
  Format: PyTorch pickle (state_dict)
  Size: 523.4 MB
  Issues: 2 security warnings

🔄 Converting to SafeTensors...
  ✓ Extracted 124 weight tensors
  ✓ Preserved metadata (epochs=50, optimizer=adam)
  ✓ Removed dangerous pickle operations

✅ Validation:
  ✓ Numerical accuracy: 100% (max diff: 2.3e-7)
  ✓ Security scan: PASS (0 issues)
  ✓ File size: 498.2 MB (5% smaller)

💾 Saved: suspicious_model.safetensors
📋 Backup: suspicious_model.pkl.backup

✨ Conversion successful! Your model is now secure.
```

### Error Handling
```
$ modelaudit convert complex_model.pkl --to onnx

❌ Conversion Error:
  This PyTorch model contains custom operations that cannot be
  converted to ONNX format.
  
  Incompatible operations:
  - CustomAttentionLayer (line 234)
  - DynamicReshape (line 567)
  
  Suggestions:
  1. Try converting to SafeTensors instead (preserves all PyTorch features)
  2. Use modelaudit remediate to make the pickle file safer
  3. See docs for manual conversion guide
```

## Testing Strategy

### 1. Unit Tests
- Each converter class
- Validation functions
- Error handling paths

### 2. Integration Tests
- End-to-end conversions
- Real model files
- Format compatibility

### 3. Security Tests
- Verify dangerous ops removed
- Scan converted files
- Fuzzing with malicious inputs

### 4. Performance Tests
- Large file handling (>1GB)
- Memory usage
- Conversion speed

## Success Metrics

1. **Conversion Success Rate**: >95% for supported formats
2. **Numerical Accuracy**: <1e-6 difference for 99% of tensors
3. **Performance**: <30 seconds for 1GB model
4. **User Satisfaction**: Clear errors, helpful suggestions

## Future Enhancements

1. **Model Optimization**
   - Quantization during conversion
   - Pruning options
   - Format-specific optimizations

2. **Cloud Integration**
   - S3/GCS direct conversion
   - HuggingFace Hub integration
   - Streaming large models

3. **Advanced Remediation**
   - Custom operation replacement
   - Automated fix suggestions
   - Security policy templates

## Open Questions

1. Should we support partial conversions (e.g., weights only)?
2. How to handle models with custom Python code?
3. Should conversion create a detailed report by default?
4. How to handle version compatibility (e.g., PyTorch 1.x vs 2.x)?

## Next Steps

1. Implement basic Pickle → SafeTensors converter
2. Create test suite with real-world models
3. Design plugin system for additional formats
4. Get user feedback on CLI interface