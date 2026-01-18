# Plan: Eliminate TensorFlow/Keras Dependency

## Status: IMPLEMENTED

This plan has been implemented. See the changes below for details.

## Summary

Replace the full TensorFlow dependency (~2GB) with lightweight protobuf stubs to enable scanning TensorFlow SavedModel files without shipping Keras (and its CVE).

## Current TensorFlow Usage Analysis

### 1. `tf_savedmodel_scanner.py` - Protobuf Parsing Only

```python
from tensorflow.core.protobuf.saved_model_pb2 import SavedModel
saved_model = SavedModel()
saved_model.ParseFromString(content)
```

**Replacement**: Use standalone protobuf stubs.

### 2. `weight_distribution_scanner.py` - Mixed Usage

| Function           | Current Code                    | Replacement Strategy              |
| ------------------ | ------------------------------- | --------------------------------- |
| Protobuf parsing   | `saved_model_pb2.SavedModel()`  | Standalone protobuf stubs         |
| Protobuf parsing   | `graph_pb2.GraphDef()`          | Standalone protobuf stubs         |
| Tensor conversion  | `tf.make_ndarray(tensor_proto)` | Custom implementation (see below) |
| Checkpoint reading | `tf.train.list_variables()`     | Skip or use tensorflow-io         |
| Checkpoint reading | `tf.train.load_variable()`      | Skip or use tensorflow-io         |

## Implementation Options

### Option A: Vendor Protobuf Stubs (Recommended)

**Effort**: Medium (1-2 weeks)
**Risk**: Low
**Maintenance**: Low ongoing

1. **Generate protobuf stubs** from TensorFlow's `.proto` files:
   - `tensorflow/core/protobuf/saved_model.proto`
   - `tensorflow/core/framework/graph.proto`
   - `tensorflow/core/framework/tensor.proto`
   - `tensorflow/core/framework/tensor_shape.proto`
   - `tensorflow/core/framework/types.proto`
   - `tensorflow/core/framework/node_def.proto`
   - `tensorflow/core/framework/attr_value.proto`

2. **Vendor the generated `_pb2.py` files** in `modelaudit/protos/tensorflow/`

3. **Implement `make_ndarray` equivalent**:

   ```python
   def tensor_proto_to_ndarray(tensor_proto) -> np.ndarray:
       """Convert TensorProto to numpy array without TensorFlow."""
       dtype = DTYPE_MAP[tensor_proto.dtype]
       shape = [d.size for d in tensor_proto.tensor_shape.dim]

       # Check for tensor_content (raw bytes)
       if tensor_proto.tensor_content:
           return np.frombuffer(tensor_proto.tensor_content, dtype=dtype).reshape(shape)

       # Fall back to typed fields (float_val, int_val, etc.)
       if dtype == np.float32:
           data = np.array(tensor_proto.float_val, dtype=dtype)
       elif dtype == np.float64:
           data = np.array(tensor_proto.double_val, dtype=dtype)
       # ... handle other types

       return data.reshape(shape) if shape else data
   ```

4. **Drop checkpoint reading** from weight_distribution_scanner (or make it optional with full TensorFlow)

### Option B: Use `tensorflow-protobuf` Package

**Effort**: Low (days)
**Risk**: Medium (outdated, last updated 2022)
**Maintenance**: Depends on upstream

1. Add `tensorflow-protobuf>=2.11.0` as dependency
2. Check if it includes `saved_model_pb2` (may need to fork/extend)
3. Still need custom `make_ndarray` implementation

**Concerns**:

- Package is unmaintained (last update: Nov 2022)
- May not include all required protos
- Stuck on TensorFlow 2.11 proto definitions

### Option C: Fork and Maintain Our Own Protobuf Package

**Effort**: Medium-High
**Risk**: Low
**Maintenance**: Medium ongoing

1. Fork `alexeygrigorev/tensorflow-protobuf`
2. Update to latest TensorFlow proto definitions
3. Add `saved_model_pb2`, `graph_pb2`
4. Publish as `modelaudit-tensorflow-protos` or similar
5. Automate updates via CI

### Option D: Keep TensorFlow but Make It Optional

**Effort**: Low
**Risk**: Low
**Maintenance**: Low

1. Keep current code but make TensorFlow truly optional
2. Document that TensorFlow scanning requires full TensorFlow
3. Add alternative "lite" mode that only does structure analysis without weight inspection
4. Dismiss the CVE alert with documented justification

## Recommended Approach: Option A

### Phase 1: Protobuf Stubs (Week 1)

1. **Create proto compilation script**:

   ```bash
   # scripts/compile_tensorflow_protos.sh
   TF_VERSION="2.18.0"
   git clone --depth 1 --branch v${TF_VERSION} https://github.com/tensorflow/tensorflow

   protoc --python_out=modelaudit/protos \
     tensorflow/core/protobuf/saved_model.proto \
     tensorflow/core/framework/graph.proto \
     # ... other required protos
   ```

2. **Vendor compiled stubs** in `modelaudit/protos/tensorflow/`

3. **Update imports**:

   ```python
   # Before
   from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

   # After
   from modelaudit.protos.tensorflow.core.protobuf.saved_model_pb2 import SavedModel
   ```

### Phase 2: Custom Tensor Conversion (Week 1-2)

1. **Implement `tensor_proto_to_ndarray()`** in `modelaudit/utils/tensorflow_compat.py`

2. **Add comprehensive tests** for all TensorFlow dtypes

3. **Update `weight_distribution_scanner.py`** to use new function

### Phase 3: Deprecate Full TensorFlow Features (Week 2)

1. **Remove or gate checkpoint reading** (`tf.train.list_variables`, `tf.train.load_variable`)
   - Option: Keep as optional feature if full TensorFlow is installed
   - Option: Remove entirely (SavedModel directories less common for security scanning)

2. **Update documentation** explaining reduced functionality

### Phase 4: Cleanup (Week 2)

1. **Remove TensorFlow from dependencies** in `pyproject.toml`
2. **Add `protobuf>=3.19.0`** as core dependency (already likely present)
3. **Update tests** to not require TensorFlow
4. **Update CI matrix** to remove TensorFlow-specific jobs

## Files to Modify

| File                                                 | Changes                                   |
| ---------------------------------------------------- | ----------------------------------------- |
| `modelaudit/scanners/tf_savedmodel_scanner.py`       | Update imports to use vendored protos     |
| `modelaudit/scanners/weight_distribution_scanner.py` | Update imports, replace `tf.make_ndarray` |
| `modelaudit/protos/`                                 | New directory for vendored protobuf stubs |
| `modelaudit/utils/tensorflow_compat.py`              | New file for `tensor_proto_to_ndarray`    |
| `pyproject.toml`                                     | Remove TensorFlow dependency              |
| `scripts/compile_tensorflow_protos.sh`               | New script for proto compilation          |
| `tests/`                                             | Update to not require TensorFlow          |

## Risks and Mitigations

| Risk                    | Mitigation                                            |
| ----------------------- | ----------------------------------------------------- |
| Proto version drift     | Document TF version used; create update automation    |
| Missing dtype support   | Comprehensive test coverage for all TensorFlow dtypes |
| Checkpoint reading loss | Document as limitation; offer full TF as optional     |
| Protobuf compatibility  | Pin protobuf version; test across versions            |

## Success Criteria

- [ ] `pip install modelaudit` does not install TensorFlow or Keras
- [ ] SavedModel scanning works without TensorFlow
- [ ] No CVE alerts from dependency scanners
- [ ] All existing tests pass (except checkpoint-specific ones)
- [ ] Package size reduced by ~2GB

## Timeline

- **Week 1**: Protobuf stubs + tensor conversion
- **Week 2**: Integration, testing, cleanup
- **Week 3**: Documentation, PR, release

## References

- [tensorflow-protobuf on PyPI](https://pypi.org/project/tensorflow-protobuf/)
- [tensorflow-protobuf on GitHub](https://github.com/alexeygrigorev/tensorflow-protobuf)
- [TensorFlow proto definitions](https://github.com/tensorflow/tensorflow/tree/master/tensorflow/core/protobuf)
- [tf.make_ndarray documentation](https://www.tensorflow.org/api_docs/python/tf/make_ndarray)
