# Dependency Management

## Philosophy

ModelAudit uses optional dependencies to keep the base installation lightweight:

- **Base install**: Only includes core dependencies (pickle, numpy, zip scanning)
- **Feature-specific installs**: Add only what you need
- **Graceful degradation**: Missing dependencies disable specific scanners, don't break the tool
- **Clear guidance**: Error messages tell you exactly what to install

## Optional Dependencies

| Feature       | Package        | Purpose                              |
| ------------- | -------------- | ------------------------------------ |
| `h5`          | h5py           | Keras H5 model scanning              |
| `pytorch`     | torch          | PyTorch model scanning               |
| `yaml`        | pyyaml         | YAML manifest scanning               |
| `safetensors` | safetensors    | SafeTensors model scanning           |
| `onnx`        | onnx           | ONNX model scanning                  |
| `dill`        | dill           | Enhanced pickle support              |
| `joblib`      | joblib         | Joblib model scanning                |
| `flax`        | flax           | Flax msgpack scanning                |
| `tflite`      | tflite-runtime | TensorFlow Lite scanning             |
| `tensorflow`  | tensorflow     | TF checkpoint reading (rarely needed)|
| `all`         | All above      | Everything                           |

## TensorFlow SavedModel Scanning (No TensorFlow Required)

TensorFlow SavedModel scanning works **without installing TensorFlow** (~2GB). We use vendored
protobuf stubs compiled from TensorFlow's `.proto` files.

**How it works:**
1. If TensorFlow is installed → use its native protos
2. If TensorFlow is NOT installed → use vendored protos from `modelaudit/protos/`

**What works without TensorFlow:**
- SavedModel structure analysis
- PyFunc/Lambda layer detection
- Dangerous operation scanning
- Keras metadata inspection

**What requires full TensorFlow:**
- Checkpoint reading (`tf.train.list_variables`, `tf.train.load_variable`)
- Weight distribution analysis on checkpoints

Most users don't need to install TensorFlow at all.

## Installation

```bash
# With pip
pip install modelaudit[tensorflow,pytorch,h5]

# With uv (development)
uv sync --extra tensorflow --extra pytorch --extra h5

# All dependencies
uv sync --extra all
```

## Development Setup

```bash
# Clone and setup
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install with uv (recommended)
uv sync --extra all    # All optional dependencies
uv sync                # Basic dependencies only

# Or with pip
pip install -e .[all]      # Development mode with all extras
pip install -e .           # Basic installation
```

## Environment Variables

- `JFROG_API_TOKEN` / `JFROG_ACCESS_TOKEN` - JFrog authentication
- `NO_COLOR` - Disable color output
- `PROMPTFOO_DISABLE_TELEMETRY` / `NO_ANALYTICS` - Disable telemetry
- `.env` file is automatically loaded if present

## Vendored TensorFlow Protos (Maintainer Guide)

The vendored protos in `modelaudit/protos/tensorflow/` are compiled from TensorFlow's `.proto`
files. They enable SavedModel scanning without the full TensorFlow package.

### When to Update

Update protos when:
- TensorFlow releases a new major version with proto changes
- A new proto field is needed for security scanning
- Bug reports indicate proto incompatibility

### How to Update

```bash
# 1. Set the TensorFlow version
export TF_VERSION=2.18.0

# 2. Run the compilation script (requires protoc)
brew install protobuf  # macOS
./scripts/compile_tensorflow_protos.sh

# 3. Test the changes
python -c "
import modelaudit.protos
print(f'Protos available: {modelaudit.protos._check_vendored_protos()}')
print(f'Using vendored: {modelaudit.protos.is_using_vendored_protos()}')
"

# 4. Run end-to-end tests
python -m modelaudit tests/assets/samples/tensorflow/safe_savedmodel/
python -m modelaudit tests/assets/samples/tensorflow/malicious_pyfunc/

# 5. Commit the updated protos
git add modelaudit/protos/
git commit -m "chore: update vendored TensorFlow protos to v${TF_VERSION}"
```

### Files

| Path | Purpose |
|------|---------|
| `modelaudit/protos/__init__.py` | Proto loading logic (TF native vs vendored) |
| `modelaudit/protos/tensorflow/` | 59 vendored `*_pb2.py` files |
| `modelaudit/utils/tensorflow_compat.py` | `tensor_proto_to_ndarray()` utility |
| `scripts/compile_tensorflow_protos.sh` | Proto compilation script |

### Proto Loading Strategy

```
1. Import modelaudit.protos
2. Check if TensorFlow is installed
3. If YES → use TensorFlow's native protos (no sys.path changes)
4. If NO → add vendored protos to sys.path
5. Subsequent `from tensorflow.core...` imports resolve correctly
```

This avoids conflicts when TensorFlow is installed alongside modelaudit.
