# Dependency Management

## Philosophy

ModelAudit uses optional dependencies to keep the base installation lightweight:

- **Base install**: Only includes core dependencies (pickle, numpy, zip scanning)
- **Feature-specific installs**: Add only what you need
- **Graceful degradation**: Missing dependencies disable specific scanners, don't break the tool
- **Clear guidance**: Error messages tell you exactly what to install

## Optional Dependencies

| Feature       | Package        | Purpose                        |
| ------------- | -------------- | ------------------------------ |
| `tensorflow`  | tensorflow     | TensorFlow SavedModel scanning |
| `h5`          | h5py           | Keras H5 model scanning        |
| `pytorch`     | torch          | PyTorch model scanning         |
| `yaml`        | pyyaml         | YAML manifest scanning         |
| `safetensors` | safetensors    | SafeTensors model scanning     |
| `onnx`        | onnx           | ONNX model scanning            |
| `dill`        | dill           | Enhanced pickle support        |
| `joblib`      | joblib         | Joblib model scanning          |
| `flax`        | flax           | Flax msgpack scanning          |
| `tflite`      | tflite-runtime | TensorFlow Lite scanning       |
| `all`         | All above      | Everything                     |

## Installation

```bash
# With pip
pip install modelaudit[tensorflow,pytorch,h5]

# With rye (development)
rye sync --features="tensorflow pytorch h5"

# All dependencies
rye sync --features all
```

## Development Setup

```bash
# Clone and setup
git clone https://github.com/promptfoo/modelaudit.git
cd modelaudit

# Install with Rye (recommended)
rye sync --features all    # All optional dependencies
rye sync                   # Basic dependencies only

# Or with pip
pip install -e .[all]      # Development mode with all extras
pip install -e .           # Basic installation
```

## Environment Variables

- `JFROG_API_TOKEN` / `JFROG_ACCESS_TOKEN` - JFrog authentication
- `NO_COLOR` - Disable color output
- `PROMPTFOO_DISABLE_TELEMETRY` / `NO_ANALYTICS` - Disable telemetry
- `.env` file is automatically loaded if present
