"""Shared constants for ModelAudit."""

# Core model file extensions that can contain executable code and should be scanned
SCANNABLE_MODEL_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Pickle-based formats (high risk)
        ".pkl",
        ".pickle",
        ".joblib",
        # PyTorch formats
        ".pt",
        ".pth",
        # TensorFlow/Keras formats
        ".h5",
        ".hdf5",
        ".keras",
        ".pb",
        ".pbtxt",
        ".tflite",
        ".lite",
        # Cross-platform formats
        ".onnx",
        ".safetensors",
        ".msgpack",
        # Binary model formats
        ".bin",
        ".ckpt",
        # PaddlePaddle formats
        ".pdmodel",
        ".pdiparams",
        ".pdopt",
        # OpenVINO formats
        ".ot",
        ".ort",
        ".ov",
        # LLM formats
        ".gguf",
        ".ggml",
        # Other ML formats
        ".pmml",
        ".mar",  # TorchServe model archive
        ".model",  # Generic model extension
        ".mlmodel",  # Core ML
        # Archive formats (can contain models)
        ".tar",
        ".tar.gz",
        ".tgz",
    }
)

# Subset of core model extensions used for license checking (lower risk, common formats)
COMMON_MODEL_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pkl",
        ".joblib",
        ".pt",
        ".pth",
        ".onnx",
        ".pb",
        ".h5",
        ".keras",
        ".safetensors",
    }
)
