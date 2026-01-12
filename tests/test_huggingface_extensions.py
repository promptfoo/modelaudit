"""Tests for centralized MODEL_EXTENSIONS in HuggingFace downloads."""

from modelaudit.utils.sources.huggingface import _get_model_extensions

# Get extensions once for all tests
MODEL_EXTENSIONS = _get_model_extensions()


def test_model_extensions_includes_common_formats():
    """Test that MODEL_EXTENSIONS includes all common model formats."""
    # Core formats
    assert ".bin" in MODEL_EXTENSIONS
    assert ".pt" in MODEL_EXTENSIONS
    assert ".pth" in MODEL_EXTENSIONS
    assert ".pkl" in MODEL_EXTENSIONS
    assert ".safetensors" in MODEL_EXTENSIONS
    assert ".onnx" in MODEL_EXTENSIONS
    assert ".h5" in MODEL_EXTENSIONS
    assert ".keras" in MODEL_EXTENSIONS


def test_model_extensions_includes_gguf_formats():
    """Test that GGUF and GGML formats are included (critical for llama.cpp models)."""
    assert ".gguf" in MODEL_EXTENSIONS
    assert ".ggml" in MODEL_EXTENSIONS
    # Note: variants like .ggjt, .ggla, .ggmf, .ggsa are not in actual scanners


def test_model_extensions_includes_jax_flax():
    """Test that JAX/Flax formats are included."""
    assert ".flax" in MODEL_EXTENSIONS
    assert ".jax" in MODEL_EXTENSIONS
    assert ".orbax" in MODEL_EXTENSIONS
    assert ".msgpack" in MODEL_EXTENSIONS


def test_model_extensions_includes_numpy():
    """Test that NumPy formats are included."""
    assert ".npy" in MODEL_EXTENSIONS
    assert ".npz" in MODEL_EXTENSIONS


def test_model_extensions_includes_framework_specific():
    """Test that framework-specific formats are included."""
    # TensorFlow
    assert ".pb" in MODEL_EXTENSIONS
    assert ".tflite" in MODEL_EXTENSIONS

    # PaddlePaddle
    assert ".pdmodel" in MODEL_EXTENSIONS
    assert ".pdiparams" in MODEL_EXTENSIONS

    # PyTorch variants
    assert ".pte" in MODEL_EXTENSIONS
    assert ".ptl" in MODEL_EXTENSIONS

    # Other formats
    assert ".pmml" in MODEL_EXTENSIONS
    assert ".joblib" in MODEL_EXTENSIONS
    assert ".dill" in MODEL_EXTENSIONS


def test_model_extensions_includes_config_files():
    """Test that config/documentation files ARE in MODEL_EXTENSIONS (they have scanners)."""
    # Manifest scanner handles these
    assert ".json" in MODEL_EXTENSIONS
    assert ".yaml" in MODEL_EXTENSIONS
    assert ".yml" in MODEL_EXTENSIONS
    # Text scanner handles these
    assert ".txt" in MODEL_EXTENSIONS
    assert ".md" in MODEL_EXTENSIONS
    assert ".markdown" in MODEL_EXTENSIONS
    assert ".rst" in MODEL_EXTENSIONS


def test_model_extensions_includes_archives():
    """Test that archive formats ARE in MODEL_EXTENSIONS (they have scanners)."""
    # Archive scanners handle these
    assert ".zip" in MODEL_EXTENSIONS
    assert ".tar" in MODEL_EXTENSIONS
    assert ".tar.gz" in MODEL_EXTENSIONS
    assert ".tgz" in MODEL_EXTENSIONS
    assert ".7z" in MODEL_EXTENSIONS


def test_model_extensions_is_set():
    """Test that MODEL_EXTENSIONS is a set for efficient lookup."""
    assert isinstance(MODEL_EXTENSIONS, set)


def test_model_extensions_not_empty():
    """Test that MODEL_EXTENSIONS has a reasonable number of formats."""
    # Should have at least 50 formats (includes all scannable files)
    assert len(MODEL_EXTENSIONS) >= 50


def test_model_extensions_all_lowercase():
    """Test that all extensions are lowercase with leading dot."""
    for ext in MODEL_EXTENSIONS:
        assert ext.startswith("."), f"Extension {ext} should start with a dot"
        assert ext == ext.lower(), f"Extension {ext} should be lowercase"


def test_gguf_repo_file_filtering():
    """Test that GGUF repos download all scannable files."""
    # Simulate a typical GGUF model repo (like TheBloke's models)
    repo_files = [
        ".gitattributes",
        "LICENSE.txt",
        "README.md",
        "USE_POLICY.md",
        "config.json",
        "llama-2-7b.Q2_K.gguf",
        "llama-2-7b.Q3_K_L.gguf",
        "llama-2-7b.Q3_K_M.gguf",
        "llama-2-7b.Q4_0.gguf",
        "llama-2-7b.Q5_0.gguf",
    ]

    # Filter using MODEL_EXTENSIONS
    model_files = [f for f in repo_files if any(f.endswith(ext) for ext in MODEL_EXTENSIONS)]

    # Should find GGUF files + scannable files (README.md, config.json)
    assert len(model_files) >= 5  # At least the GGUF files
    assert all(f.endswith(".gguf") for f in model_files if ".gguf" in f)

    # Should include scannable files
    assert "README.md" in model_files  # Text scanner
    assert "config.json" in model_files  # Manifest scanner

    # Should NOT include files without scanners
    assert ".gitattributes" not in model_files
    assert "LICENSE.txt" in model_files  # Text scanner handles .txt


def test_mixed_format_repo_filtering():
    """Test filtering a repo with multiple model formats."""
    repo_files = [
        "README.md",
        "config.json",
        "model.safetensors",
        "pytorch_model.bin",
        "model.onnx",
        "model.gguf",
        "tokenizer.json",
        "special_tokens_map.json",
    ]

    model_files = [f for f in repo_files if any(f.endswith(ext) for ext in MODEL_EXTENSIONS)]

    # Should find 8 model files (4 weights + 4 configs/docs)
    assert len(model_files) == 8
    assert "model.safetensors" in model_files
    assert "pytorch_model.bin" in model_files
    assert "model.onnx" in model_files
    assert "model.gguf" in model_files

    # Should include config/tokenizer files (manifest scanner handles .json)
    assert "README.md" in model_files  # Text scanner
    assert "config.json" in model_files  # Manifest scanner
    assert "tokenizer.json" in model_files  # Manifest scanner
    assert "special_tokens_map.json" in model_files  # Manifest scanner


def test_jax_flax_repo_filtering():
    """Test filtering a JAX/Flax model repo."""
    repo_files = [
        "README.md",
        "config.json",
        "model.msgpack",
        "checkpoint.flax",
        "params.orbax",
    ]

    model_files = [f for f in repo_files if any(f.endswith(ext) for ext in MODEL_EXTENSIONS)]

    # Should find 5 model files (3 weights + 2 configs/docs)
    assert len(model_files) == 5
    assert "model.msgpack" in model_files
    assert "checkpoint.flax" in model_files
    assert "params.orbax" in model_files

    # Should include config/docs (have scanners)
    assert "README.md" in model_files  # Text scanner
    assert "config.json" in model_files  # Manifest scanner
