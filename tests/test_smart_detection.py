"""Tests for CLI smart detection functionality."""

import tempfile

from modelaudit.utils.smart_detection import (
    detect_file_size,
    detect_input_type,
    generate_smart_defaults,
    parse_size_string,
)


def test_detect_input_type_local():
    """Test detection of local file types."""
    with tempfile.NamedTemporaryFile() as tmp:
        assert detect_input_type(tmp.name) == "local_file"

    with tempfile.TemporaryDirectory() as tmp_dir:
        assert detect_input_type(tmp_dir) == "local_directory"


def test_detect_input_type_cloud():
    """Test detection of cloud storage types."""
    assert detect_input_type("s3://bucket/model.pt") == "cloud_s3"
    assert detect_input_type("gs://bucket/model.pt") == "cloud_gcs"
    assert detect_input_type("az://container/model.pt") == "cloud_azure"
    assert detect_input_type("https://account.blob.core.windows.net/container") == "cloud_azure"


def test_detect_input_type_registries():
    """Test detection of model registry types."""
    assert detect_input_type("hf://user/model") == "huggingface"
    assert detect_input_type("https://huggingface.co/user/model") == "huggingface"
    assert detect_input_type("models:/model/v1") == "mlflow"
    assert detect_input_type("pytorch.org/hub/pytorch_vision_resnet") == "pytorch_hub"
    assert detect_input_type("https://company.jfrog.io/artifactory/repo/model.pt") == "jfrog"


def test_detect_file_size():
    """Test file size detection."""
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"test" * 100)  # 400 bytes
        tmp.flush()
        size = detect_file_size(tmp.name)
        assert size == 400


def test_generate_smart_defaults_local():
    """Test smart defaults for local files."""
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"x" * 1000)  # Small file
        tmp.flush()

        defaults = generate_smart_defaults([tmp.name])

        assert defaults["show_progress"] is False  # Small local file
        assert defaults["use_cache"] is False  # Local files don't need caching
        assert defaults["large_model_support"] is False  # Small file
        assert defaults["selective_download"] is False  # Local file
        assert defaults["skip_non_model_files"] is True  # Default behavior


def test_generate_smart_defaults_cloud():
    """Test smart defaults for cloud paths."""
    paths = ["s3://bucket/models/"]
    defaults = generate_smart_defaults(paths)

    assert defaults["use_cache"] is True  # Cloud operations should cache
    assert defaults["selective_download"] is True  # Cloud directories
    assert "timeout" in defaults
    assert defaults["timeout"] > 3600  # Cloud operations get longer timeout


def test_parse_size_string():
    """Test size string parsing."""
    assert parse_size_string("100") == 100
    assert parse_size_string("1KB") == 1024
    assert parse_size_string("5MB") == 5 * 1024 * 1024
    assert parse_size_string("2GB") == 2 * 1024 * 1024 * 1024
    assert parse_size_string("1TB") == 1024 * 1024 * 1024 * 1024

    # Test case insensitive
    assert parse_size_string("1gb") == 1024 * 1024 * 1024

    # Test invalid format
    try:
        parse_size_string("invalid")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass


def test_smart_defaults_huggingface():
    """Test smart defaults for HuggingFace models."""
    paths = ["hf://user/model"]
    defaults = generate_smart_defaults(paths)

    assert defaults["use_cache"] is True  # Remote operations should cache
    assert defaults["selective_download"] is True  # HuggingFace models
    assert "timeout" in defaults
