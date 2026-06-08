"""Tests for CLI automatic-default configuration."""

import tempfile

import pytest

from modelaudit.utils.auto_defaults import (
    detect_file_size,
    detect_input_type,
    generate_auto_defaults,
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
    assert detect_input_type("R2://bucket/model.pt") == "cloud_s3"
    assert detect_input_type("https://bucket.s3.us-west-2.amazonaws.com/model.pt") == "cloud_s3"
    assert detect_input_type("https://s3.us-west-2.amazonaws.com/bucket/model.pt") == "cloud_s3"
    assert detect_input_type("https://bucket.account.r2.cloudflarestorage.com/model.pt") == "cloud_s3"
    assert detect_input_type("gs://bucket/model.pt") == "cloud_gcs"
    assert detect_input_type("https://bucket.storage.googleapis.com/model.pt") == "cloud_gcs"
    assert detect_input_type("https://storage.cloud.google.com/bucket/model.pt") == "cloud_gcs"
    assert detect_input_type("az://container/model.pt") == "cloud_azure"
    assert detect_input_type("https://account.blob.core.windows.net/container") == "cloud_azure"
    assert detect_input_type("AZ://container/model.pt") == "cloud_azure"
    assert detect_input_type("https://bucket.s3.amazonaws.com./model.pt") == "cloud_s3"
    assert detect_input_type("https://storage.googleapis.com./bucket/model.pt") == "cloud_gcs"
    assert detect_input_type("https://bucket.s3.cn-north-1.amazonaws.com.cn/model.pt") == "cloud_s3"
    assert detect_input_type("https://s3.us-iso-east-1.amazonaws.com/bucket/model.pt") == "cloud_s3"
    assert detect_input_type("https://bucket.s3-fips.us-east-1.amazonaws.com/model.pt") == "cloud_s3"
    assert detect_input_type("https://s3-fips.us-east-1.amazonaws.com/bucket/model.pt") == "cloud_s3"
    assert detect_input_type("https://bucket.s3-accelerate.amazonaws.com/model.pt") == "cloud_s3"
    assert detect_input_type("https://bucket.s3-accelerate.dualstack.amazonaws.com/model.pt") == "cloud_s3"


@pytest.mark.parametrize(
    "url",
    [
        "https://bucket.s3.us-west-2.amazonaws.com.evil.test/model.pt",
        "https://bucket.s3-fips.us-east-1.amazonaws.com.evil.test/model.pt",
        "https://bucket.s3-accelerate.amazonaws.com.evil.test/model.pt",
        "https://storage.googleapis.com.evil.test/bucket/model.pt",
        "https://bucket.storage.googleapis.com.evil.test/model.pt",
        "https://account.r2.cloudflarestorage.com.evil.test/bucket/model.pt",
    ],
)
def test_detect_input_type_rejects_cloud_host_suffix_tricks(url: str) -> None:
    assert detect_input_type(url) == "local_file"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://bucket.s3.amazonaws.com/model.pt",
        "file://storage.googleapis.com/bucket/model.pt",
        "ssh://account.blob.core.windows.net/container/model.pt",
        "ftp://account.r2.cloudflarestorage.com/bucket/model.pt",
    ],
)
def test_detect_input_type_requires_https_for_provider_hostnames(url: str) -> None:
    assert detect_input_type(url) == "local_file"


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


def test_generate_auto_defaults_local():
    """Test automatic defaults for local files."""
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"x" * 1000)  # Small file
        tmp.flush()

        defaults = generate_auto_defaults([tmp.name])

        assert defaults["show_progress"] is False  # Small local file
        assert defaults["use_cache"] is False  # Local files don't need caching
        assert defaults["large_model_support"] is False  # Small file
        assert defaults["selective_download"] is False  # Local file
        assert defaults["skip_non_model_files"] is True  # Default behavior


def test_generate_auto_defaults_cloud():
    """Test automatic defaults for cloud paths."""
    paths = ["s3://bucket/models/"]
    defaults = generate_auto_defaults(paths)

    assert defaults["use_cache"] is True  # Cloud operations should cache
    assert defaults["selective_download"] is True  # Cloud directories
    assert "timeout" in defaults
    assert defaults["timeout"] > 3600  # Cloud operations get longer timeout


@pytest.mark.parametrize(
    "path",
    [
        "R2://bucket/models/model.pkl",
        "https://bucket.s3.us-west-2.amazonaws.com/model.pkl",
        "https://s3.us-west-2.amazonaws.com/bucket/model.pkl",
        "https://bucket.storage.googleapis.com/model.pkl",
        "https://storage.cloud.google.com/bucket/model.pkl",
    ],
)
def test_generate_auto_defaults_cloud_https_forms(path: str) -> None:
    defaults = generate_auto_defaults([path])

    assert defaults["use_cache"] is True
    assert defaults["selective_download"] is True
    assert defaults["max_file_size"] == 50 * 1024 * 1024 * 1024
    assert defaults["timeout"] > 3600


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


def test_auto_defaults_huggingface():
    """Test automatic defaults for HuggingFace models."""
    paths = ["hf://user/model"]
    defaults = generate_auto_defaults(paths)

    assert defaults["use_cache"] is True  # Remote operations should cache
    assert defaults["selective_download"] is True  # HuggingFace models
    assert "timeout" in defaults


def test_auto_defaults_jfrog() -> None:
    """JFrog URLs should keep selective download enabled by default."""
    paths = ["https://company.jfrog.io/artifactory/repo/model.pt"]
    defaults = generate_auto_defaults(paths)

    assert defaults["use_cache"] is True
    assert defaults["selective_download"] is True
