import json
import pickle
import zipfile
from pathlib import Path

import numpy as np
import pytest
from safetensors.numpy import save_file

from modelaudit.core import scan_model_directory_or_file


def create_safetensors_file(path: Path) -> None:
    data = {"t1": np.arange(4, dtype=np.float32)}
    save_file(data, str(path))


def test_assets_safetensors(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    results = scan_model_directory_or_file(str(file_path))
    assert results.assets[0].path == str(file_path)


def test_assets_zip(tmp_path: Path) -> None:
    zip_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("a.txt", "hello")
        z.writestr("b.txt", "world")

    results = scan_model_directory_or_file(str(zip_path))
    top_asset = results.assets[0]
    inner = {a["path"] for a in getattr(top_asset, "contents", [])}
    assert f"{zip_path}:a.txt" in inner
    assert f"{zip_path}:b.txt" in inner


def test_assets_safetensors_metadata(tmp_path: Path) -> None:
    """Test that SafeTensors assets include tensor metadata."""
    file_path = tmp_path / "model.safetensors"
    tensor_data = {
        "layer1.weight": np.random.randn(100, 200).astype(np.float32),
        "layer1.bias": np.random.randn(100).astype(np.float32),
        "layer2.weight": np.random.randn(50, 100).astype(np.float32),
    }
    save_file(tensor_data, str(file_path))

    results = scan_model_directory_or_file(str(file_path))
    asset = results.assets[0]

    assert asset.type == "safetensors"
    assert hasattr(asset, "tensors")
    assert hasattr(asset, "size")
    assert asset.size is not None and asset.size > 0

    # Check all tensor names are captured
    tensor_names = asset.tensors
    assert tensor_names is not None
    assert "layer1.weight" in tensor_names
    assert "layer1.bias" in tensor_names
    assert "layer2.weight" in tensor_names
    assert len(tensor_names) == 3


def test_assets_json_manifest_metadata(tmp_path: Path) -> None:
    """Test that JSON manifest assets include keys metadata."""
    config_path = tmp_path / "config.json"  # This filename will be recognized by ManifestScanner
    config_data = {
        "model_type": "bert",
        "hidden_size": 768,
        "num_attention_heads": 12,
        "vocab_size": 30522,
        "max_position_embeddings": 512,
    }
    config_path.write_text(json.dumps(config_data, indent=2))

    results = scan_model_directory_or_file(str(config_path))
    asset = results.assets[0]

    assert asset.type == "manifest"
    assert hasattr(asset, "keys")
    assert hasattr(asset, "size")

    # Check all keys are captured
    keys = asset.keys
    assert keys is not None
    assert "model_type" in keys
    assert "hidden_size" in keys
    assert "num_attention_heads" in keys
    assert "vocab_size" in keys
    assert "max_position_embeddings" in keys
    assert len(keys) == 5


def test_assets_pickle_file(tmp_path: Path) -> None:
    """Test that pickle files are captured as assets."""
    pickle_path = tmp_path / "model.pkl"
    data = {"weights": np.array([1, 2, 3, 4]), "metadata": {"version": "1.0"}}

    with open(pickle_path, "wb") as f:
        pickle.dump(data, f)

    results = scan_model_directory_or_file(str(pickle_path))
    asset = results.assets[0]

    assert asset.path == str(pickle_path)
    assert asset.type == "pickle"
    assert hasattr(asset, "size")
    assert asset.size is not None and asset.size > 0


def test_assets_nested_zip_with_models(tmp_path: Path) -> None:
    """Test that nested ZIP files with model files show proper asset structure."""
    # Create a SafeTensors file to put in the ZIP
    safetensors_data = {"weight": np.array([1.0, 2.0, 3.0]).astype(np.float32)}
    inner_st_path = tmp_path / "temp.safetensors"
    save_file(safetensors_data, str(inner_st_path))

    # Create ZIP with the SafeTensors file
    zip_path = tmp_path / "models.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.write(inner_st_path, "model.safetensors")
        # Use a config.json filename that will be recognized by ManifestScanner
        z.writestr("config.json", '{"model_type": "test", "hidden_size": 768}')

    # Clean up temp file
    inner_st_path.unlink()

    results = scan_model_directory_or_file(str(zip_path))
    zip_asset = results.assets[0]

    assert zip_asset.type == "zip"
    assert hasattr(zip_asset, "contents")
    assert zip_asset.contents is not None
    assert len(zip_asset.contents) == 2

    # Find the SafeTensors asset within the ZIP
    st_asset = None
    json_asset = None
    for content in zip_asset.contents:
        if content["path"].endswith("model.safetensors"):
            st_asset = content
        elif content["path"].endswith("config.json"):
            json_asset = content

    # Verify SafeTensors asset metadata
    assert st_asset is not None
    assert st_asset["type"] == "safetensors"
    assert "tensors" in st_asset
    assert "weight" in st_asset["tensors"]

    # Verify JSON asset metadata
    assert json_asset is not None
    assert json_asset["type"] == "manifest"
    assert "keys" in json_asset
    assert "model_type" in json_asset["keys"]
    assert "hidden_size" in json_asset["keys"]


def test_assets_directory_scan_multiple_files(tmp_path: Path) -> None:
    """Test that directory scanning captures all files as assets."""
    model_dir = tmp_path / "model_dir"
    model_dir.mkdir()

    # Create multiple files of different types
    # SafeTensors file
    st_file = model_dir / "weights.safetensors"
    st_data = {"layer": np.array([1, 2]).astype(np.float32)}
    save_file(st_data, str(st_file))

    # JSON config - use recognized filename
    config_file = model_dir / "config.json"
    config_file.write_text('{"model_type": "transformer", "hidden_size": 768}')

    # Pickle file
    pickle_file = model_dir / "state.pkl"
    with open(pickle_file, "wb") as f:
        pickle.dump({"state": "saved"}, f)

    # Binary file with unknown extension (should be handled by unknown scanner)
    unknown_file = model_dir / "data.dat"
    unknown_file.write_bytes(b"Binary data content")

    results = scan_model_directory_or_file(str(model_dir))

    # Should have 4 assets (one for each file)
    assert len(results.assets) == 4
    assert results.files_scanned == 4

    # Check that we have the expected asset types
    asset_types = {asset.type for asset in results.assets}
    expected_types = {"safetensors", "manifest", "pickle", "unknown"}
    assert asset_types == expected_types

    # Verify each file is represented
    asset_paths = {Path(asset.path).name for asset in results.assets}
    expected_files = {"weights.safetensors", "config.json", "state.pkl", "data.dat"}
    assert asset_paths == expected_files


def test_assets_structure_validation(tmp_path: Path) -> None:
    """Test that asset structure follows the expected schema."""
    file_path = tmp_path / "test.safetensors"
    data = {"tensor1": np.array([1, 2, 3]).astype(np.float32)}
    save_file(data, str(file_path))

    results = scan_model_directory_or_file(str(file_path))

    # Validate top-level structure
    assert hasattr(results, "assets")
    assert isinstance(results.assets, list)

    # Validate asset structure
    asset = results.assets[0]

    # Required fields
    assert hasattr(asset, "path")
    assert hasattr(asset, "type")
    assert isinstance(asset.path, str)
    assert isinstance(asset.type, str)

    # Optional fields (when present, should have correct types)
    if hasattr(asset, "size") and asset.size is not None:
        assert isinstance(asset.size, int)
        assert asset.size >= 0

    if hasattr(asset, "tensors") and asset.tensors is not None:
        assert isinstance(asset.tensors, list)
        for tensor_name in asset.tensors:
            assert isinstance(tensor_name, str)

    if hasattr(asset, "keys") and asset.keys is not None:
        assert isinstance(asset.keys, list)
        for key in asset.keys:
            assert isinstance(key, str)

    if hasattr(asset, "contents") and asset.contents is not None:
        assert isinstance(asset.contents, list)
        for content in asset.contents:
            assert isinstance(content, dict)
            assert "path" in content
            assert "type" in content


def test_assets_error_files_handling(tmp_path: Path) -> None:
    """Test that files causing errors are still included in assets with error type."""
    # Create a file that will be treated as unknown (no specific scanner handles .xyz files)
    bad_file = tmp_path / "corrupted.xyz"
    bad_file.write_bytes(b"not valid data")

    # Create a good file alongside it - use recognized filename
    good_file = tmp_path / "config.json"
    good_file.write_text('{"model_type": "transformer", "hidden_size": 768}')

    results = scan_model_directory_or_file(str(tmp_path))

    # Should have assets for both files
    assert len(results.assets) == 2

    # The corrupted file should be treated as unknown type (no specific error type)
    unknown_assets = [a for a in results.assets if a.type == "unknown"]
    assert len(unknown_assets) == 1

    unknown_asset = unknown_assets[0]
    assert unknown_asset.path == str(bad_file)

    # Good file should still be processed normally
    good_assets = [a for a in results.assets if a.path == str(good_file)]
    assert len(good_assets) == 1
    assert good_assets[0].type == "manifest"


def test_assets_empty_results(tmp_path: Path) -> None:
    """Test that empty directories still have assets field (empty list)."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    results = scan_model_directory_or_file(str(empty_dir))

    assert hasattr(results, "assets")
    assert isinstance(results.assets, list)
    assert len(results.assets) == 0
    assert results.files_scanned == 0


@pytest.mark.parametrize(
    "file_extension,expected_type",
    [
        (".safetensors", "safetensors"),
        (".pkl", "pickle"),
        (".zip", "zip"),
        (".txt", "unknown"),
    ],
)
def test_assets_file_type_detection(
    tmp_path: Path,
    file_extension: str,
    expected_type: str,
) -> None:
    """Test that different file types are correctly detected and typed in assets."""
    file_path = tmp_path / f"test{file_extension}"

    if file_extension == ".safetensors":
        data = {"test": np.array([1]).astype(np.float32)}
        save_file(data, str(file_path))
    elif file_extension == ".pkl":
        with open(file_path, "wb") as f:
            pickle.dump({"test": "data"}, f)
    elif file_extension == ".zip":
        with zipfile.ZipFile(file_path, "w") as z:
            z.writestr("test.txt", "content")
    else:  # .txt
        file_path.write_text("test content")

    results = scan_model_directory_or_file(str(file_path))

    asset = results.assets[0]
    assert asset.type == expected_type
    assert asset.path == str(file_path)


def test_assets_ml_config_json_detection(tmp_path: Path) -> None:
    """Test that ML model config JSON files are properly detected as manifest type."""
    # Test config.json (recognized filename)
    config_file = tmp_path / "config.json"
    config_data = {
        "model_type": "bert",
        "hidden_size": 768,
        "num_attention_heads": 12,
        "vocab_size": 30522,
    }
    config_file.write_text(json.dumps(config_data))

    results = scan_model_directory_or_file(str(config_file))
    asset = results.assets[0]

    assert asset.type == "manifest"
    assert hasattr(asset, "keys")
    assert asset.keys is not None
    assert set(asset.keys) == {
        "model_type",
        "hidden_size",
        "num_attention_heads",
        "vocab_size",
    }


def test_assets_generic_json_detection(tmp_path: Path) -> None:
    """Test that generic JSON files are detected as unknown type."""
    # Generic JSON file (not ML-specific)
    json_file = tmp_path / "data.json"
    json_file.write_text('{"test": "value", "number": 42}')

    results = scan_model_directory_or_file(str(json_file))
    asset = results.assets[0]

    # Generic JSON should be unknown type since ManifestScanner only handles ML-specific configs
    assert asset.type == "unknown"
    assert asset.path == str(json_file)
