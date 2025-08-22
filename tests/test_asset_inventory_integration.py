"""
Comprehensive integration tests for the asset inventory feature.

These tests verify that the asset inventory functionality works correctly across:
- Multiple file formats (SafeTensors, PyTorch, ZIP, JSON manifests, etc.)
- Nested archives and complex directory structures
- CLI text and JSON output formats
- Error handling and edge cases
- Real-world model directory scenarios
"""

import json
import os
import pickle
import tempfile
import zipfile
from pathlib import Path

import numpy as np
import pytest
from click.testing import CliRunner
from safetensors.numpy import save_file

from modelaudit.cli import cli
from modelaudit.core import scan_model_directory_or_file


class TestAssetInventoryIntegration:
    """Comprehensive tests for asset inventory functionality."""

    @pytest.fixture
    def complex_model_dir(self, tmp_path: Path) -> Path:
        """Create a complex model directory with multiple file types."""
        model_dir = tmp_path / "complex_model"
        model_dir.mkdir()

        # Create SafeTensors model with multiple tensors
        safetensors_file = model_dir / "model.safetensors"
        safetensors_data = {
            "embedding.weight": np.random.randn(1000, 768).astype(np.float32),
            "decoder.weight": np.random.randn(768, 50257).astype(np.float32),
            "layer_norm.bias": np.random.randn(768).astype(np.float32),
        }
        save_file(safetensors_data, str(safetensors_file))

        # Create JSON config with keys
        config_file = model_dir / "config.json"
        config_data = {
            "model_type": "transformer",
            "hidden_size": 768,
            "vocab_size": 50257,
            "num_layers": 12,
        }
        config_file.write_text(json.dumps(config_data, indent=2))

        # Create nested ZIP archive with multiple files
        nested_zip = model_dir / "weights.zip"
        with zipfile.ZipFile(nested_zip, "w") as zf:
            # Add a pickle file inside the ZIP
            pickle_data = {"model_state": {"layer1": np.array([1, 2, 3])}}
            pickle_bytes = pickle.dumps(pickle_data)
            zf.writestr("model_state.pkl", pickle_bytes)

            # Add another SafeTensors file inside the ZIP
            inner_safetensors_data = {
                "optimizer.weight": np.random.randn(100, 768).astype(np.float32),
            }
            with tempfile.NamedTemporaryFile(
                suffix=".safetensors",
                delete=False,
            ) as tmp:
                save_file(inner_safetensors_data, tmp.name)
                with open(tmp.name, "rb") as f:
                    zf.writestr("optimizer.safetensors", f.read())
                os.unlink(tmp.name)

            # Add a text file
            zf.writestr("README.txt", "Model documentation")

        # Create subdirectory with additional files
        subdir = model_dir / "tokenizer"
        subdir.mkdir()
        tokenizer_config = subdir / "tokenizer_config.json"
        tokenizer_data = {
            "tokenizer_class": "BertTokenizer",
            "vocab_size": 50257,
            "special_tokens": ["[CLS]", "[SEP]", "[MASK]"],
        }
        tokenizer_config.write_text(json.dumps(tokenizer_data, indent=2))

        return model_dir

    def test_asset_inventory_multiple_formats(self, complex_model_dir: Path):
        """Test that asset inventory captures all file formats correctly."""
        results = scan_model_directory_or_file(str(complex_model_dir))

        # Should have scanned multiple files
        assert results.files_scanned >= 4
        assert results.success is True

        # Should have assets for each file
        assets = results.assets
        assert len(assets) >= 4

        # Check for SafeTensors file with tensor metadata
        safetensors_assets = [a for a in assets if a.path.endswith("model.safetensors")]
        assert len(safetensors_assets) == 1
        st_asset = safetensors_assets[0]
        assert st_asset.type == "safetensors"
        assert hasattr(st_asset, "tensors") and st_asset.tensors is not None
        assert "embedding.weight" in st_asset.tensors
        assert "decoder.weight" in st_asset.tensors
        assert "layer_norm.bias" in st_asset.tensors
        assert hasattr(st_asset, "size") and st_asset.size is not None

        # Check for main JSON config with keys metadata
        main_config_assets = [a for a in assets if a.path.endswith("/config.json")]
        assert len(main_config_assets) == 1
        config_asset = main_config_assets[0]
        assert config_asset.type == "manifest"
        assert hasattr(config_asset, "keys") and config_asset.keys is not None
        expected_keys = ["model_type", "hidden_size", "vocab_size", "num_layers"]
        for key in expected_keys:
            assert key in config_asset.keys

        # Check for ZIP file with contents
        zip_assets = [a for a in assets if a.path.endswith("weights.zip")]
        assert len(zip_assets) == 1
        zip_asset = zip_assets[0]
        assert zip_asset.type == "zip"
        assert hasattr(zip_asset, "contents") and zip_asset.contents is not None
        assert len(zip_asset.contents) >= 3  # pickle, safetensors, text file

        # Verify nested contents have correct paths
        nested_paths = {c["path"] for c in zip_asset.contents}
        expected_nested = {
            f"{complex_model_dir}/weights.zip:model_state.pkl",
            f"{complex_model_dir}/weights.zip:optimizer.safetensors",
            f"{complex_model_dir}/weights.zip:README.txt",
        }
        assert expected_nested.issubset(nested_paths)

        # Check nested SafeTensors asset has tensor metadata
        nested_st = next(
            (c for c in zip_asset.contents if c["path"].endswith("optimizer.safetensors")),
            None,
        )
        assert nested_st is not None
        assert nested_st["type"] == "safetensors"
        assert "tensors" in nested_st
        assert "optimizer.weight" in nested_st["tensors"]

    def test_asset_inventory_directory_structure(self, complex_model_dir: Path):
        """Test that asset inventory correctly handles subdirectories."""
        results = scan_model_directory_or_file(str(complex_model_dir))

        assets = results.assets
        asset_paths = {a.path for a in assets}

        # Should include files from subdirectories
        tokenizer_config_path = str(
            complex_model_dir / "tokenizer" / "tokenizer_config.json",
        )
        assert tokenizer_config_path in asset_paths

        # Check tokenizer config asset
        tokenizer_assets = [a for a in assets if "tokenizer_config.json" in a.path]
        assert len(tokenizer_assets) == 1
        tokenizer_asset = tokenizer_assets[0]
        assert tokenizer_asset.type == "manifest"
        assert hasattr(tokenizer_asset, "keys") and tokenizer_asset.keys is not None
        assert "tokenizer_class" in tokenizer_asset.keys
        assert "special_tokens" in tokenizer_asset.keys

    def test_asset_inventory_cli_text_output(self, complex_model_dir: Path):
        """Test that asset inventory appears correctly in CLI text output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(complex_model_dir)])

        # Should succeed or have warnings but not error
        assert result.exit_code in [0, 1]

        # Note: SCANNED FILES section was removed to reduce output verbosity
        # The asset inventory is still available in JSON format
        # Just verify that the scan completed successfully and mentioned the files
        assert "SCAN SUMMARY" in result.output
        assert "Files:" in result.output

        # Should still show file paths in issues if any are found
        # The files are still being scanned and processed, just not listed separately

    def test_asset_inventory_cli_json_output(self, complex_model_dir: Path):
        """Test that asset inventory appears correctly in CLI JSON output."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", str(complex_model_dir), "--format", "json"],
        )

        # Should succeed or have warnings but not error
        assert result.exit_code in [0, 1]

        # Should be valid JSON
        output_data = json.loads(result.output)

        # Should have assets field
        assert "assets" in output_data
        assets = output_data["assets"]
        assert len(assets) >= 4

        # Verify JSON structure matches expected format from README
        for asset in assets:
            assert "path" in asset
            assert "type" in asset
            # Optional fields depending on file type
            if "tensors" in asset:
                assert isinstance(asset["tensors"], list)
            if "keys" in asset:
                assert isinstance(asset["keys"], list)
            if "contents" in asset:
                assert isinstance(asset["contents"], list)
            if "size" in asset:
                assert isinstance(asset["size"], int)

    def test_asset_inventory_nested_archives(self, tmp_path: Path):
        """Test asset inventory with deeply nested archives."""
        # Create a ZIP containing another ZIP containing a model
        inner_zip = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner_zip, "w") as inner_zf:
            # Add SafeTensors file to inner ZIP
            safetensors_data = {"weight": np.array([1, 2, 3, 4]).astype(np.float32)}
            with tempfile.NamedTemporaryFile(
                suffix=".safetensors",
                delete=False,
            ) as tmp:
                save_file(safetensors_data, tmp.name)
                with open(tmp.name, "rb") as f:
                    inner_zf.writestr("model.safetensors", f.read())
                os.unlink(tmp.name)

        outer_zip = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip, "w") as outer_zf, open(inner_zip, "rb") as f:
            outer_zf.writestr("models/inner.zip", f.read())

        results = scan_model_directory_or_file(str(outer_zip))

        # Should have the outer ZIP as main asset
        assets = results.assets
        assert len(assets) == 1
        outer_asset = assets[0]
        assert outer_asset.type == "zip"
        assert hasattr(outer_asset, "contents") and outer_asset.contents is not None

        # Should have the inner ZIP in contents
        inner_zip_asset = None
        for content in outer_asset.contents:
            if content["path"].endswith("inner.zip"):
                inner_zip_asset = content
                break

        assert inner_zip_asset is not None
        assert inner_zip_asset["type"] == "zip"
        assert "contents" in inner_zip_asset

        # Should have the SafeTensors file in the nested contents
        nested_st = None
        for content in inner_zip_asset["contents"]:
            if content["path"].endswith("model.safetensors"):
                nested_st = content
                break

        assert nested_st is not None
        assert nested_st["type"] == "safetensors"
        assert "tensors" in nested_st
        assert "weight" in nested_st["tensors"]

    def test_asset_inventory_error_handling(self, tmp_path: Path):
        """Test asset inventory with files that cause scan errors."""
        # Create a corrupted file that will be treated as unknown (no specific scanner handles .xyz files)
        corrupted_file = tmp_path / "corrupted.xyz"
        corrupted_file.write_bytes(b"invalid data")

        # Create a valid file alongside it - use recognized filename for ManifestScanner
        valid_file = tmp_path / "config.json"
        valid_file.write_text('{"model_type": "transformer", "hidden_size": 768}')

        results = scan_model_directory_or_file(str(tmp_path))

        # Should still have assets even with errors
        assert hasattr(results, "assets")
        assets = results.assets
        assert len(assets) >= 2

        # Should have unknown type for corrupted file (no specific scanner handles .xyz files)
        unknown_assets = [a for a in assets if a.type == "unknown"]
        assert len(unknown_assets) >= 1

        # Should still have valid file asset
        valid_assets = [a for a in assets if a.path.endswith("config.json")]
        assert len(valid_assets) == 1
        assert valid_assets[0].type == "manifest"

    def test_asset_inventory_single_file_scan(self, tmp_path: Path):
        """Test asset inventory when scanning a single file."""
        # Create a single SafeTensors file
        single_file = tmp_path / "single_model.safetensors"
        data = {
            "layer1.weight": np.random.randn(100, 50).astype(np.float32),
            "layer1.bias": np.random.randn(100).astype(np.float32),
        }
        save_file(data, str(single_file))

        results = scan_model_directory_or_file(str(single_file))

        # Should have exactly one asset
        assert hasattr(results, "assets")
        assets = results.assets
        assert len(assets) == 1

        asset = assets[0]
        assert asset.path == str(single_file)
        assert asset.type == "safetensors"
        assert hasattr(asset, "tensors") and asset.tensors is not None
        assert "layer1.weight" in asset.tensors
        assert "layer1.bias" in asset.tensors
        assert hasattr(asset, "size") and asset.size is not None

    def test_asset_inventory_empty_directory(self, tmp_path: Path):
        """Test asset inventory with empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        results = scan_model_directory_or_file(str(empty_dir))

        # Should complete successfully
        assert results.success is True
        assert results.files_scanned == 0

        # Should have empty assets list
        assert hasattr(results, "assets")
        assert len(results.assets) == 0

    def test_asset_inventory_with_integration_test_data(self):
        """Test asset inventory with existing integration test data."""
        test_data_dir = Path(__file__).parent / "assets/scenarios/license_scenarios"
        if not test_data_dir.exists():
            pytest.skip("Integration test data not available")

        # Test with MIT model directory
        mit_dir = test_data_dir / "mit_model"
        if mit_dir.exists():
            results = scan_model_directory_or_file(str(mit_dir))

            assert results.success is True
            assert hasattr(results, "assets")
            assets = results.assets
            assert len(assets) > 0

            # Should have different asset types
            asset_types = {a.type for a in assets}
            assert len(asset_types) > 1  # Should have multiple file types

            # Check that paths are correct
            for asset in assets:
                assert asset.path.startswith(str(mit_dir))
                assert Path(asset.path).exists()

    def test_asset_inventory_large_tensor_metadata(self, tmp_path: Path):
        """Test asset inventory with models containing many tensors."""
        # Create SafeTensors file with many tensors (like a real transformer)
        large_model = tmp_path / "large_transformer.safetensors"

        # Simulate a transformer model structure
        tensors = {}
        for layer in range(12):  # 12 transformer layers
            tensors[f"transformer.layer.{layer}.attention.self.query.weight"] = np.random.randn(768, 768).astype(
                np.float32
            )
            tensors[f"transformer.layer.{layer}.attention.self.key.weight"] = np.random.randn(768, 768).astype(
                np.float32
            )
            tensors[f"transformer.layer.{layer}.attention.self.value.weight"] = np.random.randn(768, 768).astype(
                np.float32
            )
            tensors[f"transformer.layer.{layer}.attention.output.dense.weight"] = np.random.randn(768, 768).astype(
                np.float32
            )
            tensors[f"transformer.layer.{layer}.intermediate.dense.weight"] = np.random.randn(3072, 768).astype(
                np.float32
            )
            tensors[f"transformer.layer.{layer}.output.dense.weight"] = np.random.randn(
                768,
                3072,
            ).astype(np.float32)

        save_file(tensors, str(large_model))

        results = scan_model_directory_or_file(str(large_model))

        assets = results.assets
        assert len(assets) == 1

        asset = assets[0]
        assert asset.type == "safetensors"
        assert hasattr(asset, "tensors") and asset.tensors is not None

        # Should capture all tensor names
        tensor_names = asset.tensors
        assert len(tensor_names) == 12 * 6  # 12 layers * 6 tensors per layer

        # Verify some expected tensor names are present
        assert "transformer.layer.0.attention.self.query.weight" in tensor_names
        assert "transformer.layer.11.output.dense.weight" in tensor_names

    def test_asset_inventory_cli_output_formatting(self, tmp_path: Path):
        """Test that CLI output formatting is readable and well-structured."""
        # Create a model with various asset types
        model_dir = tmp_path / "formatting_test"
        model_dir.mkdir()

        # SafeTensors with tensors
        st_file = model_dir / "model.safetensors"
        st_data = {"emb": np.array([1, 2]).astype(np.float32)}
        save_file(st_data, str(st_file))

        # JSON with keys
        json_file = model_dir / "config.json"
        json_file.write_text('{"arch": "transformer", "layers": 12}')

        # ZIP with contents
        zip_file = model_dir / "extras.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("note.txt", "test")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(model_dir)])

        # Note: SCANNED FILES section was removed to reduce output verbosity
        # Verify that the overall output structure is still well-formatted
        assert "SCAN SUMMARY" in result.output
        assert "Files:" in result.output
        assert "SECURITY FINDINGS" in result.output

        # The asset inventory is still captured but not displayed in text format
        # Users can use --format json to see detailed asset information

    def test_asset_inventory_performance_large_directory(self, tmp_path: Path):
        """Test asset inventory performance with many files."""
        # Create directory with many small files
        large_dir = tmp_path / "large_dir"
        large_dir.mkdir()

        # Create 50 small JSON files
        for i in range(50):
            json_file = large_dir / f"config_{i:03d}.json"
            json_file.write_text(f'{{"id": {i}, "name": "model_{i}"}}')

        results = scan_model_directory_or_file(str(large_dir))

        # Should complete successfully
        assert results.success is True
        assert results.files_scanned == 50

        # Should have 50 assets
        assert len(results.assets) == 50

        # Each asset should have correct metadata
        for _i, asset in enumerate(results.assets):
            assert asset.type == "manifest"
            assert hasattr(asset, "keys") and asset.keys is not None
            assert "id" in asset.keys
            assert "name" in asset.keys

        # Scan should complete in reasonable time (this test verifies no major performance regression)
        assert results.duration < 30.0  # Should take less than 30 seconds
