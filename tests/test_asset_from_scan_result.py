"""Tests for asset_from_scan_result function and tensor metadata handling."""

from modelaudit.scanners.base import ScanResult
from modelaudit.utils.helpers.assets import asset_from_scan_result


class TestAssetFromScanResult:
    """Test asset creation from scan results with various tensor metadata formats."""

    def test_tensor_dict_conversion(self):
        """Test that tensor dictionaries are converted to string names for AssetModel compatibility."""
        result = ScanResult(scanner_name="gguf")
        result.metadata = {
            "file_size": 1024,
            "tensors": [
                {"name": "weight", "type": 0, "dims": [4, 4]},
                {"name": "bias", "type": 1, "dims": [4]},
                {"name": "layer.0.weight", "type": 2, "dims": [8, 4]},
            ],
        }

        asset = asset_from_scan_result("/test/model.gguf", result)

        assert asset["path"] == "/test/model.gguf"
        assert asset["type"] == "gguf"
        assert asset["size"] == 1024
        assert asset["tensors"] == ["weight", "bias", "layer.0.weight"]

    def test_tensor_string_list_passthrough(self):
        """Test that existing string lists pass through unchanged (SafeTensors format)."""
        result = ScanResult(scanner_name="safetensors")
        result.metadata = {
            "file_size": 2048,
            "tensors": ["embedding.weight", "linear.weight", "linear.bias"],
        }

        asset = asset_from_scan_result("/test/model.safetensors", result)

        assert asset["path"] == "/test/model.safetensors"
        assert asset["type"] == "safetensors"
        assert asset["size"] == 2048
        assert asset["tensors"] == ["embedding.weight", "linear.weight", "linear.bias"]

    def test_empty_tensor_list(self):
        """Test handling of empty tensor lists."""
        result = ScanResult(scanner_name="test")
        result.metadata = {"file_size": 512, "tensors": []}

        asset = asset_from_scan_result("/test/empty.bin", result)

        assert asset["tensors"] == []

    def test_none_tensors(self):
        """Test handling when tensors is None."""
        result = ScanResult(scanner_name="test")
        result.metadata = {"file_size": 256, "tensors": None}

        asset = asset_from_scan_result("/test/none.bin", result)

        assert asset["tensors"] is None

    def test_missing_tensors_metadata(self):
        """Test when tensors metadata is not present."""
        result = ScanResult(scanner_name="test")
        result.metadata = {"file_size": 128}

        asset = asset_from_scan_result("/test/no_tensors.bin", result)

        assert "tensors" not in asset

    def test_malformed_tensor_dicts(self):
        """Test handling of tensor dictionaries without 'name' key."""
        result = ScanResult(scanner_name="test")
        result.metadata = {
            "file_size": 1024,
            "tensors": [
                {"name": "valid_tensor", "type": 0},
                {"type": 1, "dims": [4]},  # Missing 'name' key
                {"name": "another_valid", "type": 2},
            ],
        }

        asset = asset_from_scan_result("/test/malformed.bin", result)

        # Should fall back to preserving original list since not all items have 'name'
        assert asset["tensors"] == [
            {"name": "valid_tensor", "type": 0},
            {"type": 1, "dims": [4]},
            {"name": "another_valid", "type": 2},
        ]

    def test_mixed_tensor_formats(self):
        """Test handling of mixed string/dict tensors (edge case)."""
        result = ScanResult(scanner_name="test")
        result.metadata = {
            "file_size": 1024,
            "tensors": [
                "string_tensor",
                {"name": "dict_tensor", "type": 0},
            ],
        }

        asset = asset_from_scan_result("/test/mixed.bin", result)

        # Should preserve original format since not all items are dictionaries with 'name'
        assert asset["tensors"] == [
            "string_tensor",
            {"name": "dict_tensor", "type": 0},
        ]

    def test_keys_metadata_passthrough(self):
        """Test that keys metadata passes through unchanged (JSON manifests)."""
        result = ScanResult(scanner_name="manifest")
        result.metadata = {
            "file_size": 512,
            "keys": ["model_type", "architectures", "vocab_size"],
        }

        asset = asset_from_scan_result("/test/config.json", result)

        assert asset["keys"] == ["model_type", "architectures", "vocab_size"]

    def test_contents_metadata_passthrough(self):
        """Test that contents metadata passes through unchanged (ZIP files)."""
        result = ScanResult(scanner_name="zip")
        result.metadata = {
            "file_size": 4096,
            "contents": [
                {"path": "model.bin", "size": 2048},
                {"path": "config.json", "size": 256},
            ],
        }

        asset = asset_from_scan_result("/test/model.zip", result)

        assert asset["contents"] == [
            {"path": "model.bin", "size": 2048},
            {"path": "config.json", "size": 256},
        ]

    def test_comprehensive_metadata(self):
        """Test with all metadata fields present."""
        result = ScanResult(scanner_name="comprehensive")
        result.metadata = {
            "file_size": 8192,
            "tensors": [
                {"name": "encoder.weight", "type": 0, "dims": [768, 512]},
                {"name": "decoder.bias", "type": 1, "dims": [768]},
            ],
            "keys": ["encoder", "decoder", "config"],
            "contents": [{"path": "weights.bin", "size": 7680}],
        }

        asset = asset_from_scan_result("/test/comprehensive.bin", result)

        assert asset["path"] == "/test/comprehensive.bin"
        assert asset["type"] == "comprehensive"
        assert asset["size"] == 8192
        assert asset["tensors"] == ["encoder.weight", "decoder.bias"]
        assert asset["keys"] == ["encoder", "decoder", "config"]
        assert asset["contents"] == [{"path": "weights.bin", "size": 7680}]

    def test_gguf_real_world_example(self):
        """Test with real GGUF tensor metadata format."""
        result = ScanResult(scanner_name="gguf")
        result.metadata = {
            "format": "gguf",
            "version": 3,
            "n_tensors": 2,
            "n_kv": 2,
            "file_size": 1024,
            "tensors": [
                {"name": "token_embd.weight", "type": 0, "dims": [4096, 32000]},
                {"name": "output.weight", "type": 0, "dims": [32000, 4096]},
            ],
        }

        asset = asset_from_scan_result("/models/llama.gguf", result)

        assert asset["path"] == "/models/llama.gguf"
        assert asset["type"] == "gguf"
        assert asset["size"] == 1024
        assert asset["tensors"] == ["token_embd.weight", "output.weight"]
        # Other metadata should not be in asset (only path, type, size, tensors, keys, contents)
        assert "format" not in asset
        assert "version" not in asset
        assert "n_tensors" not in asset
