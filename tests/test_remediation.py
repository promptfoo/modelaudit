"""Tests for model remediation and conversion functionality."""

import pickle
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.remediation import get_converter
from modelaudit.remediation.converters.pickle_to_safetensors import (
    PickleToSafeTensorsConverter,
    RestrictedUnpickler,
)


class TestBaseConverter:
    """Test the BaseConverter abstract class."""

    def test_backup_creation(self, tmp_path):
        """Test backup file creation."""
        # Create a test file
        test_file = tmp_path / "test.pkl"
        test_file.write_text("test content")

        # Create a concrete converter for testing
        converter = PickleToSafeTensorsConverter()

        # Test backup creation
        backup_path = converter._create_backup(test_file)
        assert backup_path is not None
        assert backup_path.exists()
        assert backup_path.suffix == ".backup"
        assert backup_path.read_text() == "test content"

        # Test backup with existing backup
        backup_path2 = converter._create_backup(test_file)
        assert backup_path2 != backup_path
        assert backup_path2.exists()

    def test_size_reduction_calculation(self, tmp_path):
        """Test size reduction calculation."""
        # Create test files
        source = tmp_path / "source.pkl"
        source.write_bytes(b"x" * 1000)

        target = tmp_path / "target.st"
        target.write_bytes(b"x" * 700)

        converter = PickleToSafeTensorsConverter()
        reduction = converter._calculate_size_reduction(source, target)

        assert reduction == 30.0  # 30% reduction


class TestRestrictedUnpickler:
    """Test the RestrictedUnpickler security features."""

    def test_safe_imports_allowed(self):
        """Test that safe imports are allowed."""
        data = {
            "weight": [1.0, 2.0, 3.0],
            "config": {"layers": 3},
        }

        # Pickle the data
        pickled = pickle.dumps(data)

        # Unpickle with RestrictedUnpickler
        import io

        unpickler = RestrictedUnpickler(io.BytesIO(pickled))
        result = unpickler.load()

        assert result == data

    def test_dangerous_imports_blocked(self):
        """Test that dangerous imports are blocked."""
        # Create a dangerous pickle that tries to import os
        dangerous_data = """cos
system
(S'echo pwned'
tR."""

        import io

        unpickler = RestrictedUnpickler(io.BytesIO(dangerous_data.encode("latin1")))

        with pytest.raises(pickle.UnpicklingError, match="Blocked unsafe import"):
            unpickler.load()

    @pytest.mark.skipif("torch" not in dir(), reason="torch not available")
    def test_torch_tensors_allowed(self):
        """Test that torch tensors can be loaded."""
        import torch

        # Create a simple state dict
        state_dict = {
            "weight": torch.tensor([1.0, 2.0, 3.0]),
            "bias": torch.tensor([0.1, 0.2]),
        }

        # Pickle it
        pickled = pickle.dumps(state_dict)

        # Unpickle with RestrictedUnpickler
        import io

        unpickler = RestrictedUnpickler(io.BytesIO(pickled))
        result = unpickler.load()

        assert "weight" in result
        assert "bias" in result


class TestPickleToSafeTensorsConverter:
    """Test the Pickle to SafeTensors converter."""

    def test_can_convert(self, tmp_path):
        """Test format detection."""
        converter = PickleToSafeTensorsConverter()

        # Test supported formats
        assert converter.can_convert(Path("model.pkl"), "safetensors")
        assert converter.can_convert(Path("model.pt"), "safetensors")
        assert converter.can_convert(Path("model.pth"), "safetensors")
        assert converter.can_convert(Path("model.ckpt"), "safetensors")
        assert converter.can_convert(Path("model.bin"), "safetensors")

        # Test unsupported formats
        assert not converter.can_convert(Path("model.pkl"), "onnx")
        assert not converter.can_convert(Path("model.h5"), "safetensors")
        assert not converter.can_convert(Path("model.onnx"), "safetensors")

    def test_supported_conversions(self):
        """Test get_supported_conversions."""
        converter = PickleToSafeTensorsConverter()
        conversions = converter.get_supported_conversions()

        assert "pkl" in conversions
        assert "safetensors" in conversions["pkl"]
        assert "pt" in conversions
        assert "pth" in conversions

    @pytest.mark.skipif("safetensors" not in dir(), reason="safetensors not available")
    @pytest.mark.skipif("torch" not in dir(), reason="torch not available")
    def test_convert_simple_state_dict(self, tmp_path):
        """Test converting a simple PyTorch state dict."""
        import torch

        # Create a simple state dict
        state_dict = {
            "layer1.weight": torch.randn(10, 5),
            "layer1.bias": torch.randn(10),
            "layer2.weight": torch.randn(3, 10),
            "layer2.bias": torch.randn(3),
        }

        # Save as pickle
        source_path = tmp_path / "model.pkl"
        torch.save(state_dict, source_path)

        # Convert
        converter = PickleToSafeTensorsConverter()
        output_path = tmp_path / "model.safetensors"

        result = converter.convert(
            source_path,
            output_path,
            validate=True,
            backup=False,
        )

        assert result.success
        assert output_path.exists()
        assert result.validation_passed
        assert result.numerical_accuracy is not None
        assert result.numerical_accuracy < 1e-6
        assert result.security_issues_removed > 0

    def test_convert_without_safetensors(self, tmp_path):
        """Test error when safetensors is not available."""
        # Create a dummy pickle file
        source_path = tmp_path / "model.pkl"
        with open(source_path, "wb") as f:
            pickle.dump({"weight": [1, 2, 3]}, f)

        converter = PickleToSafeTensorsConverter()
        output_path = tmp_path / "model.safetensors"

        # Mock the import to fail
        with patch.dict("sys.modules", {"safetensors": None}):
            result = converter.convert(source_path, output_path)

        assert not result.success
        assert "safetensors package not installed" in result.error_message

    def test_extract_state_dict_variants(self):
        """Test state dict extraction from various data structures."""
        converter = PickleToSafeTensorsConverter()

        # Mock tensor check
        converter._is_tensor = MagicMock(return_value=True)

        # Test direct state dict (all values are tensors)
        data1 = {"weight": "tensor1", "bias": "tensor2"}
        state_dict, metadata = converter._extract_state_dict(data1)
        assert state_dict == data1
        assert metadata == {}

        # Test nested state dict with mixed content
        # Mock _is_tensor to return False for non-tensor values
        def mock_is_tensor(value):
            return value in ["tensor1", "tensor2"]

        converter._is_tensor = MagicMock(side_effect=mock_is_tensor)

        data2 = {
            "state_dict": {"weight": "tensor1"},
            "epoch": 10,
            "metadata": {"lr": 0.01},
        }
        state_dict, metadata = converter._extract_state_dict(data2)
        assert state_dict == {"weight": "tensor1"}
        assert "epoch" in metadata
        assert "metadata" in metadata

        # Test module with state_dict method
        mock_module = MagicMock()
        mock_module.state_dict.return_value = {"weight": "tensor1"}
        state_dict, metadata = converter._extract_state_dict(mock_module)
        assert state_dict == {"weight": "tensor1"}


class TestConverterRegistry:
    """Test the converter registry functionality."""

    def test_get_converter(self, tmp_path):
        """Test getting appropriate converter."""
        # Test getting converter for pickle -> safetensors
        pkl_file = tmp_path / "model.pkl"
        pkl_file.touch()

        converter = get_converter(pkl_file, "safetensors")
        assert converter is not None
        assert isinstance(converter, PickleToSafeTensorsConverter)

        # Test no converter available
        converter = get_converter(pkl_file, "unknown_format")
        assert converter is None

        # Test unsupported source format
        h5_file = tmp_path / "model.h5"
        h5_file.touch()
        converter = get_converter(h5_file, "safetensors")
        assert converter is None
