from unittest.mock import MagicMock, patch

import pytest

from modelaudit.scanners.tflite_scanner import _MAX_COUNT, _MAX_DIM, TFLiteScanner

# Try to import tflite to check availability
try:
    import tflite  # noqa: F401

    HAS_TFLITE = True
except ImportError:
    HAS_TFLITE = False


def test_tflite_scanner_can_handle(tmp_path):
    """Test the can_handle method when tflite is available."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some content")

    if HAS_TFLITE:
        assert TFLiteScanner.can_handle(str(path)) is True
    else:
        assert TFLiteScanner.can_handle(str(path)) is False


def test_tflite_scanner_cannot_handle_wrong_extension(tmp_path):
    """Test the can_handle method with wrong file extension."""
    path = tmp_path / "model.pb"
    path.write_bytes(b"some content")
    assert TFLiteScanner.can_handle(str(path)) is False


def test_tflite_scanner_file_not_found():
    """Test scanning non-existent file."""
    scanner = TFLiteScanner()
    result = scanner.scan("non_existent_file.tflite")
    assert not result.success
    assert "Path does not exist" in result.issues[0].message


def test_tflite_scanner_no_tflite_installed(tmp_path):
    """Test scanner behavior when tflite package is not installed."""
    path = tmp_path / "model.tflite"
    path.touch()

    with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", False):
        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert "tflite package not installed" in result.issues[0].message


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_parsing_error(tmp_path):
    """Test scanner behavior with invalid tflite data."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"invalid tflite data")

    # Mock the tflite module to simulate parsing error
    with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
        mock_tflite.Model.GetRootAsModel.side_effect = Exception("parsing error")
        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert "Invalid TFLite file or parse error" in result.issues[0].message


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_large_subgraph_count(tmp_path):
    """Test scanner behavior with excessive subgraph count."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some tflite data")

    with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
        mock_model = MagicMock()
        mock_model.SubgraphsLength.return_value = _MAX_COUNT + 1

        # Mock subgraphs to avoid iteration issues
        mock_subgraph = MagicMock()
        mock_subgraph.TensorsLength.return_value = 1
        mock_subgraph.OperatorsLength.return_value = 1

        # Mock tensor to avoid dimension checking issues
        mock_tensor = MagicMock()
        mock_tensor.ShapeLength.return_value = 1
        mock_tensor.Shape.return_value = 1
        mock_subgraph.Tensors.return_value = mock_tensor

        # Mock operator to avoid opcode checking issues
        mock_operator = MagicMock()
        mock_operator.OpcodeIndex.return_value = 0
        mock_subgraph.Operators.return_value = mock_operator

        mock_opcode = MagicMock()
        mock_opcode.BuiltinCode.return_value = mock_tflite.BuiltinOperator.ADD
        mock_model.OperatorCodes.return_value = mock_opcode

        mock_model.Subgraphs.return_value = mock_subgraph
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert "exceeds the safe limit" in result.issues[0].message


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_large_tensor_count(tmp_path):
    """Test scanner behavior with excessive tensor count."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some tflite data")

    with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
        mock_model = MagicMock()
        mock_model.SubgraphsLength.return_value = 1
        mock_subgraph = MagicMock()
        mock_subgraph.TensorsLength.return_value = _MAX_COUNT + 1
        mock_subgraph.OperatorsLength.return_value = 1
        mock_model.Subgraphs.return_value = mock_subgraph
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert "extremely large tensor or operator count" in result.issues[0].message


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_large_tensor_dimension(tmp_path):
    """Test scanner behavior with excessive tensor dimensions."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some tflite data")

    with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
        mock_model = MagicMock()
        mock_model.SubgraphsLength.return_value = 1
        mock_subgraph = MagicMock()
        mock_subgraph.TensorsLength.return_value = 1
        mock_subgraph.OperatorsLength.return_value = 1
        mock_tensor = MagicMock()
        mock_tensor.ShapeLength.return_value = 1
        mock_tensor.Shape.return_value = _MAX_DIM + 1
        mock_subgraph.Tensors.return_value = mock_tensor
        mock_model.Subgraphs.return_value = mock_subgraph
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert "Tensor dimension extremely large" in result.issues[0].message


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_custom_operator(tmp_path):
    """Test scanner behavior with custom operators."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some tflite data")

    with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
        mock_model = MagicMock()
        mock_model.SubgraphsLength.return_value = 1
        mock_subgraph = MagicMock()
        mock_subgraph.TensorsLength.return_value = 1
        mock_subgraph.OperatorsLength.return_value = 1
        mock_tensor = MagicMock()
        mock_tensor.ShapeLength.return_value = 1
        mock_tensor.Shape.return_value = 1
        mock_subgraph.Tensors.return_value = mock_tensor
        mock_operator = MagicMock()
        mock_operator.OpcodeIndex.return_value = 0
        mock_subgraph.Operators.return_value = mock_operator
        mock_opcode = MagicMock()
        mock_opcode.BuiltinCode.return_value = mock_tflite.BuiltinOperator.CUSTOM
        mock_opcode.CustomCode.return_value = b"my_custom_op"
        mock_model.OperatorCodes.return_value = mock_opcode
        mock_model.Subgraphs.return_value = mock_subgraph
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert len(result.issues) == 1
        assert "uses custom operator" in result.issues[0].message


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_safe_model(tmp_path):
    """Test scanner behavior with safe model."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some tflite data")

    with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
        mock_model = MagicMock()
        mock_model.SubgraphsLength.return_value = 1
        mock_subgraph = MagicMock()
        mock_subgraph.TensorsLength.return_value = 1
        mock_subgraph.OperatorsLength.return_value = 1
        mock_tensor = MagicMock()
        mock_tensor.ShapeLength.return_value = 1
        mock_tensor.Shape.return_value = 1
        mock_subgraph.Tensors.return_value = mock_tensor
        mock_operator = MagicMock()
        mock_operator.OpcodeIndex.return_value = 0
        mock_subgraph.Operators.return_value = mock_operator
        mock_opcode = MagicMock()
        mock_opcode.BuiltinCode.return_value = mock_tflite.BuiltinOperator.ADD
        mock_model.OperatorCodes.return_value = mock_opcode
        mock_model.Subgraphs.return_value = mock_subgraph
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert result.success
        assert not result.issues


def test_tflite_scanner_metadata_collection(tmp_path):
    """Test that scanner collects appropriate metadata."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some tflite data")

    if HAS_TFLITE:
        with patch("modelaudit.scanners.tflite_scanner.tflite") as mock_tflite:
            mock_model = MagicMock()
            mock_model.SubgraphsLength.return_value = 2
            mock_subgraph = MagicMock()
            mock_subgraph.TensorsLength.return_value = 3
            mock_subgraph.OperatorsLength.return_value = 4
            mock_tensor = MagicMock()
            mock_tensor.ShapeLength.return_value = 1
            mock_tensor.Shape.return_value = 1
            mock_subgraph.Tensors.return_value = mock_tensor
            mock_operator = MagicMock()
            mock_operator.OpcodeIndex.return_value = 0
            mock_subgraph.Operators.return_value = mock_operator
            mock_opcode = MagicMock()
            mock_opcode.BuiltinCode.return_value = mock_tflite.BuiltinOperator.ADD
            mock_model.OperatorCodes.return_value = mock_opcode
            mock_model.Subgraphs.return_value = mock_subgraph
            mock_tflite.Model.GetRootAsModel.return_value = mock_model

            scanner = TFLiteScanner()
            result = scanner.scan(str(path))

            assert "subgraph_count" in result.metadata
            assert result.metadata["subgraph_count"] == 2
            assert "tensor_counts" in result.metadata
            assert "operator_counts" in result.metadata
            assert "file_size" in result.metadata
    else:
        # When tflite is not available, should still collect basic metadata
        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert "file_size" in result.metadata
