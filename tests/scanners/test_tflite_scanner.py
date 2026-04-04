import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit import core
from modelaudit.scanners import _registry
from modelaudit.scanners.tflite_scanner import _MAX_COUNT, TFLiteScanner

# Try to import tflite to check availability
try:
    import tflite  # noqa: F401

    HAS_TFLITE = True
except ImportError:
    HAS_TFLITE = False


def test_tflite_scanner_can_handle(tmp_path: Path) -> None:
    """Test the can_handle method recognizes .tflite files regardless of tflite package."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"some content")

    # can_handle should return True for .tflite files even without the
    # tflite package installed (basic validation still works)
    assert TFLiteScanner.can_handle(str(path)) is True


def test_tflite_scanner_can_handle_missing_path() -> None:
    """Regression: can_handle returns False for non-existent .tflite paths."""
    assert TFLiteScanner.can_handle("/nonexistent/path/model.tflite") is False


def test_tflite_scanner_cannot_handle_wrong_extension(tmp_path: Path) -> None:
    """Test the can_handle method with wrong file extension."""
    path = tmp_path / "model.pb"
    path.write_bytes(b"some content")
    assert TFLiteScanner.can_handle(str(path)) is False


def test_tflite_scanner_can_handle_renamed_model_by_magic_bytes(tmp_path: Path) -> None:
    """Valid TFLite content should still route when the extension is changed."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    assert TFLiteScanner.can_handle(str(path)) is True


def test_tflite_scanner_registry_routes_renamed_model_by_magic_bytes(tmp_path: Path) -> None:
    """Registry extension prefiltering should still route renamed TFLite binaries by magic bytes."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    assert _registry.get_scanner_for_path(str(path)) is TFLiteScanner


def test_core_scan_file_routes_renamed_tflite_bin_to_tflite_scanner(tmp_path: Path) -> None:
    """End-to-end routing should prefer TFLite over PyTorch binary when `.bin` magic bytes are `TFL3`."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    result = core.scan_file(str(path))

    assert result.scanner_name == "tflite"


def test_tflite_scanner_can_handle_magic_near_match_requires_exact_offset(tmp_path: Path) -> None:
    """Near-match signatures in wrong offsets should not route non-TFLite files."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"\x00\x00\x00\x00XTFL3" + b"\x00" * 100)

    assert TFLiteScanner.can_handle(str(path)) is False


def test_tflite_scanner_file_not_found() -> None:
    """Test scanning non-existent file."""
    scanner = TFLiteScanner()
    result = scanner.scan("non_existent_file.tflite")
    assert not result.success
    assert "Path does not exist" in result.issues[0].message


def test_tflite_scanner_no_tflite_installed(tmp_path: Path) -> None:
    """Test scanner behavior when tflite package is not installed."""
    path = tmp_path / "model.tflite"
    path.touch()

    with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", False):
        scanner = TFLiteScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert "tflite package not installed" in result.issues[0].message


def test_tflite_scanner_respects_configured_file_size_limit(tmp_path: Path) -> None:
    """Regression: scan should enforce BaseScanner file-size limits before reading model bytes."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    result = TFLiteScanner(config={"max_file_read_size": 8}).scan(str(path))

    assert result.success is False
    assert any(check.name == "File Size Limit" for check in result.checks)


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_parsing_error(tmp_path: Path) -> None:
    """Test scanner behavior with invalid tflite data."""
    path = tmp_path / "model.tflite"
    # Scanner now checks for magic bytes first, so invalid data triggers that check
    path.write_bytes(b"invalid tflite data")

    scanner = TFLiteScanner()
    result = scanner.scan(str(path))
    assert not result.success
    # Scanner checks magic bytes first, so invalid data will fail the magic check
    assert any(
        "TFLite magic bytes" in issue.message or "Invalid TFLite file" in issue.message for issue in result.issues
    )


@pytest.mark.skipif(not HAS_TFLITE, reason="tflite not installed")
def test_tflite_scanner_custom_operator(tmp_path: Path) -> None:
    """Test scanner behavior with custom operators."""
    path = tmp_path / "model.tflite"
    # Create data with valid TFLite magic bytes ("TFL3" at offset 4)
    # Bytes 0-3: FlatBuffer root table offset (4 bytes)
    # Bytes 4-7: "TFL3" file identifier
    valid_header = b"\x00\x00\x00\x00TFL3" + b"\x00" * 100
    path.write_bytes(valid_header)

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
def test_tflite_scanner_safe_model(tmp_path: Path) -> None:
    """Test scanner behavior with safe model."""
    path = tmp_path / "model.tflite"
    # Create data with valid TFLite magic bytes ("TFL3" at offset 4)
    # Bytes 0-3: FlatBuffer root table offset (4 bytes)
    # Bytes 4-7: "TFL3" file identifier
    valid_header = b"\x00\x00\x00\x00TFL3" + b"\x00" * 100
    path.write_bytes(valid_header)

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


def test_tflite_scanner_metadata_collection(tmp_path: Path) -> None:
    """Test that scanner collects appropriate metadata."""
    path = tmp_path / "model.tflite"
    # Create data with valid TFLite magic bytes ("TFL3" at offset 4)
    valid_header = b"\x00\x00\x00\x00TFL3" + b"\x00" * 100
    path.write_bytes(valid_header)

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


def test_tflite_scanner_excessive_subgraph_count_stops_scan(tmp_path: Path) -> None:
    """Regression: scanner stops before iterating an excessive subgraph count."""
    path = tmp_path / "model.tflite"
    valid_header = b"\x00\x00\x00\x00TFL3" + b"\x00" * 100
    path.write_bytes(valid_header)

    with (
        patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True),
        patch("modelaudit.scanners.tflite_scanner.tflite", create=True) as mock_tflite,
        patch.dict(sys.modules, {"tflite": mock_tflite}),
    ):
        mock_model = MagicMock()
        mock_model.SubgraphsLength.return_value = _MAX_COUNT + 1
        mock_model.Subgraphs.side_effect = RuntimeError("should not iterate subgraphs")
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        result = scanner.scan(str(path))

        assert not result.success
        assert any(check.name == "Subgraph Count Validation" for check in result.checks)
        mock_model.Subgraphs.assert_not_called()


def test_tflite_scanner_model_structure_parse_errors_do_not_escape(tmp_path: Path) -> None:
    """Malformed FlatBuffer traversal errors should be converted into a scan result."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    with (
        patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True),
        patch("modelaudit.scanners.tflite_scanner.tflite", create=True) as mock_tflite,
        patch.dict(sys.modules, {"tflite": mock_tflite}),
    ):
        mock_model = MagicMock()
        mock_model.SubgraphsLength.side_effect = ValueError("boom")
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        result = TFLiteScanner().scan(str(path))

        assert result.success is False
        assert any(
            issue.message and "Invalid TFLite model structure or traversal error" in issue.message
            for issue in result.issues
        )


def test_tflite_metadata_extraction_excessive_subgraph_count_stops_early(tmp_path: Path) -> None:
    """Regression: metadata extraction refuses excessive subgraph counts without dereferencing them."""
    path = tmp_path / "model.tflite"
    valid_header = b"\x00\x00\x00\x00TFL3" + b"\x00" * 100
    path.write_bytes(valid_header)

    with (
        patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True),
        patch("modelaudit.scanners.tflite_scanner.tflite", create=True) as mock_tflite,
        patch.dict(sys.modules, {"tflite": mock_tflite}),
    ):
        mock_model = MagicMock()
        mock_model.Version.return_value = 3
        mock_model.Description.return_value = None
        mock_model.OperatorCodesLength.return_value = 0
        mock_model.SubgraphsLength.return_value = _MAX_COUNT + 1
        mock_model.Subgraphs.side_effect = RuntimeError("should not iterate subgraphs")
        mock_tflite.Model.GetRootAsModel.return_value = mock_model

        scanner = TFLiteScanner()
        metadata = scanner.extract_metadata(str(path))

        assert metadata["subgraph_count"] == _MAX_COUNT + 1
        assert "extraction_error" in metadata
        assert "safe limit" in metadata["extraction_error"]
        mock_model.Subgraphs.assert_not_called()
