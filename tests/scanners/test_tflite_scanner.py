import importlib.util
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners import _registry
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.tflite_scanner import _MAX_COUNT, TFLiteScanner
from modelaudit.utils.file.detection import detect_file_format

HAS_TFLITE = importlib.util.find_spec("tflite") is not None


def _single_file_metadata(aggregate: Any) -> Any:
    return next(iter(aggregate.file_metadata.values()))


def _assert_tflite_inconclusive_exit2(aggregate: Any, reason: str) -> None:
    metadata = _single_file_metadata(aggregate)
    assert aggregate.success is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert metadata.get("analysis_incomplete") is True
    assert reason in metadata.get("scan_outcome_reasons", [])
    assert core.determine_exit_code(aggregate) == 2
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)


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
    path = tmp_path / "model.jpg"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    assert TFLiteScanner.can_handle(str(path)) is True


def test_tflite_scanner_registry_routes_renamed_model_by_magic_bytes(tmp_path: Path) -> None:
    """Registry fallback should still route renamed TFLite binaries by magic bytes."""
    path = tmp_path / "model.jpg"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    assert _registry.get_scanner_for_path(str(path)) is TFLiteScanner


def test_core_scan_file_preserves_tflite_bin_analysis_with_pytorch_binary_primary(tmp_path: Path) -> None:
    """`.bin` retains raw analysis while a strict TFLite signature is still analyzed."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", False):
        result = core.scan_file(str(path), config={"cache_scan_results": False})

    assert TFLiteScanner.can_handle(str(path)) is False
    assert detect_file_format(str(path)) == "pytorch_binary"
    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["tflite"]
    assert "tflite_dependency_unavailable" in result.metadata["scan_outcome_reasons"]
    assert result.success is False


def test_renamed_tflite_with_skipped_suffix_routes_through_directory_scan(tmp_path: Path) -> None:
    path = tmp_path / "model.jpg"
    path.write_bytes(b"\x0c\x00\x00\x00TFL3" + b"\x00" * 100)

    assert TFLiteScanner.can_handle(str(path))
    assert detect_file_format(str(path)) == "tflite"
    assert core.scan_file(str(path)).scanner_name == "tflite"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 1
    assert "tflite" in directory.scanner_names


def test_extensionless_tflite_routes_through_directory_scan(tmp_path: Path) -> None:
    path = tmp_path / "model"
    path.write_bytes(b"\x0c\x00\x00\x00TFL3" + b"\x00" * 100)

    assert TFLiteScanner.can_handle(str(path))
    assert detect_file_format(str(path)) == "tflite"
    assert core.scan_file(str(path)).scanner_name == "tflite"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 1
    assert "tflite" in directory.scanner_names


def test_renamed_tflite_near_match_with_skipped_suffix_remains_skipped(tmp_path: Path) -> None:
    path = tmp_path / "notes.jpg"
    path.write_bytes(b"\x0c\x00\x00\x00XTFL3" + b"\x00" * 100)

    assert not TFLiteScanner.can_handle(str(path))
    assert detect_file_format(str(path)) == "unknown"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 0


@pytest.mark.parametrize(
    ("payload", "expected_format"),
    [
        (b"PK\x03\x04TFL3" + b"\x00" * 32, "zip"),
        (b"\x1f\x8b\x08\x00TFL3" + b"\x00" * 32, "gzip"),
        (b"((S'TFL3'\ntt.", "pickle"),
        (b"RKNNTFL3" + b"\x00" * 32, "rknn"),
        (b"T7\x00\x00TFL3" + b"\x00" * 32, "torch7"),
    ],
)
def test_tflite_identifier_does_not_override_stronger_content_routes(
    tmp_path: Path,
    payload: bytes,
    expected_format: str,
) -> None:
    path = tmp_path / "payload.jpg"
    path.write_bytes(payload)

    assert detect_file_format(str(path)) == expected_format


@pytest.mark.parametrize("suffix", [".dnn", ".rknn", ".t7", ".th", ".exe", ".llamafile"])
def test_tflite_identifier_does_not_override_owned_format_extensions(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"payload{suffix}"
    path.write_bytes(b"MZ\x00\x00TFL3llamafile runtime\n" if suffix in {".exe", ".llamafile"} else b"T7\x00\x00TFL3")

    assert detect_file_format(str(path)) != "tflite"


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


def test_tflite_missing_dependency_is_inconclusive_without_security_finding(tmp_path: Path) -> None:
    """Missing optional parsing support must be incomplete coverage, not a finding."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", False):
        result = TFLiteScanner().scan(str(path))
        aggregate = core.scan_model_directory_or_file(str(path), recursive=False, cache_scan_results=False)

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["tflite_dependency_unavailable"]
    assert result.metadata["operational_error_reason"] == "tflite_dependency_unavailable"
    assert any(
        issue.severity == IssueSeverity.INFO and "tflite package not installed" in issue.message
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    _assert_tflite_inconclusive_exit2(aggregate, "tflite_dependency_unavailable")


def test_tflite_missing_dependency_result_is_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", False):
            first = core.scan_model_directory_or_file(
                str(path),
                recursive=False,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = core.scan_model_directory_or_file(
                str(path),
                recursive=False,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

        _assert_tflite_inconclusive_exit2(first, "tflite_dependency_unavailable")
        _assert_tflite_inconclusive_exit2(second, "tflite_dependency_unavailable")
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    "read_exception",
    [
        OSError("simulated read failure"),
        ValueError("File read exceeds limit: 128 bytes (max: 64)"),
    ],
)
def test_tflite_read_failure_is_inconclusive_without_security_finding(
    tmp_path: Path,
    read_exception: Exception,
) -> None:
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * 100)

    with (
        patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True),
        patch("modelaudit.scanners.tflite_scanner._memory_map", side_effect=read_exception),
    ):
        result = TFLiteScanner().scan(str(path))
        aggregate = core.scan_model_directory_or_file(str(path), recursive=False, cache_scan_results=False)

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome_reasons"] == ["tflite_read_failed"]
    assert result.metadata["operational_error_reason"] == "tflite_read_failed"
    assert any(
        issue.severity == IssueSeverity.INFO and issue.message.startswith("Unable to read TFLite file for analysis")
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    _assert_tflite_inconclusive_exit2(aggregate, "tflite_read_failed")


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
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "tflite_magic_validation_failed" in result.metadata["scan_outcome_reasons"]
    # Scanner checks magic bytes first, so invalid data will fail the magic check
    assert any(
        "TFLite magic bytes" in issue.message or "Invalid TFLite file" in issue.message for issue in result.issues
    )


def test_tflite_invalid_magic_returns_inconclusive_exit2(tmp_path: Path) -> None:
    path = tmp_path / "model.tflite"
    path.write_bytes(b"invalid tflite data")

    with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True):
        direct = TFLiteScanner().scan(str(path))
        aggregate = core.scan_model_directory_or_file(str(path), recursive=False)

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "tflite_magic_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any("TFLite magic bytes" in issue.message for issue in direct.issues)
    _assert_tflite_inconclusive_exit2(aggregate, "tflite_magic_validation_failed")


def test_tflite_invalid_magic_uncached_rerun_preserves_exit2(tmp_path: Path) -> None:
    path = tmp_path / "model.tflite"
    path.write_bytes(b"invalid tflite data")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True):
            first = core.scan_model_directory_or_file(
                str(path),
                recursive=False,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            second = core.scan_model_directory_or_file(
                str(path),
                recursive=False,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

        _assert_tflite_inconclusive_exit2(first, "tflite_magic_validation_failed")
        _assert_tflite_inconclusive_exit2(second, "tflite_magic_validation_failed")
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


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
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "tflite_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
        assert any(
            issue.message and "Invalid TFLite model structure or traversal error" in issue.message
            for issue in result.issues
        )
        aggregate = core.scan_model_directory_or_file(str(path), recursive=False)
        _assert_tflite_inconclusive_exit2(aggregate, "tflite_structure_validation_failed")


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


def test_tflite_mmap_caps_at_validated_size(tmp_path: Path) -> None:
    """TOCTOU guard: if the file grew after the size check, only the validated
    prefix is mapped — not the file's larger current size."""
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x00\x00\x00TFL3" + b"\x00" * (1024 * 1024))  # ~1 MB on disk

    validated_size = 512  # size the limit check "saw" before the file grew

    with (
        patch("modelaudit.scanners.tflite_scanner.HAS_TFLITE", True),
        patch.object(TFLiteScanner, "get_file_size", return_value=validated_size),
    ):
        scanner = TFLiteScanner()
        scanner.max_file_read_size = 4096  # validated_size passes the limit
        result = scanner.scan(str(path))

    # Mapped only the validated size, not the 1 MB now on disk.
    assert result.bytes_scanned == validated_size
