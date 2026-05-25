"""Regression tests for ONNX scanner dependency handling."""

from pathlib import Path
from unittest.mock import patch

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, IssueSeverity
from modelaudit.scanners.onnx_scanner import OnnxScanner
from modelaudit.utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT


def test_onnx_file_routes_to_onnx_scanner_by_extension(tmp_path: Path) -> None:
    """ONNX files should route to OnnxScanner regardless of optional deps."""
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"not-a-real-onnx-model")

    scanner = get_scanner_for_file(str(model_path))

    assert scanner is not None
    assert isinstance(scanner, OnnxScanner)
    assert scanner.name == "onnx"


def test_onnx_scanner_reports_missing_dependency_as_warning(tmp_path: Path) -> None:
    """When ONNX runtime dependencies are missing, scan must not report clean."""
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"not-a-real-onnx-model")

    scanner = OnnxScanner()
    with (
        patch("modelaudit.scanners.onnx_scanner.HAS_ONNX", None),
        patch(
            "modelaudit.scanners.onnx_scanner._check_onnx",
            return_value=False,
        ),
    ):
        result = scanner.scan(str(model_path))

    assert not result.success
    assert any(
        issue.severity == IssueSeverity.WARNING and "onnx package not installed" in issue.message.lower()
        for issue in result.issues
    )


def test_tentative_protobuf_candidate_without_onnx_dependency_is_inconclusive(tmp_path: Path) -> None:
    """Optional ONNX support must not turn an unanalyzed candidate into a clean scan."""
    candidate_path = tmp_path / "candidate.jpg"
    candidate_path.write_bytes(b"\x42\x00" * 4097)

    scanner = OnnxScanner(config={FORMAT_VALIDATION_CONFIG_KEY: {"routed_format": PROTOBUF_MODEL_CANDIDATE_FORMAT}})
    with patch("modelaudit.scanners.onnx_scanner._check_onnx", return_value=False):
        result = scanner.scan(str(candidate_path))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "onnx_tentative_candidate_analysis_unavailable" in result.metadata["scan_outcome_reasons"]
    assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)
    assert result.metadata["tentative_protobuf_candidate_unanalyzed"] == "onnx_dependency_unavailable"
