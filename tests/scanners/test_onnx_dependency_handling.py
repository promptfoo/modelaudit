"""Regression tests for ONNX scanner dependency handling."""

from unittest.mock import patch

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.onnx_scanner import OnnxScanner


def test_onnx_file_routes_to_onnx_scanner_when_dependency_check_fails(tmp_path):
    """ONNX files should still route to OnnxScanner for explicit missing-dep reporting."""
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"not-a-real-onnx-model")

    with patch("modelaudit.scanners.onnx_scanner._check_onnx", return_value=False):
        scanner = get_scanner_for_file(str(model_path))

    assert scanner is not None
    assert isinstance(scanner, OnnxScanner)
    assert scanner.name == "onnx"


def test_onnx_scanner_reports_missing_dependency_as_warning(tmp_path):
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
