"""Regression tests for ONNX scanner dependency handling."""

from pathlib import Path
from unittest.mock import patch

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, CheckStatus, IssueSeverity
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


def test_onnx_scanner_missing_dependency_is_operational_capability_outcome(tmp_path: Path) -> None:
    """When ONNX dependencies are missing, report incomplete capability without a security finding."""
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

    assert result.success is False
    assert result.bytes_scanned == model_path.stat().st_size
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "onnx_dependency_unavailable"
    assert result.metadata["missing_dependency"] == "onnx"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    check = next(check for check in result.checks if check.name == "ONNX Capability Check")
    assert check.status == CheckStatus.FAILED
    assert check.severity == IssueSeverity.INFO
    assert check.details["required_package"] == "onnx"


def test_tentative_protobuf_candidate_without_onnx_dependency_is_inconclusive(tmp_path: Path) -> None:
    """Optional ONNX support must not turn an unanalyzed candidate into a clean scan."""
    candidate_path = tmp_path / "candidate.jpg"
    candidate_path.write_bytes(b"\x42\x00" * 4097)

    scanner = OnnxScanner(config={FORMAT_VALIDATION_CONFIG_KEY: {"routed_format": PROTOBUF_MODEL_CANDIDATE_FORMAT}})
    with patch("modelaudit.scanners.onnx_scanner._check_onnx", return_value=False):
        result = scanner.scan(str(candidate_path))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.bytes_scanned == candidate_path.stat().st_size
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "onnx_tentative_candidate_analysis_unavailable" in result.metadata["scan_outcome_reasons"]
    assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)
    assert result.metadata["tentative_protobuf_candidate_unanalyzed"] == "onnx_dependency_unavailable"
