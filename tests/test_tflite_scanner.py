import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tflite_scanner import TFLiteScanner

pytest.importorskip("tflite")


def test_tflite_scanner_can_handle(tmp_path):
    path = tmp_path / "model.tflite"
    path.write_bytes(b"\x00\x01\x02\x03")
    assert TFLiteScanner.can_handle(str(path)) is True


def test_tflite_scanner_invalid_file(tmp_path):
    path = tmp_path / "model.tflite"
    path.write_bytes(b"not a valid flatbuffer")
    scanner = TFLiteScanner()
    result = scanner.scan(str(path))
    assert not result.success
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
