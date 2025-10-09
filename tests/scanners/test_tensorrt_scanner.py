from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tensorrt_scanner import TensorRTScanner


def test_tensorrt_scanner_can_handle(tmp_path):
    path = tmp_path / "model.engine"
    path.write_bytes(b"dummy")
    assert TensorRTScanner.can_handle(str(path))


def test_tensorrt_scanner_cannot_handle_wrong_extension(tmp_path):
    path = tmp_path / "model.txt"
    path.write_bytes(b"dummy")
    assert not TensorRTScanner.can_handle(str(path))


def test_tensorrt_scanner_file_not_found():
    scanner = TensorRTScanner()
    result = scanner.scan("missing.engine")
    assert not result.success
    assert any("does not exist" in i.message.lower() for i in result.issues)


def test_tensorrt_scanner_detects_suspicious_pattern(tmp_path):
    path = tmp_path / "malicious.engine"
    path.write_bytes(b"some python code")
    result = TensorRTScanner().scan(str(path))
    assert not result.success
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_tensorrt_scanner_safe_file(tmp_path):
    path = tmp_path / "safe.engine"
    path.write_bytes(b"binarydata")
    result = TensorRTScanner().scan(str(path))
    assert result.success
    assert not result.issues
