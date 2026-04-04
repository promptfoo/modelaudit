from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tensorrt_scanner import TensorRTScanner
from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension


def test_tensorrt_scanner_can_handle(tmp_path: Path) -> None:
    path = tmp_path / "model.engine"
    path.write_bytes(b"dummy")
    assert TensorRTScanner.can_handle(str(path))


def test_tensorrt_scanner_can_handle_trt_extension(tmp_path: Path) -> None:
    path = tmp_path / "model.trt"
    path.write_bytes(b"dummy")
    assert TensorRTScanner.can_handle(str(path))
    assert detect_file_format(str(path)) == "tensorrt"
    assert detect_format_from_extension(str(path)) == "tensorrt"


def test_tensorrt_scanner_cannot_handle_wrong_extension(tmp_path: Path) -> None:
    path = tmp_path / "model.txt"
    path.write_bytes(b"dummy")
    assert not TensorRTScanner.can_handle(str(path))


def test_tensorrt_scanner_does_not_route_near_match_extensions(tmp_path: Path) -> None:
    for filename in ("model.tr", "model.trtx"):
        path = tmp_path / filename
        path.write_bytes(b"dummy")

        assert not TensorRTScanner.can_handle(str(path))
        assert detect_file_format(str(path)) != "tensorrt"
        assert detect_format_from_extension(str(path)) != "tensorrt"


def test_tensorrt_scanner_file_not_found() -> None:
    scanner = TensorRTScanner()
    result = scanner.scan("missing.engine")
    assert not result.success
    assert any("does not exist" in i.message.lower() for i in result.issues)


def test_tensorrt_scanner_detects_suspicious_pattern(tmp_path: Path) -> None:
    path = tmp_path / "malicious.engine"
    path.write_bytes(b"some python code")
    result = TensorRTScanner().scan(str(path))
    assert not result.success
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_tensorrt_scanner_detects_uppercase_and_shared_library_paths(tmp_path: Path) -> None:
    path = tmp_path / "malicious.plan"
    path.write_bytes(b"LOAD_PLUGIN=/TMP/EVIL/PLUGIN.SO\nPYTHON IMPORT EVAL")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    matched_patterns = {issue.details.get("pattern") for issue in result.issues}
    assert {"/tmp/", ".so", "python", "import", "eval"}.issubset(matched_patterns)


def test_tensorrt_scanner_detects_utf16_python_marker(tmp_path: Path) -> None:
    path = tmp_path / "utf16.engine"
    path.write_bytes("python".encode("utf-16le"))

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(issue.details.get("pattern") == "python" for issue in result.issues)


def test_tensorrt_scanner_detects_utf16be_python_marker(tmp_path: Path) -> None:
    path = tmp_path / "utf16be.engine"
    path.write_bytes("python".encode("utf-16be"))

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(issue.details.get("pattern") == "python" for issue in result.issues)


def test_tensorrt_scanner_avoids_substring_near_match_false_positives(tmp_path: Path) -> None:
    path = tmp_path / "safe.engine"
    path.write_bytes(
        b"execution_metrics evaluation_score important_tensor session.socket "
        b"attempt/tmpology LD_LIBRARY_PATH:/tmpology C:\\tmpology\\payload"
    )

    result = TensorRTScanner().scan(str(path))

    assert result.success is True
    assert result.issues == []


def test_tensorrt_scanner_detects_exec_and_eval_tokens_with_arguments(tmp_path: Path) -> None:
    path = tmp_path / "malicious.engine"
    path.write_bytes(b"execve /bin/sh\nexecvp /bin/sh\nexecvpe /bin/sh\nEVAL payload\n")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    matched_patterns = {issue.details.get("pattern") for issue in result.issues}
    assert {"exec", "eval"}.issubset(matched_patterns)


def test_tensorrt_scanner_detects_tmp_tokens_after_colon_and_windows_drive_prefix(tmp_path: Path) -> None:
    path = tmp_path / "tmp_paths.plan"
    path.write_bytes(b"LD_LIBRARY_PATH:/tmp/evil\nC:\\tmp\\payload\n")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(issue.details.get("pattern") == "/tmp/" for issue in result.issues)


def test_tensorrt_scanner_detects_standalone_three_byte_markers(tmp_path: Path) -> None:
    path = tmp_path / "standalone_markers.engine"
    path.write_bytes(b"\x00../\x00.so\x00")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    matched_patterns = {issue.details.get("pattern") for issue in result.issues}
    assert "../" in matched_patterns
    assert ".so" in matched_patterns


def test_tensorrt_scanner_safe_file(tmp_path: Path) -> None:
    path = tmp_path / "safe.engine"
    path.write_bytes(b"binarydata")
    result = TensorRTScanner().scan(str(path))
    assert result.success
    assert not result.issues
