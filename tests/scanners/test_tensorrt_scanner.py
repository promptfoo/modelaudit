from pathlib import Path

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.tensorrt_scanner import TensorRTScanner
from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension


def _minimal_pe_header() -> bytes:
    data = bytearray(b"\x00" * 0x100)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    return bytes(data)


def _minimal_elf_shared_object() -> bytes:
    return _minimal_elf_header(object_type=3)


def _minimal_elf_executable() -> bytes:
    return _minimal_elf_header(object_type=2)


def _minimal_elf_header(*, object_type: int) -> bytes:
    data = bytearray(b"\x00" * 0x80)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # ELFCLASS64
    data[5] = 1  # ELFDATA2LSB
    data[6] = 1  # EV_CURRENT
    data[16:18] = object_type.to_bytes(2, "little")
    data[18:20] = (62).to_bytes(2, "little")  # x86_64
    data[20:24] = (1).to_bytes(4, "little")  # EV_CURRENT
    return bytes(data)


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


def test_tensorrt_unavailable_read_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.engine"
    path.write_bytes(b"TensorRT safe engine metadata")

    def raise_os_error(_self: TensorRTScanner, _path: str) -> bytes:
        raise OSError("simulated TensorRT read failure")

    def raise_detection_error(_path: str) -> str:
        raise OSError("simulated TensorRT detection read failure")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr(TensorRTScanner, "_read_file_safely", raise_os_error)
    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_detection_error)
    monkeypatch.setattr("modelaudit.core.detect_file_format_from_magic", lambda _path: "unknown")
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)

    direct = TensorRTScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "TensorRT Engine Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Error reading TensorRT engine" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "tensorrt_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "tensorrt_read_failed" in direct.metadata["scan_outcome_reasons"]
    assert direct.metadata["operational_error_reason"] == "tensorrt_read_failed"
    metadata = aggregate.file_metadata[str(path)]
    assert "tensorrt_read_failed" in metadata["scan_outcome_reasons"]
    assert metadata["operational_error_reason"] == "tensorrt_read_failed"
    assert any(
        check.name == "TensorRT Engine Read" and "Error reading TensorRT engine" in check.message
        for check in aggregate.checks
    )
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_tensorrt_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "permission-denied.engine"
    path.write_bytes(b"TensorRT safe engine metadata")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = TensorRTScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.metadata["scan_outcome_reasons"] == ["tensorrt_read_failed"]
    assert direct.metadata["operational_error_reason"] == "tensorrt_read_failed"
    assert aggregate.file_metadata[str(path)]["operational_error_reason"] == "tensorrt_read_failed"
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_tensorrt_read_failure_takes_precedence_over_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malicious = tmp_path / "malicious.engine"
    malicious.write_bytes(b"python import eval")
    unreadable = tmp_path / "unreadable.plan"
    unreadable.write_bytes(b"TensorRT safe engine metadata")
    original_read = TensorRTScanner._read_file_safely

    def fail_selected_read(self: TensorRTScanner, path: str) -> bytes:
        if Path(path).name == unreadable.name:
            raise OSError("simulated TensorRT read failure")
        return original_read(self, path)

    monkeypatch.setattr(TensorRTScanner, "_read_file_safely", fail_selected_read)

    aggregate = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
    assert aggregate.file_metadata[str(unreadable)]["operational_error_reason"] == "tensorrt_read_failed"
    assert determine_exit_code(aggregate) == 2


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


def test_tensorrt_scanner_detects_windows_dll_plugin_markers(tmp_path: Path) -> None:
    path = tmp_path / "malicious.engine"
    path.write_bytes(b"plugin=malicious_plugin.dll\x00LoadLibraryExW\x00")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    matched_patterns = {issue.details.get("pattern") for issue in result.issues}
    assert {".dll", "LoadLibrary"}.issubset(matched_patterns)


def test_tensorrt_scanner_detects_embedded_pe_header(tmp_path: Path) -> None:
    path = tmp_path / "embedded_pe.engine"
    prefix = b"tensorrt engine prefix\x00"
    path.write_bytes(prefix + _minimal_pe_header())

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.details.get("pattern") == "embedded PE" and issue.details.get("offset") == len(prefix)
        for issue in result.issues
    )


def test_tensorrt_scanner_detects_embedded_pe_header_after_invalid_decoy(tmp_path: Path) -> None:
    path = tmp_path / "embedded_pe_after_decoy.engine"
    prefix = b"tensorrt engine prefix\x00"
    invalid_pe_near_match = bytearray(b"\x00" * 0x100)
    invalid_pe_near_match[0:2] = b"MZ"
    invalid_pe_near_match[0x3C:0x40] = (0x80).to_bytes(4, "little")
    invalid_pe_near_match[0x80:0x84] = b"PX\x00\x00"
    separator = b"\x00decoy boundary\x00"
    path.write_bytes(prefix + bytes(invalid_pe_near_match) + separator + _minimal_pe_header())

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.details.get("pattern") == "embedded PE"
        and issue.details.get("offset") == len(prefix) + len(invalid_pe_near_match) + len(separator)
        for issue in result.issues
    )


def test_tensorrt_scanner_detects_embedded_elf_shared_object(tmp_path: Path) -> None:
    path = tmp_path / "embedded_elf.engine"
    prefix = b"tensorrt engine prefix\x00"
    path.write_bytes(prefix + _minimal_elf_shared_object())

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.details.get("pattern") == "embedded ELF" and issue.details.get("offset") == len(prefix)
        for issue in result.issues
    )


def test_tensorrt_scanner_detects_embedded_elf_executable(tmp_path: Path) -> None:
    path = tmp_path / "embedded_elf_exec.engine"
    prefix = b"tensorrt engine prefix\x00"
    path.write_bytes(prefix + _minimal_elf_executable())

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.details.get("pattern") == "embedded ELF" and issue.details.get("offset") == len(prefix)
        for issue in result.issues
    )


def test_tensorrt_scanner_detects_plugin_shared_library_entry_points(tmp_path: Path) -> None:
    path = tmp_path / "plugin_entry_points.engine"
    path.write_bytes(b"setLoggerFinder\x00getPluginCreators\x00getCreators\x00")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    assert any(issue.details.get("pattern") == "TensorRT plugin entry point" for issue in result.issues)


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
        b"attempt/tmpology LD_LIBRARY_PATH:/tmpology C:\\tmpology\\payload "
        b"load(/tmpbackup/safe.so.txt)"
    )

    result = TensorRTScanner().scan(str(path))

    assert result.success is True
    assert result.issues == []


def test_tensorrt_scanner_avoids_windows_native_near_match_false_positives(tmp_path: Path) -> None:
    path = tmp_path / "safe.engine"
    invalid_pe_near_match = bytearray(b"\x00" * 0x100)
    invalid_pe_near_match[0:2] = b"MZ"
    invalid_pe_near_match[0x3C:0x40] = (0x80).to_bytes(4, "little")
    invalid_pe_near_match[0x80:0x84] = b"PX\x00\x00"
    path.write_bytes(
        b"plugin.dllcache KERNEL32.dllology LoadLibraryExWidget preLoadLibrary " + bytes(invalid_pe_near_match)
    )

    result = TensorRTScanner().scan(str(path))

    assert result.success is True
    assert result.issues == []


def test_tensorrt_scanner_avoids_elf_and_plugin_entry_point_near_match_false_positives(tmp_path: Path) -> None:
    path = tmp_path / "safe.engine"
    invalid_elf_near_match = bytearray(_minimal_elf_shared_object())
    invalid_elf_near_match[16:18] = (1).to_bytes(2, "little")
    path.write_bytes(b"getCreatorsWidget setLoggerFinderish getPluginCreatorsExtra " + bytes(invalid_elf_near_match))

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


def test_tensorrt_scanner_detects_tmp_tokens_after_punctuation_delimiters(tmp_path: Path) -> None:
    path = tmp_path / "punctuated_tmp.engine"
    path.write_bytes(b"load(/tmp/evil.so)\ncmd;/tmp/payload\nload(/tmp/libc.so.6)\n")

    result = TensorRTScanner().scan(str(path))

    assert result.success is False
    matched_patterns = {issue.details.get("pattern") for issue in result.issues}
    assert "/tmp/" in matched_patterns
    assert ".so" in matched_patterns


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
