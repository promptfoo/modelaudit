import builtins
import struct
from pathlib import Path
from typing import Any

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors.suspicious_symbols import BINARY_CODE_PATTERNS
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.pytorch_binary_scanner import PyTorchBinaryScanner
from tests.helpers import create_mock_onnx


def _write_chunk_boundary_payload(
    path: Path,
    pattern: bytes,
    *,
    prefix_len: int,
    suffix: bytes = b"\x00" * 128,
) -> None:
    chunk_size = 1024 * 1024
    path.write_bytes(b"\x00" * (chunk_size - prefix_len) + pattern[:prefix_len] + pattern[prefix_len:] + suffix)


def _valid_elf64_header() -> bytes:
    header = bytearray(b"\x00" * 64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    return bytes(header)


def _valid_macho32_little_header() -> bytes:
    header = bytearray(b"\x00" * 36)
    header[:4] = b"\xce\xfa\xed\xfe"
    header[4:8] = (7).to_bytes(4, "little")
    header[8:12] = (3).to_bytes(4, "little")
    header[12:16] = (2).to_bytes(4, "little")
    header[16:20] = (1).to_bytes(4, "little")
    header[20:24] = (8).to_bytes(4, "little")
    header[28:32] = (1).to_bytes(4, "little")
    header[32:36] = (8).to_bytes(4, "little")
    return bytes(header)


def test_pytorch_binary_scanner_can_handle(tmp_path):
    """Test that the scanner correctly identifies pytorch binary files."""
    scanner = PyTorchBinaryScanner()

    # Create a mock pytorch binary file
    binary_file = tmp_path / "model.bin"
    # Write some random binary data (not pickle format)
    binary_file.write_bytes(b"\x00\x01\x02\x03" * 100)

    # Should handle .bin files that are not pickle format
    assert scanner.can_handle(str(binary_file))

    # Should not handle directories
    assert not scanner.can_handle(str(tmp_path))

    # Should not handle other extensions
    other_file = tmp_path / "model.txt"
    other_file.write_text("not a binary file")
    assert not scanner.can_handle(str(other_file))


def test_pytorch_binary_scanner_basic_scan(tmp_path):
    """Test basic scanning of a pytorch binary file."""
    scanner = PyTorchBinaryScanner()

    # Create a simple binary file
    binary_file = tmp_path / "model.bin"
    # Write float data that looks like tensor data
    data = struct.pack("f" * 10, *[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    binary_file.write_bytes(data * 10)

    result = scanner.scan(str(binary_file))

    assert result.success
    assert result.bytes_scanned == len(data) * 10

    # Should have no file type validation warnings (.bin files with unknown headers are valid)
    validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]
    assert len(validation_issues) == 0


def test_pytorch_binary_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.bin"
    path.write_bytes(b"benign binary tensor weights" * 10)

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated PyTorch binary read failure")

    monkeypatch.setattr("modelaudit.scanners.pytorch_binary_scanner.open", raise_os_error, raising=False)

    direct = PyTorchBinaryScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "Binary File Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Unable to read binary file" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "pytorch_binary_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "pytorch_binary_read_failed"
    assert "pytorch_binary_read_failed" in direct.metadata["scan_outcome_reasons"]
    metadata = aggregate.file_metadata[str(path)]
    assert "pytorch_binary_read_failed" in metadata["scan_outcome_reasons"]
    assert metadata["operational_error_reason"] == "pytorch_binary_read_failed"
    assert any(
        check.name == "Binary File Read" and "Unable to read binary file" in check.message for check in aggregate.checks
    )
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_pytorch_binary_can_handle_routes_detection_read_failures_without_extra_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.bin"
    path.write_bytes(b"benign binary tensor weights" * 10)

    def raise_os_error(*_args: object, **_kwargs: object) -> str:
        raise OSError("simulated format detection read failure")

    def fail_preflight_open(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("can_handle should not preflight-open .bin files")

    monkeypatch.setattr("modelaudit.utils.file.detection.detect_file_format", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.pytorch_binary_scanner.open", fail_preflight_open, raising=False)

    assert PyTorchBinaryScanner.can_handle(str(path)) is True


def test_pytorch_binary_validation_read_failure_is_operational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "transient-read-failure.bin"
    path.write_bytes(b"benign binary tensor weights" * 10)
    real_open = builtins.open
    scanner_open_count = 0

    def fail_second_scanner_open(file: str, *args: Any, **kwargs: Any) -> Any:
        nonlocal scanner_open_count
        if file == str(path):
            scanner_open_count += 1
            if scanner_open_count == 2:
                raise OSError("simulated tensor validation read failure")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("modelaudit.scanners.pytorch_binary_scanner.open", fail_second_scanner_open, raising=False)
    result = PyTorchBinaryScanner().scan(str(path))

    assert scanner_open_count == 2
    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == ["pytorch_binary_read_failed"]
    assert result.metadata["operational_error_reason"] == "pytorch_binary_read_failed"
    assert any(
        check.name == "Binary File Read" and "Unable to read binary file" in check.message for check in result.checks
    )


def test_pytorch_binary_unreadable_path_preflight_is_operational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "permission-denied.bin"
    path.write_bytes(b"benign binary tensor weights" * 10)

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = PyTorchBinaryScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.metadata["operational_error_reason"] == "pytorch_binary_read_failed"
    assert aggregate.file_metadata[str(path)]["operational_error_reason"] == "pytorch_binary_read_failed"
    assert determine_exit_code(aggregate) == 2


def test_pytorch_binary_scanner_reports_tiny_top_level_bin_files(tmp_path: Path) -> None:
    """Top-level tiny .bin files should retain the existing size-only signal."""
    scanner = PyTorchBinaryScanner()
    tiny_bin = tmp_path / "tiny.bin"
    tiny_bin.write_bytes(b"weights")

    result = scanner.scan(str(tiny_bin))

    assert any("Suspiciously small binary file" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_accepts_tiny_nested_bin_members(tmp_path: Path) -> None:
    """Nested archive members should not emit size-only false positives."""
    scanner = PyTorchBinaryScanner(config={"_archive_depth": 1})
    tiny_bin = tmp_path / "weights.bin"
    tiny_bin.write_bytes(b"weights")

    result = scanner.scan(str(tiny_bin))

    assert result.success
    assert not any("Suspiciously small binary file" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_code_patterns(tmp_path):
    """Test detection of embedded code patterns."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with embedded code patterns
    binary_file = tmp_path / "malicious.bin"
    pattern_import = BINARY_CODE_PATTERNS[0]
    pattern_system = next(p for p in BINARY_CODE_PATTERNS if p.startswith(b"os.system"))
    data = b"\x00" * 100 + pattern_import + b"\n" + pattern_system + b"\x00" * 100
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success
    assert len(result.issues) > 0

    # Check that we found the code patterns
    found_import = False
    found_system = False
    for issue in result.issues:
        if "import os" in issue.message:
            found_import = True
        if "os.system" in issue.message:
            found_system = True

    assert found_import
    assert found_system


def test_pytorch_binary_code_patterns_affect_security_exit(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "active-code-pattern.bin"
    binary_file.write_bytes(b"\x00" * 128 + b"eval('1 + 1')" + b"\x00" * 128)

    direct = scanner.scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    code_issues = [issue for issue in direct.issues if "Suspicious code pattern found" in issue.message]
    code_checks = [check for check in direct.checks if check.name == "Embedded Code Pattern Detection"]

    assert direct.success is True
    assert code_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in code_issues)
    assert any(check.status == CheckStatus.FAILED and check.severity == IssueSeverity.WARNING for check in code_checks)
    assert any(issue.severity == IssueSeverity.WARNING for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "description",
    [
        b"The open(path) helper reads a checkpoint.",
        b"The input(shape) field is required.",
        b"Use mmap(length) for large tensors.",
        b"Call model.eval() before inference.",
        b"The docs mention os.system and subprocess.call.",
    ],
)
def test_pytorch_binary_context_dependent_code_patterns_do_not_affect_security_exit(
    tmp_path: Path,
    description: bytes,
) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "documented-helper.bin"
    binary_file.write_bytes(b"\x00" * 128 + description + b"\x00" * 128)

    direct = scanner.scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    code_issues = [issue for issue in direct.issues if "Suspicious code pattern found" in issue.message]

    assert code_issues
    assert all(issue.severity == IssueSeverity.INFO for issue in code_issues)
    assert all(issue.details["pattern_confidence"] == "context_dependent" for issue in code_issues)
    assert determine_exit_code(aggregate) == 0


def test_pytorch_binary_security_pattern_near_matches_do_not_affect_security_exit(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "benign-security-near-match.bin"
    binary_file.write_bytes(b"\x00" * 128 + b"reeval(value) and ecos.systematic labels" + b"\x00" * 128)

    direct = scanner.scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    assert not [issue for issue in direct.issues if "Suspicious code pattern found" in issue.message]
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "payload",
    [
        b"model.eval()",
        b"runner.exec()",
        b"loader.__import__('plugin')",
        b"wrapper.os.system('echo safe')",
    ],
)
def test_pytorch_binary_attribute_calls_do_not_affect_security_exit(tmp_path: Path, payload: bytes) -> None:
    binary_file = tmp_path / "attribute-call.bin"
    binary_file.write_bytes(b"\x00" * 128 + payload + b"\x00" * 128)

    direct = PyTorchBinaryScanner().scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    code_issues = [issue for issue in direct.issues if "Suspicious code pattern found" in issue.message]

    assert code_issues
    assert all(issue.severity == IssueSeverity.INFO for issue in code_issues)
    assert all(issue.details["pattern_confidence"] == "context_dependent" for issue in code_issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "payload, expected_pattern",
    [
        (b"eval ('1 + 1')", "eval("),
        (b"os \n . \t system('id')", "os.system"),
        (b"subprocess.call (['id'])", "subprocess.call"),
        (b"ctypes.cdll.LoadLibrary ('payload.so')", "ctypes.cdll"),
    ],
)
def test_pytorch_binary_security_patterns_allow_bounded_whitespace(
    tmp_path: Path,
    payload: bytes,
    expected_pattern: str,
) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "spaced-active-code.bin"
    binary_file.write_bytes(b"\x00" * 128 + payload + b"\x00" * 128)

    direct = scanner.scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    code_issues = [
        issue
        for issue in direct.issues
        if issue.details.get("pattern") == expected_pattern and issue.severity == IssueSeverity.WARNING
    ]

    assert code_issues
    assert all(issue.details["pattern_confidence"] == "high" for issue in code_issues)
    assert determine_exit_code(aggregate) == 1


def test_pytorch_binary_benign_tensor_data_stays_clean(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "benign-weights.bin"
    tensor_like_data = struct.pack("f" * 16, *[float(i) / 16 for i in range(16)])
    binary_file.write_bytes(tensor_like_data * 16)

    direct = scanner.scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    assert direct.success is True
    assert not [issue for issue in direct.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]
    assert determine_exit_code(aggregate) == 0


def test_pytorch_binary_scanner_detects_code_pattern_split_across_chunk_boundary(tmp_path: Path) -> None:
    """Suspicious code tokens split at a chunk boundary should still be detected."""
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "boundary_code_pattern.bin"
    pattern_system = next(p for p in BINARY_CODE_PATTERNS if p.startswith(b"os.system"))
    _write_chunk_boundary_payload(binary_file, pattern_system, prefix_len=4)

    result = scanner.scan(str(binary_file))

    assert result.success is True
    assert any("os.system" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_detects_spaced_code_pattern_split_across_chunk_boundary(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "boundary_spaced_code_pattern.bin"
    _write_chunk_boundary_payload(binary_file, b"os \n . \t system('id')", prefix_len=6)

    result = scanner.scan(str(binary_file))

    assert any(
        issue.details.get("pattern") == "os.system" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_binary_scanner_detects_longest_spaced_code_pattern_across_chunk_boundary(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "boundary_longest_spaced_code_pattern.bin"
    pattern = b"ctypes        .        windll        .        LoadLibrary        ("
    _write_chunk_boundary_payload(binary_file, pattern, prefix_len=len(pattern) - 1)

    result = scanner.scan(str(binary_file))

    assert any(
        issue.details.get("pattern") == "ctypes.windll" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


@pytest.mark.skip(
    reason="ML context filtering now ignores executable signatures in weight-like data to reduce false positives"
)
def test_pytorch_binary_scanner_executable_signatures_at_start(tmp_path):
    """Test detection of executable signatures at file start."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with Windows executable signature at the beginning
    binary_file = tmp_path / "real_exe.bin"
    # MZ header at offset 0 - should be detected
    data = b"MZ" + b"\x00" * 1000
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success

    # Should find the Windows executable at offset 0
    found_pe = False
    for issue in result.issues:
        if "Windows executable" in issue.message and issue.location is not None and "(offset: 0)" in issue.location:
            found_pe = True

    assert found_pe, "Should detect Windows executable at offset 0"


def test_pytorch_binary_scanner_no_false_positive_mz(tmp_path):
    """Test that MZ signature in middle of file is not flagged (false positive fix)."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with MZ signature in the middle (like BERT weights might have)
    binary_file = tmp_path / "bert_weights.bin"
    # Random data that happens to contain MZ in the middle
    import struct

    # Create float data
    floats = [0.1, 0.2, 0.3, 0.4, 0.5]
    float_data = struct.pack("f" * len(floats), *floats)
    # Add MZ signature in the middle of the file
    data = b"\x00" * 500 + b"MZ" + b"\x00" * 500 + float_data
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success

    # Should NOT find Windows executable (MZ is not at offset 0)
    found_pe = False
    for issue in result.issues:
        if "Windows executable" in issue.message:
            found_pe = True

    assert not found_pe, "Should NOT detect Windows executable when MZ is in middle of file"


def test_pytorch_binary_scanner_detects_structurally_valid_embedded_pe(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "embedded_pe.bin"
    pe_payload = bytearray(b"\x00" * 196)
    pe_payload[:2] = b"MZ"
    pe_payload[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe_payload[0x80:0x84] = b"PE\x00\x00"
    binary_file.write_bytes(b"\x00" * 512 + bytes(pe_payload))

    result = scanner.scan(str(binary_file))

    assert any(
        issue.rule_code == "S501"
        and "Windows executable" in issue.message
        and "(offset: 512)" in (issue.location or "")
        for issue in result.issues
    )


def test_pytorch_binary_scanner_detects_embedded_pe_across_chunk_boundary(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "boundary_embedded_pe.bin"
    chunk_size = 1024 * 1024
    pe_offset = chunk_size - 0x50
    pe_payload = bytearray(b"\x00" * (chunk_size + 0x80))
    pe_payload[pe_offset : pe_offset + 2] = b"MZ"
    pe_payload[pe_offset + 0x3C : pe_offset + 0x40] = (0x80).to_bytes(4, "little")
    pe_payload[pe_offset + 0x80 : pe_offset + 0x84] = b"PE\x00\x00"
    binary_file.write_bytes(pe_payload)

    result = scanner.scan(str(binary_file))

    assert any(
        issue.rule_code == "S501"
        and "Windows executable" in issue.message
        and f"(offset: {pe_offset})" in (issue.location or "")
        for issue in result.issues
    )


def test_pytorch_binary_scanner_detects_executable_signature_after_first_chunk(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_elf.bin"
    chunk_size = 1024 * 1024
    elf_offset = chunk_size + 10
    binary_file.write_bytes(b"\x00" * elf_offset + _valid_elf64_header() + b"\x00" * 128)

    result = scanner.scan(str(binary_file))
    aggregate = scan_model_directory_or_file(str(binary_file), cache_scan_results=False)

    assert any(
        issue.rule_code == "S501" and "Linux executable" in issue.message and issue.details.get("offset") == elf_offset
        for issue in result.issues
    )
    assert determine_exit_code(aggregate) == 1


def test_pytorch_binary_scanner_detects_late_executable_signature_across_chunk_boundary(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_boundary_elf.bin"
    chunk_size = 1024 * 1024
    elf_offset = 2 * chunk_size - 2
    binary_file.write_bytes(b"\x00" * elf_offset + _valid_elf64_header() + b"\x00" * 128)

    result = scanner.scan(str(binary_file))

    assert any(
        issue.rule_code == "S501" and "Linux executable" in issue.message and issue.details.get("offset") == elf_offset
        for issue in result.issues
    )


def test_pytorch_binary_scanner_ignores_invalid_mz_after_first_chunk(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_invalid_mz.bin"
    chunk_size = 1024 * 1024
    binary_file.write_bytes(b"\x00" * (chunk_size + 512) + b"MZ" + b"\x00" * 128)

    result = scanner.scan(str(binary_file))

    assert not any(issue.rule_code == "S501" and "Windows executable" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_ignores_late_elf_magic_without_valid_header(tmp_path: Path) -> None:
    binary_file = tmp_path / "late_invalid_elf.bin"
    chunk_size = 1024 * 1024
    binary_file.write_bytes(b"\xff" * (chunk_size + 512) + b"\x7fELF" + b"\xff" * 128)

    result = PyTorchBinaryScanner().scan(str(binary_file))

    assert not any(issue.rule_code == "S501" and "Linux executable" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_detects_late_little_endian_macho32(tmp_path: Path) -> None:
    binary_file = tmp_path / "late_macho32.bin"
    chunk_size = 1024 * 1024
    macho_offset = chunk_size + 512
    binary_file.write_bytes(b"\xff" * macho_offset + _valid_macho32_little_header() + b"\xff" * 128)

    result = PyTorchBinaryScanner().scan(str(binary_file))

    assert any(
        issue.rule_code == "S501"
        and "Mach-O 32-bit" in issue.message
        and issue.details.get("offset") == macho_offset
        and issue.details.get("signature") == b"\xce\xfa\xed\xfe".hex()
        for issue in result.issues
    )


def test_pytorch_binary_scanner_ignores_late_macho_magic_without_valid_header(tmp_path: Path) -> None:
    binary_file = tmp_path / "late_invalid_macho32.bin"
    chunk_size = 1024 * 1024
    binary_file.write_bytes(b"\xff" * (chunk_size + 512) + b"\xce\xfa\xed\xfe" + b"\xff" * 128)

    result = PyTorchBinaryScanner().scan(str(binary_file))

    assert not any(issue.rule_code == "S501" and "Mach-O" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_defers_ml_context_without_executable_candidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary_file = tmp_path / "no_executable_candidates.bin"
    binary_file.write_bytes(b"\xff" * (3 * 1024 * 1024))

    def fail_analysis(*_args: object, **_kwargs: object) -> dict[str, Any]:
        pytest.fail("ML context analysis must be deferred until an executable candidate exists")

    monkeypatch.setattr(
        "modelaudit.utils.helpers.ml_context.analyze_binary_for_ml_context",
        fail_analysis,
    )

    PyTorchBinaryScanner().scan(str(binary_file))


def test_pytorch_binary_scanner_caps_executable_findings_across_file(tmp_path: Path) -> None:
    binary_file = tmp_path / "many_executables.bin"
    chunk_size = 1024 * 1024
    payload = bytearray(b"\xff" * (2 * chunk_size + 1024))
    offsets = [
        *(128 + index * 128 for index in range(6)),
        *(chunk_size + 128 + index * 128 for index in range(6)),
    ]
    header = _valid_elf64_header()
    for executable_offset in offsets:
        payload[executable_offset : executable_offset + len(header)] = header
    binary_file.write_bytes(payload)

    result = PyTorchBinaryScanner().scan(str(binary_file))

    executable_issues = [
        issue for issue in result.issues if issue.rule_code == "S501" and "Linux executable" in issue.message
    ]
    assert len(executable_issues) == PyTorchBinaryScanner.MAX_EXECUTABLE_SIGNATURE_FINDINGS
    assert [issue.details["offset"] for issue in executable_issues] == offsets[:10]


def test_pytorch_binary_scanner_rejects_out_of_bounds_embedded_pe_without_opening_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = PyTorchBinaryScanner()
    pe_payload = b"MZ" + b"\x00" * 0x3A + (2048).to_bytes(4, "little")

    def fail_open(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("out-of-range PE offsets must not open the file")

    monkeypatch.setattr(builtins, "open", fail_open)

    assert scanner._is_valid_embedded_pe(pe_payload, 0, 1024, file_size=2048) is False


def test_pytorch_binary_scanner_ignores_invalid_late_shebang_alias(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_invalid_shebang.bin"
    chunk_size = 1024 * 1024
    binary_file.write_bytes(b"\x00" * (chunk_size + 512) + b"#!/bin/not-an-interpreter\n" + b"\x00" * 128)

    result = scanner.scan(str(binary_file))

    assert not any(issue.rule_code == "S501" and "Shell script shebang" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_detects_late_shebang_across_chunk_boundary_once(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_boundary_shebang.bin"
    chunk_size = 1024 * 1024
    shebang_offset = 2 * chunk_size - 10
    binary_file.write_bytes(b"\xff" * shebang_offset + b"#!/bin/bash\necho hidden\n" + b"\xff" * 128)

    result = scanner.scan(str(binary_file))

    shebang_issues = [
        issue for issue in result.issues if issue.rule_code == "S501" and "Shell script shebang" in issue.message
    ]
    assert len(shebang_issues) == 1
    assert shebang_issues[0].details["signature"] == b"#!/".hex()
    assert shebang_issues[0].details["offset"] == shebang_offset


def test_pytorch_binary_scanner_coalesces_late_shebang_aliases(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_shebang.bin"
    chunk_size = 1024 * 1024
    shebang_offset = chunk_size + 512
    binary_file.write_bytes(b"\xff" * shebang_offset + b"#!/bin/bash\necho hidden\n" + b"\xff" * 128)

    result = scanner.scan(str(binary_file))

    shebang_issues = [
        issue for issue in result.issues if issue.rule_code == "S501" and "Shell script shebang" in issue.message
    ]
    assert len(shebang_issues) == 1
    assert shebang_issues[0].details["signature"] == b"#!/".hex()
    assert shebang_issues[0].details["offset"] == shebang_offset


def test_pytorch_binary_scanner_reconsiders_carried_shebang_under_new_chunk_context(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "carried_shebang_context.bin"
    chunk_size = 1024 * 1024
    shebang = b"#!/bin/bash\n"
    shebang_offset = chunk_size - 20
    binary_file.write_bytes(b"\x00" * shebang_offset + shebang + b"\x00" * (20 - len(shebang)) + b"\xff" * 1024)

    result = scanner.scan(str(binary_file))

    shebang_issues = [
        issue for issue in result.issues if issue.rule_code == "S501" and "Shell script shebang" in issue.message
    ]
    assert len(shebang_issues) == 1
    assert shebang_issues[0].details["signature"] == b"#!/".hex()
    assert shebang_issues[0].details["offset"] == shebang_offset


def test_pytorch_binary_scanner_deduplicates_carried_shebang(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "carried_shebang.bin"
    chunk_size = 1024 * 1024
    shebang = b"#!/bin/bash\n"
    shebang_offset = chunk_size - 20
    binary_file.write_bytes(b"\xff" * shebang_offset + shebang + b"\xff" * (20 - len(shebang)) + b"\xff" * 1024)

    result = scanner.scan(str(binary_file))

    shebang_issues = [
        issue for issue in result.issues if issue.rule_code == "S501" and "Shell script shebang" in issue.message
    ]
    assert len(shebang_issues) == 1
    assert shebang_issues[0].details["signature"] == b"#!/".hex()
    assert shebang_issues[0].details["offset"] == shebang_offset


def test_pytorch_binary_scanner_ignores_invalid_late_shebang_interpreter_subpath(tmp_path: Path) -> None:
    scanner = PyTorchBinaryScanner()
    binary_file = tmp_path / "late_invalid_shebang_subpath.bin"
    chunk_size = 1024 * 1024
    binary_file.write_bytes(b"\xff" * (chunk_size + 512) + b"#!/bin/bash/not-an-interpreter\n" + b"\xff" * 128)

    result = scanner.scan(str(binary_file))

    assert not any(issue.rule_code == "S501" and "Shell script shebang" in issue.message for issue in result.issues)


@pytest.mark.skip(
    reason="ML context filtering now ignores executable signatures in weight-like data to reduce false positives"
)
def test_pytorch_binary_scanner_longer_signatures_still_detected(tmp_path):
    """Test that longer executable signatures are still detected regardless of position."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with longer signatures in the middle
    binary_file = tmp_path / "with_elf.bin"
    # ELF signature is 4 bytes - should still be detected even in middle
    data = b"\x00" * 100 + _valid_elf64_header() + b"\x00" * 100
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success

    # Should find the ELF executable (longer signature)
    found_elf = False
    for issue in result.issues:
        if "Linux executable" in issue.message:
            found_elf = True

    assert found_elf, "Should detect Linux executable (4-byte signature) even in middle of file"


def test_pytorch_binary_scanner_blacklist_patterns(tmp_path):
    """Test detection of blacklisted patterns."""
    config = {"blacklist_patterns": ["CONFIDENTIAL", "SECRET_KEY"]}
    scanner = PyTorchBinaryScanner(config)

    # Create a binary file with blacklisted patterns
    binary_file = tmp_path / "with_blacklist.bin"
    data = b"\x00" * 50 + b"CONFIDENTIAL_DATA" + b"\x00" * 50 + b"SECRET_KEY=12345" + b"\x00" * 50
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success is False
    assert len(result.issues) >= 2

    # Check that we found the blacklisted patterns
    found_confidential = False
    found_secret = False
    for issue in result.issues:
        if "CONFIDENTIAL" in issue.message:
            found_confidential = True
        if "SECRET_KEY" in issue.message:
            found_secret = True

    assert found_confidential
    assert found_secret


def test_pytorch_binary_scanner_detects_blacklist_pattern_split_across_chunk_boundary(tmp_path: Path) -> None:
    """Blacklisted tokens split at a chunk boundary should still fail the scan."""
    scanner = PyTorchBinaryScanner(config={"blacklist_patterns": ["SECRET_KEY"]})
    binary_file = tmp_path / "boundary_blacklist.bin"
    _write_chunk_boundary_payload(binary_file, b"SECRET_KEY", prefix_len=3)

    result = scanner.scan(str(binary_file))

    assert result.success is False
    assert any("SECRET_KEY" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_rejects_boundary_near_match_without_blacklist_fp(tmp_path: Path) -> None:
    """A near-match split across chunks must not become a noisy blacklist false positive."""
    scanner = PyTorchBinaryScanner(config={"blacklist_patterns": ["SECRET_KEY"]})
    binary_file = tmp_path / "boundary_blacklist_near_match.bin"
    _write_chunk_boundary_payload(binary_file, b"SECRET_KEZ", prefix_len=3)

    result = scanner.scan(str(binary_file))

    assert result.success is True
    assert not any("SECRET_KEY" in issue.message for issue in result.issues)


def test_pytorch_binary_scanner_handles_none_blacklist_config_and_detects_pe_header(tmp_path: Path) -> None:
    """`blacklist_patterns=None` should not crash and must preserve executable detection."""
    scanner = PyTorchBinaryScanner(config={"blacklist_patterns": None})
    binary_file = tmp_path / "malicious_model.bin"
    binary_file.write_bytes(b"MZ" + b"\x90\x00" * 30 + b"This program cannot be run in DOS mode" + b"\x00" * 100)

    result = scanner.scan(str(binary_file))

    assert result.success is False
    assert any("Windows executable" in issue.message for issue in result.issues)


def test_filetype_detection_for_bin_files(tmp_path):
    """Test that filetype detection correctly identifies different .bin formats."""
    from modelaudit.utils.file.detection import detect_file_format

    # Test pickle format .bin
    pickle_bin = tmp_path / "pickle.bin"
    pickle_bin.write_bytes(b"\x80\x03}q\x00.")  # Pickle protocol 3
    assert detect_file_format(str(pickle_bin)) == "pickle"

    # Test safetensors format .bin (needs proper 8-byte header length prefix)
    import struct

    safetensors_header = b'{"__metadata__": {"format": "pt"}}'
    safetensors_bin = tmp_path / "safetensors.bin"
    safetensors_bin.write_bytes(struct.pack("<Q", len(safetensors_header)) + safetensors_header + b"\x00" * 100)
    assert detect_file_format(str(safetensors_bin)) == "safetensors"

    # Test ONNX format .bin
    pytest.importorskip("onnx")
    onnx_bin = tmp_path / "onnx.bin"
    create_mock_onnx(onnx_bin)
    assert detect_file_format(str(onnx_bin)) == "onnx"

    # Test raw binary format .bin
    raw_bin = tmp_path / "raw.bin"
    raw_bin.write_bytes(b"\x00\x01\x02\x03" * 100)
    assert detect_file_format(str(raw_bin)) == "pytorch_binary"


def test_pickle_scanner_handles_pickle_bin_files(tmp_path):
    """Test that pickle scanner correctly handles .bin files with pickle content."""
    from modelaudit.scanners.pickle_scanner import PickleScanner

    scanner = PickleScanner()

    # Create a .bin file with pickle content
    pickle_bin = tmp_path / "model.bin"
    import pickle

    data = {"weights": [1.0, 2.0, 3.0]}
    with open(pickle_bin, "wb") as f:
        pickle.dump(data, f)

    # Should handle pickle .bin files
    assert scanner.can_handle(str(pickle_bin))

    # Scan should work
    result = scanner.scan(str(pickle_bin))
    assert result.success
    assert result.bytes_scanned > 0
