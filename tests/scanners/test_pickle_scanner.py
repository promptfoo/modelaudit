import os
import pickle
import pickletools
import struct
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, ClassVar

import pytest

# Skip if dill is not available before importing it
pytest.importorskip("dill")

import dill

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    EXECUTABLE_SIGNATURES,
)
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import (
    _NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES,
    _RAW_PATTERN_SCAN_LIMIT_BYTES,
    PickleScanner,
    _find_nested_pickle_match,
    _genops_with_fallback,
    _GenopsBudgetExceeded,
    _is_actually_dangerous_global,
    _is_actually_dangerous_string,
    _is_plausible_python_module,
    _is_safe_import_only_global,
    _simulate_symbolic_reference_maps,
    check_opcode_sequence,
)
from modelaudit.scanners.rule_mapper import get_pickle_opcode_rule_code
from tests.assets.generators.generate_advanced_pickle_tests import (
    generate_memo_based_attack,
    generate_multiple_pickle_attack,
    generate_stack_global_attack,
)
from tests.assets.generators.generate_evil_pickle import EvilClass

# Add the parent directory to sys.path to allow importing modelaudit
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PYTORCH_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "assets" / "samples" / "pytorch"
SYSTEM_GLOBAL_VARIANTS = {"os.system", "posix.system", "nt.system"}


# Import only what we need for the pickle scanner test


def _contains_system_global(text: str) -> bool:
    return any(target in text for target in SYSTEM_GLOBAL_VARIANTS)


def _short_binunicode(value: bytes) -> bytes:
    return b"\x8c" + bytes([len(value)]) + value


def _write_pickle_with_tail(path: Path, tail: bytes, *, pad_to_bytes: int | None = None) -> None:
    payload = pickle.dumps({"weights": [1, 2, 3]})
    if pad_to_bytes is not None and len(payload) < pad_to_bytes:
        payload += b"\x00" * (pad_to_bytes - len(payload))
    path.write_bytes(payload + tail)


def _make_opcode_padding_stream(opcode_pairs: int) -> bytes:
    return b"\x80\x02" + (b"K\x010" * opcode_pairs) + b"."


def _make_memo_expansion_pickle(iterations: int, *, inert_writes: int = 0) -> bytes:
    total_writes = iterations + inert_writes
    if not 1 <= iterations <= 255 or total_writes > 255:
        raise ValueError("iterations + inert_writes must fit in BINPUT/BINGET opcodes")

    payload = bytearray(b"\x80\x02)q\x000")
    for memo_index in range(1, iterations + 1):
        previous_index = memo_index - 1
        payload += b"h" + bytes([previous_index])
        payload += b"h" + bytes([previous_index])
        payload += b"\x86"
        payload += b"q" + bytes([memo_index])
        payload += b"0"
    for memo_index in range(iterations + 1, total_writes + 1):
        payload += b"K\x01"
        payload += b"q" + bytes([memo_index])
        payload += b"0"
    payload += b"h" + bytes([iterations]) + b"."
    return bytes(payload)


def _make_dup_heavy_pickle(iterations: int) -> bytes:
    payload = bytearray(b"\x80\x02]q\x00")
    for _ in range(iterations):
        payload += b"h\x002a0"
    payload += b"."
    return bytes(payload)


def test_direct_pickle_scanner_routes_zip_backed_malicious_pt_fixture() -> None:
    """Direct PickleScanner scans should route ZIP-backed .pt fixtures through the ZIP path."""
    fixture_path = PYTORCH_FIXTURE_DIR / "malicious_eval.pt"

    result = PickleScanner().scan(str(fixture_path))

    assert result.scanner_name == "pytorch_zip"
    assert result.success is True
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues
    ), f"Expected critical eval finding, got: {[(issue.severity.value, issue.message) for issue in result.issues]}"
    assert not any("not a valid pickle file" in issue.message.lower() for issue in result.issues)
    assert any(
        check.name == "ZIP Format Validation" and check.status == CheckStatus.PASSED for check in result.checks
    ), f"Expected ZIP validation check, got: {[(check.name, check.status.value) for check in result.checks]}"


@pytest.mark.parametrize("container_ext", [".pt", ".pth", ".bin", ".ckpt", ".pkl"])
def test_direct_pickle_scanner_routes_zip_backed_safe_pytorch_containers(container_ext: str, tmp_path: Path) -> None:
    """ZIP-backed PyTorch containers should scan as PyTorch ZIP regardless of extension."""
    fixture_path = PYTORCH_FIXTURE_DIR / "safe_model.pt"
    container_path = tmp_path / f"safe_model{container_ext}"
    container_path.write_bytes(fixture_path.read_bytes())

    result = PickleScanner().scan(str(container_path))

    assert result.scanner_name == "pytorch_zip"
    assert result.success is True
    assert result.metadata.get("pickle_files"), f"Expected embedded pickle discovery, got: {result.metadata}"
    findings = [(issue.severity.value, issue.message) for issue in result.issues]
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues), (
        f"Expected no warning/critical findings, got: {findings}"
    )
    assert not any("not a valid pickle file" in issue.message.lower() for issue in result.issues)
    assert any(
        check.name == "ZIP Format Validation" and check.status == CheckStatus.PASSED for check in result.checks
    ), f"Expected ZIP validation check, got: {[(check.name, check.status.value) for check in result.checks]}"


@pytest.mark.parametrize(
    "fixture_name",
    [
        "safe_large_model.pkl",
        "safe_model_with_encoding.pkl",
        "safe_model_with_tokens.pkl",
    ],
)
def test_safe_nested_like_pickle_fixtures_do_not_emit_security_findings(fixture_name: str) -> None:
    """Committed safe pickle fixtures should not produce warning/critical findings."""
    fixture_path = Path(__file__).resolve().parent.parent / "assets" / "samples" / "pickles" / fixture_name

    result = scan_model_directory_or_file(str(fixture_path))

    assert determine_exit_code(result) == 0, (
        f"{fixture_name} should not trigger security exit code 1. Issues: "
        f"{[(issue.severity.value, issue.message) for issue in result.issues]}"
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues), (
        f"{fixture_name} should not emit warning/critical findings: "
        f"{[(issue.severity.value, issue.message) for issue in result.issues]}"
    )
    assert not any("Detected dangerous __reduce__ pattern with ." in check.message for check in result.checks), (
        f"{fixture_name} should not emit placeholder reduce-pattern messages"
    )


def test_padding_stripped_base64_candidate_still_flags_potential_base64() -> None:
    """Padding-stripped base64 should stay detectable if it is otherwise well-formed."""
    padding_stripped = (
        "PL25iLsbINGVuY8DRvqrcGgm2bElUlp3LZLCHbZu7GfvNOJks6CuDNk2ocfYv3pDv8DGkG"
        "BqI8BqXWIYrMEgNRe6TlS37NStmZSk2lfnRu1H0bSiPg9KtqZo"
    )

    assert _is_actually_dangerous_string(padding_stripped, {}) == "potential_base64"


def test_unknown_opcode_pickle_parse_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown opcode parse failures in pickle-like files must fail closed."""
    pickle_path = tmp_path / "unknown_opcode.pkl"
    pickle_path.write_bytes(b"\x80\x04K\x01." + (b"A" * 9000) + b"os.system")

    def _raise_unknown_opcode(self: PickleScanner, _file_obj: object, _file_size: int) -> ScanResult:
        raise ValueError("at position 2, opcode b'\\xff' unknown")

    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", _raise_unknown_opcode)

    result = PickleScanner().scan(str(pickle_path))

    assert result.success is False
    assert result.metadata["file_type"] == "pickle"
    assert result.metadata["parsing_failed"] is True
    assert result.metadata["failure_reason"] == "unknown_opcode_or_format_error"
    assert any(
        check.name == "Pickle Format Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    ), f"Expected fail-closed format check, got: {[(c.name, c.status, c.severity) for c in result.checks]}"


def test_unknown_opcode_bin_parse_failure_still_scans_full_binary_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unknown opcode parse failures in .bin files should still fall back to full binary scanning."""
    bin_path = tmp_path / "unknown_opcode.bin"
    bin_path.write_bytes(b"\x80\x04K\x01." + (b"A" * 9000) + BINARY_CODE_PATTERNS[0])

    def _raise_unknown_opcode(self: PickleScanner, _file_obj: object, _file_size: int) -> ScanResult:
        raise ValueError("at position 2, opcode b'\\xff' unknown")

    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", _raise_unknown_opcode)

    result = PickleScanner().scan(str(bin_path))

    assert result.success is True
    assert result.metadata["file_type"] == "binary"
    assert result.metadata["pickle_parsing_failed"] is True
    assert result.metadata["binary_scan_completed"] is True
    assert any(check.name == "Pickle Format Check" and check.status == CheckStatus.PASSED for check in result.checks), (
        f"Expected passing .bin format check, got: {[(c.name, c.status) for c in result.checks]}"
    )
    assert any(
        check.name == "Binary Content Check" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Expected binary fallback finding, got: {[(c.name, c.status) for c in result.checks]}"


def test_small_pickle_tail_pattern_is_detected_without_raw_pattern_limit(tmp_path: Path) -> None:
    """Small pickle files should still fully analyze raw patterns without a coverage warning."""
    pickle_path = tmp_path / "small-tail.pkl"
    _write_pickle_with_tail(pickle_path, b"os.system")

    result = PickleScanner().scan(str(pickle_path))

    assert not any(check.name == "Raw Pattern Coverage Check" for check in result.checks)
    assert any("os.system" in issue.message for issue in result.issues)


def test_large_pickle_tail_pattern_surfaces_raw_pattern_limit(tmp_path: Path) -> None:
    """Large pickle files should explicitly report the bounded raw-pattern coverage."""
    pickle_path = tmp_path / "large-tail.pkl"
    _write_pickle_with_tail(
        pickle_path,
        b"os.system",
        pad_to_bytes=_RAW_PATTERN_SCAN_LIMIT_BYTES + 128,
    )

    result = PickleScanner().scan(str(pickle_path))

    raw_pattern_checks = [check for check in result.checks if check.name == "Raw Pattern Coverage Check"]
    assert len(raw_pattern_checks) == 1
    raw_pattern_check = raw_pattern_checks[0]
    assert raw_pattern_check.status == CheckStatus.FAILED
    assert raw_pattern_check.severity == IssueSeverity.INFO
    assert raw_pattern_check.details["reason"] == "raw_pattern_prefix_limit"
    assert raw_pattern_check.details["raw_pattern_analysis_limited"] is True
    assert raw_pattern_check.details["raw_pattern_scan_bytes"] == _RAW_PATTERN_SCAN_LIMIT_BYTES
    assert raw_pattern_check.details["raw_pattern_scan_limit_bytes"] == _RAW_PATTERN_SCAN_LIMIT_BYTES
    assert raw_pattern_check.details["raw_pattern_total_bytes"] == pickle_path.stat().st_size
    assert result.metadata["raw_pattern_scan_complete"] is False
    assert result.metadata["raw_pattern_scan_bytes"] == _RAW_PATTERN_SCAN_LIMIT_BYTES
    assert result.metadata["raw_pattern_total_bytes"] == pickle_path.stat().st_size
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert not any(
        "os.system" in issue.message for issue in result.issues if issue.message != raw_pattern_check.message
    )


def test_large_pickle_raw_pattern_limit_with_opcode_budget_truncation(tmp_path: Path) -> None:
    """Large files should surface both the raw-pattern prefix limit and opcode truncation."""
    pickle_path = tmp_path / "large-multistream.pkl"
    large_prefix_stream = pickle.dumps(b"A" * (_RAW_PATTERN_SCAN_LIMIT_BYTES + 128), protocol=4)
    follow_on_streams = b"".join(
        pickle.dumps({"stream": index, "weights": [1, 2, 3]}, protocol=4) for index in range(32)
    )
    pickle_path.write_bytes(large_prefix_stream + follow_on_streams)

    result = PickleScanner({"max_opcodes": 10}).scan(str(pickle_path))

    raw_pattern_checks = [check for check in result.checks if check.name == "Raw Pattern Coverage Check"]
    assert len(raw_pattern_checks) == 1
    assert "may still stop early" in raw_pattern_checks[0].message.lower()
    assert result.metadata["raw_pattern_scan_complete"] is False

    opcode_checks = [
        check for check in result.checks if check.name == "Opcode Count Check" and check.status == CheckStatus.FAILED
    ]
    assert len(opcode_checks) == 1
    assert opcode_checks[0].details["analysis_incomplete"] is True
    assert result.metadata["analysis_incomplete"] is True
    assert result.success is True


def test_scan_pickle_timeout_finishes_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Top-level pickle scans should finish unsuccessful when the timeout path trips."""
    pickle_path = tmp_path / "timeout.pkl"
    pickle_path.write_bytes(pickle.dumps({"weights": [1, 2, 3], "name": "safe"}))

    def _fake_scan_pickle_bytes(self: PickleScanner, _file_obj: object, _file_size: int) -> ScanResult:
        scan_result = self._create_result()
        scan_result.add_check(
            name="Scan Timeout Check",
            passed=False,
            message="Scanning timed out after 0.1 seconds",
            severity=IssueSeverity.INFO,
            location=str(pickle_path),
            details={"timeout": 0.1},
            rule_code="S902",
        )
        scan_result.finish(success=False)
        return scan_result

    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", _fake_scan_pickle_bytes)
    result = PickleScanner({"timeout": 0.1}).scan(str(pickle_path))

    timeout_checks = [
        check for check in result.checks if check.name == "Scan Timeout Check" and check.status == CheckStatus.FAILED
    ]
    assert len(timeout_checks) == 1
    assert "timed out" in timeout_checks[0].message.lower()
    assert result.success is False


def test_scan_pickle_bytes_uses_scan_wide_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opcode analysis should honor the scanner-wide deadline, not a fresh local timer."""
    scanner = PickleScanner({"timeout": 0.1})
    scanner.current_file_path = "timeout.pkl"
    scanner.scan_start_time = 0.0
    payload = pickle.dumps({"weights": [1, 2, 3], "name": "safe"})

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.time.time", lambda: 1.0)

    result = scanner._scan_pickle_bytes(BytesIO(payload), len(payload))

    timeout_checks = [
        check for check in result.checks if check.name == "Scan Timeout Check" and check.status == CheckStatus.FAILED
    ]
    assert len(timeout_checks) == 1
    assert result.success is False


def test_bin_tail_scan_runs_after_budget_exhaustion_with_malicious_tail(tmp_path: Path) -> None:
    """Budget exhaustion after the first STOP should not suppress .bin tail scanning."""
    first_stream = pickle.dumps({"weights": [1, 2, 3], "name": "safe"})
    follow_on_streams = b"".join(
        pickle.dumps({"stream": index, "weights": [1, 2, 3]}, protocol=4) for index in range(32)
    )
    padding = b"\x00" * max(0, 9000 - len(first_stream) - len(follow_on_streams))
    bin_path = tmp_path / "budget-tail.bin"
    bin_path.write_bytes(first_stream + follow_on_streams + padding + BINARY_CODE_PATTERNS[0])

    result = PickleScanner({"max_opcodes": 25}).scan(str(bin_path))

    assert result.success is True
    assert result.metadata["analysis_incomplete"] is True
    assert isinstance(result.metadata.get("first_pickle_end_pos"), int)
    assert any(
        check.name == "Binary Content Check" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Expected binary tail finding, got: {[(c.name, c.status, c.message) for c in result.checks]}"


def test_bin_tail_scan_after_budget_exhaustion_stays_clean_for_benign_tail(tmp_path: Path) -> None:
    """Running the post-pickle .bin tail scan after truncation should not create false positives."""
    first_stream = pickle.dumps({"weights": [1, 2, 3], "name": "safe"})
    follow_on_streams = b"".join(
        pickle.dumps({"stream": index, "weights": [1, 2, 3]}, protocol=4) for index in range(32)
    )
    padding = b"\x00" * max(0, 9000 - len(first_stream) - len(follow_on_streams))
    bin_path = tmp_path / "budget-tail-benign.bin"
    bin_path.write_bytes(first_stream + follow_on_streams + padding + b"benign-tensor-data")

    result = PickleScanner({"max_opcodes": 25}).scan(str(bin_path))

    assert result.success is True
    assert result.metadata["analysis_incomplete"] is True
    assert not any(
        check.name == "Binary Content Check" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Unexpected binary tail finding, got: {[(c.name, c.status, c.message) for c in result.checks]}"


def test_post_budget_global_scan_detects_dangerous_second_stream(tmp_path: Path) -> None:
    """Dangerous imports hidden beyond opcode budget should be detected by the fallback scan."""
    pickle_path = tmp_path / "post-budget-os-system.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = b"\x80\x02cos\nsystem\n)R."
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Global Reference Scan"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in checks[0].message
    findings = checks[0].details["dangerous_references"]
    assert any(finding["import_reference"] == "os.system" for finding in findings)
    assert result.success is False


def test_post_budget_global_scan_has_no_false_positives_for_clean_large_payload(tmp_path: Path) -> None:
    """Budget exhaustion alone should not produce post-budget findings for clean payloads."""
    pickle_path = tmp_path / "post-budget-clean.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=1024)
    clean_tail = pickle.dumps({"safe": True, "weights": [1, 2, 3]}, protocol=4)
    pickle_path.write_bytes(benign_padding + clean_tail)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    assert result.success is True
    assert any(check.name == "Opcode Count Check" and check.status == CheckStatus.FAILED for check in result.checks), (
        "Expected opcode budget exhaustion check"
    )
    assert not any(
        check.name == "Post-Budget Global Reference Scan" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), f"Unexpected post-budget findings: {[(c.name, c.message) for c in result.checks]}"


def test_post_budget_global_scan_runs_only_when_opcode_budget_is_exceeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The post-budget scan should execute only on opcode-budget truncation."""
    scanner = PickleScanner({"max_opcodes": 4096})
    call_counter = {"calls": 0}

    def _counting_scan(
        self: PickleScanner,
        _file_obj: object,
        *,
        file_size: int,
        minimum_offset: int,
        ml_context: dict[str, object],
    ) -> list[dict[str, object]]:
        del self, _file_obj, file_size, minimum_offset, ml_context
        call_counter["calls"] += 1
        return []

    monkeypatch.setattr(PickleScanner, "_scan_global_references_unbounded", _counting_scan)

    small_path = tmp_path / "small.pkl"
    small_path.write_bytes(pickle.dumps({"safe": True}, protocol=4))
    scanner.scan(str(small_path))
    assert call_counter["calls"] == 0

    scanner.max_opcodes = 16
    large_path = tmp_path / "large-budget.pkl"
    large_path.write_bytes(_make_opcode_padding_stream(opcode_pairs=256) + pickle.dumps({"safe": True}, protocol=4))
    scanner.scan(str(large_path))
    assert call_counter["calls"] == 1


def test_post_budget_global_scan_warning_only_for_unknown_import(tmp_path: Path) -> None:
    """Unknown third-party imports beyond the budget should stay at warning severity."""
    pickle_path = tmp_path / "post-budget-unknown-import.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    suspicious_stream = b"\x80\x02cmysterypkg\nloader\n."
    pickle_path.write_bytes(benign_padding + suspicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Global Reference Scan"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.WARNING
    assert "mysterypkg.loader" in checks[0].message
    assert checks[0].details["dangerous_references"] == []
    references = checks[0].details["references"]
    assert any(
        finding["import_reference"] == "mysterypkg.loader" and finding["severity"] == IssueSeverity.WARNING.value
        for finding in references
    )
    assert result.success is True


def test_post_budget_global_scan_honors_configured_byte_limit(tmp_path: Path) -> None:
    """Configured byte limits should bound how far the fallback scan can see."""
    gap = b"A" * 256
    malicious_stream = b"\x80\x02cos\nsystem\n)R."
    payload = b"B" * 32 + gap + malicious_stream
    minimum_offset = 32

    hidden_findings = PickleScanner(
        {"post_budget_global_scan_limit_bytes": len(gap) - 1}
    )._scan_global_references_unbounded(
        BytesIO(payload),
        file_size=len(payload),
        minimum_offset=minimum_offset,
        ml_context={},
    )
    visible_findings = PickleScanner(
        {"post_budget_global_scan_limit_bytes": len(gap) + len(malicious_stream)}
    )._scan_global_references_unbounded(
        BytesIO(payload),
        file_size=len(payload),
        minimum_offset=minimum_offset,
        ml_context={},
    )

    assert hidden_findings == []
    assert any(finding["import_reference"] == "os.system" for finding in visible_findings)


def test_collect_post_budget_opcodes_respects_opcode_cap() -> None:
    """Tail opcode collection should stop once it reaches the configured cap."""
    scanner = PickleScanner()

    opcodes = scanner._collect_post_budget_opcodes(
        _make_opcode_padding_stream(opcode_pairs=32),
        scan_start=0,
        deadline=None,
        scan_label="test",
        opcode_limit=8,
    )

    assert len(opcodes) == 8
    assert all(position is not None for _opcode, _arg, position in opcodes)
    assert opcodes[-1][0].name != "STOP"


def test_post_budget_global_scan_uses_stack_global_opcode_offset() -> None:
    """STACK_GLOBAL references that cross the budget boundary should still be reported."""
    raw_stack_global = _short_binunicode(b"os") + _short_binunicode(b"system") + b"\x93"
    scanner = PickleScanner()

    findings = scanner._scan_global_references_unbounded(
        BytesIO(raw_stack_global),
        file_size=len(raw_stack_global),
        minimum_offset=len(raw_stack_global) - 1,
        ml_context={},
    )

    assert len(findings) == 1
    assert findings[0]["import_reference"] == "os.system"
    assert findings[0]["opcode"] == "STACK_GLOBAL"
    assert findings[0]["offset"] == len(raw_stack_global) - 1


@pytest.mark.parametrize(
    ("builder", "memo_ops"),
    [
        (lambda value: b"\x8c" + bytes([len(value)]) + value, (b"\x94", b"\x94")),
        (lambda value: b"X" + struct.pack("<I", len(value)) + value, (b"\x94", b"\x94")),
        (lambda value: b"\x8d" + struct.pack("<Q", len(value)) + value, (b"\x94", b"\x94")),
        (lambda value: b"\x8c" + bytes([len(value)]) + value, (b"q\x00", b"q\x01")),
        (lambda value: b"\x8c" + bytes([len(value)]) + value, (b"r\x00\x00\x00\x00", b"r\x01\x00\x00\x00")),
        (lambda value: b"\x8c" + bytes([len(value)]) + value, (b"p0\n", b"p1\n")),
    ],
)
def test_post_budget_global_scan_recovers_stack_global_with_memoized_strings(
    builder: Callable[[bytes], bytes], memo_ops: tuple[bytes, bytes]
) -> None:
    """STACK_GLOBAL tails with interleaved memo opcodes should still be recovered."""
    raw_stack_global = builder(b"os") + memo_ops[0] + builder(b"system") + memo_ops[1] + b"\x93"
    scanner = PickleScanner()

    findings = scanner._scan_global_references_unbounded(
        BytesIO(raw_stack_global),
        file_size=len(raw_stack_global),
        minimum_offset=len(raw_stack_global) - 1,
        ml_context={},
    )

    assert len(findings) == 1
    assert findings[0]["import_reference"] == "os.system"
    assert findings[0]["opcode"] == "STACK_GLOBAL"
    assert findings[0]["offset"] == len(raw_stack_global) - 1


def test_scan_pickle_detects_post_budget_stack_global_with_binput(tmp_path: Path) -> None:
    """End-to-end scans should catch STACK_GLOBAL tails that use BINPUT memo opcodes."""
    pickle_path = tmp_path / "post-budget-stack-global-binput.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = b"\x80\x04" + _short_binunicode(b"os") + b"q\x00" + _short_binunicode(b"system") + b"q\x01"
    malicious_stream += b"\x93)R."
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Global Reference Scan"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in checks[0].message
    assert result.success is False


def test_post_budget_global_scan_uses_consumed_opcode_boundary(tmp_path: Path) -> None:
    """Large operands should not consume the entire post-budget tail window."""
    pickle_path = tmp_path / "post-budget-consumed-boundary.pkl"
    payload = b"\x80\x04" + b"\x8d" + struct.pack("<Q", 120) + (b"A" * 120) + b"cmysterypkg\nloader\n."
    pickle_path.write_bytes(payload)

    result = PickleScanner({"max_opcodes": 1, "post_budget_global_scan_limit_bytes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Global Reference Scan"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.WARNING
    assert "mysterypkg.loader" in checks[0].message
    expected_minimum_offset = len(b"\x80\x04") + len(b"\x8d") + struct.calcsize("<Q") + 120
    assert checks[0].details["minimum_offset"] == expected_minimum_offset
    assert result.success is True


def test_post_budget_opcode_scan_uses_consumed_opcode_boundary(tmp_path: Path) -> None:
    """Opcode tail scans should start at the consumed boundary, not inside the prior payload."""
    pickle_path = tmp_path / "post-budget-opcode-consumed-boundary.pkl"
    inner_pickle = pickle.dumps({"ab": 1}, protocol=4)
    poison_payload = b"\x8c\xff" + (b"A" * 4998)
    payload = (
        b"\x80\x04"
        + b"B"
        + struct.pack("<I", len(poison_payload))
        + poison_payload
        + b"B"
        + struct.pack("<I", len(inner_pickle))
        + inner_pickle
        + b"."
    )
    pickle_path.write_bytes(payload)

    result = PickleScanner({"max_opcodes": 1}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert "Nested pickle payload detected" in checks[0].message
    assert any(
        finding["check_name"] == "Nested Pickle Detection" and finding["details"].get("opcode") == "BINBYTES"
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert result.success is False


def test_pickle_expansion_heuristics_detect_iterative_memo_growth(tmp_path: Path) -> None:
    """Repeated memo growth chains should surface a dedicated expansion warning."""
    pickle_path = tmp_path / "memo-expansion.pkl"
    pickle_path.write_bytes(_make_memo_expansion_pickle(iterations=80))

    result = PickleScanner().scan(str(pickle_path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status == CheckStatus.FAILED
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    check = expansion_checks[0]
    assert check.severity == IssueSeverity.WARNING
    assert any("memo_growth_chain" in finding["triggers"] for finding in check.details["findings"]), check.details


def test_pickle_expansion_heuristics_detect_diluted_memo_growth(tmp_path: Path) -> None:
    """Inert memo writes must not suppress a real memo-growth expansion chain."""
    pickle_path = tmp_path / "memo-expansion-diluted.pkl"
    pickle_path.write_bytes(_make_memo_expansion_pickle(iterations=80, inert_writes=80))

    result = PickleScanner().scan(str(pickle_path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status == CheckStatus.FAILED
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    check = expansion_checks[0]
    assert any("memo_growth_chain" in finding["triggers"] for finding in check.details["findings"]), check.details


def test_pickle_expansion_heuristics_detect_dup_heavy_payload(tmp_path: Path) -> None:
    """Dense DUP usage with extreme memo recall should trigger the expansion heuristics."""
    pickle_path = tmp_path / "dup-heavy.pkl"
    pickle_path.write_bytes(_make_dup_heavy_pickle(iterations=200))

    loaded = pickle.loads(pickle_path.read_bytes())
    result = PickleScanner().scan(str(pickle_path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status == CheckStatus.FAILED
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    assert len(loaded) == 200
    assert loaded[0] is loaded
    check = expansion_checks[0]
    assert check.severity == IssueSeverity.WARNING
    assert any("excessive_dup_usage" in finding["triggers"] for finding in check.details["findings"]), check.details
    assert any("suspicious_get_put_ratio" in finding["triggers"] for finding in check.details["findings"]), (
        check.details
    )


def test_pickle_expansion_heuristics_ignore_benign_shared_reference_payload(tmp_path: Path) -> None:
    """Shared references alone should not trip the expansion heuristics."""
    shared = [1, 2, 3]
    pickle_path = tmp_path / "shared-reference.pkl"
    pickle_path.write_bytes(pickle.dumps([shared] * 1000, protocol=4))

    result = PickleScanner().scan(str(pickle_path))

    expansion_checks = [check for check in result.checks if check.name == "Pickle Expansion Heuristic Check"]
    assert len(expansion_checks) == 1, f"Expected one expansion heuristic check, got: {result.checks}"
    assert expansion_checks[0].status == CheckStatus.PASSED
    assert not any(
        check.name == "Pickle Expansion Heuristic Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), f"Unexpected expansion heuristic finding: {result.checks}"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_post_budget_expansion_scan_detects_follow_on_stream(tmp_path: Path) -> None:
    """A later-stream expansion bomb must still be detected after the opcode budget is exhausted."""
    pickle_path = tmp_path / "post-budget-expansion.pkl"
    pickle_path.write_bytes(_make_opcode_padding_stream(64) + _make_memo_expansion_pickle(iterations=80))

    result = PickleScanner({"max_opcodes": 64, "post_budget_expansion_scan_limit_bytes": 4096}).scan(str(pickle_path))

    post_budget_checks = [
        check
        for check in result.checks
        if check.name == "Post-Budget Pickle Expansion Heuristic Check" and check.status == CheckStatus.FAILED
    ]
    assert len(post_budget_checks) == 1, f"Expected one failed post-budget expansion check, got: {result.checks}"
    assert any("memo_growth_chain" in finding["triggers"] for finding in post_budget_checks[0].details["findings"]), (
        post_budget_checks[0].details
    )


def test_post_budget_expansion_scan_ignores_benign_follow_on_stream(tmp_path: Path) -> None:
    """A benign later stream must not trigger the post-budget expansion heuristic."""
    pickle_path = tmp_path / "post-budget-benign.pkl"
    pickle_path.write_bytes(_make_opcode_padding_stream(64) + pickle.dumps({"safe": True}, protocol=2))

    result = PickleScanner({"max_opcodes": 64, "post_budget_expansion_scan_limit_bytes": 4096}).scan(str(pickle_path))

    assert not any(
        check.name == "Post-Budget Pickle Expansion Heuristic Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), result.checks


@pytest.mark.parametrize(
    ("memo_write_ops", "memo_read_ops"),
    [
        ((b"\x94", b"\x94"), (b"h\x00", b"h\x01")),
        ((b"p0\n", b"p1\n"), (b"g0\n", b"g1\n")),
        ((b"r\x00\x00\x00\x00", b"r\x01\x00\x00\x00"), (b"j\x00\x00\x00\x00", b"j\x01\x00\x00\x00")),
    ],
)
def test_post_budget_global_scan_recovers_stack_global_with_memo_reads(
    memo_write_ops: tuple[bytes, bytes], memo_read_ops: tuple[bytes, bytes]
) -> None:
    """Memoized string reads should remain resolvable in the post-budget STACK_GLOBAL fallback."""
    raw_stack_global = (
        _short_binunicode(b"os")
        + memo_write_ops[0]
        + _short_binunicode(b"system")
        + memo_write_ops[1]
        + memo_read_ops[0]
        + memo_read_ops[1]
        + b"\x93"
    )
    scanner = PickleScanner()

    findings = scanner._scan_global_references_unbounded(
        BytesIO(raw_stack_global),
        file_size=len(raw_stack_global),
        minimum_offset=len(raw_stack_global) - 1,
        ml_context={},
    )

    assert len(findings) == 1
    assert findings[0]["import_reference"] == "os.system"
    assert findings[0]["opcode"] == "STACK_GLOBAL"
    assert findings[0]["offset"] == len(raw_stack_global) - 1


def test_post_budget_global_scan_recovers_unicode_stack_global() -> None:
    """UNICODE-encoded STACK_GLOBAL values should be recoverable from the post-budget tail."""
    raw_stack_global = b"\x80\x04Vos\nVsystem\n\x93."
    scanner = PickleScanner()

    findings = scanner._scan_global_references_unbounded(
        BytesIO(raw_stack_global),
        file_size=len(raw_stack_global),
        minimum_offset=0,
        ml_context={},
    )

    assert len(findings) == 1
    assert findings[0]["import_reference"] == "os.system"
    assert findings[0]["opcode"] == "STACK_GLOBAL"
    assert findings[0]["offset"] == len(raw_stack_global) - 2


def test_post_budget_global_scan_recovers_stack_global_after_frame() -> None:
    """FRAME boundaries should not suppress STACK_GLOBAL recovery in the tail scan."""
    raw_stack_global = (
        b"\x80\x04"
        + b"\x95\x0c\x00\x00\x00\x00\x00\x00\x00"
        + _short_binunicode(b"os")
        + b"\x94"
        + _short_binunicode(b"system")
        + b"\x94"
        + b"\x93."
    )
    scanner = PickleScanner()

    findings = scanner._scan_global_references_unbounded(
        BytesIO(raw_stack_global),
        file_size=len(raw_stack_global),
        minimum_offset=0,
        ml_context={},
    )

    assert len(findings) == 1
    assert findings[0]["import_reference"] == "os.system"
    assert findings[0]["opcode"] == "STACK_GLOBAL"
    assert findings[0]["offset"] == len(raw_stack_global) - 2


def test_scan_pickle_detects_post_budget_stack_global_with_binget(tmp_path: Path) -> None:
    """End-to-end scans should catch STACK_GLOBAL tails that use BINGET memo reads."""
    pickle_path = tmp_path / "post-budget-stack-global-binget.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = (
        b"\x80\x04" + _short_binunicode(b"os") + b"\x94" + _short_binunicode(b"system") + b"\x94" + b"h\x00h\x01\x93)R."
    )
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Global Reference Scan"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert "os.system" in checks[0].message
    assert result.success is False


def test_post_budget_opcode_scan_detects_nested_pickle_payload(tmp_path: Path) -> None:
    """Nested inner pickle payloads beyond the opcode budget should still be surfaced."""
    inner_pickle = pickle.dumps({"ab": 1}, protocol=4)
    pickle_path = tmp_path / "post-budget-nested-pickle.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = b"\x80\x04B" + struct.pack("<I", len(inner_pickle)) + inner_pickle + b"."
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert "Nested pickle payload detected" in checks[0].message
    assert any(
        finding["check_name"] == "Nested Pickle Detection" and finding["details"].get("opcode") == "BINBYTES"
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert not any(
        check.name == "Post-Budget Global Reference Scan" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), f"Expected opcode-based detection, got: {result.checks}"
    assert result.success is False


def test_post_budget_opcode_scan_detects_encoded_pickle_payload(tmp_path: Path) -> None:
    """Encoded inner pickle payloads beyond the opcode budget should still be surfaced."""
    import base64

    inner_pickle = pickle.dumps({"ab": 1}, protocol=4)
    encoded_pickle = base64.b64encode(inner_pickle)
    pickle_path = tmp_path / "post-budget-encoded-pickle.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = b"\x80\x04" + _short_binunicode(encoded_pickle) + b"."
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert "Encoded pickle payload detected" in checks[0].message
    assert any(
        finding["check_name"] == "Encoded Pickle Detection"
        and finding["details"].get("encoding") == "base64"
        and finding["details"].get("opcode") == "SHORT_BINUNICODE"
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert not any(
        check.name == "Post-Budget Global Reference Scan" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), f"Expected opcode-based detection, got: {result.checks}"
    assert result.success is False


def test_post_budget_opcode_scan_detects_encoded_python_payload(tmp_path: Path) -> None:
    """Encoded Python payloads beyond the opcode budget should stay aligned with the main loop."""
    import base64

    encoded_python = base64.b64encode(b"import os\nos.system('id')\n")
    pickle_path = tmp_path / "post-budget-encoded-python.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = b"\x80\x04" + _short_binunicode(encoded_python) + b"."
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.WARNING
    assert "Encoded Python code detected (base64)" in checks[0].message
    assert any(
        finding["check_name"] == "Encoded Python Code Detection"
        and finding["details"].get("encoding") == "base64"
        and finding["details"].get("opcode") == "SHORT_BINUNICODE"
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert result.success is True


def test_post_budget_opcode_scan_ignores_decoy_nested_headers_without_pickle(tmp_path: Path) -> None:
    """Valid-looking nested-pickle decoys beyond the opcode budget must stay quiet."""
    pickle_path = tmp_path / "post-budget-decoy-headers.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    decoy_headers = b"\x80\x04J" * 400
    benign_stream = b"\x80\x04B" + struct.pack("<I", len(decoy_headers)) + decoy_headers + b"."
    pickle_path.write_bytes(benign_padding + benign_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    assert not any(
        check.name == "Post-Budget Opcode Detection" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Unexpected post-budget opcode finding for decoy headers: {result.checks}"
    assert result.success is True


def test_post_budget_opcode_scan_ignores_benign_encoded_string_payload(tmp_path: Path) -> None:
    """Harmless encoded tails beyond the opcode budget must not trip post-budget findings."""
    import base64

    encoded_benign = base64.b64encode(b"just a harmless ascii string with no code execution here")
    pickle_path = tmp_path / "post-budget-benign-encoded-string.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    benign_stream = b"\x80\x04" + _short_binunicode(encoded_benign) + b"."
    pickle_path.write_bytes(benign_padding + benign_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    assert not any(
        check.name == "Post-Budget Opcode Detection" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Unexpected post-budget opcode finding for benign encoded string: {result.checks}"
    assert result.success is True


def test_post_budget_opcode_scan_detects_malformed_stack_global(tmp_path: Path) -> None:
    """Malformed STACK_GLOBAL payloads beyond the opcode budget should still fail closed."""
    pickle_path = tmp_path / "post-budget-malformed-stack-global.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    malicious_stream = b"\x80\x04\x8c\x02osK\x01\x93."
    pickle_path.write_bytes(benign_padding + malicious_stream)

    result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["check_name"] == "STACK_GLOBAL Context Check"
        and finding["details"].get("module") == "os"
        and finding["details"].get("reason") == "mixed_or_non_string"
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert not any(
        check.name == "Post-Budget Global Reference Scan" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), f"Expected opcode-based detection, got: {result.checks}"
    assert result.success is False


def test_post_budget_opcode_scan_detects_ext_reduce_target(tmp_path: Path) -> None:
    """Dangerous EXT/copyreg call targets beyond the opcode budget should still be surfaced."""
    import copyreg
    from contextlib import suppress

    inverted_registry = getattr(copyreg, "_inverted_registry", {})
    extension_registry = getattr(copyreg, "_extension_registry", {})
    existing_code = extension_registry.get(("builtins", "set"))

    ext_code = next((candidate for candidate in range(1, 256) if candidate not in inverted_registry), None)
    if ext_code is None:
        pytest.skip("No free copyreg extension code available in range 1-255")

    pickle_path = tmp_path / "post-budget-ext-reduce.pkl"
    benign_padding = _make_opcode_padding_stream(opcode_pairs=512)
    result: ScanResult | None = None

    try:
        if isinstance(existing_code, int):
            with suppress(ValueError):
                copyreg.remove_extension("builtins", "set", existing_code)

        copyreg.add_extension("builtins", "set", ext_code)
        malicious_stream = b"\x80\x02\x82" + bytes([ext_code]) + b")R."
        pickle_path.write_bytes(benign_padding + malicious_stream)

        result = PickleScanner({"max_opcodes": 64}).scan(str(pickle_path))
    finally:
        with suppress(ValueError):
            copyreg.remove_extension("builtins", "set", ext_code)
        if isinstance(existing_code, int):
            with suppress(ValueError):
                copyreg.add_extension("builtins", "set", existing_code)

    assert result is not None
    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["check_name"] == "Reduce Pattern Analysis"
        and finding["details"].get("module") == "builtins"
        and finding["details"].get("function") == "set"
        and finding["details"].get("origin_is_ext") is True
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert not any(
        check.name == "Post-Budget Global Reference Scan" and check.status == CheckStatus.FAILED
        for check in result.checks
    ), f"Expected opcode-based detection, got: {result.checks}"
    assert result.success is False


def test_post_budget_opcode_scan_preserves_cross_boundary_reduce_context(tmp_path: Path) -> None:
    """Dangerous REDUCE targets split by the opcode budget should still resolve from prefix context."""
    pickle_path = tmp_path / "post-budget-cross-boundary-reduce.pkl"
    pickle_path.write_bytes(b"\x80\x04cos\nsystem\n)R.")

    result = PickleScanner({"max_opcodes": 2}).scan(str(pickle_path))

    checks = [check for check in result.checks if check.name == "Post-Budget Opcode Detection"]
    assert len(checks) == 1, f"Expected one post-budget opcode finding, got: {result.checks}"
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].severity == IssueSeverity.CRITICAL
    assert _contains_system_global(checks[0].message)
    assert any(
        finding["check_name"] == "Reduce Pattern Analysis"
        and finding["details"].get("module") in {"os", "posix", "nt"}
        and finding["details"].get("function") == "system"
        for finding in checks[0].details["findings"]
    ), checks[0].details
    assert result.success is False


def test_post_budget_global_scan_runs_after_deadline_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deadline-triggered truncation should not continue scanning past the timeout boundary."""
    import modelaudit.scanners.pickle_scanner as pickle_scanner_module

    pickle_path = tmp_path / "post-budget-deadline.pkl"
    pickle_path.write_bytes(b"\x80\x04cmysterypkg\nloader\n.")
    call_counter = {"calls": 0}

    def _deadline_after_first_opcode(
        file_obj: BinaryIO,
        *,
        multi_stream: bool = False,
        max_items: int | None = None,
        deadline: float | None = None,
    ) -> Iterator[tuple[Any, Any, int | None]]:
        del multi_stream, max_items, deadline
        op_iter = pickletools.genops(file_obj)
        yield next(op_iter)
        raise _GenopsBudgetExceeded("deadline")

    def _counting_tail_scan(
        self: PickleScanner,
        _file_obj: object,
        *,
        file_size: int,
        minimum_offset: int,
        ml_context: dict[str, object],
    ) -> list[dict[str, object]]:
        del self, _file_obj, file_size, minimum_offset, ml_context
        call_counter["calls"] += 1
        return []

    monkeypatch.setattr(pickle_scanner_module, "_genops_with_fallback", _deadline_after_first_opcode)
    monkeypatch.setattr(PickleScanner, "_scan_global_references_unbounded", _counting_tail_scan)

    result = PickleScanner({"timeout": 1}).scan(str(pickle_path))

    timeout_checks = [check for check in result.checks if check.name == "Scan Timeout Check"]
    assert timeout_checks and timeout_checks[0].status == CheckStatus.FAILED
    assert call_counter["calls"] == 0
    checks = [check for check in result.checks if check.name == "Post-Budget Global Reference Scan"]
    assert checks == []
    assert result.metadata["post_budget_global_scan_skipped_due_to_timeout"] is True
    assert result.success is False


def test_invalid_post_budget_global_scan_limit_uses_default() -> None:
    """Invalid config values should not crash scanner construction."""
    scanner = PickleScanner({"post_budget_global_scan_limit_bytes": "not-an-int"})

    assert scanner.post_budget_global_scan_limit_bytes > 0


class TestPickleScanner(unittest.TestCase):
    def setUp(self):
        # Path to assets/samples/pickles/evil.pickle sample
        self.evil_pickle_path = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        # Create the evil pickle if it doesn't exist
        if not self.evil_pickle_path.exists():
            evil_obj = EvilClass()
            with self.evil_pickle_path.open("wb") as f:
                pickle.dump(evil_obj, f)

    def test_scan_evil_pickle(self):
        """Test that the scanner can detect the malicious pickle
        created by assets/generators/generate_evil_pickle.py"""
        scanner = PickleScanner()
        result = scanner.scan(str(self.evil_pickle_path))

        # Check that the scan completed successfully
        assert result.success

        # Check that issues were found
        assert result.has_errors

        # Print the found issues for debugging
        print(f"Found {len(result.issues)} issues:")
        for issue in result.issues:
            print(f"  - {issue.severity.name}: {issue.message}")

        # Check that specific issues were detected
        has_reduce_detection = False
        has_os_system_detection = False

        for issue in result.issues:
            if "REDUCE" in issue.message:
                has_reduce_detection = True
            if _contains_system_global(issue.message):
                has_os_system_detection = True

        assert has_reduce_detection, "Failed to detect REDUCE opcode"
        assert has_os_system_detection, "Failed to detect os.system/posix.system/nt.system reference"

    def test_scan_dill_pickle(self):
        """Scanner should flag suspicious dill references"""
        dill_pickle_path = Path(__file__).parent.parent / "assets/samples/pickles/dill_func.pkl"
        if not dill_pickle_path.exists():

            def func(x):
                return x

            with dill_pickle_path.open("wb") as f:
                dill.dump(func, f)

        scanner = PickleScanner()
        result = scanner.scan(str(dill_pickle_path))

        assert result.success
        assert result.has_errors or result.has_warnings
        assert any("dill" in issue.message for issue in result.issues)

    def test_scan_nonexistent_file(self):
        """Scanner returns failure and error issue for missing file"""
        scanner = PickleScanner()
        result = scanner.scan("nonexistent_file.pkl")

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_scan_bin_file_with_suspicious_binary_content(self):
        """Test scanning .bin file with suspicious code patterns in binary data"""
        scanner = PickleScanner()

        # Create a temporary .bin file with pickle header + suspicious binary content
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)

                # Add suspicious binary content
                pattern_import = BINARY_CODE_PATTERNS[0]
                pattern_eval = next(p for p in BINARY_CODE_PATTERNS if p.startswith(b"eval"))
                suspicious_content = b"some_data" + pattern_import + b"more_data" + pattern_eval + b"end_data"
                f.write(suspicious_content)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find suspicious patterns
                suspicious_issues = [
                    issue for issue in result.issues if "suspicious code pattern" in issue.message.lower()
                ]
                assert len(suspicious_issues) >= 2  # Should find both "import os" and "eval("

                # Check metadata
                assert "pickle_bytes" in result.metadata
                assert "binary_bytes" in result.metadata
                assert result.metadata["binary_bytes"] > 0

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_with_executable_signatures(self):
        """Test scanning .bin file with executable signatures in binary data"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"model": "test"}
                pickle.dump(simple_data, f)

                # Add binary content with executable signatures
                f.write(b"some_padding")
                sigs = list(EXECUTABLE_SIGNATURES.keys())
                f.write(sigs[0])  # PE signature
                f.write(b"padding" * 10)
                f.write(b"This program cannot be run in DOS mode")  # DOS stub
                f.write(b"more_padding")
                f.write(sigs[1])  # Another signature
                f.write(b"end_padding")
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find executable signatures
                executable_issues = [
                    issue for issue in result.issues if "executable signature" in issue.message.lower()
                ]
                assert len(executable_issues) >= 2  # Should find both PE and ELF signatures

                # Check that errors are reported for executable signatures
                error_issues = [issue for issue in executable_issues if issue.severity == IssueSeverity.CRITICAL]
                assert len(error_issues) >= 2

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_clean_binary_content(self):
        """Test scanning .bin file with clean binary content (no issues)"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)

                # Add clean binary content (simulating tensor data)
                clean_content = b"\x00" * 1000 + b"\x01" * 500 + b"\xff" * 200
                f.write(clean_content)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should not find any suspicious patterns in binary content
                binary_issues = [issue for issue in result.issues if "binary data" in issue.message.lower()]
                assert len(binary_issues) == 0
            finally:
                os.unlink(f.name)


class TestPickleScannerAdvanced(unittest.TestCase):
    def setUp(self) -> None:
        # Ensure advanced pickle assets exist
        generate_stack_global_attack()
        generate_memo_based_attack()
        generate_multiple_pickle_attack()

    def test_stack_global_detection(self) -> None:
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "stack_global_attack.pkl"))

        assert len(result.issues) > 0, "Expected issues to be detected for STACK_GLOBAL attack"
        os_issues = [
            i
            for i in result.issues
            if "os" in i.message.lower() or "posix" in i.message.lower() or "nt" in i.message.lower()
        ]
        assert len(os_issues) > 0, f"Expected OS-related issues, but found: {[i.message for i in result.issues]}"

    def test_advanced_global_reference_issue_has_rule_code(self) -> None:
        """Dangerous advanced global references should keep a rule code on the primary finding."""
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "stack_global_attack.pkl"))

        reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.details.get("associated_global") in SYSTEM_GLOBAL_VARIANTS
        ]
        assert reduce_checks, f"Expected primary REDUCE finding, got: {[i.message for i in result.issues]}"
        assert all(check.rule_code for check in reduce_checks), (
            f"Expected rule codes on primary REDUCE findings, got: {[check.rule_code for check in reduce_checks]}"
        )
        assert any(
            evidence.get("check_name") == "STACK_GLOBAL Module Check"
            and evidence.get("details", {}).get("import_reference") in SYSTEM_GLOBAL_VARIANTS
            for check in reduce_checks
            for evidence in check.details.get("supporting_evidence", [])
        ), f"Expected folded STACK_GLOBAL evidence on os/posix/nt.system finding: {reduce_checks}"

    def test_memo_object_tracking(self) -> None:
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "memo_attack.pkl"))

        assert len(result.issues) > 0, "Expected issues to be detected for memo-based attack"
        subprocess_issues = [i for i in result.issues if "subprocess" in i.message.lower()]
        assert len(subprocess_issues) > 0, (
            f"Expected subprocess issues, but found: {[i.message for i in result.issues]}"
        )


class TestDillLoadersRegression:
    def test_global_dill_loads_is_flagged(self, tmp_path: Path) -> None:
        payload = tmp_path / "global_dill_loads.pkl"
        payload.write_bytes(b"cdill\nloads\n.")

        result = PickleScanner().scan(str(payload))

        failed_global_checks = [
            check
            for check in result.checks
            if check.name == "Global Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
        ]
        assert any(check.details.get("import_reference") == "dill.loads" for check in failed_global_checks)

    def test_global_dill_load_is_flagged(self, tmp_path: Path) -> None:
        payload = tmp_path / "global_dill_load.pkl"
        payload.write_bytes(b"cdill\nload\n.")

        result = PickleScanner().scan(str(payload))

        failed_global_checks = [
            check
            for check in result.checks
            if check.name == "Global Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
        ]
        assert any(check.details.get("import_reference") == "dill.load" for check in failed_global_checks)

    def test_stack_global_dill_loads_is_flagged(self, tmp_path: Path) -> None:
        payload = tmp_path / "stack_global_dill_loads.pkl"
        payload.write_bytes(b"\x80\x04\x95\x13\x00\x00\x00\x00\x00\x00\x00\x8c\x04dill\x94\x8c\x05loads\x94\x93\x94.")

        result = PickleScanner().scan(str(payload))

        failed_stack_checks = [
            check
            for check in result.checks
            if check.name == "STACK_GLOBAL Module Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
        ]
        assert any(
            check.details.get("module") == "dill" and check.details.get("function") == "loads"
            for check in failed_stack_checks
        )

    def test_benign_pickle_with_dill_string_is_not_flagged(self, tmp_path: Path) -> None:
        payload = tmp_path / "benign_dill_string.pkl"
        with payload.open("wb") as handle:
            pickle.dump({"serializer": "dill", "metadata": "safe"}, handle)

        result = PickleScanner().scan(str(payload))

        assert result.success
        assert not any("dill." in issue.message for issue in result.issues)

    def test_existing_safe_pickle_fixture_unaffected(self) -> None:
        fixture = Path(__file__).parent.parent / "assets" / "samples" / "pickles" / "safe_data.pkl"

        result = PickleScanner().scan(str(fixture))

        assert result.success
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_dill_dump_remains_non_failing(self, tmp_path: Path) -> None:
        payload = tmp_path / "reduce_dill_dump.pkl"
        payload.write_bytes(b"\x80\x02cdill\ndump\n(tR.")

        result = PickleScanner().scan(str(payload))

        assert result.success
        assert not result.has_errors

    def test_multiple_pickle_streams(self) -> None:
        scanner = PickleScanner()
        result = scanner.scan(str(Path(__file__).parent.parent / "assets" / "pickles" / "multiple_stream_attack.pkl"))

        assert len(result.issues) > 0, "Expected issues to be detected for multiple pickle streams"
        eval_issues = [i for i in result.issues if "eval" in i.message.lower()]
        assert len(eval_issues) > 0, f"Expected eval issues, but found: {[i.message for i in result.issues]}"

    def test_reduce_pattern_detects_memoized_callable(self) -> None:
        """REDUCE analysis should resolve memoized call targets (BINGET/LONG_BINGET)."""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                payload = bytearray(b"\x80\x02")
                payload += b"cposix\nsystem\n"  # GLOBAL posix.system
                payload += b"q\x01"  # BINPUT 1 (memoize callable)
                payload += b"0"  # POP original callable from stack
                # Add filler opcodes so target isn't adjacent to REDUCE
                for i in range(12):
                    filler = f"f{i}".encode()
                    payload += b"X" + struct.pack("<I", len(filler)) + filler
                    payload += b"0"
                payload += b"h\x01"  # BINGET 1
                arg = b"echo test"
                payload += b"X" + struct.pack("<I", len(arg)) + arg
                payload += b"\x85R."  # TUPLE1 + REDUCE + STOP

                f.write(payload)
                f.flush()
                f.close()

                result = scanner.scan(f.name)

                reduce_checks = [
                    c
                    for c in result.checks
                    if c.name == "REDUCE Opcode Safety Check"
                    and c.status == CheckStatus.FAILED
                    and c.details.get("associated_global") in SYSTEM_GLOBAL_VARIANTS
                ]
                assert reduce_checks, "Expected REDUCE detection for memoized os/posix/nt.system target"
                assert any(
                    evidence.get("check_name") == "Reduce Pattern Analysis"
                    for check in reduce_checks
                    for evidence in check.details.get("supporting_evidence", [])
                ), f"Expected Reduce Pattern Analysis evidence to fold into REDUCE finding: {result.checks}"
                assert not any(
                    c.name == "Reduce Pattern Analysis" and c.status == CheckStatus.FAILED for c in result.checks
                ), f"Expected memoized reduce root cause to be deduplicated: {result.checks}"

            finally:
                os.unlink(f.name)

    def test_stack_global_uses_actual_stack_not_popped_decoys(self) -> None:
        """STACK_GLOBAL resolution should follow stack semantics, not nearby popped strings."""
        scanner = PickleScanner()

        import os
        import tempfile

        def short_binunicode(value: bytes) -> bytes:
            return b"\x8c" + bytes([len(value)]) + value

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                payload = bytearray(b"\x80\x04")
                payload += short_binunicode(b"os")
                payload += short_binunicode(b"system")

                # Push/pop decoys that should NOT affect STACK_GLOBAL target.
                for i in range(6):
                    junk = f"junk{i}".encode()
                    payload += short_binunicode(junk)
                    payload += b"0"  # POP

                # Safe-looking decoys near STACK_GLOBAL that are immediately popped.
                payload += short_binunicode(b"torch._utils")
                payload += b"0"
                payload += short_binunicode(b"_rebuild_tensor_v2")
                payload += b"0"

                payload += b"\x93"  # STACK_GLOBAL (should still resolve to os.system)
                payload += short_binunicode(b"echo test")
                payload += b"\x85R."

                f.write(payload)
                f.flush()
                f.close()

                result = scanner.scan(f.name)

                reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
                matching_reduce_checks = [
                    c for c in reduce_checks if c.status.value == "failed" and _contains_system_global(c.message)
                ]
                assert matching_reduce_checks, (
                    f"Expected REDUCE check to resolve os/posix/nt.system, got: {[c.message for c in reduce_checks]}"
                )
                assert any(
                    evidence.get("check_name") == "STACK_GLOBAL Module Check"
                    and evidence.get("details", {}).get("import_reference") in SYSTEM_GLOBAL_VARIANTS
                    for check in matching_reduce_checks
                    for evidence in check.details.get("supporting_evidence", [])
                ), f"Expected folded STACK_GLOBAL evidence on REDUCE finding: {matching_reduce_checks}"

            finally:
                os.unlink(f.name)

    def test_scan_regular_pickle_file(self):
        """Test that regular .pkl files don't trigger binary content scanning"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                # Write a simple pickle
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should not have pickle_bytes or binary_bytes metadata (not a .bin file)
                assert "pickle_bytes" not in result.metadata
                assert "binary_bytes" not in result.metadata

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_pytorch_high_confidence_skips_binary_scan(self):
        """Test that high-confidence PyTorch models skip binary scanning to avoid false positives"""
        scanner = PickleScanner()

        # Create a complex ML-like data structure that might trigger some ML detection
        # Focus on collections.OrderedDict which is a common PyTorch pattern
        import collections
        import os
        import tempfile

        # Create nested OrderedDict structures that mimic PyTorch state_dict patterns
        complex_ml_data = collections.OrderedDict(
            [
                ("features.0.weight", "tensor_data_placeholder"),
                ("features.0.bias", "tensor_data_placeholder"),
                ("features.3.weight", "tensor_data_placeholder"),
                ("features.3.bias", "tensor_data_placeholder"),
                ("classifier.weight", "tensor_data_placeholder"),
                ("classifier.bias", "tensor_data_placeholder"),
                ("_metadata", collections.OrderedDict([("version", 1)])),
                ("_modules", collections.OrderedDict()),
                ("_parameters", collections.OrderedDict()),
            ],
        )

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                pickle.dump(complex_ml_data, f)

                # Add binary content that would normally trigger warnings
                suspicious_binary_content = (
                    b"MZ"
                    + b"padding" * 100
                    + b"This program cannot be run in DOS mode"
                    + b"more_data"
                    + b"import os"
                    + b"eval("
                    + b"subprocess.call"
                )
                f.write(suspicious_binary_content)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Check the ML context that was detected
                ml_context = result.metadata.get("ml_context", {})
                ml_confidence = ml_context.get("overall_confidence", 0)
                is_pytorch = "pytorch" in ml_context.get("frameworks", {})

                # Test the logic: if pytorch detected with high confidence, binary scan should be skipped
                if is_pytorch and ml_confidence > 0.7:
                    # Should have skipped binary scanning
                    assert result.metadata.get("binary_scan_skipped") is True
                    assert "High-confidence PyTorch model detected" in result.metadata.get("skip_reason", "")

                    # Should not find binary-related issues (since binary scan was skipped)
                    binary_issues = [
                        issue
                        for issue in result.issues
                        if "binary data" in issue.message.lower() or "executable signature" in issue.message.lower()
                    ]
                    assert len(binary_issues) == 0, (
                        f"Found unexpected binary issues: {[issue.message for issue in binary_issues]}"
                    )
                else:
                    # If conditions not met, binary scan should proceed normally
                    assert result.metadata.get("binary_scan_skipped") is not True
                    print(
                        f"ML confidence too low ({ml_confidence}) or PyTorch not detected ({is_pytorch}) - "
                        f"binary scan proceeded normally"
                    )

                # Should have metadata about the scan regardless
                assert "pickle_bytes" in result.metadata
                assert "binary_bytes" in result.metadata
                assert result.metadata["binary_bytes"] > 0

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_low_confidence_performs_binary_scan(self):
        """Test that low-confidence ML models still perform binary scanning"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Create a pickle with minimal ML context (low confidence)
                low_confidence_data = {
                    "data": [1, 2, 3, 4, 5],
                    "some_weights": [0.1, 0.2, 0.3],
                }
                pickle.dump(low_confidence_data, f)

                # Add binary content with executable signatures
                f.write(b"some_padding")
                f.write(b"\x7fELF")  # Linux ELF executable signature
                f.write(b"more_padding")
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should NOT have skipped binary scanning
                assert result.metadata.get("binary_scan_skipped") is not True

                # Should have performed binary scan and found the ELF signature
                executable_issues = [
                    issue for issue in result.issues if "executable signature" in issue.message.lower()
                ]
                assert len(executable_issues) >= 1, "Should have found ELF signature"

            finally:
                os.unlink(f.name)

    def test_pe_file_detection_requires_dos_stub(self):
        """Test that PE file detection requires both MZ signature and DOS stub message"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"test": "data"}
                pickle.dump(simple_data, f)

                # Add MZ signature WITHOUT DOS stub (should not trigger PE detection)
                f.write(b"some_padding")
                f.write(b"MZ")  # PE signature but no DOS stub
                f.write(b"random_data" * 50)  # Random data without DOS stub message
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should NOT find PE executable signature (missing DOS stub)
                pe_issues = [issue for issue in result.issues if "windows executable (pe)" in issue.message.lower()]
                assert len(pe_issues) == 0, (
                    f"Should not detect PE without DOS stub, but found: {[issue.message for issue in pe_issues]}"
                )

            finally:
                os.unlink(f.name)

    def test_pe_file_detection_with_dos_stub(self):
        """Test that PE file detection works when both MZ signature and DOS stub are present"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"test": "data"}
                pickle.dump(simple_data, f)

                # Add proper PE signature WITH DOS stub
                f.write(b"some_padding")
                f.write(b"MZ")  # PE signature
                f.write(b"dos_header_data" * 5)  # Some padding
                f.write(b"This program cannot be run in DOS mode")  # DOS stub message
                f.write(b"more_data" * 10)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find PE executable signature
                pe_issues = [issue for issue in result.issues if "windows executable (pe)" in issue.message.lower()]
                assert len(pe_issues) >= 1, "Should detect PE with DOS stub"

                pe_error_issues = [issue for issue in pe_issues if issue.severity == IssueSeverity.CRITICAL]
                assert len(pe_error_issues) >= 1, "PE detection should be CRITICAL severity"

            finally:
                os.unlink(f.name)

    def test_pe_file_detection_with_dos_stub_after_offset_100(self, tmp_path: Path) -> None:
        """PE signatures with a valid DOS stub should be detected even after offset 100."""
        scanner = PickleScanner()

        test_file = tmp_path / "embedded_pe_after_offset_100.bin"
        with test_file.open("wb") as f:
            simple_data = {"test": "data"}
            pickle.dump(simple_data, f)

            # Force MZ well past 100 bytes with only a single PE signature.
            f.write(b"A" * 256)
            f.write(b"MZ")
            f.write(b"dos_header_data" * 5)
            f.write(b"This program cannot be run in DOS mode")
            f.write(b"tail_data")

        result = scanner.scan(str(test_file))

        assert result.success

        pe_issues = [issue for issue in result.issues if "windows executable (pe)" in issue.message.lower()]
        assert len(pe_issues) >= 1, "Should detect embedded PE after offset 100"
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in pe_issues), (
            "Embedded PE detection should remain CRITICAL"
        )

        ignored_pe_issues = [
            issue
            for issue in result.issues
            if "ignored" in issue.message.lower() and "pe executable patterns" in issue.message.lower()
        ]
        assert len(ignored_pe_issues) == 0, "Validated PE signatures should not be suppressed"

    def test_nested_pickle_detection(self):
        """Scanner should detect nested pickle bytes and encoded payloads"""
        scanner = PickleScanner()

        import base64
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                inner = {"a": 1}
                inner_bytes = pickle.dumps(inner)
                outer = {
                    "raw": inner_bytes,
                    "enc": base64.b64encode(inner_bytes).decode("ascii"),
                }
                pickle.dump(outer, f)
                f.flush()
                f.close()  # Close file before scanning (required on Windows to allow deletion)

                result = scanner.scan(f.name)

                assert result.success

                nested_issues = [
                    i
                    for i in result.issues
                    if "nested pickle payload" in i.message.lower() or "encoded pickle payload" in i.message.lower()
                ]
                assert nested_issues
                assert any(i.severity == IssueSeverity.CRITICAL for i in nested_issues)

            finally:
                os.unlink(f.name)


class TestPickleScannerBlocklistHardening(unittest.TestCase):
    """Regression tests for fickling/picklescan bypass hardening."""

    HELPER_REFS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("numpy.f2py.crackfortran", "getlincoef"),
        ("torch._dynamo.guards.GuardBuilder", "get"),
        ("torch.fx.experimental.symbolic_shapes.ShapeEnv", "evaluate_guards_expression"),
        ("torch.utils.collect_env", "run"),
        ("torch.utils._config_module.ConfigModule", "load_config"),
        ("torch.utils.bottleneck.__main__", "run_cprofile"),
        ("torch.utils.bottleneck.__main__", "run_autograd_prof"),
        ("torch.utils.data.datapipes.utils.decoder", "basichandlers"),
    )

    PICKLESCAN_GAP_REFS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("numpy", "load"),
        ("site", "main"),
        ("_io", "FileIO"),
        ("test.support.script_helper", "assert_python_ok"),
        ("_osx_support", "_read_output"),
        ("_aix_support", "_read_cmd_output"),
        ("_pyrepl.pager", "pipe_pager"),
        ("torch.serialization", "load"),
        ("torch._inductor.codecache", "compile_file"),
    )

    @staticmethod
    def _craft_global_reduce_pickle(module: str, func: str) -> bytes:
        """Craft a minimal pickle that uses GLOBAL + REDUCE to call module.func.

        The resulting pickle is: PROTO 2 | GLOBAL 'module func' | MARK | TUPLE | REDUCE | STOP
        This is structurally valid but should be caught by the scanner without
        actually being unpickled.
        """

        # Use protocol 2
        proto = b"\x80\x02"
        # GLOBAL opcode: 'c' followed by "module\nfunc\n"
        global_op = b"c" + f"{module}\n{func}\n".encode()
        # MARK + empty TUPLE (arguments) + REDUCE + STOP
        call_ops = b"(" + b"t" + b"R" + b"."
        return proto + global_op + call_ops

    @staticmethod
    def _craft_stack_global_reduce_pickle(module: str, func: str) -> bytes:
        """Craft protocol-4 payload with STACK_GLOBAL + REDUCE."""

        return b"\x80\x04" + _short_binunicode(module.encode()) + _short_binunicode(func.encode()) + b"\x93(tR."

    @staticmethod
    def _craft_memoized_stack_global_reduce_pickle(module: str, func: str) -> bytes:
        """Craft protocol-4 payload that recalls a memoized STACK_GLOBAL before REDUCE."""

        payload = bytearray(b"\x80\x04")
        payload += _short_binunicode(module.encode())
        payload += _short_binunicode(func.encode())
        payload += b"\x93"  # STACK_GLOBAL
        payload += b"\x94"  # MEMOIZE index 0
        payload += b"0"  # POP
        payload += b"h\x00"  # BINGET 0
        payload += b"("  # MARK
        payload += b"t"  # TUPLE
        payload += b"R"  # REDUCE
        payload += b"."
        return bytes(payload)

    @staticmethod
    def _craft_global_import_only_pickle(module: str, func: str) -> bytes:
        """Craft minimal pickle that only imports a GLOBAL and stops."""

        return TestPickleScannerBlocklistHardening._craft_global_only_pickle(module, func)

    @staticmethod
    def _craft_global_only_pickle(module: str, func: str) -> bytes:
        """Craft a minimal pickle with a bare GLOBAL reference and STOP."""

        return b"\x80\x02" + b"c" + f"{module}\n{func}\n".encode() + b"."

    def _scan_bytes(self, data: bytes, *, suffix: str = ".pkl") -> ScanResult:
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            f.write(data)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            return scanner.scan(path)
        finally:
            os.unlink(path)

    def test_nested_pickle_detection_binbytes8_and_bytearray8(self) -> None:
        """BINBYTES8/BYTEARRAY8 payloads should be scanned for nested pickles."""
        inner_bytes = pickle.dumps({"ab": 1}, protocol=4)

        for opcode_name, payload in (
            ("BINBYTES8", b"\x80\x04\x8e" + struct.pack("<Q", len(inner_bytes)) + inner_bytes + b"."),
            ("BYTEARRAY8", b"\x80\x05\x96" + struct.pack("<Q", len(inner_bytes)) + inner_bytes + b"."),
        ):
            with self.subTest(opcode_name=opcode_name):
                result = self._scan_bytes(payload)

                nested_checks = [
                    check
                    for check in result.checks
                    if check.name == "Nested Pickle Detection" and check.status == CheckStatus.FAILED
                ]
                assert any(check.details.get("opcode") == opcode_name for check in nested_checks), (
                    f"Expected nested pickle detection for {opcode_name}, got: "
                    f"{[(c.name, c.status, c.details) for c in result.checks]}"
                )

    def test_non_pickle_binbytes8_and_bytearray8_do_not_trigger_nested_detection(self) -> None:
        """Non-pickle BINBYTES8/BYTEARRAY8 payloads should not trigger nested pickle findings."""
        benign_bytes = b"not a pickle payload"

        for payload in (
            b"\x80\x04\x8e" + struct.pack("<Q", len(benign_bytes)) + benign_bytes + b".",
            b"\x80\x05\x96" + struct.pack("<Q", len(benign_bytes)) + benign_bytes + b".",
        ):
            with self.subTest(payload=payload[:3]):
                result = self._scan_bytes(payload)

                assert not any(
                    check.name == "Nested Pickle Detection" and check.status == CheckStatus.FAILED
                    for check in result.checks
                ), f"Unexpected nested pickle detection: {[(c.name, c.status, c.details) for c in result.checks]}"

    def test_nested_pickle_detection_binstring_legacy(self) -> None:
        """BINSTRING/SHORT_BINSTRING carry raw bytes as latin-1 strings; nested pickles must be detected."""
        inner_bytes = pickle.dumps({"ab": 1}, protocol=2)

        # SHORT_BINSTRING: opcode 'U', 1-byte length, protocol 2
        short_binstring_payload = b"\x80\x02U" + bytes([len(inner_bytes)]) + inner_bytes + b"."
        result = self._scan_bytes(short_binstring_payload)
        nested_checks = [
            c for c in result.checks if c.name == "Nested Pickle Detection" and c.status == CheckStatus.FAILED
        ]
        assert any(c.details.get("opcode") == "SHORT_BINSTRING" for c in nested_checks), (
            f"Expected nested pickle detection for SHORT_BINSTRING, got: "
            f"{[(c.name, c.status, c.details) for c in result.checks]}"
        )

        # BINSTRING: opcode 'T', 4-byte little-endian length, protocol 1
        binstring_payload = b"\x80\x02T" + struct.pack("<i", len(inner_bytes)) + inner_bytes + b"."
        result = self._scan_bytes(binstring_payload)
        nested_checks = [
            c for c in result.checks if c.name == "Nested Pickle Detection" and c.status == CheckStatus.FAILED
        ]
        assert any(c.details.get("opcode") == "BINSTRING" for c in nested_checks), (
            f"Expected nested pickle detection for BINSTRING, got: "
            f"{[(c.name, c.status, c.details) for c in result.checks]}"
        )

    def test_offset_nested_pickle_detection_binbytes_variants(self) -> None:
        """Nested pickles hidden behind padding in BINBYTES variants must still be found."""
        inner_bytes = pickle.dumps({"ab": 1}, protocol=4)
        padding = b"A" * 2048
        padded_inner = padding + inner_bytes

        for opcode_name, payload in (
            ("BINBYTES8", b"\x80\x04\x8e" + struct.pack("<Q", len(padded_inner)) + padded_inner + b"."),
            ("BYTEARRAY8", b"\x80\x05\x96" + struct.pack("<Q", len(padded_inner)) + padded_inner + b"."),
        ):
            with self.subTest(opcode_name=opcode_name):
                result = self._scan_bytes(payload)
                nested_checks = [
                    check
                    for check in result.checks
                    if check.name == "Nested Pickle Detection" and check.status == CheckStatus.FAILED
                ]

                assert any(
                    check.details.get("opcode") == opcode_name and check.details.get("nested_offset") == len(padding)
                    for check in nested_checks
                ), f"Expected offset nested pickle detection for {opcode_name}, got: {result.checks}"

    def test_find_nested_pickle_match_scans_past_decoy_headers(self) -> None:
        """Valid-looking decoy headers must not exhaust the bounded nested-header search."""
        inner_bytes = pickle.dumps({"ab": 1}, protocol=4)
        decoy_headers = b"\x80\x04J" * 256

        nested_match = _find_nested_pickle_match(decoy_headers + inner_bytes)

        assert nested_match is not None
        assert nested_match.offset == len(decoy_headers)

    def test_nested_pickle_detection_survives_decoy_header_flood(self) -> None:
        """Nested pickle detection must survive dense decoy header triplets."""
        inner_bytes = pickle.dumps({"ab": 1}, protocol=4)
        decoy_headers = b"\x80\x04J" * 256
        embedded = decoy_headers + inner_bytes
        payload = b"\x80\x04B" + struct.pack("<I", len(embedded)) + embedded + b"."

        result = self._scan_bytes(payload)

        assert result.success
        nested_checks = [
            check
            for check in result.checks
            if check.name == "Nested Pickle Detection" and check.status == CheckStatus.FAILED
        ]
        assert any(
            check.details.get("opcode") == "BINBYTES" and check.details.get("nested_offset") == len(decoy_headers)
            for check in nested_checks
        ), f"Expected nested pickle detection after decoy headers, got: {result.checks}"

    def test_find_nested_pickle_match_ignores_decoy_header_flood_without_pickle(self) -> None:
        """Valid-looking decoy headers alone must not look like a nested pickle."""
        decoy_headers = b"\x80\x04J" * 400

        assert _find_nested_pickle_match(decoy_headers) is None

    def test_nested_pickle_detection_ignores_decoy_header_flood_without_pickle(self) -> None:
        """Dense decoy headers without a real inner pickle must not trigger findings."""
        embedded = b"\x80\x04J" * 400
        payload = b"\x80\x04B" + struct.pack("<I", len(embedded)) + embedded + b"."

        result = self._scan_bytes(payload)

        assert not any(
            check.name == "Nested Pickle Detection" and check.status == CheckStatus.FAILED for check in result.checks
        ), f"Unexpected nested pickle detection for decoy flood: {result.checks}"

    def test_offset_nested_pickle_detection_binstring(self) -> None:
        """Offset inner pickles in BINSTRING must not evade legacy-string scanning."""
        inner_bytes = pickle.dumps({"ab": 1}, protocol=2)
        padding = b"A" * 1536
        padded_inner = padding + inner_bytes
        payload = b"\x80\x02T" + struct.pack("<i", len(padded_inner)) + padded_inner + b"."

        result = self._scan_bytes(payload)

        nested_checks = [
            c for c in result.checks if c.name == "Nested Pickle Detection" and c.status == CheckStatus.FAILED
        ]
        assert any(
            c.details.get("opcode") == "BINSTRING" and c.details.get("nested_offset") == len(padding)
            for c in nested_checks
        ), f"Expected offset nested pickle detection for BINSTRING, got: {result.checks}"

    def test_offset_encoded_nested_pickle_detection(self) -> None:
        """Base64 and hex strings should surface nested pickles even when the decoded bytes are padded."""
        import base64

        inner_bytes = pickle.dumps({"ab": 1}, protocol=4)
        padding = b"A" * 1536
        padded_inner = padding + inner_bytes

        for encoding, encoded_payload in (
            ("base64", base64.b64encode(padded_inner).decode("ascii")),
            ("hex", padded_inner.hex()),
        ):
            with self.subTest(encoding=encoding):
                outer = pickle.dumps({"payload": encoded_payload}, protocol=4)
                result = self._scan_bytes(outer)
                encoded_checks = [
                    check
                    for check in result.checks
                    if check.name == "Encoded Pickle Detection" and check.status == CheckStatus.FAILED
                ]

                assert any(
                    check.details.get("encoding") == encoding and check.details.get("nested_offset") == len(padding)
                    for check in encoded_checks
                ), f"Expected offset encoded pickle detection for {encoding}, got: {result.checks}"

    def test_non_pickle_binstring_does_not_trigger_nested_detection(self) -> None:
        """Non-pickle BINSTRING/SHORT_BINSTRING payloads should not trigger nested pickle findings."""
        benign = b"just a plain string"

        for opcode, length in (
            (b"U", bytes([len(benign)])),
            (b"T", struct.pack("<i", len(benign))),
        ):
            with self.subTest(opcode=opcode):
                payload = b"\x80\x02" + opcode + length + benign + b"."
                result = self._scan_bytes(payload)
                assert not any(
                    c.name == "Nested Pickle Detection" and c.status == CheckStatus.FAILED for c in result.checks
                ), f"Unexpected nested pickle detection: {[(c.name, c.status, c.details) for c in result.checks]}"

    def test_incomplete_trailing_header_prefix_is_ignored(self) -> None:
        """Trailing 0x80/proto fragments must not raise during nested-header search."""
        for data in (
            b"A\x80\x04",
            b"A" * (_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES - 2) + b"\x80\x04",
        ):
            with self.subTest(length=len(data)):
                assert _find_nested_pickle_match(data) is None

    def test_large_benign_raw_blob_does_not_trigger_nested_detection(self) -> None:
        """Large raw blobs with invalid header-like bytes should stay below the nested-pickle threshold."""
        benign_bytes = b"A" * 2048 + b"\x80\x04ZZ" + b"B" * (_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES + 1024)
        payload = b"\x80\x04\x8e" + struct.pack("<Q", len(benign_bytes)) + benign_bytes + b"."

        result = self._scan_bytes(payload)

        assert not any(
            check.name == "Nested Pickle Detection" and check.status == CheckStatus.FAILED for check in result.checks
        ), f"Unexpected nested pickle detection for benign blob: {result.checks}"

    def test_large_benign_encoded_blobs_do_not_trigger_nested_detection(self) -> None:
        """Large decoded blobs with fake headers should not produce encoded nested-pickle findings."""
        import base64

        benign_decoded = b"A" * 1536 + b"\x80\x04ZZ" + b"B" * 800

        for encoding, encoded_payload in (
            ("base64", base64.b64encode(benign_decoded).decode("ascii")),
            ("hex", benign_decoded.hex()),
        ):
            with self.subTest(encoding=encoding):
                outer = pickle.dumps({"payload": encoded_payload}, protocol=4)
                result = self._scan_bytes(outer)

                assert not any(
                    check.name == "Encoded Pickle Detection" and check.status == CheckStatus.FAILED
                    for check in result.checks
                ), f"Unexpected encoded nested pickle detection for {encoding}: {result.checks}"

    def test_builtins_hasattr_is_critical(self) -> None:
        """builtins.hasattr must not be allowlisted as safe."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("builtins", "hasattr"))

        assert result.success
        assert result.has_errors
        failed_reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("associated_global") == "builtins.hasattr"
        ]
        assert failed_reduce_checks, (
            f"Expected CRITICAL REDUCE primary for builtins.hasattr, got: {[check.message for check in result.checks]}"
        )
        assert any(
            evidence.get("check_name") == "Global Module Reference Check"
            and evidence.get("details", {}).get("import_reference") == "builtins.hasattr"
            for check in failed_reduce_checks
            for evidence in check.details.get("supporting_evidence", [])
        ), f"Expected folded GLOBAL evidence on builtins.hasattr finding: {failed_reduce_checks}"

    def test_dunder_builtin_hasattr_is_critical(self) -> None:
        """__builtin__.hasattr must not be allowlisted as safe."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("__builtin__", "hasattr"))

        assert result.success
        assert result.has_errors
        failed_reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("associated_global") == "__builtin__.hasattr"
        ]
        assert failed_reduce_checks, (
            f"Expected CRITICAL REDUCE primary for __builtin__.hasattr, got: "
            f"{[check.message for check in result.checks]}"
        )
        assert any(
            evidence.get("check_name") == "Global Module Reference Check"
            and evidence.get("details", {}).get("import_reference") == "__builtin__.hasattr"
            for check in failed_reduce_checks
            for evidence in check.details.get("supporting_evidence", [])
        ), f"Expected folded GLOBAL evidence on __builtin__.hasattr finding: {failed_reduce_checks}"

    def test_safe_builtins_remain_allowlisted(self) -> None:
        """Safe reconstruction builtins must remain non-failing."""
        for safe_builtin in ["set", "slice", "tuple"]:
            result = self._scan_bytes(self._craft_global_reduce_pickle("builtins", safe_builtin))

            assert result.success
            assert not result.has_errors, (
                f"Expected builtins.{safe_builtin} to remain non-failing, got: {[i.message for i in result.issues]}"
            )
            safe_global_checks = [check for check in result.checks if check.name == "Global Module Reference Check"]
            failed_builtin_checks = [
                check
                for check in result.checks
                if check.status == CheckStatus.FAILED and f"builtins.{safe_builtin}" in check.message
            ]
            assert any(
                check.status == CheckStatus.PASSED and f"builtins.{safe_builtin}" in check.message
                for check in safe_global_checks
            ), f"Expected passed Global Module Reference Check for builtins.{safe_builtin}"
            assert not any(check.status == CheckStatus.FAILED for check in safe_global_checks), (
                f"Unexpected failed Global Module Reference Check for builtins.{safe_builtin}: "
                f"{[check.message for check in safe_global_checks]}"
            )
            assert not failed_builtin_checks, (
                f"Expected builtins.{safe_builtin} to stay non-failing across all checks, "
                f"got: {[check.message for check in failed_builtin_checks]}"
            )

    def test_dangerous_builtins_still_fail(self) -> None:
        """Dangerous builtins must continue to fail after allowlist tightening."""
        for dangerous_builtin in ["eval", "open"]:
            result = self._scan_bytes(self._craft_global_reduce_pickle("builtins", dangerous_builtin))

            assert result.success
            assert result.has_errors
            failed_checks = [
                check
                for check in result.checks
                if check.status == CheckStatus.FAILED and check.severity == IssueSeverity.CRITICAL
            ]
            assert any(f"builtins.{dangerous_builtin}" in check.message for check in failed_checks), (
                f"Expected CRITICAL builtins.{dangerous_builtin} finding, "
                f"got: {[check.message for check in failed_checks]}"
            )

    def test_builtins_hasattr_stack_global_is_critical(self) -> None:
        """STACK_GLOBAL resolution for builtins.hasattr must be flagged."""
        payload = b"\x80\x04\x8c\x08builtins\x8c\x07hasattr\x93)R."

        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        failed_reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("associated_global") == "builtins.hasattr"
        ]
        assert failed_reduce_checks, (
            f"Expected CRITICAL REDUCE primary for builtins.hasattr STACK_GLOBAL payload, "
            f"got: {[check.message for check in result.checks]}"
        )
        assert any(
            evidence.get("check_name") == "STACK_GLOBAL Module Check"
            and evidence.get("details", {}).get("import_reference") == "builtins.hasattr"
            for check in failed_reduce_checks
            for evidence in check.details.get("supporting_evidence", [])
        ), f"Expected folded STACK_GLOBAL evidence on builtins.hasattr finding: {failed_reduce_checks}"

    def test_framed_protocol_four_stack_global_import_only_is_critical(self) -> None:
        """A framed protocol-4 pickle should still surface dangerous STACK_GLOBAL refs."""
        payload = pickle.dumps(eval, protocol=4)

        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        failed_stack_global_checks = [
            check
            for check in result.checks
            if check.name == "STACK_GLOBAL Module Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
        ]
        assert any("builtins.eval" in check.message for check in failed_stack_global_checks), (
            f"Expected CRITICAL STACK_GLOBAL Module Check for builtins.eval, "
            f"got: {[check.message for check in failed_stack_global_checks]}"
        )

    def test_builtins_hasattr_binput_binget_recall_is_critical(self) -> None:
        """Memoized callable recall via BINPUT/BINGET must keep builtins.hasattr dangerous."""
        payload = b"\x80\x02cbuiltins\nhasattr\nq\x010h\x01(tR."

        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        failed_reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
        ]
        assert any(check.details.get("associated_global") == "builtins.hasattr" for check in failed_reduce_checks), (
            f"Expected CRITICAL REDUCE finding for builtins.hasattr memo recall, "
            f"got: {[check.details for check in failed_reduce_checks]}"
        )

    def test_builtins_hasattr_detected_after_benign_stream(self) -> None:
        """Malicious builtins.hasattr stream should be detected after benign warm-up stream."""
        import io

        buf = io.BytesIO()
        pickle.dump({"safe": True}, buf, protocol=2)
        buf.write(self._craft_global_reduce_pickle("builtins", "hasattr"))

        result = self._scan_bytes(buf.getvalue())

        assert result.success
        assert result.has_errors
        failed_reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
        ]
        assert any(check.details.get("associated_global") == "builtins.hasattr" for check in failed_reduce_checks), (
            f"Expected CRITICAL REDUCE finding for builtins.hasattr after benign stream, "
            f"got: {[check.details for check in failed_reduce_checks]}"
        )

    def test_plausible_module_allows_mixed_case_identifiers(self) -> None:
        assert _is_plausible_python_module("EVIL")
        assert _is_plausible_python_module("EvilPkg")
        assert _is_plausible_python_module("PIL")
        assert _is_plausible_python_module("MyOrg.InternalPkg")

    def test_plausible_module_rejects_malformed_names(self) -> None:
        assert not _is_plausible_python_module("foo bar")
        assert not _is_plausible_python_module("foo..bar")
        assert not _is_plausible_python_module("foo/bar")
        assert not _is_plausible_python_module("!!!")
        assert not _is_plausible_python_module("PEDRA_2020")

    def test_mixed_case_global_reduce_is_not_suppressed(self) -> None:
        result = self._scan_bytes(self._craft_global_reduce_pickle("EvilPkg", "thing"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(c.status == CheckStatus.FAILED and "EvilPkg.thing" in c.message for c in reduce_checks), (
            f"Expected failed REDUCE check for mixed-case module, got: {[c.message for c in reduce_checks]}"
        )
        assert not any("implausible module name 'EvilPkg'" in c.message for c in reduce_checks), (
            "Mixed-case module names should not be classified as implausible"
        )

    def test_uppercase_global_reduce_is_not_suppressed(self) -> None:
        result = self._scan_bytes(self._craft_global_reduce_pickle("EVIL", "run"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(c.status == CheckStatus.FAILED and "EVIL.run" in c.message for c in reduce_checks), (
            f"Expected failed REDUCE check for uppercase module, got: {[c.message for c in reduce_checks]}"
        )
        assert not any("implausible module name 'EVIL'" in c.message for c in reduce_checks), (
            "All-uppercase module names should not be classified as implausible"
        )

    def test_pil_global_reduce_is_not_suppressed(self) -> None:
        """Legitimate mixed-case modules like PIL should no longer be treated as implausible."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("PIL", "Image"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any("PIL.Image" in c.message for c in reduce_checks), (
            f"Expected REDUCE analysis to resolve PIL.Image, got: {[c.message for c in reduce_checks]}"
        )
        assert not any("implausible module name 'PIL'" in c.message for c in reduce_checks), (
            "PIL should no longer be classified as an implausible module"
        )

    def test_mixed_case_stack_global_reduce_is_not_suppressed(self) -> None:
        result = self._scan_bytes(self._craft_stack_global_reduce_pickle("EvilPkg", "thing"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(c.status == CheckStatus.FAILED and "EvilPkg.thing" in c.message for c in reduce_checks), (
            "Expected failed REDUCE check for STACK_GLOBAL mixed-case module, "
            f"got: {[c.message for c in reduce_checks]}"
        )
        assert not any("implausible module name 'EvilPkg'" in c.message for c in reduce_checks), (
            "Mixed-case STACK_GLOBAL paths should not be suppressed as implausible"
        )

    def test_mixed_case_memoized_stack_global_reduce_is_not_suppressed(self) -> None:
        result = self._scan_bytes(self._craft_memoized_stack_global_reduce_pickle("EvilPkg", "thing"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(c.status == CheckStatus.FAILED and "EvilPkg.thing" in c.message for c in reduce_checks), (
            "Expected failed REDUCE check for memoized mixed-case STACK_GLOBAL, "
            f"got: {[c.message for c in reduce_checks]}"
        )
        assert not any("implausible module name 'EvilPkg'" in c.message for c in reduce_checks), (
            "Memoized mixed-case STACK_GLOBAL paths should not be suppressed as implausible"
        )

    def test_mixed_case_import_only_payload_still_flags_import(self) -> None:
        result = self._scan_bytes(self._craft_global_import_only_pickle("Builtins", "eval"))

        import_issues = [issue for issue in result.issues if "Suspicious reference Builtins.eval" in issue.message]
        assert import_issues, (
            "Expected suspicious import-only detection for mixed-case dangerous global, "
            f"got: {[i.message for i in result.issues]}"
        )

        benign_result = self._scan_bytes(self._craft_global_import_only_pickle("EvilPkg", "thing"))
        benign_checks = [
            check
            for check in benign_result.checks
            if check.name == "Global Module Reference Check"
            and check.details.get("import_reference") == "EvilPkg.thing"
            and check.details.get("import_only") is True
        ]
        assert benign_checks, f"Expected import-only analysis for EvilPkg.thing: {benign_result.checks}"
        assert all(check.severity == IssueSeverity.WARNING for check in benign_checks), (
            f"Mixed-case unknown imports should not be escalated as dangerous: {benign_checks}"
        )
        assert all(check.details.get("classification") == "unknown_third_party" for check in benign_checks), (
            f"Expected mixed-case benign counterpart to stay unknown_third_party: {benign_checks}"
        )
        assert not any(
            check.severity == IssueSeverity.CRITICAL and check.details.get("import_reference") == "EvilPkg.thing"
            for check in benign_result.checks
        ), f"Unexpected critical mixed-case import finding for EvilPkg.thing: {benign_result.checks}"

    def test_mixed_case_unknown_import_only_is_flagged(self) -> None:
        """Mixed-case unknown import-only refs should now reach the import-only warning path."""
        result = self._scan_bytes(self._craft_global_import_only_pickle("EvilPkg", "thing"))

        failing_checks = [
            check
            for check in result.checks
            if check.name == "Global Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.WARNING
            and check.details.get("import_reference") == "EvilPkg.thing"
            and check.details.get("import_only") is True
            and check.details.get("classification") == "unknown_third_party"
        ]
        assert failing_checks, f"Expected import-only warning for EvilPkg.thing: {result.checks}"
        assert not any(
            "implausible module name 'EvilPkg'" in check.message
            for check in result.checks
            if check.name == "Global Module Reference Check"
        ), f"Mixed-case import-only path should not be suppressed as implausible: {result.checks}"
        assert any(
            issue.severity == IssueSeverity.WARNING and "EvilPkg.thing" in issue.message for issue in result.issues
        ), f"Expected warning issue for EvilPkg.thing: {result.issues}"

    def test_mixed_case_reduce_in_later_stream_is_not_suppressed(self) -> None:
        import io

        buf = io.BytesIO()
        pickle.dump({"safe": True}, buf, protocol=2)
        buf.write(self._craft_global_reduce_pickle("EvilPkg", "thing"))

        result = self._scan_bytes(buf.getvalue())
        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(c.status == CheckStatus.FAILED and "EvilPkg.thing" in c.message for c in reduce_checks), (
            f"Expected later-stream REDUCE check for mixed-case module, got: {[c.message for c in reduce_checks]}"
        )

    def test_malformed_module_reduce_stays_implausible(self) -> None:
        result = self._scan_bytes(self._craft_global_reduce_pickle("foo..bar", "thing"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(
            c.status == CheckStatus.PASSED and "implausible module name 'foo..bar'" in c.message for c in reduce_checks
        ), f"Expected malformed module to remain implausible, got: {[c.message for c in reduce_checks]}"

    def test_uppercase_data_label_reduce_stays_implausible(self) -> None:
        result = self._scan_bytes(self._craft_global_reduce_pickle("PEDRA_2020", "thing"))

        reduce_checks = [c for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
        assert any(
            c.status == CheckStatus.PASSED and "implausible module name 'PEDRA_2020'" in c.message
            for c in reduce_checks
        ), f"Expected uppercase data label to remain implausible, got: {[c.message for c in reduce_checks]}"

    @staticmethod
    def _structural_tamper_checks(result: ScanResult) -> list:
        return [issue for issue in result.issues if issue.details.get("tamper_type") is not None]

    # ------------------------------------------------------------------
    # Fix 1: pkgutil trampoline — must be CRITICAL
    # ------------------------------------------------------------------
    def test_pkgutil_resolve_name_critical(self) -> None:
        """pkgutil.resolve_name is a dynamic resolution trampoline to arbitrary callables."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("pkgutil", "resolve_name"))
        assert result.success
        assert result.has_errors
        critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        pkgutil_issues = [i for i in critical if "pkgutil" in i.message]
        assert pkgutil_issues, f"Expected CRITICAL pkgutil issue, got: {[i.message for i in result.issues]}"

    # ------------------------------------------------------------------
    # Fix 1: uuid RCE — must be CRITICAL
    # ------------------------------------------------------------------
    def test_uuid_get_command_stdout_critical(self) -> None:
        """uuid._get_command_stdout internally calls subprocess.Popen."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("uuid", "_get_command_stdout"))
        assert result.success
        assert result.has_errors
        critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        uuid_issues = [i for i in critical if "uuid" in i.message]
        assert uuid_issues, f"Expected CRITICAL uuid issue, got: {[i.message for i in result.issues]}"

    # ------------------------------------------------------------------
    # Fix 2: Multi-stream exploit (benign stream 1 + malicious stream 2)
    # ------------------------------------------------------------------
    def test_multi_stream_benign_then_malicious(self) -> None:
        """Scanner must detect malicious globals in stream 2 even if stream 1 is benign."""
        import io

        buf = io.BytesIO()
        # Stream 1: benign
        pickle.dump({"safe": True}, buf, protocol=2)
        # Stream 2: malicious — os.system via GLOBAL+REDUCE
        buf.write(self._craft_global_reduce_pickle("os", "system"))
        data = buf.getvalue()

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [
            i
            for i in result.issues
            if i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
        ]
        assert os_issues, f"Expected CRITICAL os issue in stream 2, got: {[i.message for i in result.issues]}"

    def test_multi_stream_separator_byte_resync(self) -> None:
        """Scanner must detect malicious stream even with junk separator bytes between streams."""
        import io

        buf = io.BytesIO()
        # Stream 1: benign
        pickle.dump({"safe": True}, buf, protocol=2)
        # Junk separator byte (non-pickle byte between streams)
        buf.write(b"\x00")
        # Stream 2: malicious — os.system via GLOBAL+REDUCE
        buf.write(self._craft_global_reduce_pickle("os", "system"))
        data = buf.getvalue()

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [
            i
            for i in result.issues
            if i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
        ]
        assert os_issues, f"Expected CRITICAL os issue after separator byte, got: {[i.message for i in result.issues]}"

    def test_multi_stream_large_padding_resync(self) -> None:
        """Scanner must detect malicious streams after padding larger than 64KiB."""
        import io

        buf = io.BytesIO()
        pickle.dump({"safe": True}, buf, protocol=2)
        buf.write(b"\x00" * (70 * 1024))
        buf.write(self._craft_global_reduce_pickle("os", "system"))

        result = self._scan_bytes(buf.getvalue())

        assert result.success
        assert any(
            i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
            for i in result.issues
        ), f"Expected CRITICAL os issue after large padding, got: {[i.message for i in result.issues]}"

    def test_multi_stream_large_padding_without_follow_on_stream_is_benign(self) -> None:
        """Large non-pickle padding after a benign stream should not create security findings."""
        import io

        buf = io.BytesIO()
        pickle.dump({"safe": True}, buf, protocol=2)
        buf.write(b"\x00" * (70 * 1024))

        result = self._scan_bytes(buf.getvalue())

        assert result.success
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues), (
            f"Unexpected critical issue for benign large padding: {[i.message for i in result.issues]}"
        )

    def test_multi_stream_malformed_first_stream_still_detects_second(self) -> None:
        """Scanner must detect malicious stream 2 even when stream 1 is malformed.

        A malformed first stream that triggers a ValueError during parsing must
        not cause the scanner to return early and skip subsequent streams.
        """
        import io

        buf = io.BytesIO()
        # Stream 1: starts with valid proto + benign GLOBAL, then malformed
        # bytes that cause a ValueError (invalid UTF-8 in GLOBAL arg).
        # This triggers the stream_error + had_opcodes early-return path.
        buf.write(b"\x80\x02cbuiltins\nlen\nq\x00c\xff\n")
        # Stream 2: malicious — os.system via GLOBAL+REDUCE
        buf.write(self._craft_global_reduce_pickle("os", "system"))
        data = buf.getvalue()

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [
            i
            for i in result.issues
            if i.severity == IssueSeverity.CRITICAL and ("os" in i.message.lower() or "posix" in i.message.lower())
        ]
        assert os_issues, (
            f"Expected CRITICAL os issue from stream 2 after malformed stream 1, "
            f"got: {[i.message for i in result.issues]}"
        )

    def test_stack_global_non_string_operands_fail_closed(self) -> None:
        """STACK_GLOBAL with two integers should be treated as a malformed warning."""
        payload = b"\x80\x04K\x01K\x02\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        assert any(c.status == CheckStatus.FAILED for c in context_checks), (
            f"Expected failed STACK_GLOBAL malformed check, got: {[c.message for c in context_checks]}"
        )
        assert any(
            c.severity == IssueSeverity.WARNING
            and c.rule_code == "S205"
            and c.details.get("reason") == "mixed_or_non_string"
            for c in context_checks
        ), (
            "Expected WARNING S205 malformed STACK_GLOBAL check, got: "
            f"{[(c.severity, c.rule_code) for c in context_checks]}"
        )

    def test_stack_global_dangerous_module_plus_non_string_operand_is_critical(self) -> None:
        """A dangerous module string plus a non-string operand should escalate to CRITICAL."""
        payload = b"\x80\x04\x8c\x02osK\x01\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        assert any(
            c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.CRITICAL
            and c.rule_code == "S205"
            and c.details.get("module") == "os"
            and c.details.get("reason") == "mixed_or_non_string"
            for c in context_checks
        ), f"Expected CRITICAL malformed STACK_GLOBAL check, got: {[(c.severity, c.message) for c in context_checks]}"

    def test_stack_global_risky_ml_module_prefix_plus_non_string_operand_is_critical(self) -> None:
        """Risky ML module hints should not downgrade malformed STACK_GLOBAL findings."""
        payload = b"\x80\x04\x8c\x0dtorch._dynamoK\x01\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        assert any(
            c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.CRITICAL
            and c.rule_code == "S205"
            and c.details.get("module") == "torch._dynamo"
            and c.details.get("reason") == "mixed_or_non_string"
            for c in context_checks
        ), (
            "Expected CRITICAL malformed STACK_GLOBAL finding for risky ML prefix, got: "
            f"{[(c.severity, c.message) for c in context_checks]}"
        )

    def test_stack_global_large_bytes_operand_preview_is_bounded(self) -> None:
        """Large malformed operands should not expand finding payloads."""
        large_bytes = b"x" * 200_000
        payload = b"\x80\x04\x8c\x02osB" + struct.pack("<I", len(large_bytes)) + large_bytes + b"\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        matching_checks = [
            c
            for c in context_checks
            if c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.CRITICAL
            and c.details.get("module") == "os"
            and c.details.get("reason") == "mixed_or_non_string"
        ]
        assert matching_checks, (
            f"Expected bounded CRITICAL malformed STACK_GLOBAL check, got: "
            f"{[(c.severity, c.message) for c in context_checks]}"
        )

        check = matching_checks[0]
        function_hint = check.details.get("function", "")
        assert function_hint.startswith("bytes(len=200000, hex=0x7878787878787878"), function_hint
        assert len(function_hint) < 80, f"Expected bounded operand preview, got len={len(function_hint)}"
        assert len(check.message) < 220, f"Expected bounded context-check message, got len={len(check.message)}"

    def test_stack_global_large_string_operand_preview_is_bounded(self) -> None:
        """Large string operands should not bloat malformed STACK_GLOBAL findings."""
        large_text = b"x" * 200_000
        payload = b"\x80\x04X" + struct.pack("<I", len(large_text)) + large_text + b"K\x01\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        matching_checks = [
            c
            for c in context_checks
            if c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.WARNING
            and c.details.get("reason") == "mixed_or_non_string"
        ]
        assert matching_checks, (
            f"Expected bounded malformed STACK_GLOBAL check, got: {[(c.severity, c.message) for c in context_checks]}"
        )

        check = matching_checks[0]
        module_hint = check.details.get("module", "")
        assert module_hint.startswith("xxxxxxxx"), module_hint
        assert len(module_hint) < 160, f"Expected bounded string preview, got len={len(module_hint)}"
        assert len(check.message) < 260, f"Expected bounded context-check message, got len={len(check.message)}"

    def test_stack_global_missing_memo_preserves_unknown_sentinel(self) -> None:
        """Missing memo operands should fail closed and keep unknown sentinel details."""
        payload = b"\x80\x04\x8c\x02osh\x7f\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        assert any(
            c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.CRITICAL
            and c.rule_code == "S205"
            and c.details.get("function") == "unknown"
            and c.details.get("reason") == "missing_memo"
            for c in context_checks
        ), f"Expected missing-memo STACK_GLOBAL finding, got: {[(c.severity, c.details) for c in context_checks]}"

    def test_stack_global_safe_memoized_reference_remains_passing(self) -> None:
        """Fully resolved safe memoized STACK_GLOBAL should stay non-failing."""
        payload = b"\x80\x04\x8c\x0ctorch._utils\x94\x8c\x12_rebuild_tensor_v2\x94h\x00h\x01\x93."

        result = self._scan_bytes(payload)
        assert result.success

        module_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Module Check"]
        assert any(c.status == CheckStatus.PASSED for c in module_checks), (
            f"Expected passing safe STACK_GLOBAL module check, got: {[c.message for c in module_checks]}"
        )

    def test_stack_global_dangerous_memoized_reference_remains_failing(self) -> None:
        """Fully resolved dangerous memoized STACK_GLOBAL should remain failing."""
        payload = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94h\x00h\x01\x93."

        result = self._scan_bytes(payload)
        assert result.success

        module_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Module Check"]
        assert any(c.status == CheckStatus.FAILED for c in module_checks), (
            f"Expected failing dangerous STACK_GLOBAL module check, got: {[c.message for c in module_checks]}"
        )

    def test_truncated_stack_global_context_remains_informational(self) -> None:
        """Simple stack-underflow context should remain informational, not fail-closed."""
        payload = b"\x80\x04\x8c\x02os\x93."

        result = self._scan_bytes(payload)
        assert result.success

        context_checks = [c for c in result.checks if c.name == "STACK_GLOBAL Context Check"]
        assert any(
            c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.INFO
            and c.rule_code == "S902"
            and c.message == "STACK_GLOBAL opcode found without sufficient string context"
            for c in context_checks
        ), (
            "Expected informational STACK_GLOBAL context check, got: "
            f"{[(c.severity, c.message) for c in context_checks]}"
        )

    def test_malformed_stack_global_first_stream_still_allows_benign_second_stream(self) -> None:
        """Malformed first stream should not taint benign second-stream behavior."""
        import io

        buf = io.BytesIO()
        buf.write(b"\x80\x04K\x01K\x02\x93.")
        pickle.dump({"safe": True}, buf, protocol=2)

        result = self._scan_bytes(buf.getvalue())
        assert result.success

        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert not critical_messages, f"Unexpected CRITICAL issues: {critical_messages}"
        assert any(c.name == "STACK_GLOBAL Context Check" and c.status == CheckStatus.FAILED for c in result.checks), (
            "Expected malformed STACK_GLOBAL finding in first stream"
        )

    def test_malformed_stack_global_plus_explicit_reduce_still_flags_reduce(self) -> None:
        """Malformed STACK_GLOBAL should not suppress explicit dangerous REDUCE detection."""
        import io

        buf = io.BytesIO()
        buf.write(b"\x80\x04K\x01K\x02\x93.")
        buf.write(self._craft_global_reduce_pickle("os", "system"))

        result = self._scan_bytes(buf.getvalue())
        assert result.success
        assert result.has_errors

        reduce_messages = [i.message.lower() for i in result.issues if "reduce" in i.message.lower()]
        assert any(_contains_system_global(msg) for msg in reduce_messages), (
            f"Expected dangerous REDUCE detection alongside malformed STACK_GLOBAL, got: {reduce_messages}"
        )

    def test_duplicate_proto_same_version_reports_structural_tamper(self) -> None:
        """Duplicate PROTO in one stream should be reported as structural tampering."""
        payload = b"\x80\x02\x80\x02K\x01."

        result = self._scan_bytes(payload)
        structural_checks = self._structural_tamper_checks(result)

        assert structural_checks, "Expected structural tamper finding for duplicate PROTO"
        assert any(issue.details.get("tamper_type") == "duplicate_proto" for issue in structural_checks), (
            f"Expected duplicate_proto finding, got: {[i.details for i in structural_checks]}"
        )
        assert any(issue.details.get("tamper_type") == "misplaced_proto" for issue in structural_checks), (
            f"Expected misplaced_proto finding, got: {[i.details for i in structural_checks]}"
        )
        assert any(issue.details.get("position") == 2 for issue in structural_checks), (
            f"Expected duplicate/misplaced PROTO position to be recorded, got: {[i.details for i in structural_checks]}"
        )

    def test_duplicate_proto_mixed_versions_reports_structural_tamper(self) -> None:
        """Mixed protocol redeclaration should include both protocol numbers in details."""
        payload = b"\x80\x02\x80\x04K\x01."

        result = self._scan_bytes(payload)
        structural_checks = self._structural_tamper_checks(result)
        duplicate = [issue for issue in structural_checks if issue.details.get("tamper_type") == "duplicate_proto"]

        assert duplicate, f"Expected duplicate_proto finding, got: {[i.details for i in structural_checks]}"
        assert any(
            issue.details.get("previous_protocol") == 2 and issue.details.get("protocol") == 4 for issue in duplicate
        ), f"Expected previous/current protocol details, got: {[i.details for i in duplicate]}"

    def test_misplaced_proto_reports_structural_tamper(self) -> None:
        """PROTO appearing after another opcode should be flagged as misplaced."""
        payload = b"K\x01\x80\x02."

        result = self._scan_bytes(payload)
        structural_checks = self._structural_tamper_checks(result)

        assert any(issue.details.get("tamper_type") == "misplaced_proto" for issue in structural_checks), (
            f"Expected misplaced_proto finding, got: {[i.details for i in structural_checks]}"
        )

    def test_valid_single_and_multi_stream_proto_stays_clean(self) -> None:
        """Normal stream boundaries with one PROTO each should not produce structural findings."""
        import io

        single = pickle.dumps({"safe": True}, protocol=4)
        single_result = self._scan_bytes(single)
        assert not self._structural_tamper_checks(single_result)

        buf = io.BytesIO()
        pickle.dump({"a": 1}, buf, protocol=2)
        buf.write(b"\x00")
        pickle.dump({"b": 2}, buf, protocol=4)
        multi_result = self._scan_bytes(buf.getvalue())

        assert not self._structural_tamper_checks(multi_result)

    def test_structural_tamper_in_second_stream_is_detected(self) -> None:
        """Tamper in a later stream should still be reported after a valid first stream."""
        import io

        buf = io.BytesIO()
        pickle.dump({"safe": True}, buf, protocol=2)
        buf.write(b"\x00")
        buf.write(b"\x80\x02\x80\x02K\x01.")

        result = self._scan_bytes(buf.getvalue())
        structural_checks = self._structural_tamper_checks(result)

        assert any(issue.details.get("tamper_type") == "duplicate_proto" for issue in structural_checks), (
            f"Expected duplicate_proto finding in later stream, got: {[i.details for i in structural_checks]}"
        )
        assert any(issue.details.get("stream_offset", 0) > 0 for issue in structural_checks), (
            f"Expected later-stream offset to be recorded, got: {[i.details for i in structural_checks]}"
        )

    def test_structural_tamper_and_malicious_import_both_reported(self) -> None:
        """Structural tamper findings must not hide direct code-execution findings."""
        payload = b"\x80\x02\x80\x02" + self._craft_global_reduce_pickle("os", "system")

        result = self._scan_bytes(payload)

        structural_checks = self._structural_tamper_checks(result)
        critical_os = [
            issue
            for issue in result.issues
            if issue.severity == IssueSeverity.CRITICAL
            and ("os" in issue.message.lower() or "posix" in issue.message.lower() or "nt" in issue.message.lower())
        ]
        assert structural_checks, "Expected structural tamper findings"
        assert critical_os, f"Expected CRITICAL os/posix/nt finding, got: {[i.message for i in result.issues]}"

    def test_structural_tamper_with_safe_ml_payload_only_info_severity(self) -> None:
        """Structural findings should remain low severity when payload is otherwise benign."""
        safe_payload = pickle.dumps({"layer": "linear", "shape": [4, 8]}, protocol=2)
        payload = b"\x80\x02" + safe_payload

        result = self._scan_bytes(payload)

        structural_checks = self._structural_tamper_checks(result)
        assert structural_checks, "Expected structural tamper finding for duplicate/misplaced PROTO"
        assert all(issue.severity == IssueSeverity.INFO for issue in structural_checks)

    def test_binary_tail_after_valid_pickle_does_not_report_structural_tamper(self) -> None:
        """Binary tail data after a valid pickle should not create structural findings."""
        payload = pickle.dumps({"safe": True}, protocol=2) + (b"XYZNmore-binary-data" * 20)

        result = self._scan_bytes(payload)

        assert not self._structural_tamper_checks(result), (
            f"Unexpected structural findings for benign binary tail: {[i.details for i in result.issues]}"
        )

    # ------------------------------------------------------------------
    # Fix 3: EXT opcode registry bypass
    # ------------------------------------------------------------------
    def test_ext_reduce_extension_registry_is_flagged(self) -> None:
        """EXT1/EXT2/EXT4 + REDUCE payloads should be flagged as dangerous."""
        import copyreg
        from contextlib import suppress

        inverted_registry = getattr(copyreg, "_inverted_registry", {})
        extension_registry = getattr(copyreg, "_extension_registry", {})
        existing_code = extension_registry.get(("os", "system"))

        def _pick_free_code(start: int, end: int) -> int:
            for candidate in range(start, end + 1):
                if candidate not in inverted_registry:
                    return candidate
            pytest.skip(f"No free copyreg extension code available in range {start}-{end}")

        cases = [
            ("EXT1", b"\x82", _pick_free_code(1, 255), lambda code: bytes([code])),
            ("EXT2", b"\x83", _pick_free_code(256, 65535), lambda code: struct.pack("<H", code)),
            ("EXT4", b"\x84", _pick_free_code(65536, 131072), lambda code: struct.pack("<I", code)),
        ]

        try:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.remove_extension("os", "system", existing_code)

            for _opcode_name, opcode, ext_code, encode in cases:
                copyreg.add_extension("os", "system", ext_code)
                try:
                    # PROTO 2 | EXT*(code) | MARK | STRING | TUPLE | REDUCE | STOP
                    payload = b"\x80\x02" + opcode + encode(ext_code) + b'(S"echo pwned"\ntR.'
                    result = self._scan_bytes(payload)

                    assert result.success
                    assert result.has_errors
                    reduce_issues = [i for i in result.issues if "reduce" in i.message.lower()]
                    assert reduce_issues, f"Expected REDUCE issue, got: {[i.message for i in result.issues]}"
                    assert any(_contains_system_global(i.message) for i in reduce_issues), (
                        "Expected resolved os/posix/nt.system in REDUCE issues, "
                        f"got: {[i.message for i in reduce_issues]}"
                    )
                finally:
                    with suppress(ValueError):
                        copyreg.remove_extension("os", "system", ext_code)
        finally:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.add_extension("os", "system", existing_code)

    def test_ext_unresolved_code_still_flagged(self) -> None:
        """EXT1/EXT2/EXT4 with codes NOT in copyreg registry should still be flagged."""
        import copyreg

        inverted_registry = getattr(copyreg, "_inverted_registry", {})

        def _pick_unregistered_code(start: int, end: int) -> int:
            for candidate in range(start, end + 1):
                if candidate not in inverted_registry:
                    return candidate
            pytest.skip(f"No unregistered copyreg code in range {start}-{end}")

        cases = [
            ("EXT1", b"\x82", _pick_unregistered_code(1, 255), lambda code: bytes([code])),
            ("EXT2", b"\x83", _pick_unregistered_code(256, 65535), lambda code: struct.pack("<H", code)),
            ("EXT4", b"\x84", _pick_unregistered_code(65536, 131072), lambda code: struct.pack("<I", code)),
        ]

        for opcode_name, opcode, ext_code, encode in cases:
            # Verify the code is truly unregistered
            assert ext_code not in inverted_registry, (
                f"{opcode_name} code {ext_code} unexpectedly in copyreg._inverted_registry"
            )
            # PROTO 2 | EXT*(code) | MARK | STRING | TUPLE | REDUCE | STOP
            payload = b"\x80\x02" + opcode + encode(ext_code) + b'(S"echo pwned"\ntR.'
            result = self._scan_bytes(payload)

            assert result.success, f"{opcode_name}: scan did not succeed"
            assert result.has_errors, (
                f"{opcode_name}: unresolved EXT code {ext_code} + REDUCE was not flagged, "
                f"issues: {[i.message for i in result.issues]}"
            )
            # The scanner should flag the REDUCE even when the EXT target is unresolved
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert critical_issues, (
                f"{opcode_name}: expected CRITICAL issue for unresolved EXT code {ext_code}, "
                f"got: {[i.message for i in result.issues]}"
            )

    def test_ext_resolved_to_safe_global_still_fails_due_to_ext_origin(self) -> None:
        """Resolved copyreg EXT targets must stay dangerous even when the target looks safe."""
        import copyreg
        from contextlib import suppress

        inverted_registry = getattr(copyreg, "_inverted_registry", {})
        extension_registry = getattr(copyreg, "_extension_registry", {})
        existing_code = extension_registry.get(("builtins", "set"))

        ext_code = next((candidate for candidate in range(1, 256) if candidate not in inverted_registry), None)
        if ext_code is None:
            pytest.skip("No free copyreg extension code available in range 1-255")

        try:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.remove_extension("builtins", "set", existing_code)

            copyreg.add_extension("builtins", "set", ext_code)
            try:
                payload = b"\x80\x02\x82" + bytes([ext_code]) + b")R."
                result = self._scan_bytes(payload)

                assert result.success
                assert result.has_errors
                reduce_checks = [
                    c
                    for c in result.checks
                    if c.name == "REDUCE Opcode Safety Check"
                    and c.status == CheckStatus.FAILED
                    and c.details.get("associated_global") == "builtins.set"
                    and c.details.get("origin_is_ext") is True
                ]
                assert reduce_checks, [c.details for c in result.checks if c.name == "REDUCE Opcode Safety Check"]
            finally:
                with suppress(ValueError):
                    copyreg.remove_extension("builtins", "set", ext_code)
        finally:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.add_extension("builtins", "set", existing_code)

    # ------------------------------------------------------------------
    # Fix 3b: ZIP proto0/1 extension bypass
    # ------------------------------------------------------------------
    def test_zip_entry_with_proto0_pickle_text_extension_is_detected(self) -> None:
        """Protocol 0 pickle payloads in ZIP entries should not be skipped by extension."""
        import tempfile
        import zipfile

        from modelaudit.core import scan_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "payload.zip"

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("payload.txt", b'cos\nsystem\n(S"echo pwned"\ntR.')

            result = scan_file(str(zip_path))

            assert result.success
            assert result.has_errors
            critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert any(_contains_system_global(msg) for msg in critical_messages), (
                f"Expected critical os/posix/nt.system issue, got: {critical_messages}"
            )

    # ------------------------------------------------------------------
    # Fix 3c: parser crash resilience on mixed malformed payloads
    # ------------------------------------------------------------------
    def test_malformed_unicode_tail_still_flags_dangerous_global(self) -> None:
        """Malformed tails should not suppress opcode-level dangerous global detection."""
        # Valid prefix with dangerous GLOBAL, followed by malformed GLOBAL bytes
        # that previously caused parse fallback before opcode analysis completed.
        payload = b"\x80\x02cbuiltins\n__import__\nq\x00c\xff\n"

        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors

        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("__import__" in msg for msg in critical_messages), (
            f"Expected CRITICAL __import__ detection, got: {critical_messages}"
        )

    def test_malformed_unicode_tail_with_benign_prefix_does_not_raise_critical(self) -> None:
        """Malformed tails after benign opcodes should not create CRITICAL findings."""
        payload = b"\x80\x02cbuiltins\nlen\nq\x00c\xff\n"

        result = self._scan_bytes(payload)

        assert result.success
        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert not critical_messages, f"Unexpected CRITICAL benign detection: {critical_messages}"

    # ------------------------------------------------------------------
    # Fix 3: joblib.load loader trampoline bypass
    # ------------------------------------------------------------------
    def test_joblib_load_reduce_is_critical(self) -> None:
        """joblib.load + REDUCE should be treated as dangerous, not allowlisted."""
        payload = b"\x80\x04cjoblib\nload\n\x8c\x0bpayload.pkl\x85R."
        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("joblib.load" in msg for msg in critical_messages), (
            f"Expected CRITICAL joblib.load issue, got: {critical_messages}"
        )

    def test_pickle_unpickler_reduce_is_critical(self) -> None:
        """_pickle.Unpickler must never be treated as a safe global."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("_pickle", "Unpickler"))

        assert result.success
        assert result.has_errors
        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("_pickle.unpickler" in msg for msg in critical_messages), (
            f"Expected CRITICAL _pickle.Unpickler issue, got: {critical_messages}"
        )

    def test_pickle_pickler_reduce_is_critical(self) -> None:
        """_pickle.Pickler must never be treated as a safe global."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("_pickle", "Pickler"))

        assert result.success
        assert result.has_errors
        critical_messages = [i.message.lower() for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("_pickle.pickler" in msg for msg in critical_messages), (
            f"Expected CRITICAL _pickle.Pickler issue, got: {critical_messages}"
        )

    def test_copyreg_add_extension_import_only_is_flagged(self) -> None:
        """copyreg.add_extension import references must be treated as suspicious."""
        result = self._scan_bytes(self._craft_global_import_only_pickle("copyreg", "add_extension"))

        assert result.success
        assert result.has_errors
        failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
        matching_checks = [check for check in failed_checks if "copyreg.add_extension" in check.message.lower()]
        assert matching_checks, (
            f"Expected suspicious copyreg.add_extension finding, got: {[check.message for check in failed_checks]}"
        )
        assert any(check.severity == IssueSeverity.CRITICAL for check in matching_checks), (
            f"Expected CRITICAL copyreg.add_extension finding, got: "
            f"{[(check.severity, check.message) for check in matching_checks]}"
        )
        assert not any(check.severity == IssueSeverity.WARNING for check in matching_checks), (
            "Did not expect WARNING copyreg.add_extension finding, "
            f"got: {[(check.severity, check.message) for check in matching_checks]}"
        )

    def test_copyreg_remove_extension_import_only_is_flagged(self) -> None:
        """copyreg.remove_extension import references must be treated as suspicious."""
        result = self._scan_bytes(self._craft_global_import_only_pickle("copyreg", "remove_extension"))

        assert result.success
        assert result.has_errors
        failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
        matching_checks = [check for check in failed_checks if "copyreg.remove_extension" in check.message.lower()]
        assert matching_checks, (
            f"Expected suspicious copyreg.remove_extension finding, got: {[check.message for check in failed_checks]}"
        )
        assert any(check.severity == IssueSeverity.CRITICAL for check in matching_checks), (
            f"Expected CRITICAL copyreg.remove_extension finding, got: "
            f"{[(check.severity, check.message) for check in matching_checks]}"
        )
        assert not any(check.severity == IssueSeverity.WARNING for check in matching_checks), (
            "Did not expect WARNING copyreg.remove_extension finding, "
            f"got: {[(check.severity, check.message) for check in matching_checks]}"
        )

    def _assert_reduce_target_severity(self, function_name: str, expected_severity: IssueSeverity) -> None:
        """Assert the executed-call findings for a functools REDUCE target use the expected severity."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("functools", function_name))

        assert result.success
        if expected_severity == IssueSeverity.CRITICAL:
            assert result.has_errors
        else:
            assert not result.has_errors

        target = f"functools.{function_name}"
        reduce_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.details.get("associated_global") == target
        ]
        assert reduce_checks, [check.message for check in result.checks]
        assert all(check.severity == expected_severity for check in reduce_checks), (
            f"Unexpected REDUCE severities for {target}: {[(check.severity, check.message) for check in reduce_checks]}"
        )

        assert any(
            evidence.get("check_name") == "Reduce Pattern Analysis"
            and evidence.get("details", {}).get("module") == "functools"
            and evidence.get("details", {}).get("function") == function_name
            for check in reduce_checks
            for evidence in check.details.get("supporting_evidence", [])
        ), f"Expected reduce-pattern evidence to fold into {target}: {result.checks}"
        assert not any(
            check.name == "Reduce Pattern Analysis"
            and check.status == CheckStatus.FAILED
            and check.details.get("module") == "functools"
            and check.details.get("function") == function_name
            for check in result.checks
        ), f"Expected {target} reduce-pattern failure to be deduplicated: {result.checks}"

    def test_functools_reduce_remains_critical(self) -> None:
        """functools.reduce must remain CRITICAL even while partial stays WARNING."""
        self._assert_reduce_target_severity("reduce", IssueSeverity.CRITICAL)

    def test_functools_partial_remains_warning(self) -> None:
        """functools.partial should still be downgraded to WARNING."""
        self._assert_reduce_target_severity("partial", IssueSeverity.WARNING)

    def test_functools_partialmethod_remains_warning(self) -> None:
        """functools.partialmethod should inherit the same WARNING downgrade as partial."""
        self._assert_reduce_target_severity("partialmethod", IssueSeverity.WARNING)

    def _assert_ext_resolved_functools_ref_is_critical(self, target_name: str) -> None:
        """EXT-origin functools refs must remain CRITICAL despite warning downgrades for direct refs."""
        import copyreg
        from contextlib import suppress

        inverted_registry = getattr(copyreg, "_inverted_registry", {})
        extension_registry = getattr(copyreg, "_extension_registry", {})
        existing_code = extension_registry.get(("functools", target_name))
        ext_code = next((candidate for candidate in range(1, 256) if candidate not in inverted_registry), None)
        if ext_code is None:
            pytest.skip("No free copyreg extension code available in range 1-255")

        try:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.remove_extension("functools", target_name, existing_code)

            copyreg.add_extension("functools", target_name, ext_code)
            try:
                result = self._scan_bytes(b"\x80\x02\x82" + bytes([ext_code]) + b")R.")

                assert result.success
                assert result.has_errors
                target_issues = [
                    issue for issue in result.issues if f"functools.{target_name}" in issue.message.lower()
                ]
                assert target_issues, (
                    f"Expected functools.{target_name} findings, got: {[issue.message for issue in result.issues]}"
                )
                assert all(issue.severity == IssueSeverity.CRITICAL for issue in target_issues), (
                    f"Expected CRITICAL functools.{target_name} findings, got: "
                    f"{[(issue.severity, issue.message) for issue in target_issues]}"
                )
            finally:
                with suppress(ValueError):
                    copyreg.remove_extension("functools", target_name, ext_code)
        finally:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.add_extension("functools", target_name, existing_code)

    def test_ext_resolved_functools_partial_remains_critical(self) -> None:
        """EXT-origin functools.partial must remain CRITICAL."""
        self._assert_ext_resolved_functools_ref_is_critical("partial")

    def test_ext_resolved_functools_partialmethod_remains_critical(self) -> None:
        """EXT-origin functools.partialmethod must remain CRITICAL."""
        self._assert_ext_resolved_functools_ref_is_critical("partialmethod")

    def test_multistream_functools_partial_promotes_warning_to_critical(self) -> None:
        """A later EXT-resolved functools.partial must upgrade an earlier warning primary."""
        import copyreg
        from contextlib import suppress

        inverted_registry = getattr(copyreg, "_inverted_registry", {})
        extension_registry = getattr(copyreg, "_extension_registry", {})
        existing_code = extension_registry.get(("functools", "partial"))
        ext_code = next((candidate for candidate in range(1, 256) if candidate not in inverted_registry), None)
        if ext_code is None:
            pytest.skip("No free copyreg extension code available in range 1-255")

        try:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.remove_extension("functools", "partial", existing_code)

            copyreg.add_extension("functools", "partial", ext_code)
            try:
                payload = self._craft_global_reduce_pickle("functools", "partial")
                payload += b"\x80\x02\x82" + bytes([ext_code]) + b")R."

                result = self._scan_bytes(payload)

                assert result.success
                assert result.has_errors

                reduce_checks = [
                    check
                    for check in result.checks
                    if check.name == "REDUCE Opcode Safety Check"
                    and check.status == CheckStatus.FAILED
                    and check.details.get("associated_global") == "functools.partial"
                ]
                assert len(reduce_checks) == 1, [check.details for check in result.checks]
                reduce_check = reduce_checks[0]
                assert reduce_check.severity == IssueSeverity.CRITICAL, reduce_check.details
                assert reduce_check.details.get("origin_is_ext") is True, reduce_check.details
                assert any(
                    evidence.get("check_name") == "REDUCE Opcode Safety Check"
                    and evidence.get("severity") == IssueSeverity.WARNING.value
                    and evidence.get("details", {}).get("associated_global") == "functools.partial"
                    and evidence.get("details", {}).get("origin_is_ext") is not True
                    for evidence in reduce_check.details.get("supporting_evidence", [])
                ), (
                    "Expected warning REDUCE evidence to be folded into promoted "
                    f"functools.partial finding: {reduce_check.details}"
                )

                partial_issues = [issue for issue in result.issues if "functools.partial" in issue.message.lower()]
                assert partial_issues, [issue.message for issue in result.issues]
                assert all(issue.severity == IssueSeverity.CRITICAL for issue in partial_issues), (
                    f"Expected surviving functools.partial issue to remain CRITICAL, got: "
                    f"{[(issue.severity, issue.message) for issue in partial_issues]}"
                )
            finally:
                with suppress(ValueError):
                    copyreg.remove_extension("functools", "partial", ext_code)
        finally:
            if isinstance(existing_code, int):
                with suppress(ValueError):
                    copyreg.add_extension("functools", "partial", existing_code)

    # ------------------------------------------------------------------
    # Fix 4: NEWOBJ_EX with dangerous class
    # ------------------------------------------------------------------
    def test_newobj_ex_dangerous_class(self) -> None:
        """NEWOBJ_EX opcode with a dangerous class should be flagged."""
        # Craft pickle: PROTO 4 | GLOBAL 'os _wrap_close' | EMPTY_TUPLE | EMPTY_DICT | NEWOBJ_EX | STOP
        # Protocol 4 is needed for NEWOBJ_EX (opcode 0x92)
        proto = b"\x80\x04"
        global_op = b"c" + b"os\n_wrap_close\n"
        empty_tuple = b")"
        empty_dict = b"}"
        newobj_ex = b"\x92"  # NEWOBJ_EX opcode
        stop = b"."
        data = proto + global_op + empty_tuple + empty_dict + newobj_ex + stop

        result = self._scan_bytes(data)
        assert result.success
        assert result.has_errors
        os_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL and "os" in i.message.lower()]
        assert os_issues, f"Expected CRITICAL os issue for NEWOBJ_EX, got: {[i.message for i in result.issues]}"

    # ------------------------------------------------------------------
    # Fix 1: Spot-check newly-added modules
    # ------------------------------------------------------------------
    def test_smtplib_blocked(self) -> None:
        """smtplib module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("smtplib", "SMTP"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "smtplib" in i.message for i in result.issues), (
            f"Expected CRITICAL smtplib issue, got: {[i.message for i in result.issues]}"
        )

    def test_httplib_import_only_global_blocked(self) -> None:
        """Python 2 httplib alias GLOBAL imports should match http.client danger handling."""
        payload = b"\x80\x02chttplib\nHTTPSConnection\n."
        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
        assert any(
            check.severity == IssueSeverity.CRITICAL
            and check.rule_code == "S303"
            and "httplib.HTTPSConnection" in check.message
            for check in failed_checks
        ), f"Expected S303 CRITICAL httplib import finding, got: {[c.message for c in failed_checks]}"

    def test_httplib_reduce_blocked(self) -> None:
        """Python 2 httplib alias REDUCE payloads should be treated as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("httplib", "HTTPSConnection"))

        assert result.success
        assert result.has_errors
        failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
        assert any(
            check.severity == IssueSeverity.CRITICAL
            and check.rule_code == "S201"
            and "httplib.HTTPSConnection" in check.message
            for check in failed_checks
        ), f"Expected S201 CRITICAL httplib reduce finding, got: {[c.message for c in failed_checks]}"

    def test_http_client_coverage_unchanged(self) -> None:
        """Existing http.client dangerous-global coverage should remain stable."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("http.client", "HTTPSConnection"))

        assert result.success
        assert result.has_errors
        failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
        assert any(
            check.severity == IssueSeverity.CRITICAL
            and check.rule_code == "S201"
            and "http.client.HTTPSConnection" in check.message
            for check in failed_checks
        ), f"Expected CRITICAL http.client reduce finding, got: {[c.message for c in failed_checks]}"

    def test_safe_stdlib_import_remains_non_failing(self) -> None:
        """Benign stdlib import-only globals should stay non-failing."""
        payload = b"\x80\x02cdatetime\ndatetime\n."
        result = self._scan_bytes(payload)

        assert result.success
        assert not result.has_errors
        assert not [check for check in result.checks if check.status == CheckStatus.FAILED]

    def test_sqlite3_blocked(self) -> None:
        """sqlite3 module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("sqlite3", "connect"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "sqlite3" in i.message for i in result.issues), (
            f"Expected CRITICAL sqlite3 issue, got: {[i.message for i in result.issues]}"
        )

    def test_tarfile_blocked(self) -> None:
        """tarfile module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("tarfile", "open"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "tarfile" in i.message for i in result.issues), (
            f"Expected CRITICAL tarfile issue, got: {[i.message for i in result.issues]}"
        )

    # NOTE: ctypes test omitted — ctypes added to ALWAYS_DANGEROUS_MODULES in PR #518

    def test_marshal_blocked(self) -> None:
        """marshal module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("marshal", "loads"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "marshal" in i.message for i in result.issues), (
            f"Expected CRITICAL marshal issue, got: {[i.message for i in result.issues]}"
        )

    def test_cloudpickle_blocked(self) -> None:
        """cloudpickle module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("cloudpickle", "loads"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "cloudpickle" in i.message for i in result.issues), (
            f"Expected CRITICAL cloudpickle issue, got: {[i.message for i in result.issues]}"
        )

    def test_webbrowser_blocked(self) -> None:
        """webbrowser module should be flagged as dangerous."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("webbrowser", "open"))
        assert result.has_errors
        assert any(i.severity == IssueSeverity.CRITICAL and "webbrowser" in i.message for i in result.issues), (
            f"Expected CRITICAL webbrowser issue, got: {[i.message for i in result.issues]}"
        )

    def test_helper_import_only_refs_are_critical(self) -> None:
        """Validated helper refs should never scan clean as bare GLOBAL payloads."""
        for module, func in self.HELPER_REFS:
            result = self._scan_bytes(self._craft_global_only_pickle(module, func))
            full_ref = f"{module}.{func}"

            assert result.success, f"Scan failed for {full_ref}"
            assert result.has_errors, f"Expected failing result for {full_ref}"
            assert any(check.status == CheckStatus.FAILED and full_ref in check.message for check in result.checks), (
                f"Expected failed helper-global check for {full_ref}, checks: {[c.message for c in result.checks]}"
            )

    def test_helper_reduce_payloads_by_subgroup_are_critical(self) -> None:
        """At least one executable REDUCE payload per helper subgroup should be critical."""
        subgroup_refs = (
            ("numpy.f2py.crackfortran", "getlincoef"),
            ("torch._dynamo.guards.GuardBuilder", "get"),
            ("torch.utils.collect_env", "run"),
        )

        for module, func in subgroup_refs:
            result = self._scan_bytes(self._craft_global_reduce_pickle(module, func))
            full_ref = f"{module}.{func}"

            assert result.success, f"Scan failed for {full_ref}"
            assert result.has_errors, f"Expected failing result for {full_ref}"
            assert any(
                check.name == "REDUCE Opcode Safety Check"
                and check.status == CheckStatus.FAILED
                and check.severity == IssueSeverity.CRITICAL
                and full_ref in check.message
                for check in result.checks
            ), f"Expected CRITICAL REDUCE check for {full_ref}, checks: {[c.message for c in result.checks]}"

    def test_memoized_stack_global_helper_ref_is_critical(self) -> None:
        """Memoized STACK_GLOBAL helper refs should resolve and fail."""
        module = b"torch.fx.experimental.symbolic_shapes.ShapeEnv"
        func = b"evaluate_guards_expression"
        payload = (
            b"\x80\x04"
            + b"\x8c"
            + bytes([len(module)])
            + module
            + b"\x94"
            + b"\x8c"
            + bytes([len(func)])
            + func
            + b"\x94"
            + b"\x93."
        )
        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        target = "torch.fx.experimental.symbolic_shapes.ShapeEnv.evaluate_guards_expression"
        assert any(check.status == CheckStatus.FAILED and target in check.message for check in result.checks), (
            f"Expected failed STACK_GLOBAL helper detection, checks: {[c.message for c in result.checks]}"
        )

    def test_safe_torch_and_numpy_reconstruction_helpers_remain_non_failing(self) -> None:
        """Safe reconstruction helpers should continue to stay clean."""
        safe_refs = (
            ("torch._utils", "_rebuild_tensor_v2"),
            ("numpy.core.multiarray", "_reconstruct"),
        )

        for module, func in safe_refs:
            result = self._scan_bytes(self._craft_global_only_pickle(module, func))
            full_ref = f"{module}.{func}"

            assert result.success, f"Scan failed for safe ref {full_ref}"
            assert not any(
                check.status == CheckStatus.FAILED and full_ref in check.message for check in result.checks
            ), f"Unexpected failed check for safe ref {full_ref}: {[c.message for c in result.checks]}"

    def test_safe_nearby_helper_refs_remain_non_failing(self) -> None:
        """Exact helper coverage must not widen to safe neighbors outside risky-ML prefixes."""
        safe_neighbor_refs = (
            ("torch.fx.experimental.symbolic_shapes.ShapeEnv", "create_symbol"),
            ("torch.utils.collect_env", "get_env_info"),
            ("torch.utils._config_module", "install_config_module"),
            ("torch.utils.data.datapipes.utils.decoder", "handle_extension"),
        )

        for module, func in safe_neighbor_refs:
            result = self._scan_bytes(self._craft_global_only_pickle(module, func))
            full_ref = f"{module}.{func}"

            assert result.success, f"Scan failed for safe neighbor {full_ref}"
            assert not any(
                check.status == CheckStatus.FAILED and full_ref in check.message for check in result.checks
            ), f"Unexpected failed check for safe neighbor {full_ref}: {[c.message for c in result.checks]}"

    def test_helper_ref_with_legacy_code_string_reports_both_signals(self) -> None:
        """Dangerous-global detection should coexist with legacy string-pattern alerts."""
        payload = b"\x80\x04\x8c\x0a__import__\x940ctorch.utils.collect_env\nrun\n."
        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        messages = [issue.message for issue in result.issues]
        assert any("torch.utils.collect_env.run" in msg for msg in messages), (
            f"Expected helper dangerous-global message, got: {messages}"
        )
        assert any("legacy dangerous pattern detected: __import__" in msg.lower() for msg in messages), (
            f"Expected legacy dangerous-string signal, got: {messages}"
        )

    def test_helper_imports_use_exact_why_explanations(self) -> None:
        """Exact helper refs should populate a specific why explanation, not fall back to None."""
        result = self._scan_bytes(self._craft_global_only_pickle("torch.utils.collect_env", "run"))

        why_texts = [issue.why or "" for issue in result.issues if "torch.utils.collect_env.run" in issue.message]
        assert any("subprocess" in why.lower() and "benign model loading" in why.lower() for why in why_texts), (
            f"Expected exact why explanation for torch.utils.collect_env.run, got: {why_texts}"
        )

    def test_multi_stream_httplib_detected_in_second_stream(self) -> None:
        """Scanner should detect httplib payload hidden in a second pickle stream."""
        benign_stream = pickle.dumps({"safe": True}, protocol=2)
        payload = benign_stream + b"\x80\x02chttplib\nHTTPSConnection\n."
        result = self._scan_bytes(payload)

        assert result.success
        assert result.has_errors
        assert any(
            issue.severity == IssueSeverity.CRITICAL and "httplib" in issue.message.lower() for issue in result.issues
        ), f"Expected CRITICAL httplib issue in second stream, got: {[i.message for i in result.issues]}"

    def test_zip_entry_with_httplib_payload_is_detected(self) -> None:
        """Scanner should detect httplib payload embedded in a zip entry."""
        import zipfile

        from modelaudit.core import scan_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "httplib-payload.zip"

            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("nested.pkl", self._craft_global_reduce_pickle("httplib", "HTTPSConnection"))

            result = scan_file(str(zip_path))

            assert result.success
            assert result.has_errors
            assert any(
                issue.severity == IssueSeverity.CRITICAL
                and "httplib.httpsconnection" in issue.message.lower()
                and issue.details.get("zip_entry") == "nested.pkl"
                for issue in result.issues
            ), f"Expected CRITICAL httplib zip issue, got: {[i.message for i in result.issues]}"

    def test_picklescan_gap_globals_are_critical_on_import_only(self) -> None:
        """Validated PickleScan dangerous globals should fail even without REDUCE."""
        for module, func in self.PICKLESCAN_GAP_REFS:
            result = self._scan_bytes(self._craft_global_only_pickle(module, func))
            assert result.has_errors, f"Expected failing checks for {module}.{func}"
            assert any(
                check.name == "Global Module Reference Check"
                and check.status == CheckStatus.FAILED
                and check.severity == IssueSeverity.CRITICAL
                and check.rule_code == "S206"
                and f"{module}.{func}" in check.message
                for check in result.checks
            ), f"Expected CRITICAL global check for {module}.{func}, checks: {[c.message for c in result.checks]}"

    def test_picklescan_gap_globals_are_critical_with_reduce(self) -> None:
        """Validated PickleScan dangerous globals should fail as CRITICAL in REDUCE flows."""
        for module, func in self.PICKLESCAN_GAP_REFS:
            result = self._scan_bytes(self._craft_global_reduce_pickle(module, func))
            assert result.has_errors, f"Expected failing checks for {module}.{func}"
            assert any(
                check.name == "REDUCE Opcode Safety Check"
                and check.status == CheckStatus.FAILED
                and check.severity == IssueSeverity.CRITICAL
                and f"{module}.{func}" in check.message
                for check in result.checks
            ), f"Expected CRITICAL REDUCE check for {module}.{func}, checks: {[c.message for c in result.checks]}"
            assert not any(
                "non-allowlisted global" in check.message and f"{module}.{func}" in check.message
                for check in result.checks
                if check.name == "REDUCE Opcode Safety Check"
            ), f"Dangerous global should not degrade to a generic warning for {module}.{func}"

    def test_picklescan_gap_imports_use_exact_why_explanations(self) -> None:
        """Exact dotted-name explanations should be used for new dangerous refs."""
        result = self._scan_bytes(self._craft_global_only_pickle("numpy", "load"))

        why_texts = [issue.why or "" for issue in result.issues if "numpy.load" in issue.message]
        assert any("recursively deserialize object arrays" in why.lower() for why in why_texts), (
            f"Expected exact numpy.load explanation, got: {why_texts}"
        )

    def test_comment_token_does_not_bypass_picklescan_gap_detection(self) -> None:
        """A comment-like string literal must not suppress dangerous global detection."""
        comment_token = b"# not a real comment"
        comment_prefix = b"\x8c" + bytes([len(comment_token)]) + comment_token + b"0"
        payload = b"\x80\x02" + comment_prefix + b"cnumpy\nload\n."

        result = self._scan_bytes(payload)

        assert any(
            check.name == "Global Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and "numpy.load" in check.message
            for check in result.checks
        ), f"Expected numpy.load detection despite comment token, checks: {[c.message for c in result.checks]}"

    def test_safe_nearby_imports_remain_non_failing(self) -> None:
        """Nearby safe imports should remain non-failing to avoid broad module false positives."""
        for module, func in [("site", "addsitedir"), ("_io", "BytesIO"), ("torch", "Tensor"), ("numpy", "array")]:
            result = self._scan_bytes(self._craft_global_only_pickle(module, func))
            assert result.success
            assert not any(
                check.name in {"Global Module Reference Check", "Advanced Global Reference Check"}
                and check.status == CheckStatus.FAILED
                and f"{module}.{func}" in check.message
                for check in result.checks
            ), f"Unexpected failing import check for safe reference {module}.{func}"

    def test_existing_reference_behavior_unchanged(self) -> None:
        """Existing dangerous references should remain failing after the expansion."""
        for module, func in [
            ("joblib", "load"),
            ("pip", "main"),
            ("pydoc", "pipepager"),
            ("venv", "create"),
        ]:
            result = self._scan_bytes(self._craft_global_reduce_pickle(module, func))
            assert any(
                check.name == "REDUCE Opcode Safety Check"
                and check.status == CheckStatus.FAILED
                and f"{module}.{func}" in check.message
                for check in result.checks
            ), f"Expected REDUCE detection for {module}.{func}, checks: {[c.message for c in result.checks]}"

    def test_pytorch_reduce_warning_includes_complete_cve_metadata(self) -> None:
        """PyTorch-specific REDUCE warnings should carry the full CVE metadata bundle."""
        result = self._scan_bytes(self._craft_global_reduce_pickle("datetime", "datetime"), suffix=".pt")

        matching_checks = [
            check
            for check in result.checks
            if check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("cve_id") == "CVE-2025-32434"
        ]
        assert matching_checks, f"Expected CVE-tagged REDUCE warning, checks: {[c.message for c in result.checks]}"

        details = matching_checks[0].details or {}
        assert details["cvss"] == 9.8
        assert details["cwe"] == "CWE-502"
        assert "weights_only=True" in details["description"]
        assert "PyTorch 2.6.0" in details["remediation"]

    def test_picklescan_gap_detected_in_second_pickle_stream(self) -> None:
        """Dangerous loader hidden in a second stream should still be detected."""
        import io

        buffer = io.BytesIO()
        pickle.dump({"safe": True}, buffer, protocol=2)
        buffer.write(self._craft_global_reduce_pickle("numpy", "load"))

        result = self._scan_bytes(buffer.getvalue())
        assert any(
            check.name == "REDUCE Opcode Safety Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and "numpy.load" in check.message
            for check in result.checks
        ), f"Expected numpy.load detection in second stream, checks: {[c.message for c in result.checks]}"


def test_picklescan_gap_detected_inside_zip_entry(tmp_path: Path) -> None:
    """Dangerous primitive inside a ZIP entry should be detected by archive scanning."""
    import zipfile

    from modelaudit.core import scan_file

    payload = TestPickleScannerBlocklistHardening._craft_global_reduce_pickle("numpy", "load")
    zip_path = tmp_path / "numpy_loader_payload.zip"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("weights.pkl", payload)

    result = scan_file(str(zip_path))

    assert result.success
    assert result.has_errors
    assert any(issue.severity == IssueSeverity.CRITICAL and "numpy.load" in issue.message for issue in result.issues), (
        f"Expected CRITICAL numpy.load issue in zip entry, got: {[i.message for i in result.issues]}"
    )


class TestCVE20251716PipMainBlocklist(unittest.TestCase):
    """Test CVE-2025-1716: pickle bypass via pip.main() as callable."""

    def test_pip_main_detected_as_critical(self) -> None:
        """Pickle with GLOBAL pip.main + REDUCE should be flagged CRITICAL."""
        # Protocol 2 pickle: GLOBAL pip\nmain\n, EMPTY_TUPLE, REDUCE, STOP
        payload = b"\x80\x02cpip\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            result = scanner.scan(path)

            # Should have CRITICAL issues referencing pip.main
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, (
                f"pip.main should be flagged as CRITICAL. Issues: {[i.message for i in result.issues]}"
            )
            assert any("pip" in i.message for i in critical_issues), (
                f"Should reference pip in message. Issues: {[i.message for i in critical_issues]}"
            )
        finally:
            os.unlink(path)

    def test_pip_internal_main_detected(self) -> None:
        """Pickle with GLOBAL pip._internal.main should be flagged."""
        payload = b"\x80\x02cpip._internal\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            result = scanner.scan(path)

            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, (
                f"pip._internal.main should be flagged. Issues: {[i.message for i in result.issues]}"
            )
            assert any("pip" in i.message.lower() for i in critical_issues), (
                f"Should reference pip in message. Issues: {[i.message for i in critical_issues]}"
            )
        finally:
            os.unlink(path)

    def test_comment_token_does_not_bypass_pip_detection(self) -> None:
        """Embedding a comment-like token in a malicious pip payload must not suppress detection."""
        # Build a pickle that includes a benign SHORT_BINUNICODE string containing "#"
        # before the dangerous pip.main GLOBAL+REDUCE sequence.
        # Protocol 2: PROTO 2, SHORT_BINUNICODE "# comment", POP, GLOBAL pip\nmain\n, EMPTY_TUPLE, REDUCE, STOP
        comment_token = b"# this is a comment"
        comment_op = b"\x8c" + bytes([len(comment_token)]) + comment_token  # SHORT_BINUNICODE
        pop_op = b"0"  # POP to discard the string from the stack
        payload = b"\x80\x02" + comment_op + pop_op + b"cpip\nmain\n)R."
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            path = f.name
        try:
            scanner = PickleScanner()
            result = scanner.scan(path)

            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, (
                f"Comment token must not suppress pip.main detection. Issues: {[i.message for i in result.issues]}"
            )
            assert any("pip" in i.message.lower() for i in critical_issues), (
                f"Should reference pip in message despite comment token. Issues: {[i.message for i in critical_issues]}"
            )
        finally:
            os.unlink(path)

    def test_pip_main_in_always_dangerous(self) -> None:
        """Verify pip.main is in ALWAYS_DANGEROUS_FUNCTIONS set."""
        from modelaudit.scanners.pickle_scanner import ALWAYS_DANGEROUS_FUNCTIONS

        assert "pip.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._internal.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._internal.cli.main.main" in ALWAYS_DANGEROUS_FUNCTIONS
        assert "pip._vendor.distlib.scripts.ScriptMaker" in ALWAYS_DANGEROUS_FUNCTIONS

    def test_pip_module_in_always_dangerous_modules(self) -> None:
        """Verify pip module prefixes are in ALWAYS_DANGEROUS_MODULES set."""
        from modelaudit.scanners.pickle_scanner import ALWAYS_DANGEROUS_MODULES

        assert "pip" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal.cli" in ALWAYS_DANGEROUS_MODULES
        assert "pip._internal.cli.main" in ALWAYS_DANGEROUS_MODULES
        assert "pip._vendor" in ALWAYS_DANGEROUS_MODULES
        assert "pip._vendor.distlib" in ALWAYS_DANGEROUS_MODULES
        assert "pip._vendor.distlib.scripts" in ALWAYS_DANGEROUS_MODULES

    def test_prefix_matching_catches_deep_pip_submodules(self) -> None:
        """Verify _is_dangerous_module catches pip sub-modules not explicitly listed."""
        from modelaudit.scanners.pickle_scanner import _is_dangerous_module

        # These are not explicitly in the set but should match via prefix
        assert _is_dangerous_module("pip._internal.cli.main_parser")
        assert _is_dangerous_module("pip._vendor.distlib.scripts.run")
        assert _is_dangerous_module("pip._internal.commands.install")
        # Non-pip modules should not match
        assert not _is_dangerous_module("pipx.main")
        assert not _is_dangerous_module("pipeline.process")


def test_scan_legitimate_pytorch_pickle_memory_error_is_non_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Memory limits on legitimate .pt files should be surfaced as informational scanner limitation."""
    model_path = tmp_path / "legitimate_model.pt"
    header = b"\x80\x02ctorch\nOrderedDict\nq\x00."
    model_path.write_bytes(header + b"state_dict" + b"\x00" * (1024 * 1024 + 64))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: {("torch", "OrderedDict", "GLOBAL")},
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert resource_limit_check.details["analysis_incomplete"] is True
    assert resource_limit_check.details["scanner_limitation"] is True

    assert result.metadata["memory_limited"] is True
    assert result.metadata["scanner_limitation"] is True
    assert result.metadata["analysis_incomplete"] is True

    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    assert len(info_issues) == 1
    assert info_issues[0].message == "Scan limited by model complexity and memory budget"
    assert not any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and "Unable to parse pickle file" in issue.message
        for issue in result.issues
    )


def test_scan_legitimate_pytorch_bin_memory_error_is_informational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Memory limits on legitimate pytorch_model.bin should be informational only."""
    model_path = tmp_path / "pytorch_model.bin"
    header = b"\x80\x02ctorch\nOrderedDict\nq\x00."
    model_path.write_bytes(header + b"state_dict" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: {
            ("torch._utils", "_rebuild_tensor_v2", "GLOBAL"),
            ("collections", "OrderedDict", "GLOBAL"),
        },
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert resource_limit_check.details["analysis_incomplete"] is True
    assert resource_limit_check.details["scanner_limitation"] is True
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_dill_memory_error_without_dill_globals_not_downgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dangerous-looking dill prefixes must not qualify for the INFO downgrade."""
    model_path = tmp_path / "suspicious.dill"
    model_path.write_bytes(b"\x80\x04cdill\nloads\nq\x00." + b"dill" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: set(),
    )

    result = PickleScanner().scan(str(model_path))

    assert not any(check.name == "Pickle Parse Resource Limit" for check in result.checks)
    format_validation_checks = [check for check in result.checks if check.name == "Pickle Format Validation"]
    assert len(format_validation_checks) == 1
    assert format_validation_checks[0].status == CheckStatus.FAILED
    assert format_validation_checks[0].severity == IssueSeverity.WARNING
    assert format_validation_checks[0].details["exception_type"] == "MemoryError"


def test_scan_joblib_memory_error_requires_joblib_globals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only .joblib files with parsed framework globals should downgrade to INFO."""
    model_path = tmp_path / "legitimate.joblib"
    model_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00." + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: {
            ("joblib.numpy_pickle", "NumpyArrayWrapper", "GLOBAL")
        },
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert not any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and "Unable to parse pickle file" in issue.message
        for issue in result.issues
    )


def test_scan_joblib_memory_error_without_joblib_globals_not_downgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Marker bytes alone must not qualify a .joblib file for INFO downgrade."""
    model_path = tmp_path / "suspicious.joblib"
    model_path.write_bytes(b"\x80\x04joblibsklearn" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: set(),
    )

    result = PickleScanner().scan(str(model_path))

    assert not any(check.name == "Pickle Parse Resource Limit" for check in result.checks)
    format_validation_checks = [check for check in result.checks if check.name == "Pickle Format Validation"]
    assert len(format_validation_checks) == 1
    assert format_validation_checks[0].status == CheckStatus.FAILED
    assert format_validation_checks[0].severity == IssueSeverity.WARNING
    assert format_validation_checks[0].details["exception_type"] == "MemoryError"


def test_scan_dill_memory_error_with_dill_globals_is_informational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Legitimate dill globals should still allow the scanner-limitation downgrade."""
    model_path = tmp_path / "legitimate.dill"
    model_path.write_bytes(b"\x80\x04" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: {("dill", "dump", "GLOBAL")},
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_plain_dill_memory_error_without_globals_is_informational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plain-object dill files should keep the scanner-limitation downgrade path."""
    model_path = tmp_path / "plain.dill"
    model_path.write_bytes(dill.dumps([1, 2, 3]))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: set(),
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_dill_memory_error_with_internal_dill_globals_is_informational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Internal dill globals should qualify for the scanner-limitation downgrade."""
    model_path = tmp_path / "legitimate.dill"
    model_path.write_bytes(b"\x80\x04" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: {("_dill", "dump", "GLOBAL")},
    )

    result = PickleScanner().scan(str(model_path))

    resource_limit_checks = [check for check in result.checks if check.name == "Pickle Parse Resource Limit"]
    assert len(resource_limit_checks) == 1
    resource_limit_check = resource_limit_checks[0]
    assert resource_limit_check.status == CheckStatus.FAILED
    assert resource_limit_check.severity == IssueSeverity.INFO
    assert resource_limit_check.details["reason"] == "memory_limit_on_legitimate_model"
    assert resource_limit_check.details["exception_type"] == "MemoryError"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_joblib_memory_error_with_dangerous_prefix_not_downgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Marker bytes must not hide a dangerous pickle prefix in .joblib files."""
    model_path = tmp_path / "suspicious.joblib"
    model_path.write_bytes(b"\x80\x02cbuiltins\neval\nq\x00." + b"joblibsklearnnumpy" + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: set(),
    )

    result = PickleScanner().scan(str(model_path))

    assert not any(check.name == "Pickle Parse Resource Limit" for check in result.checks)
    format_validation_checks = [check for check in result.checks if check.name == "Pickle Format Validation"]
    assert len(format_validation_checks) == 1
    assert format_validation_checks[0].status == CheckStatus.FAILED
    assert format_validation_checks[0].severity == IssueSeverity.WARNING
    assert format_validation_checks[0].details["exception_type"] == "MemoryError"


def test_scan_memory_error_with_dangerous_globals_not_downgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dangerous globals must keep MemoryError path as warning, not limitation-info downgrade."""
    model_path = tmp_path / "pytorch_model.bin"
    model_path.write_bytes(b"\x80\x02cbuiltins\neval\nq\x00." + b"\x00" * (256 * 1024))

    def _raise_memory_error(*args: object, **kwargs: object) -> object:
        raise MemoryError("simulated parser memory limit")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _raise_memory_error)
    monkeypatch.setattr(
        PickleScanner,
        "_is_legitimate_pytorch_model",
        lambda self, path: True,  # force heuristic pass; dangerous-global gate must still block downgrade
    )
    monkeypatch.setattr(
        PickleScanner,
        "_extract_globals_advanced",
        lambda self, file_obj, multiple_pickles=True, **kwargs: {("builtins", "eval", "GLOBAL")},
    )

    result = PickleScanner().scan(str(model_path))

    assert not any(check.name == "Pickle Parse Resource Limit" for check in result.checks)
    format_validation_checks = [check for check in result.checks if check.name == "Pickle Format Validation"]
    assert len(format_validation_checks) == 1
    assert format_validation_checks[0].status == CheckStatus.FAILED
    assert format_validation_checks[0].severity == IssueSeverity.WARNING
    assert format_validation_checks[0].details["exception_type"] == "MemoryError"


def test_recursion_with_security_findings_uses_limitation_note(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only true RecursionError should preserve findings via the limitation note."""
    model_path = tmp_path / "malicious.pkl"
    model_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    def _flag_security(
        self: PickleScanner,
        _data: bytes,
        result: ScanResult,
        context_path: str,
    ) -> None:
        result.add_check(
            name="Dangerous Pattern Detection",
            passed=False,
            message="Suspicious raw pickle pattern detected",
            severity=IssueSeverity.WARNING,
            location=context_path,
        )

    def _raise_recursion(self: PickleScanner, _file_obj: BinaryIO, _file_size: int) -> ScanResult:
        raise RecursionError("simulated recursion depth")

    monkeypatch.setattr(PickleScanner, "_scan_for_dangerous_patterns", _flag_security)
    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", _raise_recursion)

    result = PickleScanner().scan(str(model_path))

    limitation_checks = [
        check
        for check in result.checks
        if check.name == "Recursion Depth Check" and check.details.get("reason") == "recursion_with_security_findings"
    ]
    assert len(limitation_checks) == 1
    assert limitation_checks[0].severity == IssueSeverity.INFO
    assert result.metadata["recursion_limited"] is True
    assert result.success is True
    assert any(
        issue.severity == IssueSeverity.WARNING and issue.message == "Suspicious raw pickle pattern detected"
        for issue in result.issues
    )


def test_non_recursion_exception_with_security_findings_avoids_limitation_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-recursion failures must not take the recursion-limitation downgrade path."""
    model_path = tmp_path / "malicious.pkl"
    model_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    def _flag_security(
        self: PickleScanner,
        _data: bytes,
        result: ScanResult,
        context_path: str,
    ) -> None:
        result.add_check(
            name="Dangerous Pattern Detection",
            passed=False,
            message="Suspicious raw pickle pattern detected",
            severity=IssueSeverity.WARNING,
            location=context_path,
        )

    def _raise_runtime(self: PickleScanner, _file_obj: BinaryIO, _file_size: int) -> ScanResult:
        raise RuntimeError("simulated scanner bug")

    monkeypatch.setattr(PickleScanner, "_scan_for_dangerous_patterns", _flag_security)
    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", _raise_runtime)

    result = PickleScanner().scan(str(model_path))

    assert not any(check.details.get("reason") == "recursion_with_security_findings" for check in result.checks)
    assert result.metadata.get("recursion_limited") is not True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "pickle_file_open_failed"
    file_open_checks = [check for check in result.checks if check.name == "Pickle File Open"]
    assert len(file_open_checks) == 1
    assert file_open_checks[0].status == CheckStatus.FAILED
    assert file_open_checks[0].severity == IssueSeverity.CRITICAL
    assert result.success is False


def test_extract_globals_advanced_respects_max_opcodes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advanced extraction should stop after max_opcodes instead of parsing everything."""
    scanner = PickleScanner({"max_opcodes": 3})
    consumed: list[int] = []

    def _fake_genops(_data: object) -> Iterator[tuple[object, object, int]]:
        for i in range(10):
            consumed.append(i)
            yield (type("Op", (), {"name": "GLOBAL"})(), f"mod{i} func{i}", i)

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _fake_genops)

    globals_found = scanner._extract_globals_advanced(data=BytesIO(b"x"), multiple_pickles=False)

    assert consumed == [0, 1, 2]
    assert globals_found == {
        ("mod0", "func0", "GLOBAL"),
        ("mod1", "func1", "GLOBAL"),
        ("mod2", "func2", "GLOBAL"),
    }


def test_extract_globals_advanced_respects_scan_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advanced extraction should honor active scan timeout budget."""
    scanner = PickleScanner({"timeout": 1})
    scanner.scan_start_time = 100.0
    consumed: list[int] = []

    def _fake_genops(_data: object) -> Iterator[tuple[object, object, int]]:
        for i in range(10):
            consumed.append(i)
            yield (type("Op", (), {"name": "GLOBAL"})(), f"timeout{i} func{i}", i)

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _fake_genops)
    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.time.time", lambda: 102.0)

    globals_found = scanner._extract_globals_advanced(data=BytesIO(b"x"), multiple_pickles=False)

    assert consumed == []
    assert globals_found == set()


def test_extract_globals_advanced_respects_max_opcodes_in_buffered_second_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advanced extraction should not emit partial buffered opcodes from a later stream."""
    scanner = PickleScanner({"max_opcodes": 3})
    call_count = 0
    second_stream_consumed: list[int] = []

    def _fake_genops(data: BytesIO) -> Iterator[tuple[object, object, int]]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            for i in range(2):
                yield (type("Op", (), {"name": "GLOBAL"})(), f"first{i} func{i}", i)
            data.seek(1)
            return

        for i in range(10):
            second_stream_consumed.append(i)
            yield (type("Op", (), {"name": "GLOBAL"})(), f"second{i} func{i}", i)

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _fake_genops)

    globals_found = scanner._extract_globals_advanced(data=BytesIO(b"xy"), multiple_pickles=True)

    assert second_stream_consumed == [0]
    assert globals_found == {
        ("first0", "func0", "GLOBAL"),
        ("first1", "func1", "GLOBAL"),
    }


def test_genops_with_fallback_does_not_emit_buffered_partial_second_stream_on_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Buffered follow-on streams should not emit partial opcodes when the budget is exhausted."""
    call_count = 0
    second_stream_consumed: list[int] = []

    def _fake_genops(data: BytesIO) -> Iterator[tuple[object, object, int]]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            for i in range(2):
                yield (type("Op", (), {"name": "GLOBAL"})(), f"first{i} func{i}", i)
            data.seek(1)
            return

        for i in range(10):
            second_stream_consumed.append(i)
            yield (type("Op", (), {"name": "GLOBAL"})(), f"second{i} func{i}", i)

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.pickletools.genops", _fake_genops)

    ops = []
    op_iter = _genops_with_fallback(BytesIO(b"xy"), multi_stream=True, max_items=3)
    with pytest.raises(_GenopsBudgetExceeded, match="max_items"):
        while True:
            ops.append(next(op_iter))

    assert second_stream_consumed == [0]
    assert [arg for _opcode, arg, _pos in ops] == ["first0 func0", "first1 func1"]


def test_scan_pickle_reports_opcode_budget_truncation_for_buffered_follow_on_stream(tmp_path: Path) -> None:
    """Budget exhaustion in a later buffered stream should surface the tail detection."""
    clean_path = tmp_path / "clean.pkl"
    clean_path.write_bytes(pickle.dumps({"weights": [1, 2, 3], "name": "safe"}))

    class Evil:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (os.system, ("echo pr700-budget",))

    evil_path = tmp_path / "evil.pkl"
    with evil_path.open("wb") as f:
        pickle.dump(Evil(), f)

    combined_path = tmp_path / "combined.pkl"
    combined_path.write_bytes(clean_path.read_bytes() + evil_path.read_bytes())

    result = PickleScanner({"max_opcodes": 25}).scan(str(combined_path))

    opcode_checks = [
        check for check in result.checks if check.name == "Opcode Count Check" and check.status == CheckStatus.FAILED
    ]
    assert len(opcode_checks) == 1
    assert opcode_checks[0].severity == IssueSeverity.INFO
    assert "opcode budget" in opcode_checks[0].message.lower()
    assert opcode_checks[0].details["analysis_incomplete"] is True
    assert result.metadata["analysis_incomplete"] is True
    post_budget_checks = [
        check
        for check in result.checks
        if check.name == "Post-Budget Global Reference Scan" and check.status == CheckStatus.FAILED
    ]
    assert len(post_budget_checks) == 1
    assert post_budget_checks[0].severity == IssueSeverity.CRITICAL
    assert any(
        finding["import_reference"].endswith(".system")
        for finding in post_budget_checks[0].details.get("dangerous_references", [])
    )
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_extract_globals_advanced_preserves_partial_globals_when_genops_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advanced extraction should keep globals parsed before a late generator failure."""
    scanner = PickleScanner()

    def _fake_genops_with_fallback(
        _data: BytesIO,
        *,
        multi_stream: bool = False,
        max_items: int | None = None,
        deadline: float | None = None,
    ) -> Iterator[tuple[object, object, int]]:
        del multi_stream, max_items, deadline
        yield (type("Op", (), {"name": "GLOBAL"})(), "kept func", 0)
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner._genops_with_fallback", _fake_genops_with_fallback)

    globals_found = scanner._extract_globals_advanced(data=BytesIO(b"x"), multiple_pickles=False)

    assert globals_found == {("kept", "func", "GLOBAL")}


def test_extract_globals_advanced_skips_symbolic_post_processing_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeout exhaustion should return partial direct globals without extra O(n) work."""
    scanner = PickleScanner({"timeout": 1})
    scanner.scan_start_time = 100.0
    build_calls: list[list[tuple[object, object, int | None]]] = []

    def _fake_genops_with_fallback(
        _data: BytesIO,
        *,
        multi_stream: bool = False,
        max_items: int | None = None,
        deadline: float | None = None,
    ) -> Iterator[tuple[object, object, int]]:
        del multi_stream, max_items, deadline
        yield (type("Op", (), {"name": "GLOBAL"})(), "early func", 0)
        yield (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 1)

    def _fake_simulate_symbolic_reference_maps(
        opcodes: list[tuple[object, object, int | None]],
    ) -> tuple[
        dict[int, tuple[str, str]],
        dict[int, tuple[str, str]],
        dict[int, int],
        dict[int, bool],
        dict[int, dict[str, str]],
        dict[int, object],
    ]:
        build_calls.append(opcodes)
        return {}, {}, {}, {}, {}, {}

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner._genops_with_fallback", _fake_genops_with_fallback)
    monkeypatch.setattr(
        "modelaudit.scanners.pickle_scanner._simulate_symbolic_reference_maps",
        _fake_simulate_symbolic_reference_maps,
    )
    monkeypatch.setattr("modelaudit.scanners.pickle_scanner.time.time", lambda: 102.0)

    globals_found = scanner._extract_globals_advanced(data=BytesIO(b"x"), multiple_pickles=False)

    assert globals_found == {("early", "func", "GLOBAL")}
    assert build_calls == []


class TestPickleImportOnlyGlobalFindings:
    def test_import_only_safety_helper_keeps_torch_load_unsafe(self) -> None:
        ml_context: dict[str, object] = {}

        assert _is_actually_dangerous_global("torch", "load", ml_context)
        assert not _is_safe_import_only_global("torch", "load", ml_context)
        assert _is_safe_import_only_global("builtins", "set", ml_context)

    def test_import_only_safety_helper_blocks_recursive_loaders(self) -> None:
        ml_context: dict[str, object] = {}

        assert not _is_safe_import_only_global("dill", "load", ml_context)
        assert not _is_safe_import_only_global("dill", "loads", ml_context)
        assert not _is_safe_import_only_global("joblib", "_pickle_load", ml_context)

    def test_import_only_global_malicious_is_flagged(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_global.pkl"
        payload_path.write_bytes(b"cevilpkg\nthing\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "Global Module Reference Check" and c.status == CheckStatus.FAILED
        ]
        assert failed_checks
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "evilpkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]
        assert any("evilpkg.thing" in c.message for c in matched)

    def test_import_only_global_mixed_case_module_is_flagged(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_global_mixed_case.pkl"
        payload_path.write_bytes(b"cEvilPkg\nthing\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "Global Module Reference Check" and c.status == CheckStatus.FAILED
        ]
        assert failed_checks
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "EvilPkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]
        assert any("EvilPkg.thing" in c.message for c in matched)

    def test_import_only_global_comment_token_bypass_still_fails(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_global_comment_token.pkl"
        payload_path.write_bytes(b"\x80\x04" + _short_binunicode(b"# benign comment token") + b"0cevilpkg\nthing\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "Global Module Reference Check" and c.status == CheckStatus.FAILED
        ]
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "evilpkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]
        assert any("evilpkg.thing" in c.message for c in matched)

    def test_import_only_stack_global_is_flagged(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_stack_global.pkl"
        payload_path.write_bytes(b"\x80\x04\x8c\x07evilpkg\x8c\x05thing\x93.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "STACK_GLOBAL Module Check" and c.status == CheckStatus.FAILED
        ]
        assert failed_checks
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "evilpkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]
        assert any("evilpkg.thing" in c.message for c in matched)

    def test_import_only_stack_global_comment_token_bypass_still_fails(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_stack_global_comment_token.pkl"
        payload_path.write_bytes(
            b"\x80\x04"
            + _short_binunicode(b"# benign comment token")
            + b"0"
            + _short_binunicode(b"evilpkg")
            + _short_binunicode(b"thing")
            + b"\x93."
        )

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "STACK_GLOBAL Module Check" and c.status == CheckStatus.FAILED
        ]
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "evilpkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]
        assert any("evilpkg.thing" in c.message for c in matched)

    @pytest.mark.parametrize(
        ("payload", "check_name", "ref"),
        [
            (b"ctorch\nload\n.", "Global Module Reference Check", "torch.load"),
            (b"\x80\x04\x8c\x05torch\x8c\x04load\x93.", "STACK_GLOBAL Module Check", "torch.load"),
        ],
    )
    def test_import_only_torch_load_payloads_are_flagged(
        self, tmp_path: Path, payload: bytes, check_name: str, ref: str
    ) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / f"{check_name.replace(' ', '_').lower()}.pkl"
        payload_path.write_bytes(payload)

        result = scanner.scan(str(payload_path))

        failed_checks = [c for c in result.checks if c.name == check_name and c.status == CheckStatus.FAILED]
        assert failed_checks, [c.message for c in result.checks]
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == ref and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]
        assert any(ref in c.message for c in matched)

    def test_import_only_joblib_pickle_load_payload_is_flagged(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_joblib_pickle_load.pkl"
        payload_path.write_bytes(b"cjoblib\n_pickle_load\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.name == "Global Module Reference Check"
            and c.status == CheckStatus.FAILED
            and c.severity == IssueSeverity.CRITICAL
        ]
        assert failed_checks, [c.message for c in result.checks]
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "joblib._pickle_load"
            and c.details.get("import_only") is True
            and c.details.get("classification") == "dangerous"
        ]
        assert matched, [c.details for c in failed_checks]

    @pytest.mark.parametrize(
        ("payload", "check_name"),
        [
            (b"\x80\x04cjoblib\n_pickle_load\n\x8c\x0bpayload.pkl\x85R.", "Global Module Reference Check"),
            (
                b"\x80\x04\x8c\x06joblib\x8c\x0c_pickle_load\x93\x8c\x0bpayload.pkl\x85R.",
                "STACK_GLOBAL Module Check",
            ),
        ],
    )
    def test_executed_joblib_pickle_load_payloads_are_not_allowlisted(
        self, tmp_path: Path, payload: bytes, check_name: str
    ) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / f"{check_name.replace(' ', '_').lower()}_joblib_pickle_load.pkl"
        payload_path.write_bytes(payload)

        result = scanner.scan(str(payload_path))

        import_only_failures = [
            c
            for c in result.checks
            if c.name == check_name
            and c.status == CheckStatus.FAILED
            and c.details.get("import_only") is True
            and c.details.get("import_reference") == "joblib._pickle_load"
        ]
        assert not import_only_failures, [c.details for c in result.checks if c.name == check_name]
        assert any(
            c.name == "REDUCE Opcode Safety Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("associated_global") == "joblib._pickle_load"
            for c in result.checks
        )

    @pytest.mark.parametrize(
        ("payload", "check_name", "ref"),
        [
            (b"cTorch\nload\n.", "Global Module Reference Check", "Torch.load"),
            (b"\x80\x04\x8c\x05Torch\x8c\x04load\x93.", "STACK_GLOBAL Module Check", "Torch.load"),
        ],
    )
    def test_import_only_mixed_case_dangerous_refs_stay_critical(
        self, tmp_path: Path, payload: bytes, check_name: str, ref: str
    ) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / f"mixed_case_{check_name.replace(' ', '_').lower()}.pkl"
        payload_path.write_bytes(payload)

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.name == check_name and c.status == CheckStatus.FAILED and c.severity == IssueSeverity.CRITICAL
        ]
        assert failed_checks, [c.message for c in result.checks]
        matched = [
            c
            for c in failed_checks
            if c.details.get("classification") == "dangerous"
            and c.details.get("import_only") is True
            and c.details.get("import_reference") == ref
        ]
        assert matched, [c.details for c in failed_checks]

    @pytest.mark.parametrize(
        ("payload", "check_name", "ref"),
        [
            (b"cImportlib\nresources\n.", "Global Module Reference Check", "Importlib.resources"),
            (b"\x80\x04\x8c\tImportlib\x8c\tresources\x93.", "STACK_GLOBAL Module Check", "Importlib.resources"),
        ],
    )
    def test_import_only_mixed_case_dangerous_module_refs_stay_critical(
        self, tmp_path: Path, payload: bytes, check_name: str, ref: str
    ) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / f"mixed_case_module_{check_name.replace(' ', '_').lower()}.pkl"
        payload_path.write_bytes(payload)

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.name == check_name and c.status == CheckStatus.FAILED and c.severity == IssueSeverity.CRITICAL
        ]
        matched = [
            c
            for c in failed_checks
            if c.details.get("classification") == "dangerous"
            and c.details.get("import_only") is True
            and c.details.get("import_reference") == ref
        ]
        assert matched, [c.details for c in failed_checks]

    @pytest.mark.parametrize(
        "payload,ref",
        [
            (b"cbuiltins\nset\n.", "builtins.set"),
            (b"ccollections\nOrderedDict\n.", "collections.OrderedDict"),
            (b"cnumpy.core.multiarray\n_reconstruct\n.", "numpy.core.multiarray._reconstruct"),
            (b"csklearn.pipeline\nPipeline\n.", "sklearn.pipeline.Pipeline"),
        ],
    )
    def test_import_only_safe_globals_remain_non_failing(self, tmp_path: Path, payload: bytes, ref: str) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / f"safe_{ref.replace('.', '_')}.pkl"
        payload_path.write_bytes(payload)

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.status == CheckStatus.FAILED
            and ref in c.message
            and c.name in {"Global Module Reference Check", "STACK_GLOBAL Module Check"}
        ]
        assert not failed_checks, [c.message for c in failed_checks]

    def test_import_only_stdlib_constructor_remains_non_failing(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_datetime.pkl"
        payload_path.write_bytes(b"cdatetime\ndatetime\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.status == CheckStatus.FAILED
            and c.name == "Global Module Reference Check"
            and "datetime.datetime" in c.message
        ]
        assert not failed_checks, [c.message for c in failed_checks]

    def test_import_only_safe_stack_global_parity_remains_non_failing(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "safe_stack_global_builtins_set.pkl"
        payload_path.write_bytes(b"\x80\x04\x8c\x08builtins\x8c\x03set\x93.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.status == CheckStatus.FAILED
            and c.name in {"Global Module Reference Check", "STACK_GLOBAL Module Check"}
            and "builtins.set" in c.message
        ]
        assert not failed_checks, [c.message for c in failed_checks]

    def test_import_only_stdlib_constructor_stack_global_parity_remains_non_failing(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_datetime_stack_global.pkl"
        payload_path.write_bytes(b"\x80\x04\x8c\x08datetime\x8c\x08datetime\x93.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.status == CheckStatus.FAILED
            and c.name in {"Global Module Reference Check", "STACK_GLOBAL Module Check"}
            and "datetime.datetime" in c.message
        ]
        assert not failed_checks, [c.message for c in failed_checks]

    def test_executed_import_only_allowlist_ref_is_not_marked_safe_allowlisted(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "executed_datetime_reduce.pkl"
        payload_path.write_bytes(b"cdatetime\ndatetime\n)R.")

        result = scanner.scan(str(payload_path))

        passed_checks = [
            c
            for c in result.checks
            if c.name == "Global Module Reference Check"
            and c.status == CheckStatus.PASSED
            and c.details.get("import_reference") == "datetime.datetime"
            and c.details.get("classification") == "safe_allowlisted"
            and c.details.get("import_only") is False
        ]
        assert not passed_checks, [c.details for c in result.checks if c.name == "Global Module Reference Check"]
        assert any(
            c.name == "REDUCE Opcode Safety Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("associated_global") == "datetime.datetime"
            for c in result.checks
        )

    def test_import_only_data_label_like_module_is_ignored(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_data_label.pkl"
        payload_path.write_bytes(b"cPEDRA_2020\nthing\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.status == CheckStatus.FAILED
            and c.name == "Global Module Reference Check"
            and "PEDRA_2020.thing" in c.message
        ]
        assert not failed_checks, [c.message for c in failed_checks]

    def test_import_only_data_label_like_stack_global_module_is_ignored(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_data_label_stack_global.pkl"
        payload_path.write_bytes(b"\x80\x04\x8c\nPEDRA_2020\x8c\x05thing\x93.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c
            for c in result.checks
            if c.status == CheckStatus.FAILED
            and c.name in {"Global Module Reference Check", "STACK_GLOBAL Module Check"}
            and "PEDRA_2020.thing" in c.message
        ]
        assert not failed_checks, [c.message for c in failed_checks]

    def test_import_only_malicious_in_second_stream_is_flagged(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "second_stream_import_only.pkl"
        payload_path.write_bytes(b"cbuiltins\nset\n." + b"cevilpkg\nthing\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "Global Module Reference Check" and c.status == CheckStatus.FAILED
        ]
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "evilpkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]

    def test_import_only_malicious_first_stream_with_benign_second_stream_is_flagged(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "first_stream_import_only.pkl"
        payload_path.write_bytes(b"cevilpkg\nthing\n." + b"cbuiltins\nset\n.")

        result = scanner.scan(str(payload_path))

        failed_checks = [
            c for c in result.checks if c.name == "Global Module Reference Check" and c.status == CheckStatus.FAILED
        ]
        matched = [
            c
            for c in failed_checks
            if c.details.get("import_reference") == "evilpkg.thing" and c.details.get("import_only") is True
        ]
        assert matched, [c.details for c in failed_checks]

    def test_reduce_backed_global_does_not_emit_import_only_failure(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "reduce_global.pkl"
        payload_path.write_bytes(b"cos\nsystem\n(Vecho hi\ntR.")

        result = scanner.scan(str(payload_path))

        import_only_failures = [
            c
            for c in result.checks
            if c.name == "Global Module Reference Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("import_only") is True
        ]
        assert not import_only_failures, [c.message for c in import_only_failures]
        assert any(c.name == "REDUCE Opcode Safety Check" and c.status == CheckStatus.FAILED for c in result.checks)

    def test_reduce_backed_stack_global_does_not_emit_import_only_failure(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "reduce_stack_global.pkl"
        payload_path.write_bytes(b"\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x07echo hi\x85R.")

        result = scanner.scan(str(payload_path))

        import_only_failures = [
            c
            for c in result.checks
            if c.name == "STACK_GLOBAL Module Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("import_only") is True
        ]
        assert not import_only_failures, [c.message for c in import_only_failures]
        assert any(c.name == "REDUCE Opcode Safety Check" and c.status == CheckStatus.FAILED for c in result.checks)

    def test_same_reference_import_only_origin_is_folded_into_later_reduce(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "import_only_then_reduce.pkl"
        payload_path.write_bytes(b"cevilpkg\nthing\ncevilpkg\nthing\n(tR.")

        result = scanner.scan(str(payload_path))

        import_only_failures = [
            c
            for c in result.checks
            if c.name == "Global Module Reference Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("import_only") is True
            and c.details.get("import_reference") == "evilpkg.thing"
        ]
        assert not import_only_failures, [c.details for c in result.checks]

        reduce_checks = [
            c
            for c in result.checks
            if c.name == "REDUCE Opcode Safety Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("associated_global") == "evilpkg.thing"
        ]
        assert len(reduce_checks) == 1, [c.details for c in result.checks]
        assert any(
            evidence.get("check_name") == "Global Module Reference Check"
            and evidence.get("details", {}).get("import_only") is True
            and evidence.get("details", {}).get("import_reference") == "evilpkg.thing"
            for evidence in reduce_checks[0].details.get("supporting_evidence", [])
        ), f"Expected folded import-only evidence on REDUCE finding: {reduce_checks[0].details}"
        assert not any(
            c.name == "Reduce Pattern Analysis"
            and c.status == CheckStatus.FAILED
            and c.details.get("module") == "evilpkg"
            and c.details.get("function") == "thing"
            for c in result.checks
        ), f"Expected single primary finding for evilpkg.thing: {result.checks}"

    def test_same_stack_global_reference_import_only_origin_is_folded_into_later_reduce(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "stack_global_import_only_then_reduce.pkl"
        payload_path.write_bytes(
            b"\x80\x04"
            + _short_binunicode(b"evilpkg")
            + _short_binunicode(b"thing")
            + b"\x93"
            + _short_binunicode(b"evilpkg")
            + _short_binunicode(b"thing")
            + b"\x93)R."
        )

        result = scanner.scan(str(payload_path))

        import_only_failures = [
            c
            for c in result.checks
            if c.name == "STACK_GLOBAL Module Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("import_only") is True
            and c.details.get("import_reference") == "evilpkg.thing"
        ]
        assert not import_only_failures, [c.details for c in result.checks]

        reduce_checks = [
            c
            for c in result.checks
            if c.name == "REDUCE Opcode Safety Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("associated_global") == "evilpkg.thing"
        ]
        assert len(reduce_checks) == 1, [c.details for c in result.checks]
        assert any(
            evidence.get("check_name") == "STACK_GLOBAL Module Check"
            and evidence.get("details", {}).get("import_only") is True
            and evidence.get("details", {}).get("import_reference") == "evilpkg.thing"
            for evidence in reduce_checks[0].details.get("supporting_evidence", [])
        ), f"Expected folded STACK_GLOBAL evidence on REDUCE finding: {reduce_checks[0].details}"
        assert not any(
            c.name == "Reduce Pattern Analysis"
            and c.status == CheckStatus.FAILED
            and c.details.get("module") == "evilpkg"
            and c.details.get("function") == "thing"
            for c in result.checks
        ), f"Expected single primary finding for evilpkg.thing: {result.checks}"

    def test_same_reference_across_streams_is_folded_into_single_primary_finding(self, tmp_path: Path) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / "multistream_import_then_reduce.pkl"
        payload_path.write_bytes(b"cos\nsystem\n." + b"cos\nsystem\n(Vecho hi\ntR.")

        result = scanner.scan(str(payload_path))

        primary_reduce_checks = [
            c
            for c in result.checks
            if c.name == "REDUCE Opcode Safety Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("associated_global") in SYSTEM_GLOBAL_VARIANTS
        ]
        assert len(primary_reduce_checks) == 1, [c.details for c in result.checks]
        assert any(
            evidence.get("check_name") == "Global Module Reference Check"
            and evidence.get("details", {}).get("import_only") is True
            and evidence.get("details", {}).get("import_reference") in SYSTEM_GLOBAL_VARIANTS
            for evidence in primary_reduce_checks[0].details.get("supporting_evidence", [])
        ), f"Expected multistream import-only evidence on REDUCE finding: {primary_reduce_checks[0].details}"
        assert not any(
            c.name == "Global Module Reference Check"
            and c.status == CheckStatus.FAILED
            and c.details.get("import_only") is True
            and c.details.get("import_reference") in SYSTEM_GLOBAL_VARIANTS
            for c in result.checks
        ), f"Expected os/posix/nt.system import-only failure to fold into the REDUCE finding: {result.checks}"
        assert not any(
            c.name == "Reduce Pattern Analysis"
            and c.status == CheckStatus.FAILED
            and c.details.get("module") == "os"
            and c.details.get("function") == "system"
            for c in result.checks
        ), f"Expected os/posix/nt.system to emit a single primary finding across streams: {result.checks}"

    @pytest.mark.parametrize(
        ("payload", "check_name"),
        [
            (b"\x80\x02cos\nsystem\n)\x81.", "Global Module Reference Check"),
            (b"\x80\x04\x8c\x02os\x8c\x06system\x93)\x81.", "STACK_GLOBAL Module Check"),
            (b"\x80\x04cos\nsystem\n)}\x92.", "Global Module Reference Check"),
            (b"\x80\x04\x8c\x02os\x8c\x06system\x93)}\x92.", "STACK_GLOBAL Module Check"),
            (b"(cos\nsystem\no.", "Global Module Reference Check"),
            (b"\x80\x04(\x8c\x02os\x8c\x06system\x93o.", "STACK_GLOBAL Module Check"),
        ],
    )
    def test_constructor_backed_refs_do_not_emit_import_only_failures(
        self, tmp_path: Path, payload: bytes, check_name: str
    ) -> None:
        scanner = PickleScanner()
        payload_path = tmp_path / f"{check_name.replace(' ', '_').lower()}_constructor.pkl"
        payload_path.write_bytes(payload)

        result = scanner.scan(str(payload_path))

        import_only_failures = [
            c
            for c in result.checks
            if c.name == check_name and c.status == CheckStatus.FAILED and c.details.get("import_only") is True
        ]
        assert not import_only_failures, [c.details for c in result.checks if c.name == check_name]
        assert any(
            c.name == "INST/OBJ/NEWOBJ/NEWOBJ_EX Opcode Safety Check" and c.status == CheckStatus.FAILED
            for c in result.checks
        )

    def test_symbolic_simulation_inst_clears_marked_arguments(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "MARK"})(), None, 0),
            (type("Op", (), {"name": "UNICODE"})(), "evilpkg", 1),
            (type("Op", (), {"name": "INST"})(), "collections OrderedDict", 2),
            (type("Op", (), {"name": "BUILD"})(), None, 3),
            (type("Op", (), {"name": "UNICODE"})(), "thing", 4),
            (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 5),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert callable_refs[2] == ("collections", "OrderedDict")
        assert callable_origin_refs[2] == 2
        assert callable_origin_is_ext == {}
        assert mutation_target_refs == {}
        assert 5 not in stack_global_refs
        assert malformed_stack_globals[5]["reason"] == "insufficient_context"

    def test_symbolic_simulation_protocol_five_buffers_preserve_stack_alignment(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "UNICODE"})(), "evilpkg", 0),
            (type("Op", (), {"name": "NEXT_BUFFER"})(), None, 1),
            (type("Op", (), {"name": "READONLY_BUFFER"})(), None, 2),
            (type("Op", (), {"name": "BINPUT"})(), 0, 3),
            (type("Op", (), {"name": "POP"})(), None, 4),
            (type("Op", (), {"name": "UNICODE"})(), "thing", 5),
            (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 6),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert stack_global_refs[6] == ("evilpkg", "thing")
        assert callable_refs == {}
        assert callable_origin_refs == {}
        assert callable_origin_is_ext == {}
        assert malformed_stack_globals == {}
        assert mutation_target_refs == {}

    def test_symbolic_simulation_unknown_opcode_uses_generic_stack_effect_metadata(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "UNICODE"})(), "os", 0),
            (type("Op", (), {"name": "UNICODE"})(), "garbage", 1),
            (type("Op", (), {"name": "FUTURE_POP_OPCODE", "stack_before": [object()], "stack_after": []})(), None, 2),
            (type("Op", (), {"name": "UNICODE"})(), "system", 3),
            (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 4),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert stack_global_refs[4] == ("os", "system")
        assert callable_refs == {}
        assert callable_origin_refs == {}
        assert callable_origin_is_ext == {}
        assert malformed_stack_globals == {}
        assert mutation_target_refs == {}

    def test_symbolic_simulation_generic_stack_effect_preserves_setitems_target(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "EMPTY_DICT"})(), None, 0),
            (type("Op", (), {"name": "MARK"})(), None, 1),
            (type("Op", (), {"name": "UNICODE"})(), "key", 2),
            (type("Op", (), {"name": "UNICODE"})(), "garbage", 3),
            (type("Op", (), {"name": "FUTURE_POP_OPCODE", "stack_before": [object()], "stack_after": []})(), None, 4),
            (type("Op", (), {"name": "UNICODE"})(), "value", 5),
            (type("Op", (), {"name": "SETITEMS"})(), None, 6),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert stack_global_refs == {}
        assert callable_refs == {}
        assert callable_origin_refs == {}
        assert callable_origin_is_ext == {}
        assert malformed_stack_globals == {}
        assert mutation_target_refs[6].kind == "dict"

    def test_symbolic_simulation_stack_neutral_opcode_does_not_shift_stack_global(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "UNICODE"})(), "evilpkg", 0),
            (type("Op", (), {"name": "FRAME", "stack_before": [], "stack_after": []})(), None, 1),
            (type("Op", (), {"name": "UNICODE"})(), "thing", 2),
            (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 3),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert stack_global_refs[3] == ("evilpkg", "thing")
        assert callable_refs == {}
        assert callable_origin_refs == {}
        assert callable_origin_is_ext == {}
        assert malformed_stack_globals == {}
        assert mutation_target_refs == {}

    def test_symbolic_simulation_pop_removes_decoy_before_stack_global(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "UNICODE"})(), "torch", 0),
            (type("Op", (), {"name": "UNICODE"})(), "decoy", 1),
            (type("Op", (), {"name": "POP"})(), None, 2),
            (type("Op", (), {"name": "UNICODE"})(), "nn", 3),
            (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 4),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert stack_global_refs[4] == ("torch", "nn")
        assert callable_refs == {}
        assert callable_origin_refs == {}
        assert callable_origin_is_ext == {}
        assert malformed_stack_globals == {}
        assert mutation_target_refs == {}

    def test_symbolic_simulation_stop_resets_stack_before_stack_global(self) -> None:
        opcodes = [
            (type("Op", (), {"name": "UNICODE"})(), "torch", 0),
            (type("Op", (), {"name": "STOP"})(), None, 1),
            (type("Op", (), {"name": "UNICODE"})(), "nn", 2),
            (type("Op", (), {"name": "STACK_GLOBAL"})(), None, 3),
        ]

        (
            stack_global_refs,
            callable_refs,
            callable_origin_refs,
            callable_origin_is_ext,
            malformed_stack_globals,
            mutation_target_refs,
        ) = _simulate_symbolic_reference_maps(opcodes)

        assert 3 not in stack_global_refs
        assert callable_refs == {}
        assert callable_origin_refs == {}
        assert callable_origin_is_ext == {}
        assert malformed_stack_globals[3]["reason"] == "insufficient_context"
        assert mutation_target_refs == {}


@pytest.mark.parametrize(
    ("module_name", "func_name", "payload"),
    [
        ("torch.jit", "load", b"\x80\x02ctorch.jit\nload\n."),
        ("torch._dynamo", "optimize", b"\x80\x02ctorch._dynamo\noptimize\n."),
        ("torch", "compile", b"\x80\x02ctorch\ncompile\n."),
        ("numpy.f2py", "compile", b"\x80\x02cnumpy.f2py\ncompile\n."),
        ("numpy.distutils.core", "setup", b"\x80\x02cnumpy.distutils.core\nsetup\n."),
        (
            "torch.storage",
            "_load_from_bytes",
            b"\x80\x02ctorch.storage\n_load_from_bytes\n.",
        ),
    ],
)
def test_risky_ml_import_only_globals_are_detected(
    tmp_path: Path, module_name: str, func_name: str, payload: bytes
) -> None:
    """Import-only risky ML GLOBAL refs should be flagged even without REDUCE."""
    path = tmp_path / f"{module_name.replace('.', '_')}_{func_name}.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    full_ref = f"{module_name}.{func_name}"
    failing_checks = [
        check
        for check in result.checks
        if check.name == "Global Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("import_reference") == full_ref
    ]
    matching_issues = [issue for issue in result.issues if full_ref in issue.message]

    assert failing_checks, f"Expected failed GLOBAL check for {full_ref}, got: {result.checks}"
    assert all(check.severity == IssueSeverity.CRITICAL for check in failing_checks), (
        f"Expected CRITICAL GLOBAL finding for {full_ref}, got: "
        f"{[(check.severity, check.message) for check in failing_checks]}"
    )
    assert matching_issues, f"Expected issue for risky ML import {full_ref}, got: {result.issues}"
    assert any(issue.why for issue in matching_issues), f"Expected explanation for risky ML import {full_ref}"


def test_build_on_non_safe_global_emits_setstate_warning(tmp_path: Path) -> None:
    """BUILD should be flagged when it mutates an object from a non-safe global."""
    scanner = PickleScanner()
    payload_path = tmp_path / "build_setstate_non_safe.pkl"
    payload_path.write_bytes(b"\x80\x02cevilpkg\nStateCarrier\n)R}b.")

    result = scanner.scan(str(payload_path))

    build_pattern_checks = [
        check
        for check in result.checks
        if check.name == "BUILD Opcode Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("pattern") == "BUILD_SETSTATE_NON_SAFE_GLOBAL"
    ]
    assert build_pattern_checks, [check.details for check in result.checks if check.name == "BUILD Opcode Analysis"]
    assert build_pattern_checks[0].severity == IssueSeverity.WARNING
    assert build_pattern_checks[0].message == (
        "Detected potential __setstate__ exploitation via BUILD with evilpkg.StateCarrier"
    )
    assert build_pattern_checks[0].rule_code == get_pickle_opcode_rule_code("BUILD")
    assert build_pattern_checks[0].details.get("associated_global") == "evilpkg.StateCarrier"
    assert build_pattern_checks[0].details.get("module") == "evilpkg"
    assert build_pattern_checks[0].details.get("function") == "StateCarrier"
    assert build_pattern_checks[0].details.get("position") == 27
    assert "__setstate__" in str(build_pattern_checks[0].details.get("description", ""))


def test_tree_marker_threshold_escalation_blocked_by_dangerous_global() -> None:
    """Tree-marker threshold escalation should not apply when risky ML globals are present."""
    opcodes: list[tuple[object, object, int]] = [
        (type("Op", (), {"name": "GLOBAL"})(), "sklearn.ensemble._forest RandomForestClassifier", 0),
    ]
    opcodes.extend((type("Op", (), {"name": "REDUCE"})(), None, index) for index in range(1, 62))

    callable_refs = dict.fromkeys(range(1, 62), ("numpy", "load"))
    suspicious = check_opcode_sequence(
        opcodes,
        {"is_ml_content": True, "frameworks": {"sklearn": {}}, "overall_confidence": 0.9},
        stack_global_refs={},
        callable_refs=callable_refs,
        callable_origin_is_ext={},
    )

    assert any(seq.get("pattern") == "MANY_DANGEROUS_OPCODES" for seq in suspicious), suspicious


def test_safe_builtin_global_does_not_block_tree_threshold_escalation() -> None:
    """Allowlisted globals from dangerous modules must not suppress tree-model threshold escalation."""
    opcodes: list[tuple[object, object, int]] = [
        (type("Op", (), {"name": "GLOBAL"})(), "sklearn.ensemble._forest RandomForestClassifier", 0),
        (type("Op", (), {"name": "GLOBAL"})(), "builtins set", 1),
    ]
    for index in range(2, 122, 2):
        opcodes.append((type("Op", (), {"name": "REDUCE"})(), None, index))
        opcodes.append((type("Op", (), {"name": "BUILD"})(), None, index + 1))

    callable_refs = dict.fromkeys(range(2, 122, 2), ("sklearn.tree._tree", "Tree"))
    suspicious = check_opcode_sequence(
        opcodes,
        {"is_ml_content": True, "frameworks": {"sklearn": {}}, "overall_confidence": 0.9},
        stack_global_refs={},
        callable_refs=callable_refs,
        callable_origin_is_ext={},
    )

    assert not any(seq.get("pattern") == "MANY_DANGEROUS_OPCODES" for seq in suspicious), suspicious


def test_clean_sklearn_build_sequence_stays_below_opcode_alert_threshold() -> None:
    """Legitimate sklearn REDUCE+BUILD patterns should remain suppressed."""
    opcodes: list[tuple[object, object, int]] = [
        (type("Op", (), {"name": "GLOBAL"})(), "sklearn.ensemble._forest RandomForestClassifier", 0),
    ]
    for index in range(1, 121, 2):
        opcodes.append((type("Op", (), {"name": "REDUCE"})(), None, index))
        opcodes.append((type("Op", (), {"name": "BUILD"})(), None, index + 1))

    callable_refs = dict.fromkeys(range(1, 121, 2), ("sklearn.tree._tree", "Tree"))
    suspicious = check_opcode_sequence(
        opcodes,
        {"is_ml_content": True, "frameworks": {"sklearn": {}}, "overall_confidence": 0.9},
        stack_global_refs={},
        callable_refs=callable_refs,
        callable_origin_is_ext={},
    )

    assert not suspicious


@pytest.mark.parametrize(
    ("module_name", "func_name", "payload"),
    [
        ("torch", "jit", b"\x80\x02ctorch\njit\n."),
        ("torch", "_dynamo", b"\x80\x02ctorch\n_dynamo\n."),
        ("torch", "_inductor", b"\x80\x02ctorch\n_inductor\n."),
        ("numpy", "f2py", b"\x80\x02cnumpy\nf2py\n."),
        ("numpy", "distutils", b"\x80\x02cnumpy\ndistutils\n."),
        ("torch", "compile.__globals__", b"\x80\x02ctorch\ncompile.__globals__\n."),
        ("torch", "jit.script", b"\x80\x02ctorch\njit.script\n."),
        ("torch", "_dynamo.optimize", b"\x80\x02ctorch\n_dynamo.optimize\n."),
        ("torch", "storage._load_from_bytes", b"\x80\x02ctorch\nstorage._load_from_bytes\n."),
        (
            "torch.storage",
            "_load_from_bytes.__code__",
            b"\x80\x02ctorch.storage\n_load_from_bytes.__code__\n.",
        ),
        ("numpy", "distutils.core.setup", b"\x80\x02cnumpy\ndistutils.core.setup\n."),
    ],
)
def test_risky_ml_parent_attribute_globals_are_detected(
    tmp_path: Path, module_name: str, func_name: str, payload: bytes
) -> None:
    """Parent/attribute GLOBAL forms must not bypass risky ML import detection."""
    path = tmp_path / f"{module_name}_{func_name}.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    full_ref = f"{module_name}.{func_name}"
    failing_checks = [
        check
        for check in result.checks
        if check.name in {"Global Module Reference Check", "Advanced Global Reference Check"}
        and check.status == CheckStatus.FAILED
        and (
            check.details.get("import_reference") == full_ref
            or (check.details.get("module") == module_name and check.details.get("function") == func_name)
        )
    ]

    assert failing_checks, f"Expected failed GLOBAL check for {full_ref}, got: {result.checks}"
    check_summaries = [(check.severity, check.message) for check in failing_checks]
    assert all(check.severity == IssueSeverity.CRITICAL for check in failing_checks), (
        f"Expected CRITICAL GLOBAL finding for {full_ref}, got: {check_summaries}"
    )
    assert any(full_ref in issue.message for issue in result.issues), (
        f"Expected issue for risky ML import {full_ref}, got: {[issue.message for issue in result.issues]}"
    )


def test_comment_token_does_not_bypass_risky_ml_import_detection(tmp_path: Path) -> None:
    """A comment-like string must not suppress risky ML import-only detection."""
    comment_token = b"# benign comment token"
    comment_prefix = b"\x8c" + bytes([len(comment_token)]) + comment_token + b"0"
    payload = b"\x80\x02" + comment_prefix + b"ctorch\ncompile.__globals__\n."

    path = tmp_path / "torch_compile_comment.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name in {"Global Module Reference Check", "Advanced Global Reference Check"}
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and (
            check.details.get("import_reference") == "torch.compile.__globals__"
            or (check.details.get("module") == "torch" and check.details.get("function") == "compile.__globals__")
        )
        for check in result.checks
    ), f"Expected torch.compile.__globals__ detection despite comment token, checks: {result.checks}"


def test_risky_ml_reduce_target_is_detected(tmp_path: Path) -> None:
    """Risky ML globals should remain CRITICAL when later consumed by REDUCE."""
    path = tmp_path / "torch_jit_reduce.pkl"
    path.write_bytes(b"\x80\x02ctorch.jit\nload\n(tR.")

    result = PickleScanner().scan(str(path))
    reduce_checks = [
        check
        for check in result.checks
        if check.name == "REDUCE Opcode Safety Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("associated_global") == "torch.jit.load"
    ]

    assert reduce_checks, f"Expected REDUCE finding for torch.jit.load, got: {result.checks}"
    assert all(check.severity == IssueSeverity.CRITICAL for check in reduce_checks), (
        f"Expected CRITICAL REDUCE finding for torch.jit.load, got: "
        f"{[(check.severity, check.message) for check in reduce_checks]}"
    )
    assert any(
        evidence.get("check_name") == "Reduce Pattern Analysis"
        and evidence.get("details", {}).get("module") == "torch.jit"
        and evidence.get("details", {}).get("function") == "load"
        for check in reduce_checks
        for evidence in check.details.get("supporting_evidence", [])
    ), f"Expected Reduce Pattern Analysis evidence for torch.jit.load, got: {result.checks}"
    assert not any(
        check.name == "Reduce Pattern Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("module") == "torch.jit"
        and check.details.get("function") == "load"
        for check in result.checks
    ), f"Expected torch.jit.load to emit a single primary finding, got: {result.checks}"


def test_comment_token_does_not_bypass_risky_ml_reduce_detection(tmp_path: Path) -> None:
    """A comment-like string must not suppress risky ML REDUCE detection."""
    comment_token = b"# not a real comment"
    comment_prefix = b"\x8c" + bytes([len(comment_token)]) + comment_token + b"0"
    payload = b"\x80\x02" + comment_prefix + b"ctorch.jit\nload\n)R."

    path = tmp_path / "torch_jit_comment_reduce.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "REDUCE Opcode Safety Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("associated_global") == "torch.jit.load"
        for check in result.checks
    ), f"Expected torch.jit.load REDUCE detection despite comment token, checks: {result.checks}"
    assert any(
        evidence.get("check_name") == "Reduce Pattern Analysis"
        and evidence.get("details", {}).get("module") == "torch.jit"
        and evidence.get("details", {}).get("function") == "load"
        for check in result.checks
        if check.name == "REDUCE Opcode Safety Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("associated_global") == "torch.jit.load"
        for evidence in check.details.get("supporting_evidence", [])
    ), f"Expected Reduce Pattern Analysis evidence despite comment token, checks: {result.checks}"
    assert not any(
        check.name == "Reduce Pattern Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("module") == "torch.jit"
        and check.details.get("function") == "load"
        for check in result.checks
    ), f"Expected torch.jit.load to emit a single primary finding despite comment token, got: {result.checks}"


def test_risky_ml_stack_global_detection(tmp_path: Path) -> None:
    """Risky ML imports hidden behind STACK_GLOBAL should be detected."""

    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"torch.jit")
    payload += _short_binunicode(b"load")
    payload += b"\x93"  # STACK_GLOBAL
    payload += b"."  # STOP

    path = tmp_path / "torch_jit_stack_global.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    failing_checks = [
        check
        for check in result.checks
        if check.name == "STACK_GLOBAL Module Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("module") == "torch.jit"
        and check.details.get("function") == "load"
    ]

    assert failing_checks, f"Expected STACK_GLOBAL torch.jit.load detection. Checks: {result.checks}"
    assert all(check.severity == IssueSeverity.CRITICAL for check in failing_checks), (
        f"Expected CRITICAL STACK_GLOBAL finding for torch.jit.load, got: "
        f"{[(check.severity, check.message) for check in failing_checks]}"
    )
    assert any(issue.why for issue in result.issues if "torch.jit.load" in issue.message)


def test_risky_ml_parent_attribute_stack_global_detection(tmp_path: Path) -> None:
    """STACK_GLOBAL parent/attribute refs should trigger the risky ML policy."""
    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"numpy")
    payload += _short_binunicode(b"distutils")
    payload += b"\x93"  # STACK_GLOBAL
    payload += b"."  # STOP

    path = tmp_path / "numpy_distutils_stack_global.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    failing_checks = [
        check
        for check in result.checks
        if check.name == "STACK_GLOBAL Module Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module") == "numpy"
        and check.details.get("function") == "distutils"
    ]

    assert failing_checks, f"Expected STACK_GLOBAL numpy.distutils detection. Checks: {result.checks}"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "numpy.distutils" in issue.message for issue in result.issues
    ), f"Expected CRITICAL numpy.distutils issue. Issues: {[issue.message for issue in result.issues]}"


def test_risky_ml_dotted_stack_global_detection(tmp_path: Path) -> None:
    """STACK_GLOBAL dotted qualnames should not bypass risky ML matching."""

    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"torch")
    payload += _short_binunicode(b"storage._load_from_bytes")
    payload += b"\x93"  # STACK_GLOBAL
    payload += b"."  # STOP

    path = tmp_path / "torch_storage_stack_global.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    failing_checks = [
        check
        for check in result.checks
        if check.name in {"STACK_GLOBAL Module Check", "Advanced Global Reference Check"}
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module") == "torch"
        and check.details.get("function") == "storage._load_from_bytes"
    ]

    assert failing_checks, f"Expected STACK_GLOBAL torch.storage._load_from_bytes detection. Checks: {result.checks}"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "torch.storage._load_from_bytes" in issue.message
        for issue in result.issues
    )


def test_risky_ml_memoized_stack_global_reuse_is_detected(tmp_path: Path) -> None:
    """Memoized risky STACK_GLOBAL references should remain detectable when recalled by REDUCE."""

    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"torch._dynamo")
    payload += _short_binunicode(b"optimize")
    payload += b"\x93"  # STACK_GLOBAL
    payload += b"\x94"  # MEMOIZE index 0
    payload += b"0"  # POP
    payload += _short_binunicode(b"torch")
    payload += _short_binunicode(b"nn")
    payload += b"\x93"  # STACK_GLOBAL (benign concrete callable)
    payload += b"0"  # POP
    payload += b"h\x00"  # BINGET 0
    payload += b")"  # EMPTY_TUPLE
    payload += b"R"  # REDUCE
    payload += b"."  # STOP

    path = tmp_path / "torch_dynamo_memo.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    reduce_checks = [
        check
        for check in result.checks
        if check.name == "REDUCE Opcode Safety Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("associated_global") == "torch._dynamo.optimize"
    ]

    assert reduce_checks, (
        f"Expected REDUCE detection for memoized torch._dynamo.optimize recall. Checks: {result.checks}"
    )


def test_safe_ml_parent_attribute_global_remains_non_failing(tmp_path: Path) -> None:
    """Safe parent/attribute ML globals should not be swept up by the risky policy."""
    for module_name, func_name, payload in [
        ("torch", "nn", b"\x80\x02ctorch\nnn\n."),
        ("torch", "nn.functional.relu", b"\x80\x02ctorch\nnn.functional.relu\n."),
    ]:
        path = tmp_path / f"{module_name}_{func_name.replace('.', '_')}.pkl"
        path.write_bytes(payload)

        result = PickleScanner().scan(str(path))

        issue_summaries = [(issue.severity, issue.message) for issue in result.issues]
        full_ref = f"{module_name}.{func_name}"
        assert not any(
            check.name == "Global Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.details.get("import_reference") == full_ref
            for check in result.checks
        ), f"Unexpected failing GLOBAL check for safe ref {full_ref}: {result.checks}"
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues), (
            f"Safe {module_name}.{func_name} import should not be flagged. Issues: {issue_summaries}"
        )


@pytest.mark.parametrize(
    ("payload", "safe_ref"),
    [
        (b"\x80\x02ctorch\nTensor\n.", "torch.Tensor"),
        (b"\x80\x02ctorch._utils\n_rebuild_tensor\n.", "torch._utils._rebuild_tensor"),
        (b"\x80\x02cnumpy.core.multiarray\n_reconstruct\n.", "numpy.core.multiarray._reconstruct"),
    ],
)
def test_safe_ml_reconstruction_globals_remain_non_failing(tmp_path: Path, payload: bytes, safe_ref: str) -> None:
    """Known safe ML reconstruction globals should not become noisy."""
    path = tmp_path / f"{safe_ref.replace('.', '_')}.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))
    assert not any(
        check.name == "Global Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("import_reference") == safe_ref
        for check in result.checks
    ), f"Unexpected failing GLOBAL check for safe reconstruction ref {safe_ref}: {result.checks}"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues), (
        f"Safe reconstruction ref {safe_ref} should not fail. Issues: "
        f"{[(i.severity, i.message) for i in result.issues]}"
    )


def test_safe_pytorch_state_dict_pickle_remains_non_failing(tmp_path: Path) -> None:
    """State-dict-style payloads should not start failing under the risky-ML policy."""
    import collections

    safe_state_dict = collections.OrderedDict(
        [
            ("layer1.weight", [1.0, 2.0, 3.0]),
            ("layer1.bias", [0.1, 0.2, 0.3]),
            ("layer2.weight", [4.0, 5.0, 6.0]),
        ]
    )
    payload = {
        "state_dict": safe_state_dict,
        "_metadata": collections.OrderedDict([("", {"version": 1})]),
    }
    path = tmp_path / "safe_state_dict.pth"
    with path.open("wb") as handle:
        pickle.dump(payload, handle, protocol=2)

    result = PickleScanner().scan(str(path))

    assert not any(
        check.name in {"Global Module Reference Check", "REDUCE Opcode Safety Check"}
        and check.status == CheckStatus.FAILED
        and (
            check.details.get("import_reference") == "collections.OrderedDict"
            or check.details.get("associated_global") == "collections.OrderedDict"
        )
        for check in result.checks
    ), f"Safe state_dict payload should not fail OrderedDict checks. Checks: {result.checks}"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues), (
        "Safe state-dict payload should not be noisy. Issues: "
        f"{[(issue.severity, issue.message) for issue in result.issues]}"
    )


def test_safe_then_risky_ml_stream_still_flags_risky_import(tmp_path: Path) -> None:
    """Risky imports in later streams must be detected after safe ML globals."""
    safe_stream = b"\x80\x02ctorch._utils\n_rebuild_tensor\n."
    risky_stream = b"\x80\x02ctorch._inductor\ncompile_fx\n."

    path = tmp_path / "safe_then_risky.pkl"
    path.write_bytes(safe_stream + risky_stream)

    result = PickleScanner().scan(str(path))
    assert any(
        check.name == "Global Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("import_reference") == "torch._inductor.compile_fx"
        for check in result.checks
    ), f"Expected CRITICAL later-stream GLOBAL check, got: {result.checks}"
    assert not any(
        check.name == "Global Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("import_reference") == "torch._utils._rebuild_tensor"
        for check in result.checks
    ), f"Safe first-stream ref should not fail GLOBAL checks. Checks: {result.checks}"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "torch._inductor.compile_fx" in issue.message
        for issue in result.issues
    ), f"Expected critical later-stream issue. Issues: {[i.message for i in result.issues]}"
    assert not any("torch._utils._rebuild_tensor" in issue.message for issue in result.issues), (
        f"Safe global should not be flagged. Issues: {[i.message for i in result.issues]}"
    )


if __name__ == "__main__":
    unittest.main()
