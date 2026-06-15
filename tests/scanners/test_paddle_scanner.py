import builtins
import struct
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.paddle_scanner import PaddleScanner
from modelaudit.utils.file.detection import validate_file_type


def _write_chunk_boundary_payload(path: Path, pattern: bytes, *, prefix_len: int, suffix: bytes = b"") -> None:
    chunk_size = 1024 * 1024
    path.write_bytes(b"\x00" * (chunk_size - prefix_len) + pattern[:prefix_len] + pattern[prefix_len:] + suffix)


def test_paddle_scanner_can_handle(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"dummy")
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        assert PaddleScanner.can_handle(str(path))


def test_paddle_scanner_cannot_handle_without_paddle(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"dummy")
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", False):
        assert not PaddleScanner.can_handle(str(path))


def test_paddle_scanner_detects_suspicious_pattern(tmp_path: Path) -> None:
    content = b"os.system('ls')"
    path = tmp_path / "model.pdmodel"
    path.write_bytes(content)
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))
        suspicious_issues = [i for i in result.issues if "suspicious" in i.message.lower()]

    assert suspicious_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in suspicious_issues)


def test_paddle_scanner_detects_pattern_split_across_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    _write_chunk_boundary_payload(path, b"os.system", prefix_len=4)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert any(issue.details.get("pattern") == "os.system" for issue in result.issues)


def test_paddle_scanner_detects_binary_only_pattern_split_across_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    _write_chunk_boundary_payload(path, b"compile(", prefix_len=4)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert any(issue.details.get("pattern") == "compile(" for issue in result.issues)


def test_paddle_scanner_detects_regex_only_pattern_split_across_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    _write_chunk_boundary_payload(path, b"base64.b64decode", prefix_len=7)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert any(issue.details.get("pattern") == r"base64\.b64decode" for issue in result.issues)


def test_paddle_scanner_ignores_near_match_split_across_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    _write_chunk_boundary_payload(path, b"os.systen", prefix_len=4)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert not any(issue.details.get("pattern") == "os.system" for issue in result.issues)


def test_paddle_scanner_caps_repeated_binary_pattern_findings_per_chunk(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"open(" * 1024)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert sum(issue.details.get("pattern") == "open(" for issue in result.issues) == 1


def test_paddle_scanner_fails_closed_for_unbounded_regex_prefix_at_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    chunk_size = 1024 * 1024
    path.write_bytes(b"\x00" * (chunk_size - 140) + b"getattr(" + b" " * 180 + b"os, 'system')")

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["scan_outcome_reasons"] == ["paddle_unbounded_regex_boundary"]
    assert any(check.name == "Paddle Boundary Coverage" for check in result.checks)


def test_paddle_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.pdmodel"
    path.write_bytes(b"safe paddle model metadata")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated Paddle read failure")

    def raise_detection_error(_path: str) -> str:
        raise OSError("simulated Paddle detection read failure")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.scanners.paddle_scanner.open", raise_os_error, raising=False)
    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_detection_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        direct = PaddleScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "Paddle File Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Error reading file" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "paddle_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error_reason"] == "paddle_read_failed"
    assert "paddle_read_failed" in direct.metadata["scan_outcome_reasons"]
    metadata = aggregate.file_metadata[str(path)]
    assert "paddle_read_failed" in metadata["scan_outcome_reasons"]
    assert metadata["operational_error_reason"] == "paddle_read_failed"
    assert any(check.name == "Paddle File Read" and "Error reading file" in check.message for check in aggregate.checks)
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_paddle_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "permission-denied.pdmodel"
    path.write_bytes(b"safe paddle model metadata")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        direct = PaddleScanner().scan(str(path))
        aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.metadata["scan_outcome_reasons"] == ["paddle_read_failed"]
    assert direct.metadata["operational_error_reason"] == "paddle_read_failed"
    assert aggregate.file_metadata[str(path)]["operational_error_reason"] == "paddle_read_failed"
    assert determine_exit_code(aggregate) == 2


def test_paddle_read_failure_takes_precedence_over_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malicious = tmp_path / "malicious.pdmodel"
    malicious.write_bytes(b"os.system('ls')")
    unreadable = tmp_path / "unreadable.pdmodel"
    unreadable.write_bytes(b"safe paddle model metadata")
    real_open = builtins.open

    def fail_selected_read(path: str, *args: Any, **kwargs: Any) -> Any:
        if Path(path).name == unreadable.name:
            raise OSError("simulated Paddle read failure")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("modelaudit.scanners.paddle_scanner.open", fail_selected_read, raising=False)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        aggregate = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert any(issue.severity == IssueSeverity.WARNING for issue in aggregate.issues)
    assert aggregate.file_metadata[str(unreadable)]["operational_error_reason"] == "paddle_read_failed"
    assert determine_exit_code(aggregate) == 2


def test_paddle_scanner_deduplicates_variable_width_regex_across_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    chunk_size = 1024 * 1024
    path.write_bytes(b"\x00" * (chunk_size - 120) + b"import " + b"a" * 200)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert sum(issue.details.get("pattern") == r"\bimport\s+[\w\.]+" for issue in result.issues) == 1
    assert result.success is True


def test_paddle_scanner_preserves_unicode_identifier_detection(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    unicode_identifier = "\U0001d698\U0001d69c"
    path.write_text(
        f'{unicode_identifier} = __import__("os")\ngetattr({unicode_identifier}, "system")',
        encoding="utf-8",
    )

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = PaddleScanner().scan(str(path))

    assert any(
        issue.details.get("pattern") == r"getattr\s*\(\s*\w+\s*,\s*['\"]system['\"]\s*\)" for issue in result.issues
    )


def test_paddle_suspicious_pdmodel_aggregate_exit_code_is_security_finding(tmp_path: Path) -> None:
    """Suspicious .pdmodel patterns should be warning-level security findings."""
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"os.system('ls')")

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = scan_model_directory_or_file(str(path), cache_scan_results=False)

    warning_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
    assert result.success is False
    assert result.has_errors is False
    assert determine_exit_code(result) == 1
    assert warning_issues


def test_paddle_scanner_missing_dependency(tmp_path: Path) -> None:
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"dummy")
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", False):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert any("paddlepaddle" in i.message for i in result.issues)
        # Find the paddlepaddle-related issue specifically
        paddle_issues = [i for i in result.issues if "paddlepaddle" in i.message]
        assert len(paddle_issues) > 0
        # Missing optional dependency is WARNING severity
        assert paddle_issues[0].severity == IssueSeverity.WARNING


# ---- Tests for false-positive fixes ----


def test_pdiparams_hex_escape_not_flagged(tmp_path: Path) -> None:
    """Raw float32 tensor data in .pdiparams should NOT trigger the hex-escape
    pattern (\\x[0-9a-fA-F]{2}).  Before the fix every .pdiparams file was
    flagged because lossy UTF-8 decoding of float bytes produces \\xNN runs."""
    # Build a payload of 1024 random-looking float32 values whose byte
    # representation, when decoded with errors="ignore", will contain
    # sequences that match \\x[0-9a-fA-F]{2}.
    import random

    random.seed(42)
    floats = [random.uniform(-1e6, 1e6) for _ in range(1024)]
    raw = struct.pack(f"<{len(floats)}f", *floats)

    path = tmp_path / "weights.pdiparams"
    path.write_bytes(raw)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    hex_issues = [i for i in result.issues if "\\x[0-9a-fA-F]{2}" in i.details.get("pattern", "")]
    assert hex_issues == [], f"Hex-escape pattern should be suppressed for .pdiparams, got {hex_issues}"


def test_pdiparams_dunder_pattern_not_flagged(tmp_path: Path) -> None:
    """The __[\\w]+__ (magic-method) regex should be suppressed for .pdiparams
    files because random binary data decoded as UTF-8 can coincidentally match."""
    raw = b"\x00__fake__\x00" + b"\xff" * 200
    path = tmp_path / "weights.pdiparams"
    path.write_bytes(raw)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    dunder_issues = [i for i in result.issues if "__[\\w]+__" in i.details.get("pattern", "")]
    assert dunder_issues == [], f"Dunder pattern should be suppressed for .pdiparams, got {dunder_issues}"


def test_pdiparams_real_threats_still_detected(tmp_path: Path) -> None:
    """Even with FP suppression, genuinely suspicious content in a .pdiparams
    file (e.g. 'import os', 'eval(') must still be reported."""
    content = b"padding " + b"import os" + b" eval(payload) " + b"os.system('rm -rf /')"
    path = tmp_path / "bad_weights.pdiparams"
    path.write_bytes(content)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    patterns_found = {i.details.get("pattern", "") for i in result.issues}
    # These should NOT be suppressed
    assert any("import os" in p for p in patterns_found), "import os should be detected"
    assert any("eval(" in p for p in patterns_found), "eval( should be detected"
    assert any("os.system" in p for p in patterns_found), "os.system should be detected"
    assert all(i.severity == IssueSeverity.WARNING for i in result.issues)


def test_paddle_suspicious_pdiparams_aggregate_exit_code_is_security_finding(tmp_path: Path) -> None:
    """Suspicious .pdiparams patterns should be warning-level security findings."""
    path = tmp_path / "bad_weights.pdiparams"
    path.write_bytes(b"padding " + b"import os" + b" eval(payload) " + b"os.system('rm -rf /')")

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        result = scan_model_directory_or_file(str(path), cache_scan_results=False)

    warning_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
    assert result.success is False
    assert result.has_errors is False
    assert determine_exit_code(result) == 1
    assert warning_issues


def test_pdmodel_hex_escape_still_flagged(tmp_path: Path) -> None:
    """For .pdmodel files (protobuf model descriptors), the hex-escape pattern
    should NOT be suppressed -- only .pdiparams gets the suppression."""
    # Craft content that contains a literal hex escape sequence in text form
    content = b"normal protobuf data \\x41\\x42 more data"
    path = tmp_path / "model.pdmodel"
    path.write_bytes(content)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    hex_issues = [i for i in result.issues if "\\x[0-9a-fA-F]{2}" in i.details.get("pattern", "")]
    assert len(hex_issues) > 0, "Hex-escape pattern should still fire for .pdmodel files"


def test_pdmodel_magic_bytes_validation_passes(tmp_path: Path) -> None:
    """A .pdmodel file should pass file-type validation even though it has no
    distinctive magic bytes (protobuf files start with arbitrary field tags)."""
    # Write some plausible protobuf-like bytes
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"\x08\x01\x12\x0asome_data_here_for_testing")

    assert validate_file_type(str(path)), ".pdmodel should pass file type validation (no magic byte mismatch)"


def test_pdiparams_magic_bytes_validation_passes(tmp_path: Path) -> None:
    """A .pdiparams file should pass file-type validation even though its raw
    tensor data has no recognisable magic bytes."""
    path = tmp_path / "weights.pdiparams"
    # Write raw float data (no recognisable magic bytes)
    path.write_bytes(struct.pack("<4f", 1.0, -2.5, 3.14, 0.0))

    assert validate_file_type(str(path)), ".pdiparams should pass file type validation (no magic byte mismatch)"
