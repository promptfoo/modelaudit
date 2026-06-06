import zlib
from pathlib import Path

import numpy as np
import pytest

# Skip if joblib is not available before importing it
pytest.importorskip("joblib")

import joblib

from modelaudit.scanners.joblib_scanner import JoblibScanner

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"


def test_joblib_scanner_basic(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    scanner = JoblibScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.bytes_scanned > 0


def test_joblib_default_decompressed_cap_tracks_file_read_budget() -> None:
    scanner = JoblibScanner()

    assert scanner.max_decompressed_size == scanner.max_file_read_size

    scanner = JoblibScanner({"max_file_read_size": 2 * 1024 * 1024})

    assert scanner.max_decompressed_size == 2 * 1024 * 1024

    scanner = JoblibScanner({"max_file_read_size": 0, "max_decompressed_size": 1024 * 1024 * 1024})

    assert scanner.max_decompressed_size == 1024 * 1024 * 1024

    scanner = JoblibScanner({"max_file_read_size": 2 * 1024 * 1024, "max_decompressed_size": 4 * 1024 * 1024})

    assert scanner.max_decompressed_size == 2 * 1024 * 1024


def test_joblib_scanner_respects_explicit_decompressed_cap(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    result = JoblibScanner({"max_decompressed_size": 64 * 1024}).scan(str(path))

    assert result.success is True
    assert not any(
        check.name == "Compression Bomb Detection" and check.status.value == "failed" for check in result.checks
    )


def test_joblib_scanner_fails_before_large_decompression_allocation(tmp_path: Path) -> None:
    path = tmp_path / "oversized.joblib"
    path.write_bytes(zlib.compress(b"A" * 4096))

    result = JoblibScanner({"max_decompressed_size": 128, "max_decompression_ratio": 1000.0}).scan(str(path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "joblib_wrapper_decode_failed"
    failed_check = next(check for check in result.checks if check.name == "Compression Bomb Detection")
    assert failed_check.status.value == "failed"
    assert "Decompressed size too large" in failed_check.message
    assert "max: 128" in failed_check.message


def test_joblib_scanner_closes_bytesio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure BytesIO objects used for pickles are closed."""
    import io

    closed = {}

    class TrackedBytesIO(io.BytesIO):
        def close(self) -> None:
            closed["closed"] = True
            super().close()

    monkeypatch.setattr(io, "BytesIO", TrackedBytesIO)

    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    scanner = JoblibScanner()
    scanner.scan(str(path))

    assert closed.get("closed") is True


def test_joblib_scanner_marks_incomplete_pickle_inconclusive_without_dangerous_findings(tmp_path: Path) -> None:
    path = tmp_path / "truncated.joblib"
    path.write_bytes(b"\x80\x04}q\x00")

    result = JoblibScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity.value == "info"
    assert parse_issue.details.get("category") == "parse_error"
    assert parse_issue.details.get("failure_reason") == "unknown_opcode_or_format_error"
    assert not any(issue.severity.value in {"warning", "critical"} for issue in result.issues)


def test_joblib_scanner_preserves_pickle_rule_codes_on_embedded_pickle() -> None:
    supply_chain_path = _ASSETS_DIR / "exploits" / "exploit4_supply_chain_attack.pkl"
    decode_chain_path = _ASSETS_DIR / "samples" / "pickles" / "decode_exec_chain.pkl"

    supply_chain_result = JoblibScanner().scan(str(supply_chain_path))
    decode_chain_result = JoblibScanner().scan(str(decode_chain_path))

    assert any(issue.rule_code == "S201" for issue in supply_chain_result.issues)
    assert any(
        issue.rule_code == "S604" and issue.details.get("legacy_rule_aliases") == ["S104"]
        for issue in decode_chain_result.issues
    )
