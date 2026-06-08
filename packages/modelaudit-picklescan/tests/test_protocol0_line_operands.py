from __future__ import annotations

from modelaudit_picklescan import SafetyVerdict, ScanStatus, scan_bytes


def test_scan_bytes_fails_closed_for_overlong_protocol0_line_operand() -> None:
    max_protocol0_line_operand_bytes = 8 * 1024 * 1024
    payload = b"S'" + (b"A" * (max_protocol0_line_operand_bytes - 1)) + b"'\n."

    report = scan_bytes(payload, source="overlong-protocol0-string.pkl")

    assert report.status == ScanStatus.ERROR
    assert report.verdict != SafetyVerdict.CLEAN
    assert report.errors
    parse_error = report.errors[0]
    assert parse_error.category == "parse_error"
    assert "protocol 0 line operand exceeds" in parse_error.message
