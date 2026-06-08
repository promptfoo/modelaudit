from __future__ import annotations

import base64
import pickle
from collections.abc import Mapping

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes

MAX_PROTOCOL0_LINE_OPERAND_BYTES = 8 * 1024 * 1024
SCAN_LIMIT_OVERHEAD_BYTES = 16


def _nested_overlong_protocol0_line_operand() -> bytes:
    # Protocol 0 line operand length includes the surrounding single quotes.
    overlong_line_operand_bytes = MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1
    overlong_operand_body_bytes = overlong_line_operand_bytes - len(b"''")
    return b"cos\nsystem\n(S'" + (b"A" * overlong_operand_body_bytes) + b"'\ntR."


def test_scan_bytes_accepts_exact_limit_protocol0_line_operand() -> None:
    payload = b"S'" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES - 2)) + b"'\n."

    report = scan_bytes(payload, source="exact-limit-protocol0-string.pkl")

    assert report.status != ScanStatus.ERROR
    assert not report.errors


def test_scan_bytes_fails_closed_for_overlong_protocol0_line_operand() -> None:
    payload = b"S'" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES - 1)) + b"'\n."

    report = scan_bytes(payload, source="overlong-protocol0-string.pkl")

    assert report.status == ScanStatus.ERROR
    assert report.verdict != SafetyVerdict.CLEAN
    assert report.errors
    parse_error = report.errors[0]
    assert parse_error.category == "parse_error"
    assert "protocol 0 line operand exceeds" in parse_error.message


@pytest.mark.parametrize("as_unicode", [False, True])
def test_scan_bytes_fails_closed_for_nested_overlong_protocol0_line_operand(
    as_unicode: bool,
) -> None:
    nested_payload = _nested_overlong_protocol0_line_operand()
    nested_value = nested_payload.decode("ascii") if as_unicode else nested_payload
    payload = pickle.dumps(nested_value, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-overlong-protocol0-string.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + SCAN_LIMIT_OVERHEAD_BYTES,
            max_string_literal_scan_chars=len(nested_payload) + SCAN_LIMIT_OVERHEAD_BYTES,
        ),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL"
        and finding.details.get("module") == "os"
        and finding.details.get("name") == "system"
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "S213" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    incomplete_notice = next(notice for notice in report.notices if notice.code == "nested_pickle_incomplete")
    nested_notices = incomplete_notice.details.get("nested_notices")
    assert isinstance(nested_notices, (list, tuple))
    assert any(
        isinstance(notice, Mapping)
        and notice.get("code") == "parse_incomplete"
        and isinstance(notice.get("details"), Mapping)
        and "protocol 0 line operand exceeds" in str(notice["details"].get("exception"))
        for notice in nested_notices
    )


def test_scan_bytes_fails_closed_for_base64_nested_overlong_protocol0_line_operand() -> None:
    nested_payload = _nested_overlong_protocol0_line_operand()
    encoded = base64.b64encode(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source="base64-nested-overlong-protocol0-string.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + SCAN_LIMIT_OVERHEAD_BYTES,
            max_string_literal_scan_chars=len(encoded) + SCAN_LIMIT_OVERHEAD_BYTES,
        ),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(notice.code == "nested_pickle_incomplete" for notice in report.notices)


@pytest.mark.parametrize(
    ("encoding", "expected_rule_code"),
    [("raw", "S213"), ("base64", "S601")],
)
def test_scan_bytes_fails_closed_when_nested_overlong_protocol0_operand_hits_depth_limit(
    encoding: str,
    expected_rule_code: str,
) -> None:
    nested_payload = _nested_overlong_protocol0_line_operand()
    if encoding == "raw":
        outer_value: bytes | str = nested_payload
    else:
        outer_value = base64.b64encode(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(outer_value, protocol=4),
        source=f"depth-limited-{encoding}-overlong-protocol0-string.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + SCAN_LIMIT_OVERHEAD_BYTES,
            max_string_literal_scan_chars=len(outer_value) + SCAN_LIMIT_OVERHEAD_BYTES,
            max_nested_depth=0,
        ),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule_code
        and finding.details.get("analysis_incomplete") is True
        and finding.details.get("incomplete_reason") == "max_nested_depth"
        for finding in report.findings
    )
    assert any(
        notice.code == "nested_pickle_incomplete"
        and notice.details.get("max_nested_depth") == 0
        and notice.details.get("incomplete_reason") == "max_nested_depth"
        for notice in report.notices
    )


@pytest.mark.parametrize("as_unicode", [False, True])
def test_scan_bytes_fails_closed_for_nested_overlong_protocol0_line_operand_after_inst(
    as_unicode: bool,
) -> None:
    nested_payload = b"(ios\nsystem\n(S'" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES - 1)) + b"'\ntR."
    nested_value = nested_payload.decode("ascii") if as_unicode else nested_payload
    payload = pickle.dumps(nested_value, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-inst-overlong-protocol0-string.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + 16,
            max_string_literal_scan_chars=len(nested_payload) + 16,
        ),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("opcode") == "INST"
        and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "S213" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    incomplete_notice = next(notice for notice in report.notices if notice.code == "nested_pickle_incomplete")
    nested_notices = incomplete_notice.details.get("nested_notices")
    assert isinstance(nested_notices, (list, tuple))
    assert any(
        isinstance(notice, Mapping)
        and notice.get("code") == "parse_incomplete"
        and isinstance(notice.get("details"), Mapping)
        and "protocol 0 line operand exceeds" in str(notice["details"].get("exception"))
        for notice in nested_notices
    )


@pytest.mark.parametrize("as_unicode", [False, True])
def test_scan_bytes_ignores_unstructured_nested_overlong_protocol0_near_match(
    as_unicode: bool,
) -> None:
    nested_value_bytes = b"S'" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1))
    nested_value = nested_value_bytes.decode("ascii") if as_unicode else nested_value_bytes
    payload = pickle.dumps(nested_value, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-overlong-protocol0-near-match.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_value_bytes) + SCAN_LIMIT_OVERHEAD_BYTES,
            max_string_literal_scan_chars=len(nested_value) + SCAN_LIMIT_OVERHEAD_BYTES,
        ),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "S213" for finding in report.findings)
    assert not any(notice.code == "nested_pickle_incomplete" for notice in report.notices)
