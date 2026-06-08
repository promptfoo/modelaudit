from __future__ import annotations

import base64
import pickle
from collections.abc import Mapping

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes

MAX_PROTOCOL0_LINE_OPERAND_BYTES = 8 * 1024 * 1024


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
    nested_payload = b"cos\nsystem\n(S'" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES - 1)) + b"'\ntR."
    nested_value = nested_payload.decode("ascii") if as_unicode else nested_payload
    payload = pickle.dumps(nested_value, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-overlong-protocol0-string.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + 16,
            max_string_literal_scan_chars=len(nested_payload) + 16,
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


@pytest.mark.parametrize("as_unicode", [False, True])
@pytest.mark.parametrize(
    ("payload_kind", "prefix"),
    [
        ("dangerous_suffix", b"S'"),
        ("first_global", b"cos\n"),
        ("first_inst", b"ios\n"),
    ],
)
def test_scan_bytes_fails_closed_when_structure_follows_overlong_protocol0_operand(
    as_unicode: bool, payload_kind: str, prefix: bytes
) -> None:
    suffix = b"'\n0cos\nsystem\n)R." if payload_kind == "dangerous_suffix" else b"\n."
    nested_payload = prefix + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1)) + suffix
    nested_value = nested_payload.decode("ascii") if as_unicode else nested_payload
    payload = pickle.dumps(nested_value, protocol=4)

    report = scan_bytes(
        payload,
        source=f"nested-overlong-{payload_kind}.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + 16,
            max_string_literal_scan_chars=len(nested_value) + 16,
        ),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(notice.code == "nested_pickle_incomplete" for notice in report.notices)


def test_scan_bytes_fails_closed_for_base64_overlong_first_global_operand() -> None:
    nested_payload = b"cos\n" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1)) + b"\n."
    encoded = base64.b64encode(nested_payload).decode("ascii")
    payload = pickle.dumps(encoded, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-overlong-first-global-base64.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + 16,
            max_string_literal_scan_chars=len(encoded) + 16,
        ),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(notice.code == "nested_pickle_incomplete" for notice in report.notices)


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
            max_nested_pickle_bytes=len(nested_value_bytes) + 16,
            max_string_literal_scan_chars=len(nested_value) + 16,
        ),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "S213" for finding in report.findings)
    assert not any(notice.code == "nested_pickle_incomplete" for notice in report.notices)
