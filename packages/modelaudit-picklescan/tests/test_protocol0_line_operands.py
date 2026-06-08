from __future__ import annotations

import base64
import pickle
from collections.abc import Mapping

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes

MAX_PROTOCOL0_LINE_OPERAND_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_NESTED_PICKLE_BYTES = 2 * 1024 * 1024


def _escaped_hex(payload: bytes) -> str:
    return "".join(f"\\x{byte:02x}" for byte in payload)


def _mixed_hex(payload: bytes) -> str:
    return f"\\x{payload[0]:02x}{payload[1:].hex()}"


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


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [("base64", "S601"), ("escaped_hex", "S602"), ("mixed_hex", "S602")],
)
@pytest.mark.parametrize("opcode_prefix", [b"c", b"(i"])
def test_scan_bytes_fails_closed_for_oversized_encoded_custom_global_name(
    opcode_prefix: bytes,
    encoding: str,
    expected_rule: str,
) -> None:
    nested_payload = opcode_prefix + b"custommodule\n" + (b"A" * (DEFAULT_MAX_NESTED_PICKLE_BYTES + 1)) + b"\n."
    if encoding == "base64":
        encoded = base64.b64encode(nested_payload).decode("ascii")
    elif encoding == "escaped_hex":
        encoded = _escaped_hex(nested_payload)
    else:
        encoded = _mixed_hex(nested_payload)

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source=f"oversized-custom-global-{encoding}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("module", [b"config", b"os"])
@pytest.mark.parametrize("encoding", ["base64", "escaped_hex", "mixed_hex"])
def test_scan_bytes_ignores_oversized_encoded_global_like_prose(
    module: bytes,
    encoding: str,
) -> None:
    nested_text = b"c" + module + b"\n" + (b"A" * (DEFAULT_MAX_NESTED_PICKLE_BYTES + 1)) + b"\nplain footer\n"
    if encoding == "base64":
        encoded = base64.b64encode(nested_text).decode("ascii")
    elif encoding == "escaped_hex":
        encoded = _escaped_hex(nested_text)
    else:
        encoded = _mixed_hex(nested_text)

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source=f"oversized-{encoding}-global-like-prose.pkl",
    )

    assert not any(finding.rule_code in {"S601", "S602"} for finding in report.findings)


@pytest.mark.parametrize("prefix", [b"cos\n", b"ios\n"])
@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64"])
def test_scan_bytes_fails_closed_when_default_nested_budget_clips_global_name(
    prefix: bytes,
    encoding: str,
) -> None:
    nested_payload = prefix + (b"A" * (DEFAULT_MAX_NESTED_PICKLE_BYTES + 1)) + b"\n."
    if encoding == "unicode":
        nested_value: bytes | str = nested_payload.decode("ascii")
    elif encoding == "base64":
        nested_value = base64.b64encode(nested_payload).decode("ascii")
    else:
        nested_value = nested_payload

    report = scan_bytes(
        pickle.dumps(nested_value, protocol=4),
        source=f"default-limit-{encoding}.pkl",
    )

    expected_rule = "S601" if encoding == "base64" else "S213"
    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64"])
def test_scan_bytes_fails_closed_when_default_budget_clips_after_execution_setup(
    encoding: str,
) -> None:
    nested_payload = (
        b"csafe_module\nfactory\np0\n0(S'true'\ntp1\n0S'"
        + (b"A" * (DEFAULT_MAX_NESTED_PICKLE_BYTES + 1))
        + b"'\n0g0\ng1\nR."
    )
    if encoding == "unicode":
        nested_value: bytes | str = nested_payload.decode("ascii")
    elif encoding == "base64":
        nested_value = base64.b64encode(nested_payload).decode("ascii")
    else:
        nested_value = nested_payload

    report = scan_bytes(
        pickle.dumps(nested_value, protocol=4),
        source=f"default-limit-execution-setup-{encoding}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    expected_rule = "S601" if encoding == "base64" else "S213"
    assert any(
        finding.rule_code == expected_rule and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    if encoding != "base64":
        assert any(notice.code == "nested_payload_truncated" for notice in report.notices)


@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64", "hex"])
def test_scan_bytes_ignores_large_text_with_global_like_prefix(encoding: str) -> None:
    nested_bytes = b"config\n" + (b"A" * (DEFAULT_MAX_NESTED_PICKLE_BYTES + 1)) + b"\nplain footer\n"
    if encoding == "unicode":
        nested_value: bytes | str = nested_bytes.decode("ascii")
    elif encoding == "base64":
        nested_value = base64.b64encode(nested_bytes).decode("ascii")
    elif encoding == "hex":
        nested_value = nested_bytes.hex()
    else:
        nested_value = nested_bytes

    report = scan_bytes(
        pickle.dumps(nested_value, protocol=4),
        source=f"large-global-like-text-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "S213" for finding in report.findings)


def test_scan_bytes_ignores_benign_footer_after_overlong_protocol0_operand() -> None:
    nested_payload = b"S'" + (b"A" * (MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1)) + b"'\nrandom benign footer\n"
    payload = pickle.dumps(nested_payload, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-overlong-benign-footer.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + 16,
            max_string_literal_scan_chars=len(nested_payload) + 16,
        ),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "S213" for finding in report.findings)
    assert not any(notice.code == "nested_pickle_incomplete" for notice in report.notices)


@pytest.mark.parametrize("as_unicode", [False, True])
def test_scan_bytes_ignores_short_incomplete_global_near_match(as_unicode: bool) -> None:
    nested_value_bytes = b"cfoo\nbar"
    nested_value = nested_value_bytes.decode("ascii") if as_unicode else nested_value_bytes

    report = scan_bytes(
        pickle.dumps(nested_value, protocol=4),
        source="short-incomplete-global-near-match.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "S213" for finding in report.findings)
    assert not any(notice.code == "nested_pickle_incomplete" for notice in report.notices)


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
