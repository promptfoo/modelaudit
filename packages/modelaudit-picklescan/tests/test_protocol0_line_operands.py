from __future__ import annotations

import base64
import pickle
from collections.abc import Mapping

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes

MAX_PROTOCOL0_LINE_OPERAND_BYTES = 8 * 1024 * 1024
SCAN_LIMIT_OVERHEAD_BYTES = 16


def _overlong_protocol0_operand_body() -> bytes:
    # Protocol 0 line operand length includes the surrounding single quotes.
    overlong_line_operand_bytes = MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1
    overlong_operand_body_bytes = overlong_line_operand_bytes - len(b"''")
    return b"A" * overlong_operand_body_bytes


def _nested_overlong_protocol0_line_operand() -> bytes:
    return b"cos\nsystem\n(S'" + _overlong_protocol0_operand_body() + b"'\ntR."


def _long_scalar_before_reduce_protocol0_pickle(opcode: bytes) -> bytes:
    if opcode == b"F":
        scalar = b"F" + (b"1" * 257) + b"\n"
    elif opcode == b"I":
        scalar = b"I" + (b"1" * 257) + b"\n"
    elif opcode == b"L":
        scalar = b"L" + (b"1" * 256) + b"L\n"
    elif opcode == b"P":
        scalar = b"P" + (b"A" * 257) + b"\n"
    elif opcode == b"S":
        scalar = b"S'" + (b"A" * 257) + b"'\n"
    elif opcode == b"g":
        scalar = b"Np0\n0g" + (b"0" * 257) + b"\n"
    elif opcode == b"p":
        scalar = b"Np" + (b"0" * 257) + b"\n"
    else:
        scalar = b"V" + (b"A" * 257) + b"\n"
    return scalar + b"0cos\nsystem\n(S'id'\ntR."


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
    [("base64", "S601"), ("hex", "S602")],
)
def test_scan_bytes_detects_inline_encoded_protocol0_pickle_before_suffix(
    encoding: str,
    expected_rule_code: str,
) -> None:
    nested_payload = b"cos\nsystem\n)R."
    encoded = base64.b64encode(nested_payload).decode("ascii") if encoding == "base64" else nested_payload.hex()

    report = scan_bytes(
        pickle.dumps({"outer": f"prefix-{encoded}-suffix"}, protocol=4),
        source=f"inline-{encoding}-nested-protocol0.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule_code
        and finding.details.get("encoding") == encoding
        and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("opcode", [b"I", b"S", b"V"])
def test_scan_bytes_detects_base64_pickle_after_long_protocol0_scalar(opcode: bytes) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(opcode)
    encoded = base64.b64encode(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source="base64-long-scalar-before-reduce.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("module") == "os"
        and finding.details.get("name") == "system"
        for finding in report.findings
    )


@pytest.mark.parametrize("opcode", [b"I", b"S", b"V"])
@pytest.mark.parametrize("wrapper", ["A", "="])
def test_scan_bytes_detects_wrapped_base64_pickle_after_long_protocol0_scalar(
    opcode: bytes,
    wrapper: str,
) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(opcode)
    encoded = base64.b64encode(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(f"{wrapper}{encoded}", protocol=4),
        source="wrapped-base64-long-scalar-before-reduce.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


@pytest.mark.parametrize("opcode", [b"F", b"I", b"L", b"P", b"S", b"V", b"g", b"p"])
@pytest.mark.parametrize("decoded_prefix_len", [0, 1, 2])
def test_scan_bytes_detects_base64_pickle_at_each_decoded_offset(
    opcode: bytes,
    decoded_prefix_len: int,
) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(opcode)
    encoded = base64.b64encode((b"X" * decoded_prefix_len) + nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source="base64-long-scalar-decoded-offset.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


@pytest.mark.parametrize("opcode", [b"g", b"p"])
def test_scan_bytes_does_not_charge_contextual_probe_prefix_to_nested_limit(opcode: bytes) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(opcode)
    encoded = base64.b64encode(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source="base64-contextual-line-exact-nested-limit.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload),
            max_string_literal_scan_chars=len(encoded) + SCAN_LIMIT_OVERHEAD_BYTES,
        ),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    encoded_findings = [finding for finding in report.findings if finding.rule_code == "S601"]
    assert encoded_findings
    assert all(
        isinstance(payload_size := finding.details.get("payload_size"), int)
        and payload_size <= len(nested_payload)
        and finding.details.get("analysis_incomplete") is not True
        for finding in encoded_findings
    )
    assert not any(notice.code == "encoded_nested_payload_truncated" for notice in report.notices)


@pytest.mark.parametrize("separator", ["!", " "])
def test_scan_bytes_detects_lenient_base64_pickle_after_long_protocol0_scalar(
    separator: str,
) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(b"V")
    encoded = base64.b64encode(nested_payload).decode("ascii")
    separated = separator.join(encoded[index : index + 4] for index in range(0, len(encoded), 4))

    report = scan_bytes(
        pickle.dumps(separated, protocol=4),
        source="lenient-base64-long-scalar-before-reduce.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


def test_scan_bytes_detects_sparse_lenient_base64_pickle_after_long_protocol0_scalar() -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(b"V")
    encoded = base64.b64encode(nested_payload).decode("ascii")
    separated = ("!" * 4000).join(encoded)

    report = scan_bytes(
        pickle.dumps(separated, protocol=4),
        source="sparse-lenient-base64-long-scalar-before-reduce.pkl",
    )

    assert len(separated) > 1024 * 1024
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


def test_scan_bytes_ignores_sparse_unterminated_protocol0_base64_scalar() -> None:
    encoded = base64.b64encode(b"V" + (b"A" * 257)).decode("ascii")
    separated = ("!" * 4000).join(encoded)

    report = scan_bytes(
        pickle.dumps(separated, protocol=4),
        source="sparse-unterminated-protocol0-base64-scalar.pkl",
    )

    assert len(separated) > 1024 * 1024
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert not any(notice.code == "nested_probe_limit_exceeded" for notice in report.notices)


def test_scan_bytes_ignores_large_unterminated_protocol0_base64_scalar() -> None:
    encoded_scalar = base64.b64encode(b"V" + (b"A" * 257)).decode("ascii")
    encoded = encoded_scalar + ("!" * ((1024 * 1024) + 512))

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source="unterminated-protocol0-base64-scalar.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert not any(notice.code == "nested_probe_limit_exceeded" for notice in report.notices)


@pytest.mark.parametrize("opcode", [b"F", b"I", b"L", b"S", b"V", b"g", b"p"])
def test_scan_bytes_keeps_wrapped_benign_long_scalar_base64_pickle_clean(opcode: bytes) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(opcode).split(b"0cos", maxsplit=1)[0] + b"."
    encoded = base64.b64encode(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps(f"A{encoded}", protocol=4),
        source="wrapped-benign-base64-long-scalar.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_fails_closed_for_long_scalar_base64_pickle_beyond_mid_scan_budget() -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(b"V")
    encoded = base64.b64encode(nested_payload).decode("ascii")
    wrapped = ("A" * ((1024 * 1024) + 1)) + encoded + ("B" * 65)

    report = scan_bytes(
        pickle.dumps(wrapped, protocol=4),
        source="base64-long-scalar-beyond-mid-scan-budget.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


def test_scan_bytes_detects_later_base64_pickle_after_lenient_benign_prefix() -> None:
    benign = base64.b64encode(b"I42\n.").decode("ascii").rstrip("=")
    malicious = base64.b64encode(b"cos\nsystem\n)R.").decode("ascii").rstrip("=")

    report = scan_bytes(
        pickle.dumps(f"{benign}!{malicious}", protocol=4),
        source="base64-later-pickle-after-lenient-prefix.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


def test_scan_bytes_keeps_multiple_lenient_benign_base64_pickles_clean() -> None:
    first = base64.b64encode(b"I42\n.").decode("ascii").rstrip("=")
    second = base64.b64encode(b"S'ok'\n.").decode("ascii").rstrip("=")

    report = scan_bytes(
        pickle.dumps(f"{first}!{second}", protocol=4),
        source="multiple-lenient-benign-base64-pickles.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize(
    ("encoding", "expected_rule_code"),
    [("base64", "S601"), ("hex", "S602")],
)
def test_scan_bytes_fails_closed_for_oversized_inline_encoded_protocol0_pickle(
    encoding: str,
    expected_rule_code: str,
) -> None:
    nested_payload = b"cos\nsystem\n)R."
    encoded = base64.b64encode(nested_payload).decode("ascii") if encoding == "base64" else nested_payload.hex()

    report = scan_bytes(
        pickle.dumps({"outer": f"prefix-{encoded}-suffix"}, protocol=4),
        source=f"oversized-inline-{encoding}-nested-protocol0.pkl",
        options=ScanOptions(max_nested_pickle_bytes=4),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule_code
        and finding.details.get("encoding") == encoding
        and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("case_name", "encoded", "encoding", "expected_rule_code"),
    [
        (
            "base64-extra-padding",
            "Y29zCnN5c3RlbQopUi4===",
            "base64",
            "S601",
        ),
        (
            "base64-ignored-separator",
            "Y29z!CnN5c3RlbQopUi4=",
            "base64",
            "S601",
        ),
        (
            "base64-second-symbol-gap",
            f"Y{'!' * 64}29zCnN5c3RlbQopUi4=",
            "base64",
            "S601",
        ),
        (
            "base64-prefix-gap",
            f"Y29z{'!' * 256}CnN5c3RlbQopUi4=",
            "base64",
            "S601",
        ),
        (
            "base64-internal-padding",
            "Y29z==CnN5c3RlbQopUi4=",
            "base64",
            "S601",
        ),
        (
            "hex-dangling-nibble",
            "636f730a73797374656d0a29522ef",
            "hex",
            "S602",
        ),
        (
            "hex-whitespace",
            "63 6f 73 0a 73 79 73 74 65 6d 0a 29 52 2e",
            "hex",
            "S602",
        ),
        (
            "hex-whitespace-gap",
            f"63{' ' * 247}6f730a73797374656d0a29522e",
            "hex",
            "S602",
        ),
    ],
)
def test_scan_bytes_detects_leniently_decodable_inline_protocol0_pickle(
    case_name: str,
    encoded: str,
    encoding: str,
    expected_rule_code: str,
) -> None:
    report = scan_bytes(
        pickle.dumps({"outer": f"prefix-{encoded}-suffix"}, protocol=4),
        source=f"lenient-inline-{case_name}-nested-protocol0.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule_code
        and finding.details.get("encoding") == encoding
        and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )


def test_scan_bytes_fails_closed_for_base64_pickle_across_probe_cap_gap() -> None:
    encoded = f"Y{'!' * (1024 * 1024 - 2)}29zCnN5c3RlbQopUi4="

    report = scan_bytes(
        pickle.dumps({"outer": f"prefix-{encoded}-suffix"}, protocol=4),
        source="base64-probe-cap-gap-nested-protocol0.pkl",
        options=ScanOptions(max_nested_pickle_bytes=4),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


def test_scan_bytes_detects_base64_pickle_beyond_probe_cap() -> None:
    nested_payload = b"cos\nsystem\n)R."
    base64_payload = base64.b64encode(nested_payload).decode("ascii")
    encoded = f"{base64_payload[0]}{'!' * (1024 * 1024 + 65)}{base64_payload[1:]}"
    assert base64.b64decode(encoded) == nested_payload

    report = scan_bytes(
        pickle.dumps({"outer": f"prefix-{encoded}-suffix"}, protocol=4),
        source="base64-beyond-probe-cap-nested-protocol0.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("encoding", ["base64", "hex"])
def test_scan_bytes_keeps_benign_encoded_pickle_beyond_probe_cap_clean(encoding: str) -> None:
    nested_payload = b"\x80\x04N."
    if encoding == "base64":
        encoded_payload = base64.b64encode(nested_payload).decode("ascii")
        value = f"{encoded_payload[0]}{'!' * (1024 * 1024 + 65)}{encoded_payload[1:]}"
        assert base64.b64decode(value) == nested_payload
    else:
        encoded_payload = nested_payload.hex()
        value = f"{encoded_payload[:2]}{' ' * (1024 * 1024 + 65)}{encoded_payload[2:]}"
        assert bytes.fromhex(value) == nested_payload

    report = scan_bytes(
        pickle.dumps(value, protocol=4),
        source=f"benign-{encoding}-beyond-probe-cap.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_ignores_incomplete_base64_near_match_beyond_probe_cap() -> None:
    value = f"S{'!' * (1024 * 1024 + 65)}Q"

    report = scan_bytes(
        pickle.dumps(value, protocol=4),
        source="incomplete-base64-beyond-probe-cap.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_ignores_repeated_protocol0_scalar_prefix_near_matches() -> None:
    report = scan_bytes(
        pickle.dumps("S!" * 128, protocol=4),
        source="repeated-protocol0-scalar-prefix-near-match.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert not any(notice.code == "nested_probe_limit" for notice in report.notices)


def test_scan_bytes_keeps_raw_scan_for_lenient_whole_base64_near_match() -> None:
    value = "gAROLg!cos\nsystem\n)R."

    report = scan_bytes(
        pickle.dumps(value, protocol=4),
        source="lenient-base64-with-raw-nested-protocol0.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


def test_scan_bytes_fails_closed_when_encoded_prefix_hides_later_pickle_beyond_budget() -> None:
    nested_payloads = b"\x80\x04N." + b"cos\nsystem\n)R."
    encoded = base64.b64encode(nested_payloads).decode("ascii")

    report = scan_bytes(
        pickle.dumps(encoded, protocol=4),
        source="encoded-benign-prefix-before-budgeted-payload.pkl",
        options=ScanOptions(max_nested_pickle_bytes=4),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(notice.code == "encoded_nested_payload_truncated" for notice in report.notices)


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
    nested_payload = b"(ios\nsystem\n(S'" + _overlong_protocol0_operand_body() + b"'\ntR."
    nested_value = nested_payload.decode("ascii") if as_unicode else nested_payload
    payload = pickle.dumps(nested_value, protocol=4)

    report = scan_bytes(
        payload,
        source="nested-inst-overlong-protocol0-string.pkl",
        options=ScanOptions(
            max_nested_pickle_bytes=len(nested_payload) + SCAN_LIMIT_OVERHEAD_BYTES,
            max_string_literal_scan_chars=len(nested_payload) + SCAN_LIMIT_OVERHEAD_BYTES,
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
