from __future__ import annotations

import base64
import os
import pickle

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes


class MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return os.system, ("echo pwned",)


LONG_PROTOCOL0_LITERAL_PAYLOADS = [
    pytest.param(b"cattacker\nfactory\n(V" + (b"A" * 2000) + b"\ntR.", id="unicode"),
    pytest.param(
        b"cattacker\nfactory\nX" + (2000).to_bytes(4, "little") + (b"A" * 2000) + b"\x85R.",
        id="binunicode",
    ),
]


def _encode_nested_value(payload: bytes, encoding: str) -> bytes | str:
    if encoding == "raw":
        return payload
    if encoding == "unicode":
        return payload.decode("latin1")
    if encoding == "base64":
        return base64.b64encode(payload).decode("ascii")
    return payload.hex()


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [
        ("raw", "S213"),
        ("unicode", "S213"),
        ("base64", "S601"),
        ("hex", "S602"),
    ],
)
@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_minimum_nested_budget_fails_closed(
    protocol: int,
    encoding: str,
    expected_rule: str,
) -> None:
    nested_payload = pickle.dumps(MaliciousPayload(), protocol=protocol)
    nested_value: bytes | str
    if encoding == "raw":
        nested_value = nested_payload
    elif encoding == "unicode":
        nested_value = nested_payload.decode("latin1")
    elif encoding == "base64":
        nested_value = base64.b64encode(nested_payload).decode("ascii")
    else:
        nested_value = nested_payload.hex()

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"minimum-budget-protocol-{protocol}-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=2),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == expected_rule for finding in report.findings)


def test_minimum_nested_budget_fails_closed_for_unknown_protocol0_global() -> None:
    nested_payload = b"cxxx\nxxx\n)R."

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="minimum-budget-unknown-protocol0-global.pkl",
        options=ScanOptions(max_nested_pickle_bytes=2),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [
        ("raw", "S213"),
        ("unicode", "S213"),
        ("base64", "S601"),
        ("hex", "S602"),
    ],
)
def test_minimum_nested_budget_fails_closed_for_mark_prefixed_inst(
    encoding: str,
    expected_rule: str,
) -> None:
    nested_value = _encode_nested_value(b"(ios\nsystem\n.", encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"minimum-budget-inst-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=2),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == expected_rule for finding in report.findings)


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [
        ("raw", "S213"),
        ("unicode", "S213"),
        ("base64", "S601"),
        ("hex", "S602"),
    ],
)
def test_minimum_nested_budget_fails_closed_for_explicit_protocol0_header(
    encoding: str,
    expected_rule: str,
) -> None:
    nested_payload = b"\x80\x00X\x08\x00\x00\x00attackerQ."
    nested_value: bytes | str
    if encoding == "raw":
        nested_value = nested_payload
    elif encoding == "unicode":
        nested_value = nested_payload.decode("latin1")
    elif encoding == "base64":
        nested_value = base64.b64encode(nested_payload).decode("ascii")
    else:
        nested_value = nested_payload.hex()

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"minimum-budget-explicit-protocol0-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=2),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == expected_rule for finding in report.findings)


@pytest.mark.parametrize(
    "nested_value",
    [
        b"cp",
        b"cposix\n",
        b"(instance)",
    ],
)
def test_minimum_nested_budget_leaves_protocol0_near_matches_clean(
    nested_value: bytes,
) -> None:
    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source="minimum-budget-protocol0-near-match.pkl",
        options=ScanOptions(max_nested_pickle_bytes=2),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "S213" for finding in report.findings)


@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64", "hex"])
def test_minimum_nested_budget_leaves_invalid_protocol6_header_clean(encoding: str) -> None:
    invalid_payload = b"\x80\x06not-a-pickle"
    nested_value = _encode_nested_value(invalid_payload, encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"minimum-budget-invalid-protocol6-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=2),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code in {"S213", "S601", "S602"} for finding in report.findings)


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [
        ("raw", "S213"),
        ("unicode", "S213"),
        ("base64", "S601"),
        ("hex", "S602"),
    ],
)
@pytest.mark.parametrize("budget", [2, 8, 16, 64])
@pytest.mark.parametrize("filler_len", [0, 1, 47, 48, 63, 64])
def test_nested_budget_detects_valid_pickle_after_invalid_protocol_header(
    encoding: str,
    expected_rule: str,
    budget: int,
    filler_len: int,
) -> None:
    nested_payload = b"\x80\x06" + (b"!" * filler_len) + b"cos\nsystem\n)R."
    nested_value = _encode_nested_value(nested_payload, encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"invalid-protocol-with-valid-suffix-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=budget),
    )

    expected_status = ScanStatus.INCONCLUSIVE if budget < len(b"cos\nsystem\n)R.") else ScanStatus.COMPLETE
    assert report.status == expected_status
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == expected_rule for finding in report.findings)


@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64", "hex"])
@pytest.mark.parametrize("budget", [2, 8, 16, ScanOptions().max_nested_pickle_bytes])
@pytest.mark.parametrize(
    "prose",
    [
        b"config\nvalue\nplain prose",
        b"config\nvalue\nplain prose\n",
        b"instance\nvalue\nplain prose",
        b"instance\nvalue\nplain prose\n",
        b"client\nlist\ndetailed prose",
        (
            b"instance prose instance instance audit\n"
            b"list status prose nested config nested list\n"
            b"client budget value\n"
            b"status audit audit audit nested plain client\n"
        ),
        (
            b"client config instance\n"
            b"value list budget client\n"
            b"client nested model\n"
            b"audit instance plain config budget client report\n"
        ),
        (b"client plain config report instance list client instance\nstatus\nconfig\ninstance budget report value\n"),
        b"client\nstatus\njust plain prose\nget\n",
        b"config\nvalue\n(Value " + (b"x" * 2000) + b"\n",
    ],
)
def test_nested_budget_leaves_multiline_opcode_like_prose_clean(
    prose: bytes,
    budget: int,
    encoding: str,
) -> None:
    nested_value = _encode_nested_value(prose, encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"multiline-prose-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=budget),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code in {"S213", "S601", "S602"} for finding in report.findings)


@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64", "hex"])
def test_truncated_opaque_binary_prefix_remains_clean(encoding: str) -> None:
    opaque_value = b"\x80\x04" + (b"A" * 8)
    nested_value: bytes | str
    if encoding == "raw":
        nested_value = opaque_value
    elif encoding == "unicode":
        nested_value = opaque_value.decode("latin1")
    elif encoding == "base64":
        nested_value = base64.b64encode(opaque_value).decode("ascii")
    else:
        nested_value = opaque_value.hex()

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"opaque-binary-prefix-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=8),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code in {"S213", "S601", "S602"} for finding in report.findings)


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [
        ("raw", "S213"),
        ("unicode", "S213"),
        ("base64", "S601"),
        ("hex", "S602"),
    ],
)
@pytest.mark.parametrize("budget", [2, 8, 1024])
def test_minimum_nested_budget_fails_closed_for_long_protocol0_global(
    encoding: str,
    expected_rule: str,
    budget: int,
) -> None:
    nested_payload = b"cattacker\nfactory\n(" + (b"N" * 2000) + b"tR."
    nested_value = _encode_nested_value(nested_payload, encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"minimum-budget-long-global-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=budget),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == expected_rule for finding in report.findings)


@pytest.mark.parametrize(
    ("encoding", "expected_rule"),
    [
        ("raw", "S213"),
        ("unicode", "S213"),
        ("base64", "S601"),
        ("hex", "S602"),
    ],
)
@pytest.mark.parametrize("budget", [2, 8, 1024])
@pytest.mark.parametrize("nested_payload", LONG_PROTOCOL0_LITERAL_PAYLOADS)
def test_nested_budget_fails_closed_for_long_protocol0_literal(
    encoding: str,
    expected_rule: str,
    budget: int,
    nested_payload: bytes,
) -> None:
    nested_value = _encode_nested_value(nested_payload, encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"minimum-budget-long-literal-{encoding}.pkl",
        options=ScanOptions(max_nested_pickle_bytes=budget),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == expected_rule for finding in report.findings)


@pytest.mark.parametrize("encoding", ["raw", "unicode", "base64", "hex"])
@pytest.mark.parametrize("nested_payload", LONG_PROTOCOL0_LITERAL_PAYLOADS)
def test_default_nested_budget_scans_long_protocol0_literal(
    encoding: str,
    nested_payload: bytes,
) -> None:
    nested_value = _encode_nested_value(nested_payload, encoding)

    report = scan_bytes(
        pickle.dumps({"outer": nested_value}, protocol=4),
        source=f"default-budget-long-literal-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
