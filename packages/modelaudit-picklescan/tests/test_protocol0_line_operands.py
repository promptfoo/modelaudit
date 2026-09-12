from __future__ import annotations

import base64
import binascii
import os
import pickle
import struct
import time
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from modelaudit_picklescan import SafetyVerdict, ScanOptions, ScanStatus, scan_bytes, scan_file
from modelaudit_picklescan import api as picklescan_api

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


def _benign_long_scalar_protocol0_pickle(opcode: bytes) -> bytes:
    prefix = _long_scalar_before_reduce_protocol0_pickle(opcode).split(b"cos\nsystem\n", maxsplit=1)[0]
    if prefix.endswith(b"0"):
        prefix = prefix[:-1]
    return prefix + b"."


def _proto0_string_literal(value: bytes) -> bytes:
    literal = value.decode("latin-1").encode("unicode_escape").replace(b"'", b"\\'")
    return b"S'" + literal + b"'\n."


def _binbytes_literal_pickle(value: bytes) -> bytes:
    return b"B" + struct.pack("<I", len(value)) + value + b"."


def _short_binunicode(data: bytes) -> bytes:
    assert len(data) < 256
    return b"\x8c" + bytes([len(data)]) + data


def _float_storage_persistent_id_payload_for_bytes(key: str, data: bytes) -> bytes:
    element_count = max(1, len(data) // 4)
    return (
        b"\x80\x04("
        + _short_binunicode(b"storage")
        + _short_binunicode(b"torch")
        + _short_binunicode(b"FloatStorage")
        + b"\x93"
        + _short_binunicode(key.encode("ascii"))
        + _short_binunicode(b"cpu")
        + b"K"
        + bytes([element_count])
        + b"tQ."
    )


def _frame(payload: bytes) -> bytes:
    return b"\x95" + struct.pack("<Q", len(payload)) + payload


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


def test_trusted_storage_probe_routes_byte_literal_after_trivial_stream() -> None:
    nested_payload = b"cos\nsystem\n)R."
    sample = b"N." + _binbytes_literal_pickle(base64.b64encode(nested_payload))

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(sample, sample_is_prefix=False) is True


def test_trusted_storage_probe_routes_nested_extension_reference_literal() -> None:
    sample = b"U\x03\x82\x01.."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(sample, sample_is_prefix=False) is True


def test_trusted_storage_probe_scans_full_expanded_malformed_separator_run() -> None:
    nested_payload = b"cos\nsystem\n)R."
    sample = b"N." + (b"!" * 5000) + _proto0_string_literal(base64.b64encode(nested_payload))

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(sample, sample_is_prefix=False) is True


def test_trusted_storage_probe_expands_frame_without_stop_at_boundary() -> None:
    frame_payload = b"\x85"
    padding = b" " * (picklescan_api._TRUSTED_STORAGE_PICKLE_PROBE_BYTES - len(b"N.") - len(_frame(frame_payload)))
    sample = b"N." + padding + _frame(frame_payload)

    assert (
        picklescan_api._proto0_or_1_trusted_storage_probe_needs_expanded_sample(
            sample,
            entry_size=len(sample) + len(b"cos\nsystem\n)R."),
        )
        is True
    )


def test_trusted_storage_probe_expands_after_complete_frame_at_boundary() -> None:
    first_frame = _frame(b"]")
    padding = b" " * (picklescan_api._TRUSTED_STORAGE_PICKLE_PROBE_BYTES - len(b"N.") - len(first_frame) - 1)
    sample = b"N." + padding + first_frame + b"\x95"

    assert (
        picklescan_api._proto0_or_1_trusted_storage_probe_needs_expanded_sample(
            sample,
            entry_size=len(sample) + 32,
        )
        is True
    )


def test_trusted_storage_probe_expands_inst_operand_at_boundary() -> None:
    sample = b"N." + (b" " * (picklescan_api._TRUSTED_STORAGE_PICKLE_PROBE_BYTES - len(b"N.") - 1)) + b"i"

    assert (
        picklescan_api._proto0_or_1_trusted_storage_probe_needs_expanded_sample(
            sample,
            entry_size=len(sample) + len(b"posix\nsystem\n."),
        )
        is True
    )


def test_storage_literal_route_bounds_long_base64_without_size_only_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    decode_lengths: list[int] = []

    def bounded_decode(token: bytes, *, validate: bool) -> bytes:
        assert validate is True
        decode_lengths.append(len(token))
        assert len(token) <= picklescan_api._MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES
        return b"ordinary metadata"

    monkeypatch.setattr(picklescan_api.base64, "b64decode", bounded_decode)
    token = b"A" * (picklescan_api._MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES + 1024)

    assert picklescan_api._base64_literal_value_has_suspicious_text(token) is False
    assert decode_lengths
    assert max(decode_lengths) <= picklescan_api._MAX_STORAGE_LITERAL_BASE64_DECODE_INPUT_BYTES


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


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_detects_base64_long_protocol0_pickle_in_byte_literals(
    container: type[bytes] | type[bytearray],
) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(b"V")
    encoded = container(base64.b64encode(nested_payload))

    report = scan_bytes(
        pickle.dumps(encoded, protocol=5),
        source=f"base64-long-protocol0-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("module") == "os"
        and finding.details.get("name") == "system"
        for finding in report.findings
    )


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("invalid_utf8_position", ["prefix", "suffix"])
def test_scan_bytes_detects_base64_byte_literals_with_invalid_utf8_wrappers(
    container: type[bytes] | type[bytearray],
    invalid_utf8_position: str,
) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(b"V")
    encoded = base64.b64encode(nested_payload)
    wrapped = b"\xff" + encoded if invalid_utf8_position == "prefix" else encoded + b"\xff"

    report = scan_bytes(
        pickle.dumps(container(wrapped), protocol=5),
        source=f"wrapped-base64-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("module") == "os"
        and finding.details.get("name") == "system"
        for finding in report.findings
    )


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("invalid_utf8_position", ["prefix", "suffix"])
def test_scan_bytes_detects_over_budget_invalid_utf8_wrapped_base64_byte_literals(
    container: type[bytes] | type[bytearray],
    invalid_utf8_position: str,
) -> None:
    nested_payload = _long_scalar_before_reduce_protocol0_pickle(b"V")
    encoded = base64.b64encode(nested_payload)
    scan_limit = len(encoded) + 8
    padding = b"\xff" * (scan_limit + 1)
    wrapped = padding + encoded if invalid_utf8_position == "prefix" else encoded + padding

    report = scan_bytes(
        pickle.dumps(container(wrapped), protocol=5),
        source=f"over-budget-wrapped-base64-{container.__name__}.pkl",
        options=ScanOptions(max_string_literal_scan_chars=scan_limit),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_fails_closed_for_invalid_utf8_encoded_payload_hidden_beyond_literal_budget(
    container: type[bytes] | type[bytearray],
) -> None:
    encoded = base64.b64encode(_long_scalar_before_reduce_protocol0_pickle(b"V"))
    scan_limit = 64
    padding = b"\xff" * (scan_limit + 1)
    wrapped = padding + encoded + padding

    report = scan_bytes(
        pickle.dumps(container(wrapped), protocol=5),
        source=f"hidden-over-budget-base64-{container.__name__}.pkl",
        options=ScanOptions(max_string_literal_scan_chars=scan_limit),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict != SafetyVerdict.CLEAN
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("decoded_prefix", [b"", b"X", b"junk"])
def test_scan_bytes_keeps_benign_base64_byte_literals_clean(
    container: type[bytes] | type[bytearray],
    decoded_prefix: bytes,
) -> None:
    encoded = container(base64.b64encode(decoded_prefix + _benign_long_scalar_protocol0_pickle(b"V")))

    report = scan_bytes(
        pickle.dumps(encoded, protocol=5),
        source=f"benign-base64-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("invalid_utf8_position", ["prefix", "suffix"])
def test_scan_bytes_keeps_benign_base64_byte_literals_with_invalid_utf8_clean(
    container: type[bytes] | type[bytearray],
    invalid_utf8_position: str,
) -> None:
    encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    wrapped = b"\xff" + encoded if invalid_utf8_position == "prefix" else encoded + b"\xff"

    report = scan_bytes(
        pickle.dumps(container(wrapped), protocol=5),
        source=f"benign-wrapped-base64-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("encoding", ["base64", "hex"])
@pytest.mark.parametrize("decoded", [b"\x80\x04N.README", b"(README benign text"])
def test_scan_bytes_keeps_execution_like_encoded_byte_literal_text_clean(
    container: type[bytes] | type[bytearray],
    encoding: str,
    decoded: bytes,
) -> None:
    encoded = base64.b64encode(decoded) if encoding == "base64" else decoded.hex().encode("ascii")

    report = scan_bytes(
        pickle.dumps(container(encoded), protocol=5),
        source=f"benign-{encoding}-execution-like-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("encoded_first", [False, True])
def test_scan_bytes_keeps_raw_nested_scan_for_mixed_encoded_byte_literals(
    container: type[bytes] | type[bytearray],
    encoded_first: bool,
) -> None:
    benign_encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    raw_malicious = b"cos\nsystem\n(S'id'\ntR."
    payload = benign_encoded + b"!" + raw_malicious if encoded_first else raw_malicious + b"!" + benign_encoded

    report = scan_bytes(
        pickle.dumps(container(payload), protocol=5),
        source=f"mixed-encoded-raw-{container.__name__}.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("module") == "os"
        and finding.details.get("name") == "system"
        for finding in report.findings
    )


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_keeps_fail_closed_raw_scan_for_truncated_persid_after_encoded_literal(
    container: type[bytes] | type[bytearray],
) -> None:
    benign_encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    payload = benign_encoded + b"!Pevil\n"

    report = scan_bytes(
        pickle.dumps(container(payload), protocol=5),
        source=f"encoded-plus-truncated-persid-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "PERSISTENT_ID" for finding in report.findings)
    assert any(
        finding.rule_code == "S213" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_keeps_raw_scan_after_invalid_base64_padding(
    container: type[bytes] | type[bytearray],
) -> None:
    benign_encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    payload = benign_encoded + b"NQ"

    report = scan_bytes(
        pickle.dumps(container(payload), protocol=5),
        source=f"base64-invalid-padding-raw-suffix-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "PERSISTENT_ID" for finding in report.findings)
    assert any(
        finding.rule_code == "S213" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_ignores_benign_suffix_after_padded_base64_pickle(
    container: type[bytes] | type[bytearray],
) -> None:
    benign_encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    payload = container(benign_encoded + b"ab")

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"base64-benign-raw-suffix-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize(
    "prefix",
    [b" ", b"# ", b"!", b"prefix:", b"\xff", b"A", b"AA", b"AAA", b"junk", b"prefix"],
)
@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_ignores_benign_wrapped_padded_base64_suffix(
    container: type[bytes] | type[bytearray],
    prefix: bytes,
) -> None:
    benign_encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    payload = container(prefix + benign_encoded + b"ab")

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"wrapped-base64-benign-suffix-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize(
    "raw_payload",
    [
        b"NQAAgAROLgAAAAAA",
        b"NQAAAAAAgAROLg==",
        b"NNQAgAROLgAAAAAA",
        b"NNNQgAROLgAAAAAA",
        b"N0NQgAROLgAAAAAA",
        b"AAAANQAAgAROLgAAAAAA",
        b"AAAANQAAAAAAgAROLg==",
        (b"A" * 16) + b"NQAAAAAAgAROLg==",
        b"BBBBNQAAAAAAgAROLg==",
        b"NQ" + (b"A" * 18) + base64.b64encode(b"V" + (b"A" * 300) + b"\n."),
        ((b"C+" + (b"A" * 43)) * 6) + b"QgAROLgAAAAAA",
        b"N" + (b"2" * 80) + b"QgAROLgAAAAAA",
        b"K1QgAROLgAAAAAA",
        b"M12QgAROLg==",
        b"J1234QgAROLgAAAAAA",
        b"G12345678QgAROLgAAAAAA",
        b"N2QgAROLgAAAAAA",
        b"C+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAgAROLgAAAA",
        b"U+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAgAROLgAAAA",
    ],
)
def test_scan_bytes_preserves_raw_execution_inside_strict_base64_token(
    container: type[bytes] | type[bytearray],
    raw_payload: bytes,
) -> None:
    payload = container(raw_payload)

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"strict-base64-with-raw-persid-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "PERSISTENT_ID" for finding in report.findings)
    assert any(
        finding.rule_code == "S213" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize("raw_suffix", [b"NQ", b"NNQ", b"N0NQ"])
def test_scan_bytes_preserves_raw_execution_after_unpadded_base64_pickle(
    container: type[bytes] | type[bytearray],
    raw_suffix: bytes,
) -> None:
    benign_encoded = base64.b64encode(b"V" + (b"A" * 300) + b"\n.")
    assert not benign_encoded.endswith(b"=")
    payload = container(benign_encoded + raw_suffix)

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"unpadded-base64-raw-suffix-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "PERSISTENT_ID" for finding in report.findings)


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_keeps_multiple_benign_base64_tokens_clean(
    container: type[bytes] | type[bytearray],
) -> None:
    benign_encoded = base64.b64encode(_benign_long_scalar_protocol0_pickle(b"V"))
    payload = container(benign_encoded + b"ab!" + benign_encoded)

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"multiple-benign-base64-tokens-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_detects_malicious_base64_token_after_padded_token(
    container: type[bytes] | type[bytearray],
) -> None:
    benign_encoded = base64.b64encode(pickle.dumps(None, protocol=4))
    malicious_encoded = base64.b64encode(pickle.dumps(os.system, protocol=4))
    payload = container(benign_encoded + malicious_encoded)

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"padded-token-before-malicious-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_GLOBAL" for finding in report.findings)


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_keeps_repeated_raw_execution_near_matches_clean(
    container: type[bytes] | type[bytearray],
) -> None:
    payload = container(b"ordinaryCNQHtext" * 65)

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"repeated-raw-near-match-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_detects_malicious_token_after_unterminated_base64_scalar(
    container: type[bytes] | type[bytearray],
) -> None:
    unterminated_scalar = base64.b64encode(b"VAAAA")
    malicious_encoded = base64.b64encode(_long_scalar_before_reduce_protocol0_pickle(b"V"))
    payload = container(unterminated_scalar + b"!" + malicious_encoded)

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"unterminated-prefix-before-malicious-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)


@pytest.mark.parametrize("container", [bytes, bytearray])
def test_scan_bytes_detects_binary_pickle_inside_unterminated_base64_scalar(
    container: type[bytes] | type[bytearray],
) -> None:
    payload = container(base64.b64encode(b"S" + pickle.dumps(os.system, protocol=4)))

    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"unterminated-scalar-with-binary-pickle-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_GLOBAL" for finding in report.findings)


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize(
    "decoded",
    [b"Pevil\nAAAAAAAA", b"\x80\x04N.Pevil\n", b"README\x80\x04NQ"],
)
def test_scan_bytes_fails_closed_for_encoded_truncated_execution_prefixes(
    container: type[bytes] | type[bytearray],
    decoded: bytes,
) -> None:
    encoded = container(base64.b64encode(decoded))

    report = scan_bytes(
        pickle.dumps(encoded, protocol=5),
        source=f"encoded-truncated-execution-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "PERSISTENT_ID" for finding in report.findings)
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(notice.code == "nested_pickle_incomplete" for notice in report.notices)
    assert not any(notice.code == "encoded_nested_payload_truncated" for notice in report.notices)


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize(
    "decoded",
    [
        b"\x80\x04N.README",
        b"(README is ordinary text",
        b"README is ordinary text",
        b"ordinary CNQH text",
        b"junkPevil\n",
    ],
)
def test_scan_bytes_keeps_encoded_execution_opcode_near_matches_clean(
    container: type[bytes] | type[bytearray],
    decoded: bytes,
) -> None:
    encoded = container(base64.b64encode(decoded))

    report = scan_bytes(
        pickle.dumps(encoded, protocol=5),
        source=f"encoded-execution-near-match-{container.__name__}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_bounds_unterminated_protocol0_base64_scalar_runtime() -> None:
    encoded = base64.b64encode(b"V" + (b"A" * 100_000))

    started = time.monotonic()
    report = scan_bytes(
        pickle.dumps(encoded, protocol=5),
        source="unterminated-protocol0-base64-byte-literal.pkl",
    )
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_bounds_strict_base64_junk_runtime() -> None:
    payload = (b"junk" * 25_000) + b"Q"

    started = time.monotonic()
    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source="bounded-strict-base64-junk.pkl",
        options=ScanOptions(timeout_s=0.05),
    )
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_bounds_valid_utf8_encoded_byte_literal_prefilter() -> None:
    literal = b"gA" * (512 * 1024)

    started = time.monotonic()
    report = scan_bytes(
        pickle.dumps(literal, protocol=5),
        source="bounded-valid-utf8-byte-literal.pkl",
        options=ScanOptions(max_string_literal_scan_chars=64, timeout_s=0.05),
    )
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict != SafetyVerdict.CLEAN
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


@pytest.mark.parametrize("container", [bytes, bytearray])
@pytest.mark.parametrize(
    "payload_bytes",
    [b"UA" * 2_500_000, b"N" * 5_000_000],
    # Multi-megabyte parametrized values become the test id, which pytest writes
    # into PYTEST_CURRENT_TEST; Windows rejects env vars over 32767 chars, so give
    # the cases short ids.
    ids=["utf8_pair_5mb", "ascii_n_5mb"],
)
def test_scan_bytes_bounds_valid_utf8_byte_literal_runtime(
    container: type[bytes] | type[bytearray],
    payload_bytes: bytes,
) -> None:
    payload = container(payload_bytes)

    started = time.monotonic()
    report = scan_bytes(
        pickle.dumps(payload, protocol=5),
        source=f"bounded-valid-utf8-{container.__name__}.pkl",
        options=ScanOptions(max_string_literal_scan_chars=1024),
    )
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict != SafetyVerdict.CLEAN
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


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


@pytest.mark.parametrize("separator_count", [9, 16])
def test_trusted_storage_probe_routes_encoded_pickle_after_long_malformed_separator(
    separator_count: int,
) -> None:
    nested_payload = b"cposix\nsystem\n(S'echo hidden'\ntR."
    encoded = base64.b64encode(nested_payload)
    payload = b"N." + (b"Z" * separator_count) + b"S'" + encoded + b"'\n."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_skips_long_malformed_separator_literal_near_match() -> None:
    payload = b"N." + (b"Z" * 16) + b"S'benign-token'\n."

    assert not picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def _headerless_binary_nested_pickle() -> bytes:
    return b"\x8c\x02os\x8c\x06system\x93)R."


@pytest.mark.parametrize(
    "literal_value",
    [
        _headerless_binary_nested_pickle(),
        base64.b64encode(_headerless_binary_nested_pickle()),
        binascii.hexlify(_headerless_binary_nested_pickle()),
    ],
)
def test_trusted_storage_probe_routes_headerless_binary_nested_pickle_literal(literal_value: bytes) -> None:
    payload = b"S'" + literal_value + b"'\n."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_preserves_embedded_bytes_in_mixed_unicode_literal() -> None:
    nested_pickle = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x93\x8c\x04true\x94\x85R."
    payload = pickle.dumps("\u2603" + nested_pickle.decode("latin-1"), protocol=0)

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_routes_frame_first_headerless_binary_nested_literal() -> None:
    literal_value = base64.b64encode(_headerless_binary_nested_pickle())
    frame_payload = b"\x8c" + bytes([len(literal_value)]) + literal_value + b"."
    payload = b"\x95" + len(frame_payload).to_bytes(8, "little") + frame_payload

    assert picklescan_api._frame_first_trusted_storage_probe_should_scan(payload)


def test_trusted_storage_probe_routes_compile_call_literal() -> None:
    payload = b"S\"compile('print(1)', 'x', 'exec')\"\n."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_routes_wrapped_encoded_suspicious_text_literal() -> None:
    encoded = base64.b64encode(b"os.system('id')")
    wrapped = b"\n".join(encoded[index : index + 4] for index in range(0, len(encoded), 4))
    payload = b"U" + bytes([len(wrapped)]) + wrapped + b"."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_skips_headerless_binary_literal_near_match() -> None:
    payload = b"S'\x8c\x02ok\x94.'\n."

    assert not picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_skips_stack_global_without_operands_after_trivial_prefix() -> None:
    payload = b"N.\x93.\x00\x00"

    assert not picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_routes_raw_pickle_after_binary_candidate_budget_noise() -> None:
    literal = (b"\x8c" * 65) + b"cbuiltins\nopen\n(S'file'\ntR."
    payload = b"T" + len(literal).to_bytes(4, "little") + literal + b"."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_skips_raw_binary_candidate_budget_noise_near_match() -> None:
    literal = (b"\x8c" * 65) + (b"\xff" * 16)

    assert not picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_skips_repeated_text_candidate_budget_near_match() -> None:
    literal = b"abc" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)
    payload = _proto0_string_literal(literal)

    assert not picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_bounds_repeated_global_candidate_search() -> None:
    literal = (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)) + (b"c" * 60_000) + b"!"
    started_at = time.monotonic()

    assert not picklescan_api._literal_value_has_raw_nested_security_pickle(literal)
    assert time.monotonic() - started_at < 1.0


def test_trusted_storage_probe_routes_global_after_malformed_global_candidate() -> None:
    literal = (
        (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 6))
        + b"foo\nbad! "
        + b"cctypes\nCDLL\n(S'evil.so'\ntR."
    )

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_routes_binary_pickle_after_raw_candidate_budget_gap() -> None:
    nested_pickle = b"\x80\x04cbuiltins\neval\n(S'1+1'\ntR."
    literal = (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)) + b"ZZZZ" + nested_pickle

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_routes_binary_pickle_after_long_raw_candidate_budget_gap() -> None:
    nested_pickle = b"\x80\x04\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x8c\x031+1\x94\x85R."
    literal = (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)) + (b"!" * 9_000) + nested_pickle

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_routes_later_binary_pickle_after_benign_binary_decoy() -> None:
    benign_decoy = pickle.dumps(None, protocol=4)
    nested_pickle = b"\x80\x04\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x8c\x031+1\x94\x85R."
    literal = (
        b"N." + (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 6)) + benign_decoy + b"!" + nested_pickle
    )

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_routes_headerless_binary_pickle_after_budget_noise() -> None:
    nested_pickle = b"\x8c\x02os\x8c\x06system\x93)R."
    literal = (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)) + (b"!" * 100) + nested_pickle

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_routes_extension_opcode_after_budget_noise() -> None:
    literal = (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)) + (b"A" * 10) + b"\x82\x01."

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_skips_incomplete_extension_opcode_after_budget_noise() -> None:
    literal = (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1)) + (b"A" * 10) + b"\x82\x01"

    assert not picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_trusted_storage_probe_routes_later_pickle_after_incomplete_extension_budget_noise() -> None:
    nested_pickle = b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x031+1\x85R."
    literal = (
        (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1))
        + (b"A" * 10)
        + b"\x82\x01"
        + (b" " * picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATE_BYTES)
        + nested_pickle
    )

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_raw_nested_extension_budget_exhaustion_routes_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    literal = (
        (b"c" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 1))
        + (b"(" * (picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES + 6))
        + b"\xff"
        + (b"\x82\x01" * 1900)
    )

    def fail_if_called(_candidate: bytes) -> bool:
        raise AssertionError("fallback parser should not run after extension context budget exhaustion")

    monkeypatch.setattr(
        picklescan_api,
        "_extension_candidate_after_exhausted_context_should_scan",
        fail_if_called,
    )
    parse_budget_remaining = [picklescan_api._MAX_RAW_NESTED_PICKLE_CANDIDATES]

    assert picklescan_api._raw_nested_extension_opcode_candidate_has_structural_signal(
        literal,
        parse_budget_remaining,
    )
    assert parse_budget_remaining == [0]


def test_trusted_storage_probe_routes_legacy_raw_candidate_budget_exhaustion() -> None:
    literal = (b"\x82" * 65) + (b"\xff" * 16)

    assert picklescan_api._literal_value_has_raw_nested_security_pickle(literal)


def test_scan_file_keeps_float_storage_extension_like_bytes_clean(tmp_path: Path) -> None:
    storage_blob = b"\x8c\x01\xff\x3f\x82\x01\xff\x3f"
    model_path = tmp_path / "float-storage-extension-like-bytes.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", _float_storage_persistent_id_payload_for_bytes("0", storage_blob))
        zip_file.writestr("archive/data/0", storage_blob)

    report = scan_file(model_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert tuple(report.metadata.get("pickle_files", ())) == ("archive/data.pkl",)


def test_trusted_storage_probe_routes_encoded_pickle_after_binary_candidate_budget_noise() -> None:
    encoded = base64.b64encode((b"\x8c" * 65) + b"cbuiltins\nopen\n(S'file'\ntR.")
    payload = b"S'" + encoded + b"'\n."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_routes_bytearray8_literal_after_trivial_prefix() -> None:
    encoded = base64.b64encode(b"cposix\nsystem\n)R.")
    payload = b"N.\x96" + len(encoded).to_bytes(8, "little") + encoded + b"."

    assert picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


def test_trusted_storage_probe_skips_encoded_binary_candidate_budget_noise_near_match() -> None:
    encoded = base64.b64encode((b"\x8c" * 65) + (b"\xff" * 16))
    payload = b"S'" + encoded + b"'\n."

    assert not picklescan_api._proto0_or_1_trusted_storage_probe_should_scan(payload, sample_is_prefix=False)


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
