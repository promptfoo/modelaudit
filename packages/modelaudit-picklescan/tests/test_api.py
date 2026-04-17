from __future__ import annotations

import base64
import binascii
import collections
import datetime
import decimal
import functools
import io
import os
import pickle
import re
import tarfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath

import pytest

import modelaudit_picklescan.api as package_api
from modelaudit_picklescan import (
    PickleScanner,
    SafetyVerdict,
    ScanOptions,
    ScanStatus,
    Severity,
    scan_bytes,
    scan_file,
)

EXPECTED_SYSTEM_GLOBAL = "nt.system" if os.name == "nt" else "posix.system"
SYSTEM_GLOBALS = frozenset({"nt.system", "os.system", "posix.system"})


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _make_pre_memoized_post_budget_stack_global_payload(tail: bytes) -> bytes:
    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"subprocess") + b"\x94"
    payload += _short_binunicode(b"run") + b"\x94"
    payload += b"\x880" * 4
    payload += tail
    return bytes(payload)


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


def _corrupt_first_byte(payload: bytes) -> bytes:
    corrupted = bytearray(payload)
    corrupted[0] ^= 0xFF
    return bytes(corrupted)


class MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


class UnreadableStream(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        raise OSError("simulated stream read failure")


class RuntimeFailingStream(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        raise RuntimeError("simulated runtime stream read failure")


class NoBulkReadStream(io.BytesIO):
    def __init__(self, payload: bytes, *, max_read_size: int) -> None:
        super().__init__(payload)
        self.max_read_size = max_read_size
        self.max_seen_read_size = 0

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            raise AssertionError("scan_stream() attempted an unbounded bulk read")
        self.max_seen_read_size = max(self.max_seen_read_size, size)
        if size > self.max_read_size:
            raise AssertionError(f"scan_stream() attempted a bulk read of {size} bytes")
        return super().read(size)


class NoUnboundedReadlineStream(io.BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.max_seen_readline_size = 0
        self.unbounded_readline_attempted = False

    def readline(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            self.unbounded_readline_attempted = True
            raise AssertionError("scan_stream() attempted an unbounded line read")
        self.max_seen_readline_size = max(self.max_seen_readline_size, size)
        return super().readline(size)


class NonSeekableExactLimitStream(io.BytesIO):
    def __init__(self, payload: bytes, *, limit: int) -> None:
        super().__init__(payload)
        self.limit = limit
        self.bytes_returned = 0

    def seekable(self) -> bool:
        return False

    def read(self, size: int | None = -1) -> bytes:
        if self.bytes_returned >= self.limit:
            raise AssertionError("scan_stream() attempted an overflow probe on a non-seekable stream")
        chunk = super().read(size)
        self.bytes_returned += len(chunk)
        return chunk


def test_scan_bytes_returns_clean_report_for_safe_pickle() -> None:
    report = scan_bytes(pickle.dumps({"weights": [1, 2, 3]}), source="safe.pkl")

    assert report.source == "safe.pkl"
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.is_clean is True
    assert report.findings == ()
    assert report.errors == ()
    assert report.coverage.opcode_count is not None
    assert report.coverage.opcode_count > 0


def test_scan_bytes_reports_opcode_counts_metadata() -> None:
    report = scan_bytes(b"\x80\x04}\x94\x8c\x03key\x94K\x01s.", source="opcode-counts.pkl")

    opcode_counts = report.metadata["opcode_counts"]
    assert opcode_counts["PROTO"] == 1
    assert opcode_counts["EMPTY_DICT"] == 1
    assert opcode_counts["SETITEM"] == 1


def test_scan_bytes_clamps_excessive_timeout_without_engine_error() -> None:
    report = scan_bytes(
        pickle.dumps({"weights": [1, 2, 3]}, protocol=4),
        source="huge-timeout.pkl",
        options=ScanOptions(timeout_s=1.0e18),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.errors == ()


def test_scan_bytes_detects_reduce_invoking_os_system() -> None:
    report = scan_bytes(pickle.dumps(MaliciousPayload()), source="payload.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.has_security_findings is True
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert not any(finding.rule_code == "DANGEROUS_GLOBAL" for finding in report.findings)
    assert any(EXPECTED_SYSTEM_GLOBAL in finding.message for finding in report.findings)
    assert any(finding.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for finding in report.findings)
    assert any(
        ref["import_reference"] == EXPECTED_SYSTEM_GLOBAL and ref["is_dangerous"] is True
        for ref in report.metadata["import_references"]
    )


def test_scan_bytes_treats_protocol5_buffer_stack_global_as_malformed() -> None:
    payload = b"\x80\x05\x8c\x04safe\x94\x97\x8c\x08anything\x94\x93."

    report = scan_bytes(payload, source="next-buffer-stack-global.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "MALFORMED_STACK_GLOBAL" for finding in report.findings)


def test_scan_bytes_escalates_main_reduce_to_malicious() -> None:
    report = scan_bytes(b"c__main__\nDanger\n)R.", source="main-reduce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "__main__.Danger"
        for finding in report.findings
    )


def test_scan_bytes_ignores_comment_only_importlib_literal() -> None:
    report = scan_bytes(pickle.dumps({"doc": "importlib # harmless"}, protocol=4), source="importlib-comment.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_ignores_wrapped_version_dunder_metadata() -> None:
    report = scan_bytes(pickle.dumps({"doc": "['__version__']"}, protocol=4), source="version-metadata.pkl")

    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_detects_protocol0_encoded_nested_pickle_mid_literal() -> None:
    nested = b"cos\nsystem\n)R."
    encoded = "prefix-" + base64.b64encode(nested).decode("ascii")

    report = scan_bytes(pickle.dumps({"outer": encoded}, protocol=4), source="protocol0-nested-b64.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S601" for finding in report.findings)
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


@pytest.mark.parametrize("protocol", [2, 3, 4, 5])
def test_scan_bytes_detects_binary_protocol_encoded_nested_pickle_mid_literal(protocol: int) -> None:
    nested = pickle.dumps(MaliciousPayload(), protocol=protocol)
    encoded = "prefix-" + base64.b64encode(nested).decode("ascii")

    report = scan_bytes(pickle.dumps({"outer": encoded}, protocol=4), source=f"protocol{protocol}-nested-b64.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S601" for finding in report.findings)
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


def test_scan_bytes_detects_junk_prefixed_small_raw_nested_pickle() -> None:
    nested = b"cos\nsystem\n)R."

    report = scan_bytes(pickle.dumps({"outer": b"JUNK" + nested}, protocol=4), source="junk-nested-raw.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


@pytest.mark.parametrize(
    "separator",
    [
        b"\x00" * 64,
        b"\x00" * 4096,
        b"# padding that looks like text\n",
        b"MARK" * 16,
    ],
)
def test_scan_bytes_detects_follow_on_malicious_pickle_streams(separator: bytes) -> None:
    payload = pickle.dumps({"safe": True}, protocol=4) + separator + b"cos\nsystem\n)R."

    report = scan_bytes(payload, source="multi-stream.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(notice.code == "follow_on_stream_detected" for notice in report.notices)
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


@pytest.mark.parametrize(
    ("second_stream", "expected_reference"),
    [
        (b"cos\nsystem\n)R.", SYSTEM_GLOBALS),
        (b"chttplib\nHTTPConnection\n)R.", frozenset({"httplib.HTTPConnection"})),
    ],
)
def test_scan_bytes_detects_large_padding_follow_on_high_risk_streams(
    second_stream: bytes,
    expected_reference: frozenset[str],
) -> None:
    payload = pickle.dumps({"safe": True}, protocol=4) + (b"\x00" * 4096) + second_stream

    report = scan_bytes(payload, source="large-padding-follow-on.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(notice.code == "follow_on_stream_detected" for notice in report.notices)
    assert any(finding.details.get("import_reference") in expected_reference for finding in report.findings)


def test_scan_bytes_does_not_promote_benign_follow_on_stream() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4) + (b"\x00" * 4096) + pickle.dumps({"benign": True}, protocol=4)

    report = scan_bytes(payload, source="benign-follow-on.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert not report.findings
    assert not any(notice.code == "follow_on_stream_detected" for notice in report.notices)


def test_scan_bytes_detects_malicious_stream_after_malformed_prefix() -> None:
    payload = b"\x80\x04\xff" + (b"\x00" * 32) + b"cos\nsystem\n)R."

    report = scan_bytes(payload, source="malformed-prefix-stream.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


def test_scan_bytes_warns_on_iterative_memo_growth() -> None:
    report = scan_bytes(_make_memo_expansion_pickle(iterations=80), source="memo-expansion.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PICKLE_EXPANSION"
        and finding.severity == Severity.WARNING
        and "memo_growth_chain" in finding.details["findings"][0]["triggers"]
        for finding in report.findings
    )


def test_scan_bytes_warns_on_dup_heavy_expansion_payload() -> None:
    report = scan_bytes(_make_dup_heavy_pickle(iterations=200), source="dup-heavy.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PICKLE_EXPANSION"
        and "excessive_dup_usage" in finding.details["findings"][0]["triggers"]
        and "suspicious_get_put_ratio" in finding.details["findings"][0]["triggers"]
        for finding in report.findings
    )


def test_scan_bytes_does_not_warn_on_benign_shared_references() -> None:
    shared = [1, 2, 3]
    report = scan_bytes(pickle.dumps([shared] * 1000, protocol=4), source="shared-reference.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "PICKLE_EXPANSION" for finding in report.findings)


def test_scan_bytes_bounds_follow_on_probe_recursion_for_pickle_like_binary_tail() -> None:
    payload = pickle.dumps({"safe": True}, protocol=2) + (b"XYZNmore-binary-data" * 20)

    report = scan_bytes(payload, source="binary-tail.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()


def test_scan_bytes_reports_duplicate_and_misplaced_proto_tamper() -> None:
    report = scan_bytes(b"\x80\x02\x80\x04K\x01.", source="duplicate-proto.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "STRUCTURAL_TAMPER"
        and finding.severity == Severity.WARNING
        and finding.details.get("tamper_type") == "duplicate_proto"
        and finding.details.get("previous_protocol") == 2
        and finding.details.get("protocol") == 4
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "STRUCTURAL_TAMPER" and finding.details.get("tamper_type") == "misplaced_proto"
        for finding in report.findings
    )


def test_scan_bytes_does_not_report_structural_tamper_for_binary_tail() -> None:
    payload = pickle.dumps({"safe": True}, protocol=2) + (b"XYZNmore-binary-data" * 20)

    report = scan_bytes(payload, source="binary-tail.pkl")

    assert all(finding.rule_code != "STRUCTURAL_TAMPER" for finding in report.findings)


def test_scan_bytes_warns_on_post_budget_memo_growth_tail() -> None:
    payload = _make_opcode_padding_stream(64) + _make_memo_expansion_pickle(iterations=80)

    report = scan_bytes(
        payload,
        source="post-budget-expansion.pkl",
        options=ScanOptions(max_opcodes=64, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PICKLE_EXPANSION"
        and finding.details.get("post_budget") is True
        and "memo_growth_chain" in finding.details["findings"][0]["triggers"]
        for finding in report.findings
    )


def test_scan_bytes_escalates_copyreg_extension_reduce() -> None:
    report = scan_bytes(b"\x80\x04\x82\x01)R.", source="extension-reduce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("opaque_extension") is True
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("payload", "opcode", "code"),
    [
        (b"\x80\x04\x82\x01)R.", "EXT1", 1),
        (b"\x80\x04\x83\x01\x00)R.", "EXT2", 1),
        (b"\x80\x04\x84\x01\x00\x00\x00)R.", "EXT4", 1),
    ],
)
def test_scan_bytes_escalates_all_copyreg_extension_reduce_opcodes(
    payload: bytes,
    opcode: str,
    code: int,
) -> None:
    report = scan_bytes(payload, source=f"{opcode.lower()}-reduce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("opcode") == "REDUCE"
        and finding.details.get("name") == f"code_{code}"
        and finding.details.get("opaque_extension") is True
        for finding in report.findings
    )


def test_scan_bytes_records_unresolved_copyreg_extension_without_reduce() -> None:
    report = scan_bytes(b"\x80\x04\x82\x01.", source="extension-ref.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "EXTENSION_REF"
        and finding.severity == Severity.WARNING
        and finding.details.get("opcode") == "EXT1"
        for finding in report.findings
    )


def test_scan_bytes_keeps_copyreg_extension_data_reference_suspicious() -> None:
    report = scan_bytes(b"\x80\x04\x82\x01\x85.", source="extension-data-ref.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "EXTENSION_REF" for finding in report.findings)
    assert all(finding.rule_code != "DANGEROUS_CALL" for finding in report.findings)


def test_scan_bytes_detects_follow_on_copyreg_extension_reduce() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4) + (b"\x00" * 256) + b"\x80\x04\x82\x01)R."

    report = scan_bytes(payload, source="follow-on-extension-reduce.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(notice.code == "follow_on_stream_detected" for notice in report.notices)
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("opaque_extension") is True
        for finding in report.findings
    )


def test_scan_bytes_detects_build_on_constructed_dangerous_global() -> None:
    payload = b"cos\nsystem\n)R}b."

    report = scan_bytes(payload, source="build-dangerous.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("opcode") == "BUILD"
        and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("payload", "opcode"),
    [
        (b"Pexternal-storage-key\n.", "PERSID"),
        (b"\x80\x04\x8c\x14external-storage-key\x94Q.", "BINPERSID"),
    ],
)
def test_scan_bytes_flags_untrusted_persistent_ids(payload: bytes, opcode: str) -> None:
    report = scan_bytes(payload, source="persistent-id.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == opcode for finding in report.findings
    )


def test_scan_bytes_recurses_into_nested_persid_payload() -> None:
    inner = b"\x80\x04cos\nsystem\nPfake_id\n."
    outer = pickle.dumps({"inner": inner}, protocol=4)

    report = scan_bytes(outer, source="nested-persid.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213" and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == "PERSID"
        for finding in report.findings
    )


def test_scan_bytes_continues_raw_nested_scan_after_data_only_payload() -> None:
    nested_bytes = b"AAAAAA\x80\x04}.BBBBBBcos\nsystem\n)R.CCCC"
    payload = b"\x80\x04B" + len(nested_bytes).to_bytes(4, "little") + nested_bytes + b"."

    report = scan_bytes(payload, source="nested-benign-before-malicious.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(notice.code == "nested_payload_detected" for notice in report.notices)
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("payload_size") == len(b"cos\nsystem\n)R.")
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


def test_scan_bytes_continues_encoded_nested_scan_after_data_only_payload() -> None:
    decoded = b"\x80\x04}." + b"cos\nsystem\n)R."
    payload = pickle.dumps(base64.b64encode(decoded).decode("ascii"), protocol=4)

    report = scan_bytes(payload, source="encoded-benign-before-malicious.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(notice.code == "encoded_nested_payload_detected" for notice in report.notices)
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("payload_size") == len(b"cos\nsystem\n)R.")
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x02T\x18\x00\x00\x00AAAAAAcos\nsystem\n)R.BBBB.",
        b"\x80\x02U\x18AAAAAAcos\nsystem\n)R.BBBB.",
        b"\x80\x02S'AAAAAAcos\\x0asystem\\x0a)R.BBBB'\n.",
    ],
    ids=["binstring", "short-binstring", "protocol0-string"],
)
def test_scan_bytes_scans_legacy_string_opcodes_for_raw_nested_payloads(payload: bytes) -> None:
    report = scan_bytes(payload, source="legacy-string-raw-nested.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("payload_size") == len(b"cos\nsystem\n)R.")
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


def test_scan_bytes_fails_closed_on_malformed_nested_persid_payload() -> None:
    inner = b"\x80\x04cos\nsystem\nP\nfake_id\n."
    outer = pickle.dumps({"inner": inner}, protocol=4)

    report = scan_bytes(outer, source="nested-malformed-persid.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("nested_has_execution_opcode") is True
        and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_scan_bytes_flags_canonical_pytorch_storage_persistent_ids() -> None:
    payload = (
        b"\x80\x04(\x8c\x07storage\x94\x8c\x05torch\x94\x8c\x0cFloatStorage\x94\x93\x8c\x01k\x94\x8c\x03cpu\x94K\x01tQ."
    )

    report = scan_bytes(payload, source="pytorch-storage.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == "BINPERSID"
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("pytorch_storage_key") == "k"
        for finding in report.findings
    )
    assert report.notices == ()


def test_scan_bytes_flags_noncanonical_pytorch_storage_persistent_ids() -> None:
    payload = b"\x80\x04(\x8c\x07storage\x94\x8c\x12torch.FloatStorage\x94\x8c\x04evil\x94\x8c\x03cpu\x94K\x01tQ."

    report = scan_bytes(payload, source="noncanonical-pytorch-storage.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == "BINPERSID"
        for finding in report.findings
    )
    assert report.notices == ()


def test_scan_bytes_flags_deeply_nested_persistent_id_preview() -> None:
    payload = b"\x80\x04)" + (b"\x85" * 1500) + b"Q."

    report = scan_bytes(payload, source="deep-persistent-id.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert report.errors == ()
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == "BINPERSID"
        for finding in report.findings
    )


def test_scan_bytes_flags_pytorch_storage_persistent_ids_with_bool_size() -> None:
    payload = (
        b"\x80\x04(\x8c\x07storage\x94\x8c\x05torch\x94\x8c\x0cFloatStorage\x94\x93\x8c\x01k\x94\x8c\x03cpu\x94\x88tQ."
    )

    report = scan_bytes(payload, source="bool-sized-pytorch-storage.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == "BINPERSID"
        for finding in report.findings
    )
    assert report.notices == ()


def test_scan_bytes_flags_pytorch_storage_persistent_ids_with_extra_fields() -> None:
    payload = (
        b"\x80\x04(\x8c\x07storage\x94\x8c\x05torch\x94\x8c\x0cFloatStorage\x94\x93"
        b"\x8c\x01k\x94\x8c\x03cpu\x94K\x01\x8c\x04evil\x94tQ."
    )

    report = scan_bytes(payload, source="extra-field-pytorch-storage.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("opcode") == "BINPERSID"
        for finding in report.findings
    )
    assert report.notices == ()


def test_scan_bytes_attributes_reduce_calls_to_the_callable_operand_not_nested_args() -> None:
    payload = b"cbuiltins\nlen\n(cos\nsystem\ntR."

    report = scan_bytes(payload, source="reduce-args.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )
    assert not any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("payload", "source"),
    [
        (b"cbuiltins\nlen\n}cos\nsystem\nK\x01s\x85R.", "setitem-args.pkl"),
        (b"cbuiltins\nlen\n}(cos\nsystem\nK\x01u\x85R.", "setitems-args.pkl"),
    ],
)
def test_scan_bytes_dict_mutation_operands_do_not_become_reduce_call_targets(payload: bytes, source: str) -> None:
    report = scan_bytes(payload, source=source)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )
    assert not any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("payload", "source"),
    [
        (b"\x80\x04cbuiltins\nlen\nq\x00cos\nsystem\n\x94h\x01\x8c\x04echo\x85R.", "memoize-after-put.pkl"),
        (b"\x80\x04cbuiltins\nlen\nqdcos\nsystem\n\x94h\x01\x8c\x04echo\x85R.", "memoize-after-sparse-put.pkl"),
    ],
)
def test_scan_bytes_memoize_index_uses_runtime_memo_size_after_explicit_memo_write(
    payload: bytes,
    source: str,
) -> None:
    report = scan_bytes(payload, source=source)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_scan_stream_uses_explicit_source_and_does_not_leak_prior_scan_state() -> None:
    scanner = PickleScanner()

    safe_report = scanner.scan_bytes(pickle.dumps({"safe": True}), source="safe.pkl")
    malicious_report = scanner.scan_stream(
        io.BytesIO(pickle.dumps(MaliciousPayload())),
        source="payload.pkl",
    )

    assert safe_report.source == "safe.pkl"
    assert malicious_report.source == "payload.pkl"
    assert malicious_report.verdict == SafetyVerdict.MALICIOUS
    assert all(
        finding.location is not None and "payload.pkl" in finding.location for finding in malicious_report.findings
    )


def test_scan_file_scans_strict_pickle_path(tmp_path: Path) -> None:
    payload_path = tmp_path / "safe.pkl"
    payload_path.write_bytes(pickle.dumps({"safe": True}))

    report = scan_file(payload_path)

    assert report.source == str(payload_path)
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.coverage.bytes_total == payload_path.stat().st_size


def test_scan_file_does_not_treat_suffix_only_zip_as_pytorch(tmp_path: Path) -> None:
    archive_path = tmp_path / "not-a-checkpoint.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"safe": True}, protocol=4))

    report = scan_file(archive_path)

    assert report.metadata.get("container_type") != "pytorch_zip"
    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN


def test_scan_file_scans_pytorch_zip_data_pickle(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    report = scan_file(archive_path)

    assert report.source == str(archive_path)
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.metadata["container_type"] == "pytorch_zip"
    assert list(report.metadata["pickle_files"]) == ["archive/data.pkl"]
    assert report.coverage.bytes_total == archive_path.stat().st_size
    assert report.coverage.bytes_scanned > 0


def test_scan_file_detects_hidden_pytorch_zip_pickle_member_with_data_pickle(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.pt"
    hidden_payload = b"cposix\nsystem\n(S'echo hidden'\ntR."
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
        archive.writestr("archive/payload", hidden_payload)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert list(report.metadata["pickle_files"]) == ["archive/data.pkl", "archive/payload"]
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.location is not None
        and f"{archive_path}:archive/payload" in finding.location
        for finding in report.findings
    )


def test_scan_file_does_not_route_benign_storage_blob_as_hidden_pickle(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
        archive.writestr("archive/data/0", b"\x00" * 1024)
        archive.writestr("archive/notes", b"cat is a category label, not a GLOBAL opcode stream")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert list(report.metadata["pickle_files"]) == ["archive/data.pkl"]


def test_scan_file_marks_hidden_pytorch_zip_probe_failure_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
        archive.writestr("archive/payload", b"maybe hidden")

    original_open = zipfile.ZipFile.open

    def fail_hidden_probe_open(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> object:
        member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
        if member_name == "archive/payload":
            raise NotImplementedError("unsupported compression method")
        return original_open(archive, name, mode=mode, pwd=pwd, force_zip64=force_zip64)

    monkeypatch.setattr(zipfile.ZipFile, "open", fail_hidden_probe_open)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.errors == ()
    assert list(report.metadata["pickle_files"]) == ["archive/data.pkl"]
    probe_notices = [notice for notice in report.notices if notice.code == "pytorch_zip_member_probe_failed"]
    assert len(probe_notices) == 1
    assert probe_notices[0].location == f"{archive_path}:archive/payload"
    assert probe_notices[0].details["analysis_incomplete"] is True
    assert probe_notices[0].details["exception_type"] == "NotImplementedError"


def test_scan_file_detects_malicious_pytorch_zip_data_pickle(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps(MaliciousPayload(), protocol=4))
        archive.writestr("version", "3\n")
        archive.writestr("byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert all(
        finding.location is not None and f"{archive_path}:data.pkl" in finding.location for finding in report.findings
    )


def test_scan_file_scans_pickle_members_without_data_pickle_in_pytorch_zip(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.bin"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("custom.pkl", pickle.dumps(MaliciousPayload(), protocol=4))
        archive.writestr("version", "3\n")
        archive.writestr("byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert list(report.metadata["pickle_files"]) == ["custom.pkl"]
    assert any(
        finding.location is not None and f"{archive_path}:custom.pkl" in finding.location for finding in report.findings
    )


def test_scan_file_returns_error_report_for_pytorch_zip_member_access_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "encrypted.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("version", "3\n")
        archive.writestr("byteorder", "little")

    original_open = zipfile.ZipFile.open

    def fail_member_open(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> object:
        member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
        if member_name == "data.pkl":
            raise RuntimeError("unsupported encrypted member")
        return original_open(archive, name, mode=mode, pwd=pwd, force_zip64=force_zip64)

    monkeypatch.setattr(zipfile.ZipFile, "open", fail_member_open)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert len(report.errors) == 1
    assert report.errors[0].category == "zip_error"
    assert report.errors[0].exception_type == "RuntimeError"
    assert report.errors[0].location == f"{archive_path}:data.pkl"


def test_scan_file_leaves_generic_data_pickle_zip_as_raw_pickle_input(tmp_path: Path) -> None:
    archive_path = tmp_path / "generic.jpg"
    entry = zipfile.ZipInfo("data.pkl", (1980, 1, 1, 0, 0, 0))
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(entry, pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    report = scan_file(archive_path)

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert "container_type" not in report.metadata


def test_scan_file_marks_oversized_pytorch_zip_member_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES", 4)
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("version", "3\n")
        archive.writestr("byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(notice.code == "pytorch_zip_member_size_limit" for notice in report.notices)


def test_scan_file_enforces_pytorch_zip_entry_cap_before_opening_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_ENTRIES", 2)
    archive_path = tmp_path / "entry-limit.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("version", "3\n")
        archive.writestr("byteorder", "little")

    class UnexpectedZipFile:
        def __init__(self, path: Path, mode: str) -> None:
            del path, mode
            raise AssertionError("entry limit should be enforced before ZipFile opens the archive")

    monkeypatch.setattr(package_api.zipfile, "ZipFile", UnexpectedZipFile)

    report = PickleScanner()._scan_pytorch_zip_file(
        archive_path,
        source=str(archive_path),
        size=archive_path.stat().st_size,
    )

    assert report is not None
    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    notices = [notice for notice in report.notices if notice.code == "pytorch_zip_entry_limit"]
    assert len(notices) == 1
    assert notices[0].details["analysis_incomplete"] is True
    assert notices[0].details["entry_count"] == 3
    assert notices[0].details["max_entries"] == 2


def test_scan_file_scans_pytorch_zip_member_partial_bytes_on_short_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "short-read.pt"
    archive_path.write_bytes(b"fake zip placeholder")
    payload = pickle.dumps(MaliciousPayload(), protocol=4)

    data_entry = zipfile.ZipInfo("data.pkl")
    data_entry.file_size = len(payload) + 8
    version_entry = zipfile.ZipInfo("version")
    version_entry.file_size = 2

    class ShortReadArchive:
        def __init__(self, path: Path, mode: str) -> None:
            self.path = path
            self.mode = mode

        def __enter__(self) -> ShortReadArchive:
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            return None

        def infolist(self) -> list[zipfile.ZipInfo]:
            return [data_entry, version_entry]

        def open(
            self,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> io.BytesIO:
            del mode, pwd, force_zip64
            member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if member_name == "data.pkl":
                return io.BytesIO(payload)
            return io.BytesIO(b"3\n")

    monkeypatch.setattr(package_api.zipfile, "ZipFile", ShortReadArchive)

    report = PickleScanner()._scan_pytorch_zip_file(
        archive_path,
        source=str(archive_path),
        size=archive_path.stat().st_size,
    )

    assert report is not None
    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert any(error.category == "short_read" for error in report.errors)
    assert report.metadata["container_type"] == "pytorch_zip"


def test_scan_file_returns_error_report_for_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.pkl"

    report = scan_file(missing_path)

    assert report.source == str(missing_path)
    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert len(report.errors) == 1
    assert report.errors[0].category == "io_error"
    assert report.errors[0].exception_type == "FileNotFoundError"
    assert report.coverage.bytes_scanned == 0
    assert report.coverage.bytes_total is None
    assert report.coverage.raw_scan_complete is False
    assert report.coverage.opcode_scan_complete is False


def test_scan_stream_returns_error_report_for_read_failures() -> None:
    report = PickleScanner().scan_stream(UnreadableStream(), source="broken-stream.pkl", size=16)

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert len(report.errors) == 1
    assert report.errors[0].category == "io_error"
    assert report.errors[0].exception_type == "OSError"
    assert report.coverage.bytes_scanned == 0
    assert report.coverage.bytes_total == 16
    assert report.coverage.raw_scan_complete is False
    assert report.coverage.opcode_scan_complete is False


def test_scan_stream_returns_error_report_for_runtime_read_failures() -> None:
    report = PickleScanner().scan_stream(RuntimeFailingStream(), source="broken-stream.pkl", size=16)

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert len(report.errors) == 1
    assert report.errors[0].category == "io_error"
    assert report.errors[0].exception_type == "RuntimeError"
    assert report.coverage.bytes_scanned == 0
    assert report.coverage.bytes_total == 16


def test_scan_stream_returns_empty_input_error_for_empty_unknown_size_stream() -> None:
    report = PickleScanner().scan_stream(io.BytesIO(b""), source="empty-stream.pkl")

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert len(report.errors) == 1
    assert report.errors[0].category == "empty_input"
    assert report.coverage.bytes_scanned == 0
    assert report.coverage.bytes_total is None
    assert report.coverage.raw_scan_complete is False
    assert report.coverage.opcode_scan_complete is False


def test_scan_stream_treats_negative_size_as_unknown_size() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    report = PickleScanner().scan_stream(io.BytesIO(payload), source="unknown-size.pkl", size=-1)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.errors == ()
    assert report.coverage.bytes_total is None
    assert report.coverage.bytes_scanned == len(payload)


def test_native_payload_scan_normalizes_negative_private_size_guard() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    report = package_api._scan_pickle_payload_native(
        payload,
        source="private-negative-size.pkl",
        options=ScanOptions(),
        bytes_total=-1,
        position_offset=-5,
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.errors == ()
    assert report.coverage.bytes_total is None
    assert report.coverage.bytes_scanned == len(payload)


def test_scan_stream_fails_closed_on_short_reads_for_expected_size() -> None:
    payload = pickle.dumps({"safe": True})
    expected_size = len(payload) + 8

    report = PickleScanner().scan_stream(
        io.BytesIO(payload),
        source="truncated-stream.pkl",
        size=expected_size,
    )

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert len(report.errors) == 1
    assert report.errors[0].category == "short_read"
    assert report.coverage.bytes_scanned == len(payload)
    assert report.coverage.bytes_total == expected_size
    assert report.coverage.raw_scan_complete is False
    assert report.coverage.opcode_scan_complete is False


def test_scan_stream_scans_partial_bytes_on_short_read() -> None:
    payload = pickle.dumps(MaliciousPayload(), protocol=4)
    expected_size = len(payload) + 8

    report = PickleScanner().scan_stream(
        io.BytesIO(payload),
        source="malicious-short-read.pkl",
        size=expected_size,
    )

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert any(error.category == "short_read" for error in report.errors)
    assert report.metadata["stream_short_read"] is True
    assert report.coverage.bytes_scanned == len(payload)
    assert report.coverage.bytes_total == expected_size


def test_scan_stream_incrementally_reads_bounded_streams_without_preloading_entire_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pickle.dumps(list(range(512)), protocol=4)
    stream = NoBulkReadStream(payload, max_read_size=32)
    monkeypatch.setattr(package_api, "_RUST_STREAM_READ_CHUNK_SIZE", 32)

    report = PickleScanner().scan_stream(stream, source="chunked.pkl", size=len(payload))

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.coverage.bytes_scanned == len(payload)
    assert stream.max_seen_read_size <= 32


def test_scan_stream_honors_explicit_reads_without_declared_size() -> None:
    payload = pickle.dumps(b"a" * 64, protocol=4)

    report = PickleScanner(ScanOptions(max_unbounded_stream_read_bytes=len(payload) + 1)).scan_stream(
        io.BytesIO(payload),
        source="unknown-size-binbytes.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.errors == ()
    assert report.coverage.bytes_scanned == len(payload)


def test_scan_stream_allows_unknown_size_stream_at_exact_total_cap() -> None:
    payload = pickle.dumps(b"a" * 64, protocol=4)

    report = PickleScanner(ScanOptions(max_unbounded_stream_read_bytes=len(payload))).scan_stream(
        io.BytesIO(payload),
        source="unknown-size-exact-cap.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.errors == ()
    assert report.coverage.bytes_scanned == len(payload)


def test_scan_stream_enforces_total_unbounded_stream_read_limit() -> None:
    payload = pickle.dumps(b"a" * 64, protocol=4)

    report = PickleScanner(ScanOptions(max_unbounded_stream_read_bytes=8)).scan_stream(
        io.BytesIO(payload),
        source="unknown-size-over-limit.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not any(error.category == "io_error" for error in report.errors)
    assert any(notice.code == "unbounded_stream_truncated" for notice in report.notices)


def test_scan_stream_does_not_overflow_probe_non_seekable_unknown_size_streams() -> None:
    payload = pickle.dumps(b"a" * 64, protocol=4)
    stream = NonSeekableExactLimitStream(payload, limit=8)

    report = PickleScanner(ScanOptions(max_unbounded_stream_read_bytes=8)).scan_stream(
        stream,
        source="unknown-size-nonseek-exact-cap.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert not any(error.category == "io_error" for error in report.errors)
    assert any(notice.code == "unbounded_stream_truncated" for notice in report.notices)


def test_scan_stream_enforces_total_known_stream_read_limit() -> None:
    payload = pickle.dumps(b"a" * 64, protocol=4)
    stream = NoBulkReadStream(payload, max_read_size=8)

    report = PickleScanner(ScanOptions(max_known_stream_read_bytes=8)).scan_stream(
        stream,
        source="known-size-over-limit.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not any(error.category == "io_error" for error in report.errors)
    notice = next(notice for notice in report.notices if notice.code == "known_stream_truncated")
    assert notice.details["bytes_scanned"] == 8
    assert report.coverage.bytes_total == len(payload)
    assert stream.max_seen_read_size <= 8


def test_scan_stream_known_size_cap_does_not_report_native_short_read() -> None:
    pickle_prefix = pickle.dumps({"safe": True}, protocol=4)
    payload = pickle_prefix + (b"ignored-tail" * 8)

    report = PickleScanner(ScanOptions(max_known_stream_read_bytes=len(pickle_prefix))).scan_stream(
        io.BytesIO(payload),
        source="known-size-complete-prefix.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.errors == ()
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)
    assert report.coverage.bytes_scanned == len(pickle_prefix)
    assert report.coverage.bytes_total == len(payload)


def test_scan_stream_bounds_protocol_zero_readline_without_declared_size() -> None:
    stream = NoUnboundedReadlineStream(b"S'" + (b"a" * 64))

    report = PickleScanner(ScanOptions(max_unbounded_stream_read_bytes=8)).scan_stream(
        stream,
        source="unterminated-protocol-zero.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not any(error.category == "io_error" for error in report.errors)
    assert any(notice.code == "unbounded_stream_truncated" for notice in report.notices)
    assert stream.unbounded_readline_attempted is False
    assert stream.max_seen_readline_size <= 8


def test_scan_options_rejects_invalid_unbounded_stream_read_limit() -> None:
    with pytest.raises(ValueError, match="max_unbounded_stream_read_bytes"):
        ScanOptions(max_unbounded_stream_read_bytes=0)


def test_scan_options_rejects_invalid_known_stream_read_limit() -> None:
    with pytest.raises(ValueError, match="max_known_stream_read_bytes"):
        ScanOptions(max_known_stream_read_bytes=0)


def test_scan_bytes_flags_malformed_stack_global_operands() -> None:
    payload = b"\x80\x04K\x01K\x02\x93."

    report = scan_bytes(payload, source="malformed-stack-global.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "MALFORMED_STACK_GLOBAL" for finding in report.findings)


def test_scan_bytes_reports_parse_errors_without_security_findings() -> None:
    report = scan_bytes(b"not a pickle", source="bad.bin")

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert len(report.errors) == 1
    assert report.errors[0].category == "parse_error"


def test_scan_bytes_reports_inconclusive_status_when_opcode_budget_is_reached() -> None:
    payload = pickle.dumps([1, 2, 3, 4, 5], protocol=4)
    report = scan_bytes(payload, source="budget.pkl", options=ScanOptions(max_opcodes=2))

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert any(notice.code == "opcode_budget" for notice in report.notices)


def test_scan_bytes_post_budget_tail_starts_at_budget_boundary() -> None:
    payload = b"\x80\x04cos\nsystem\n."

    report = scan_bytes(payload, source="budget-tail.pkl", options=ScanOptions(max_opcodes=1))

    assert report.status == ScanStatus.INCONCLUSIVE
    assert any(finding.rule_code == "POST_BUDGET_GLOBAL" for finding in report.findings)


def test_scan_bytes_post_budget_tail_handles_stack_global_at_boundary() -> None:
    payload = b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93."

    report = scan_bytes(payload, source="budget-stack-global.pkl", options=ScanOptions(max_opcodes=5))

    assert report.status == ScanStatus.INCONCLUSIVE
    assert any(finding.rule_code == "POST_BUDGET_GLOBAL" for finding in report.findings)


def test_scan_bytes_post_budget_tail_detects_default_protocol_stack_global() -> None:
    payload = b"\x80\x04\x88\x88" + pickle.dumps(MaliciousPayload(), protocol=4)[2:]

    report = scan_bytes(
        payload,
        source="budget-default-protocol-stack-global.pkl",
        options=ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and f"{finding.details.get('module')}.{finding.details.get('name')}" in SYSTEM_GLOBALS
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "payload_suffix",
    [
        b"S'sub\\x70rocess'\nS'run'\n\x93)R.",
        b"Vsub\\u0070rocess\nVrun\n\x93)R.",
    ],
    ids=["string-escape", "unicode-escape"],
)
def test_scan_bytes_post_budget_tail_detects_protocol0_stack_global(payload_suffix: bytes) -> None:
    payload = b"\x80\x04\x88\x88" + payload_suffix

    report = scan_bytes(
        payload,
        source="budget-protocol0-stack-global.pkl",
        options=ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
        for finding in report.findings
    )


def test_scan_bytes_post_budget_tail_detects_prememoized_stack_global() -> None:
    payload = _make_pre_memoized_post_budget_stack_global_payload(b"h\x00h\x01\x93)R.")

    report = scan_bytes(
        payload,
        source="budget-prememo-stack-global.pkl",
        options=ScanOptions(max_opcodes=7, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "tail",
    [
        b"h\x00" + _short_binunicode(b"run") + b"\x93)R.",
        _short_binunicode(b"subprocess") + b"h\x01\x93)R.",
        b"h\x00U\x03run\x93)R.",
        b"h\x00S'run'\n\x93)R.",
        b"S'subprocess'\nh\x01\x93)R.",
    ],
    ids=[
        "memo-module-inline-name",
        "inline-module-memo-name",
        "memo-module-short-binstring-name",
        "memo-module-protocol0-name",
        "protocol0-module-memo-name",
    ],
)
def test_scan_bytes_post_budget_tail_detects_mixed_prememoized_stack_global(tail: bytes) -> None:
    payload = _make_pre_memoized_post_budget_stack_global_payload(tail)

    report = scan_bytes(
        payload,
        source="budget-prememo-mixed-stack-global.pkl",
        options=ScanOptions(max_opcodes=7, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "tail",
    [
        b"h\x00h\x0120\x93)R.",
        b"h\x00(0h\x01\x93)R.",
        b"h\x00N0h\x01\x93)R.",
    ],
    ids=["dup-pop", "mark-pop", "none-pop"],
)
def test_scan_bytes_post_budget_tail_detects_interleaved_prememoized_stack_global(tail: bytes) -> None:
    payload = _make_pre_memoized_post_budget_stack_global_payload(tail)

    report = scan_bytes(
        payload,
        source="budget-prememo-interleaved-stack-global.pkl",
        options=ScanOptions(max_opcodes=7, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "tail",
    [
        _short_binunicode(b"subprocess") + b"q\x05" + _short_binunicode(b"run") + b"q\x06h\x05h\x06\x93)R.",
        _short_binunicode(b"subprocess") + b"p5\n" + _short_binunicode(b"run") + b"p6\ng5\ng6\n\x93)R.",
        _short_binunicode(b"subprocess") + b"\x94" + _short_binunicode(b"run") + b"\x94h\x00h\x01\x93)R.",
    ],
    ids=["binput-binget", "put-get", "memoize-binget"],
)
def test_scan_bytes_post_budget_tail_tracks_tail_local_memo_writes(tail: bytes) -> None:
    payload = b"\x80\x04\x88" + tail

    report = scan_bytes(
        payload,
        source="budget-tail-local-memo-stack-global.pkl",
        options=ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
        for finding in report.findings
    )


def test_scan_bytes_handles_multiple_pickle_streams() -> None:
    payload = pickle.dumps({"a": 1}, protocol=4) + pickle.dumps(MaliciousPayload(), protocol=4)

    report = scan_bytes(payload, source="stacked.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.coverage.bytes_scanned == len(payload)


def test_scan_bytes_flags_suspicious_exec_string_literals() -> None:
    report = scan_bytes(
        pickle.dumps({"code": "exec('import os; os.system(\"ls\")')"}),
        source="string-payload.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "SUSPICIOUS_STRING" and "exec(" in finding.message for finding in report.findings)


def test_scan_bytes_allows_common_dunder_metadata_literals() -> None:
    report = scan_bytes(
        pickle.dumps(
            {
                "__version__": "1.0.0",
                "__metadata__": {"format": "safe"},
                "__schema__": "model-card-v1",
                "__name__": "example-model",
                "__dict__": {"shape": "metadata"},
                "__slots__": ("weight", "bias"),
                "__module__": "example",
                "__qualname__": "Example",
                "__annotations__": {"weight": "Tensor"},
            }
        ),
        source="dunder-metadata.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "SUSPICIOUS_STRING" for finding in report.findings)


def test_scan_bytes_allows_benign_security_documentation_strings() -> None:
    report = scan_bytes(
        pickle.dumps(
            {
                "doc": [
                    "Do not call os.system(command) from model loading code.",
                    "subprocess.run(args) is documented here as a blocked API.",
                    "An import statement loads a module.",
                    "importlib.import_module(name) is referenced in Python docs.",
                    "base64.b64decode(data) decodes text but is not executed here.",
                    r"The bytes are written as \x80 in the file format reference.",
                    "https://example.invalid/docs/os.system is a URL path, not code.",
                    "__reduce__ is a pickle protocol hook.",
                ]
            },
            protocol=4,
        ),
        source="security-docs.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("literal", ["__a__", "__x_y__"])
def test_scan_bytes_allows_user_defined_dunder_metadata_literals(literal: str) -> None:
    report = scan_bytes(pickle.dumps({"metadata": literal}, protocol=4), source="user-dunder.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize(
    ("literal", "expected_pattern"),
    [
        ("os.popen('id')", "os.popen"),
        ("subprocess.run(['id'])", "subprocess call"),
        ("getattr(os, 'system')('id')", "getattr system"),
        ("base64.b64decode(blob)", "base64.b64decode"),
        ("joblib.load(path)", "pickle loader call"),
        ("cloudpickle.loads(blob)", "pickle loader call"),
        ("copyreg.add_extension(module, name, code)", "copyreg extension"),
    ],
)
def test_scan_bytes_flags_expanded_suspicious_string_patterns(literal: str, expected_pattern: str) -> None:
    report = scan_bytes(pickle.dumps({"code": literal}), source="string-pattern.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "SUSPICIOUS_STRING" and finding.details.get("pattern") == expected_pattern
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("literal", "pattern"),
    [
        (b"os.system('id')", "base64 os.system"),
        (b"eval(x)", "base64 eval("),
    ],
)
def test_scan_bytes_flags_base64_encoded_code_string_literals(literal: bytes, pattern: str) -> None:
    encoded = base64.b64encode(literal).decode("ascii")

    report = scan_bytes(pickle.dumps({"code": encoded}), source="encoded-code-string.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "SUSPICIOUS_STRING" and finding.details.get("pattern") == pattern
        for finding in report.findings
    )


def test_scan_bytes_can_decode_stack_global_from_memoized_operands() -> None:
    payload = b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94h\x00h\x01\x93."

    report = scan_bytes(payload, source="stack-global.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any("posix.system" in finding.message for finding in report.findings)


def test_scan_bytes_warns_on_functools_partial_without_marking_benign_partial_malicious() -> None:
    payload = pickle.dumps(functools.partial(int, base=10), protocol=4)

    report = scan_bytes(payload, source="partial.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code in {"DANGEROUS_CALL", "DANGEROUS_GLOBAL"}
        and finding.severity.value == "warning"
        and finding.details.get("import_reference") == "functools.partial"
        for finding in report.findings
    )
    assert not any(finding.severity.value == "critical" for finding in report.findings)


def test_scan_bytes_does_not_flag_dill_dump_as_dangerous() -> None:
    payload = b"\x80\x02cdill\ndump\n(tR."

    report = scan_bytes(payload, source="dill-dump.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_flags_dill_loads_as_dangerous() -> None:
    payload = b"cdill\nloads\n."

    report = scan_bytes(payload, source="dill-loads.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "dill.loads"
        for finding in report.findings
    )


def test_scan_bytes_flags_dill_load_as_dangerous() -> None:
    payload = b"cdill\nload\n."

    report = scan_bytes(payload, source="dill-load.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "dill.load"
        for finding in report.findings
    )


@pytest.mark.parametrize("helper", ["load_module", "load_session"])
def test_scan_bytes_flags_dill_loader_helpers_as_dangerous(helper: str) -> None:
    payload = f"cdill\n{helper}\n.".encode()

    report = scan_bytes(payload, source=f"dill-{helper}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == f"dill.{helper}"
        for finding in report.findings
    )


def test_scan_bytes_allows_benign_dill_text_literal() -> None:
    payload = pickle.dumps({"note": "dill is mentioned in documentation only"}, protocol=4)

    report = scan_bytes(payload, source="dill-note.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (b"cbase64\nb64decode\n(tR.", "base64.b64decode"),
        (b"cbase64\nb64encode\n(tR.", "base64.b64encode"),
        (b"cbase64\ndecode\n(tR.", "base64.decode"),
        (b"ccodecs\ndecode\n(tR.", "codecs.decode"),
        (b"ccodecs\nencode\n(tR.", "codecs.encode"),
        (b"cpip\nmain\n(tR.", "pip.main"),
        (b"cnumpy\nload\n(tR.", "numpy.load"),
        (b"cshutil\nrmtree\n(tR.", "shutil.rmtree"),
        (b"ctarfile\nopen\n(tR.", "tarfile.open"),
        (b"cwebbrowser\nopen\n(tR.", "webbrowser.open"),
        (b"czipfile\nZipFile\n(tR.", "zipfile.ZipFile"),
        (b"cbuiltins\nglobals\n(tR.", "builtins.globals"),
        (b"csmtplib\nSMTP\n(tR.", "smtplib.SMTP"),
        (b"chttplib\nHTTPConnection\n(tR.", "httplib.HTTPConnection"),
        (b"csqlite3\nconnect\n(tR.", "sqlite3.connect"),
        (b"cmarshal\nloads\n(tR.", "marshal.loads"),
        (b"ccloudpickle\nload\n(tR.", "cloudpickle.load"),
        (b"ccloudpickle\nloads\n(tR.", "cloudpickle.loads"),
        (b"cpkgutil\nresolve_name\n(tR.", "pkgutil.resolve_name"),
    ],
)
def test_scan_bytes_flags_expanded_high_risk_callables(payload: bytes, expected_reference: str) -> None:
    report = scan_bytes(payload, source=f"{expected_reference}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )


def test_scan_bytes_flags_newobj_ex_dangerous_class() -> None:
    payload = b"\x80\x04cos\nsystem\n)}\x92."

    report = scan_bytes(payload, source="newobj-ex.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("opcode") == "NEWOBJ_EX"
        and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (
            pickle.dumps(uuid.UUID("12345678-1234-5678-1234-567812345678"), protocol=4),
            "uuid.UUID",
        ),
        (b"clogging\ngetLogger\n.", "logging.getLogger"),
        (b"ctempfile\nNamedTemporaryFile\n.", "tempfile.NamedTemporaryFile"),
        (pickle.dumps(tarfile.TarInfo("weights.bin"), protocol=4), "tarfile.TarInfo"),
        (pickle.dumps(zipfile.ZipInfo("weights.bin"), protocol=4), "zipfile.ZipInfo"),
    ],
)
def test_scan_bytes_does_not_treat_benign_stdlib_module_references_as_dangerous(
    payload: bytes, expected_reference: str
) -> None:
    report = scan_bytes(payload, source=f"{expected_reference}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        ref["import_reference"] == expected_reference and ref["is_dangerous"] is False
        for ref in report.metadata["import_references"]
    )


@pytest.mark.parametrize(
    ("payload", "expected_reference", "expected_severity", "expected_verdict"),
    [
        (
            b"cuuid\n_get_command_stdout\n(tR.",
            "uuid._get_command_stdout",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\n_popen\n(tR.",
            "uuid._popen",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\n_ifconfig_getnode\n(tR.",
            "uuid._ifconfig_getnode",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\n_ip_getnode\n(tR.",
            "uuid._ip_getnode",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\n_arp_getnode\n(tR.",
            "uuid._arp_getnode",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\n_lanscan_getnode\n(tR.",
            "uuid._lanscan_getnode",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\n_netstat_getnode\n(tR.",
            "uuid._netstat_getnode",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cuuid\ngetnode\n(tR.",
            "uuid.getnode",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cctypes\nCDLL\n(tR.",
            "ctypes.CDLL",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cctypes\ncast\n(tR.",
            "ctypes.cast",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"ccProfile\nrun\n(tR.",
            "cProfile.run",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cpdb\nrun\n(tR.",
            "pdb.run",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"ctimeit\ntimeit\n(tR.",
            "timeit.timeit",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"cprofile\nrun\n(tR.",
            "profile.run",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"c_thread\nallocate_lock\n(tR.",
            "_thread.allocate_lock",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"clinecache\ngetline\n(tR.",
            "linecache.getline",
            Severity.WARNING,
            SafetyVerdict.SUSPICIOUS,
        ),
        (
            b"clogging.config\nfileConfig\n(tR.",
            "logging.config.fileConfig",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"clogging.config\ndictConfig\n(tR.",
            "logging.config.dictConfig",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"clogging.config\nlisten\n(tR.",
            "logging.config.listen",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"czipimport\nzipimporter\n(tR.",
            "zipimport.zipimporter",
            Severity.CRITICAL,
            SafetyVerdict.MALICIOUS,
        ),
        (
            b"ctempfile\nmktemp\n(tR.",
            "tempfile.mktemp",
            Severity.WARNING,
            SafetyVerdict.SUSPICIOUS,
        ),
    ],
)
def test_scan_bytes_keeps_exact_risky_stdlib_functions_flagged(
    payload: bytes,
    expected_reference: str,
    expected_severity: Severity,
    expected_verdict: SafetyVerdict,
) -> None:
    report = scan_bytes(payload, source=f"{expected_reference}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == expected_verdict
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == expected_severity
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )


def test_scan_bytes_flags_private_dill_constructors_as_dangerous() -> None:
    payload = b"\x80\x02cdill._dill\n_create_function\n)R."

    report = scan_bytes(payload, source="dill-create-function.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "dill._dill._create_function"
        for finding in report.findings
    )


def test_scan_bytes_resolves_short_binstring_stack_global_operands() -> None:
    payload = b"\x80\x04U\x0bcollectionsU\x0bOrderedDict\x93."

    report = scan_bytes(payload, source="ordered-dict.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert report.to_dict()["metadata"]["import_references"] == [
        {
            "import_reference": "collections.OrderedDict",
            "module": "collections",
            "name": "OrderedDict",
            "opcode": "STACK_GLOBAL",
            "position": 28,
            "is_dangerous": False,
        }
    ]


def test_scan_bytes_warns_on_main_module_global_references() -> None:
    payload = b"\x80\x04\x8c\x08__main__\x94\x8c\x0aCustomType\x94\x93."

    report = scan_bytes(payload, source="custom-main.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "S203"
        and finding.severity.value == "warning"
        and finding.details.get("import_reference") == "__main__.CustomType"
        for finding in report.findings
    )


def test_scan_bytes_does_not_scan_raw_binbytes_payloads_as_text_strings() -> None:
    # Opaque tensor byte blobs are probed for nested pickle streams, but are not
    # decoded as source text in the standalone package; root ModelAudit raw
    # detectors own non-pickle text scanning on bounded file windows.
    payload = pickle.dumps({"blob": b"A" * 256 + b"subprocess.run exec("}, protocol=4)

    report = scan_bytes(payload, source="tensor-bytes.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_records_data_only_raw_nested_pickle_payloads_as_notices() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="nested-raw.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == "nested_payload_detected"
        and notice.details.get("encoding") == "raw"
        and notice.details.get("nested_has_execution_opcode") is False
        for notice in report.notices
    )


@pytest.mark.parametrize(
    "inner_obj",
    [
        datetime.datetime(2024, 1, 2, 3, 4, 5),
        datetime.timedelta(days=2, seconds=3),
        decimal.Decimal("12.34"),
        uuid.UUID("12345678-1234-5678-1234-567812345678"),
        collections.OrderedDict([("a", 1), ("b", 2)]),
        collections.Counter("abcaba"),
        PurePosixPath("/tmp/model.bin"),
        re.compile(r"a+b?"),
        slice(1, 10, 2),
        range(10),
    ],
)
@pytest.mark.parametrize("encoding", ["raw", "base64", "hex"])
def test_scan_bytes_treats_benign_nested_constructor_pickles_as_notices(
    inner_obj: object,
    encoding: str,
) -> None:
    nested_payload = pickle.dumps(inner_obj, protocol=4)
    if encoding == "raw":
        outer_value: bytes | str = nested_payload
        expected_notice = "nested_payload_detected"
    elif encoding == "base64":
        outer_value = base64.b64encode(nested_payload).decode("ascii")
        expected_notice = "encoded_nested_payload_detected"
    else:
        outer_value = binascii.hexlify(nested_payload).decode("ascii")
        expected_notice = "encoded_nested_payload_detected"

    report = scan_bytes(
        pickle.dumps({"outer": outer_value}, protocol=4),
        source=f"benign-nested-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == expected_notice
        and notice.details.get("encoding") == encoding
        and notice.details.get("nested_has_execution_opcode") is True
        for notice in report.notices
    )


@pytest.mark.parametrize("encoding", ["raw", "base64", "hex"])
def test_scan_bytes_does_not_escalate_warning_only_nested_payloads_to_critical(
    encoding: str,
) -> None:
    nested_payload = pickle.dumps(functools.partial(int, base=10), protocol=4)
    if encoding == "raw":
        outer_value: bytes | str = nested_payload
    elif encoding == "base64":
        outer_value = base64.b64encode(nested_payload).decode("ascii")
    else:
        outer_value = binascii.hexlify(nested_payload).decode("ascii")

    report = scan_bytes(
        pickle.dumps({"outer": outer_value}, protocol=4),
        source=f"warning-only-nested-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert not any(finding.severity == Severity.CRITICAL for finding in report.findings)
    assert not any(finding.rule_code in {"S213", "S601", "S602"} for finding in report.findings)
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.WARNING
        and finding.details.get("import_reference") == "functools.partial"
        for finding in report.findings
    )


@pytest.mark.parametrize("encoding", ["raw", "base64", "hex"])
def test_scan_bytes_flags_unclassified_nested_execution_callables(encoding: str) -> None:
    nested_payload = b"\x80\x04cbuiltins\nprint\n\x8c\x0bnested ping\x85R."
    if encoding == "raw":
        outer_value: bytes | str = nested_payload
        expected_rule_code = "S213"
    elif encoding == "base64":
        outer_value = base64.b64encode(nested_payload).decode("ascii")
        expected_rule_code = "S601"
    else:
        outer_value = binascii.hexlify(nested_payload).decode("ascii")
        expected_rule_code = "S602"

    report = scan_bytes(
        pickle.dumps({"outer": outer_value}, protocol=4),
        source=f"unclassified-nested-execution-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == expected_rule_code and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )


def test_scan_bytes_records_data_only_raw_nested_pickle_hidden_inside_large_literal_as_notice() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = b"A" * 64 + nested_payload + b"B" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-raw-nested.pkl",
        options=ScanOptions(max_nested_pickle_bytes=len(nested_payload) + 16),
    )

    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(notice.code == "nested_payload_detected" for notice in report.notices)


def test_scan_bytes_ignores_invalid_raw_nested_pickle_near_match_hidden_inside_large_literal() -> None:
    nested_payload = _corrupt_first_byte(pickle.dumps({"inner": "data"}, protocol=4))
    hidden_payload = b"A" * 64 + nested_payload + b"B" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-raw-nested-near-match.pkl",
        options=ScanOptions(max_nested_pickle_bytes=len(nested_payload) + 16),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "S213" for finding in report.findings)


def test_scan_bytes_surfaces_nested_pickle_inner_findings() -> None:
    nested_payload = pickle.dumps(MaliciousPayload(), protocol=4)

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="nested-malicious.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.message.startswith("Nested pickle finding:")
        and finding.details.get("nested_encoding") == "raw"
        and finding.details.get("nested_details", {}).get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_scan_bytes_surfaces_deep_nested_pickle_findings_without_parse_incomplete() -> None:
    deepest_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    nested_payload = pickle.dumps({"middle": deepest_payload}, protocol=4)

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="deep-nested-malicious.pkl",
        options=ScanOptions(max_nested_depth=2),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert not any(
        notice.code == "parse_incomplete" and notice.details.get("exception_type") == "TypeError"
        for notice in report.notices
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.message.startswith("Nested pickle finding: Nested pickle finding:")
        and finding.details.get("nested_details", {}).get("nested_details", {}).get("import_reference")
        in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_scan_bytes_default_depth_surfaces_two_layer_encoded_nested_findings() -> None:
    deepest_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    nested_payload = pickle.dumps(
        {"middle": base64.b64encode(deepest_payload).decode("ascii")},
        protocol=4,
    )
    outer_payload = pickle.dumps(
        {"outer": base64.b64encode(nested_payload).decode("ascii")},
        protocol=4,
    )

    report = scan_bytes(outer_payload, source="default-deep-encoded-nested.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.message.startswith("Nested pickle finding: Nested pickle finding:")
        and finding.details.get("nested_details", {}).get("nested_details", {}).get("import_reference")
        in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_scan_bytes_marks_parent_inconclusive_when_nested_analysis_is_incomplete() -> None:
    nested_payload = pickle.dumps({"code": "A" * 128}, protocol=4)

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="nested-incomplete.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)
    assert any(
        notice.code == "nested_pickle_incomplete"
        and notice.details.get("nested_status") == ScanStatus.INCONCLUSIVE.value
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


def test_scan_bytes_flags_oversized_nested_pickle_prefix_without_deep_parse() -> None:
    nested_payload = b"\x80\x04]K\x01aK\x02aK\x03aK\x04a"

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="nested-oversized.pkl",
        options=ScanOptions(max_nested_pickle_bytes=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert report.is_clean is False
    assert report.coverage.opcode_scan_complete is False
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("analysis_incomplete") is True
        and finding.details.get("payload_size") == len(nested_payload)
        for finding in report.findings
    )
    assert any(
        notice.code == "nested_payload_truncated"
        and notice.details.get("encoding") == "raw"
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


@pytest.mark.parametrize(
    "opaque_blob",
    [
        b"A" * 64 + b"\x80\x04" + (b"\xff" * 64),
        b"A" * 64 + b"i\x69\xb2\x09\x48\xbe\x7d\x02\x6b\x23\x5f\xe0\xf7\x0a\x8a\x5c\x77",
    ],
)
def test_scan_bytes_ignores_invalid_pickle_prefix_inside_opaque_bytes(opaque_blob: bytes) -> None:
    report = scan_bytes(
        pickle.dumps({"outer": opaque_blob}, protocol=4),
        source="opaque-random-bytes.pkl",
        options=ScanOptions(max_nested_pickle_bytes=8),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize("fragment", [b"q\x00.", b"t.", b"cfoo\nbar\n0."])
def test_scan_bytes_does_not_flag_stack_invalid_nested_pickle_fragments(fragment: bytes) -> None:
    report = scan_bytes(pickle.dumps({"outer": fragment}, protocol=4), source="nested-fragment.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "S213" for finding in report.findings)


@pytest.mark.parametrize("fragment", [b"q\x00.", b"t.", b"cfoo\nbar\n0."])
def test_scan_bytes_does_not_flag_stack_invalid_encoded_pickle_fragments(fragment: bytes) -> None:
    encoded = base64.b64encode(fragment).decode("ascii")
    report = scan_bytes(pickle.dumps({"outer": encoded}, protocol=4), source="nested-fragment.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "S601" for finding in report.findings)


def test_scan_bytes_records_data_only_base64_nested_pickle_payloads_as_notices() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": base64.b64encode(nested_payload).decode("ascii")}, protocol=4),
        source="nested-base64.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == "encoded_nested_payload_detected"
        and notice.details.get("encoding") == "base64"
        and notice.details.get("nested_has_execution_opcode") is False
        for notice in report.notices
    )


def test_scan_bytes_detects_comment_wrapped_base64_nested_pickle_payloads() -> None:
    nested_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    encoded = base64.b64encode(nested_payload).decode("ascii")
    wrapped = f"# this is doc\n# {encoded[:12]}\n# {encoded[12:]}\n# more"

    report = scan_bytes(
        pickle.dumps({"outer": wrapped}, protocol=4),
        source="wrapped-base64-nested.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S601" for finding in report.findings)
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("nested_encoding") == "base64"
        and finding.details.get("nested_details", {}).get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_scan_bytes_records_data_only_base64_nested_pickle_hidden_inside_large_literal_as_notice() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = "A" * 64 + base64.b64encode(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-base64-nested.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(notice.code == "encoded_nested_payload_detected" for notice in report.notices)
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_ignores_invalid_base64_nested_pickle_near_match_hidden_inside_large_literal() -> None:
    nested_payload = _corrupt_first_byte(pickle.dumps({"inner": "data"}, protocol=4))
    hidden_payload = "A" * 64 + base64.b64encode(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-base64-nested-near-match.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_records_data_only_hex_nested_pickle_payloads_as_notices() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": binascii.hexlify(nested_payload).decode("ascii")}, protocol=4),
        source="nested-hex.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == "encoded_nested_payload_detected"
        and notice.details.get("encoding") == "hex"
        and notice.details.get("nested_has_execution_opcode") is False
        for notice in report.notices
    )


def test_scan_bytes_records_data_only_hex_nested_pickle_hidden_inside_large_literal_as_notice() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = "A" * 64 + binascii.hexlify(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-hex-nested.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(notice.code == "encoded_nested_payload_detected" for notice in report.notices)
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_ignores_invalid_hex_nested_pickle_near_match_hidden_inside_large_literal() -> None:
    nested_payload = _corrupt_first_byte(pickle.dumps({"inner": "data"}, protocol=4))
    hidden_payload = "A" * 64 + binascii.hexlify(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-hex-nested-near-match.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_records_data_only_escaped_hex_nested_pickle_payloads_as_notices() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    escaped_hex_payload = "".join(f"\\x{byte:02x}" for byte in nested_payload)

    report = scan_bytes(
        pickle.dumps({"outer": escaped_hex_payload}, protocol=4),
        source="nested-escaped-hex.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == "encoded_nested_payload_detected"
        and notice.details.get("encoding") == "escaped_hex"
        and notice.details.get("nested_has_execution_opcode") is False
        for notice in report.notices
    )


def test_scan_bytes_applies_nested_byte_budget_after_unescaping_hex_literals() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    escaped_hex_payload = "".join(f"\\x{byte:02x}" for byte in nested_payload)

    report = scan_bytes(
        pickle.dumps({"outer": escaped_hex_payload}, protocol=4),
        source="nested-escaped-hex-budget.pkl",
        options=ScanOptions(max_nested_pickle_bytes=len(nested_payload)),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == "encoded_nested_payload_detected"
        and notice.details.get("encoding") == "escaped_hex"
        and notice.details.get("analysis_incomplete") is not True
        for notice in report.notices
    )


def test_scan_bytes_records_truncated_literal_scan_notice() -> None:
    report = scan_bytes(
        pickle.dumps({"code": "A" * 128}, protocol=4),
        source="large-string.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.is_clean is False
    assert report.coverage.opcode_scan_complete is False
    assert any(
        notice.code == "literal_scan_truncated"
        and notice.details.get("literal_length") == 128
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


def test_scan_bytes_flags_suspicious_literal_content_across_truncated_literal_windows() -> None:
    hidden_payload = "A" * 32 + "os.system('id')" + "B" * 32

    report = scan_bytes(
        pickle.dumps({"code": hidden_payload}, protocol=4),
        source="hidden-large-string.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert report.is_clean is False
    assert any(
        finding.rule_code == "SUSPICIOUS_STRING" and finding.details.get("pattern") == "os.system"
        for finding in report.findings
    )
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_flags_suspicious_literal_content_across_default_long_literal_windows() -> None:
    gap_padding = "A" * (4 * 1024 * 1024 + 2048)
    hidden_payload = gap_padding + "os.system('id')" + gap_padding

    report = scan_bytes(
        pickle.dumps({"code": hidden_payload}, protocol=4),
        source="default-hidden-large-string.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "SUSPICIOUS_STRING" and finding.details.get("pattern") == "os.system"
        for finding in report.findings
    )
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_flags_suspicious_literal_content_beyond_default_prefix_suffix_windows() -> None:
    gap_padding = "A" * (8 * 1024 * 1024 + 4096)
    hidden_payload = gap_padding + "os.system('id')" + gap_padding

    report = scan_bytes(
        pickle.dumps({"code": hidden_payload}, protocol=4),
        source="middle-hidden-large-string.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "SUSPICIOUS_STRING" and finding.details.get("pattern") == "os.system"
        for finding in report.findings
    )
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


def test_scan_bytes_still_checks_bounded_encoded_nested_windows_for_truncated_literals() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    padded_encoded_payload = base64.b64encode(nested_payload).decode("ascii") + ("A" * 128)

    report = scan_bytes(
        pickle.dumps({"outer": padded_encoded_payload}, protocol=4),
        source="padded-encoded-nested.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(notice.code == "encoded_nested_payload_detected" for notice in report.notices)
    assert any(notice.code == "literal_scan_truncated" for notice in report.notices)


@pytest.mark.parametrize(
    ("literal", "encoding", "rule_code"),
    [
        (base64.b64encode(pickle.dumps({"inner": "data"}, protocol=4)).decode("ascii"), "base64", "S601"),
        (binascii.hexlify(pickle.dumps({"inner": "data"}, protocol=4)).decode("ascii"), "hex", "S602"),
    ],
)
def test_scan_bytes_fails_closed_for_encoded_nested_payload_over_byte_limit(
    literal: str,
    encoding: str,
    rule_code: str,
) -> None:
    report = scan_bytes(
        pickle.dumps({"outer": literal}, protocol=4),
        source=f"oversized-{encoding}-nested.pkl",
        options=ScanOptions(max_nested_pickle_bytes=4),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == rule_code
        and finding.details.get("encoding") == encoding
        and finding.details.get("analysis_incomplete") is True
        and finding.details.get("max_nested_pickle_bytes") == 4
        for finding in report.findings
    )
    assert any(
        notice.code == "encoded_nested_payload_truncated"
        and notice.details.get("encoding") == encoding
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


def test_scan_bytes_collapses_protocol5_buffer_opcode_notices() -> None:
    report = scan_bytes(b"\x80\x05\x97\x97\x98\x97\x98.", source="many-buffer-opcodes.pkl")

    buffer_notices = [notice for notice in report.notices if notice.code == "buffer_opcode"]
    assert len(buffer_notices) == 1
    assert buffer_notices[0].details["buffer_opcode_count"] == 5
    assert buffer_notices[0].details["next_buffer_count"] == 3
    assert buffer_notices[0].details["readonly_buffer_count"] == 2
    assert buffer_notices[0].details["readonly_buffer_empty_stack_count"] == 0


def test_scan_bytes_preserves_readonly_buffer_empty_stack_parity() -> None:
    report = scan_bytes(b"\x80\x05\x98\x93.", source="readonly-empty-stack.pkl")

    finding = next(finding for finding in report.findings if finding.rule_code == "MALFORMED_STACK_GLOBAL")
    assert finding.details["module_operand"] == "NoneType:None"
    assert finding.details["name_operand"] == "NoneType:None"
    buffer_notice = next(notice for notice in report.notices if notice.code == "buffer_opcode")
    assert buffer_notice.details["readonly_buffer_empty_stack_count"] == 1


def test_scan_bytes_records_oversized_frame_notice() -> None:
    report = scan_bytes(b"\x80\x04\x95\xfe\xff\xff\xff\xff\xff\xff\xff}.", source="oversized-frame.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    notice = next(notice for notice in report.notices if notice.code == "oversized_frame")
    assert notice.details["frame_length"] == 0xFFFFFFFFFFFFFFFE
    assert notice.details["remaining_bytes"] == 2


def test_scan_stream_preserves_absolute_offsets_from_current_stream_position() -> None:
    prefix = b"HEADER"
    payload = pickle.dumps(MaliciousPayload())
    stream = io.BytesIO(prefix + payload)
    stream.seek(len(prefix))

    report = PickleScanner().scan_stream(stream, source="embedded.npy", size=len(payload))

    assert report.metadata["first_pickle_end_pos"] == len(prefix) + len(payload)
    finding_positions = [
        int(match.group(1))
        for finding in report.findings
        if finding.location is not None and "embedded.npy" in finding.location
        for match in [re.search(r"\(pos (\d+)\)$", finding.location)]
        if match is not None
    ]
    assert finding_positions
    assert all(position >= len(prefix) for position in finding_positions)
