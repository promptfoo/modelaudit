from __future__ import annotations

import base64
import binascii
import collections
import copyreg
import datetime
import decimal
import faulthandler
import functools
import io
import logging
import os
import pickle
import re
import sys
import tarfile
import uuid
import warnings
import zipfile
from pathlib import Path, PurePosixPath
from typing import cast

import pytest

import modelaudit_picklescan.api as package_api
from modelaudit_picklescan import (
    Finding,
    PickleReport,
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
_PROTOCOL_MUTATION_EVENTS: list[tuple[str, str]] = []


class ProtocolMutationTarget:
    def __setitem__(self, key: str, value: str) -> None:
        _PROTOCOL_MUTATION_EVENTS.append((key, value))


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _global(module: bytes, name: bytes) -> bytes:
    return b"c" + module + b"\n" + name + b"\n"


def _binunicode(data: bytes) -> bytes:
    return b"X" + len(data).to_bytes(4, "little") + data


def _concrete_pathlib_class_name() -> str:
    return "WindowsPath" if os.name == "nt" else "PosixPath"


def _pathlib_method_reduce_payload(target: Path, method: str) -> bytes:
    class_name = _concrete_pathlib_class_name()
    return (
        b"\x80\x04"
        + f"cpathlib\n{class_name}\n".encode("ascii")
        + _binunicode(str(target).encode())
        + b"\x85R\x94"
        + f"cpathlib\n{class_name}.{method}\n".encode("ascii")
        + b"h\x00\x85R."
    )


def _file_mode_reduce_payload(module: bytes, name: bytes, target: Path, mode: bytes) -> bytes:
    return (
        b"\x80\x04c"
        + module
        + b"\n"
        + name
        + b"\n"
        + _binunicode(str(target).encode())
        + _short_binunicode(mode)
        + b"\x86R."
    )


def _dbm_open_payload(base: Path) -> bytes:
    return b"\x80\x04cdbm\nopen\n" + _binunicode(str(base).encode()) + _short_binunicode(b"c") + b"\x86R."


def _maildir_payload(maildir: Path) -> bytes:
    return b"\x80\x04cmailbox\nMaildir\n" + _binunicode(str(maildir).encode()) + b"\x88\x86R."


def _named_temporary_file_payload(directory: Path) -> bytes:
    return (
        b"\x80\x04ctempfile\nNamedTemporaryFile\n("
        + _short_binunicode(b"w+b")
        + b"J\xff\xff\xff\xff"
        + b"N"
        + b"N"
        + _short_binunicode(b"")
        + _short_binunicode(b"pickle-")
        + _binunicode(str(directory).encode())
        + b"\x89"
        + b"tR."
    )


def _temporary_directory_payload(parent: Path) -> bytes:
    return (
        b"\x80\x04ctempfile\nTemporaryDirectory\n("
        + _short_binunicode(b"")
        + _short_binunicode(b"pickle-")
        + _binunicode(str(parent).encode())
        + b"tR."
    )


def _configparser_read_get_payload(config_path: Path, read_method: bytes) -> bytes:
    return (
        b"\x80\x04"
        b"cconfigparser\nConfigParser\n)R\x94"
        + _global(b"configparser", read_method)
        + b"h\x00"
        + _binunicode(str(config_path).encode())
        + b"\x86R0"
        b"cconfigparser\nConfigParser.get\n"
        b"h\x00" + _short_binunicode(b"secrets") + _short_binunicode(b"token") + b"\x87R."
    )


def _argparse_filetype_payload(target: Path) -> bytes:
    return (
        b"\x80\x04"
        b"cargparse\nFileType\n"
        + _short_binunicode(b"w")
        + b"\x85R\x94"
        + b"h\x00"
        + _binunicode(str(target).encode())
        + b"\x85R."
    )


def _copyreg_pickle_payload() -> bytes:
    return b"\x80\x04ccopyreg\npickle\ncdecimal\nDecimal\ncbuiltins\nstr\n\x86R."


def _copyreg_dispatch_table_update_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.update\nccopyreg\ndispatch_table\n}cdecimal\nDecimal\ncbuiltins\nstr\ns\x86R."


def _copyreg_dispatch_table_setitem_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.__setitem__\nccopyreg\ndispatch_table\ncdecimal\nDecimal\ncbuiltins\nstr\n\x87R."


def _copyreg_dispatch_table_operator_setitem_payload() -> bytes:
    return b"\x80\x04coperator\nsetitem\nccopyreg\ndispatch_table\ncdecimal\nDecimal\ncbuiltins\nstr\n\x87R."


def _copyreg_dispatch_table_operator_ior_payload() -> bytes:
    return b"\x80\x04coperator\nior\nccopyreg\ndispatch_table\n}cdecimal\nDecimal\ncbuiltins\nstr\ns\x86R."


def _copyreg_dispatch_table_setdefault_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.setdefault\nccopyreg\ndispatch_table\ncdecimal\nDecimal\ncbuiltins\nstr\n\x87R."


def _copyreg_dispatch_table_ior_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.__ior__\nccopyreg\ndispatch_table\n}cdecimal\nDecimal\ncbuiltins\nstr\ns\x86R."


def _copyreg_dispatch_table_pop_union_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.pop\nccopyreg\ndispatch_table\n" + _global(b"types", b"UnionType") + b"\x86R."


def _copyreg_dispatch_table_delitem_union_payload() -> bytes:
    return (
        b"\x80\x04cbuiltins\ndict.__delitem__\nccopyreg\ndispatch_table\n" + _global(b"types", b"UnionType") + b"\x86R."
    )


def _copyreg_dispatch_table_operator_delitem_union_payload() -> bytes:
    return b"\x80\x04coperator\ndelitem\nccopyreg\ndispatch_table\n" + _global(b"types", b"UnionType") + b"\x86R."


def _copyreg_dispatch_table_popitem_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.popitem\nccopyreg\ndispatch_table\n\x85R."


def _copyreg_dispatch_table_clear_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.clear\nccopyreg\ndispatch_table\n\x85R."


def _warnings_filters_list_clear_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.clear\ncwarnings\nfilters\n\x85R."


def _warnings_filters_operator_imul_payload() -> bytes:
    return b"\x80\x04coperator\nimul\ncwarnings\nfilters\nK\x00\x86R."


def _warning_ignore_filter_tuple_payload() -> bytes:
    return b"(" + _short_binunicode(b"ignore") + b"Ncbuiltins\nWarning\nNK\x00t"


def _warnings_filters_list_insert_ignore_payload() -> bytes:
    return (
        b"\x80\x04"
        b"cbuiltins\nlist.insert\n"
        b"cwarnings\nfilters\n"
        b"K\x00" + _warning_ignore_filter_tuple_payload() + b"\x87R."
    )


def _warnings_filters_list_pop_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.pop\ncwarnings\nfilters\nK\x00\x86R."


def _warnings_filters_list_setitem_ignore_payload() -> bytes:
    return (
        b"\x80\x04"
        b"cbuiltins\nlist.__setitem__\n"
        b"cwarnings\nfilters\n"
        b"K\x00" + _warning_ignore_filter_tuple_payload() + b"\x87R."
    )


def _logging_root_handlers_list_clear_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.clear\nclogging\nroot.handlers\n\x85R."


def _logging_root_handlers_list_pop_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.pop\nclogging\nroot.handlers\nK\x00\x86R."


def _logging_root_handlers_list_delitem_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.__delitem__\nclogging\nroot.handlers\nK\x00\x86R."


def _local_list_append_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.append\n]K\x01\x86R."


def _local_list_clear_payload() -> bytes:
    return b"\x80\x04cbuiltins\nlist.clear\n]K\x01a\x85R."


def _local_dict_setitem_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.__setitem__\n}K\x01K\x02\x87R."


def _local_dict_update_payload() -> bytes:
    return b"\x80\x04cbuiltins\ndict.update\n}}K\x01K\x02s\x86R."


def _local_operator_setitem_payload() -> bytes:
    return b"\x80\x04coperator\nsetitem\n}K\x01K\x02\x87R."


def _local_operator_ior_payload() -> bytes:
    return b"\x80\x04coperator\nior\n}}K\x01K\x02s\x86R."


def _local_operator_imul_payload() -> bytes:
    return b"\x80\x04coperator\nimul\n]K\x01aK\x00\x86R."


def _operator_setitem_constructed_object_payload() -> bytes:
    return (
        b"\x80\x04" + _global(__name__.encode("ascii"), b"ProtocolMutationTarget") + b")R\x94"
        b"coperator\nsetitem\n"
        b"h\x00" + _short_binunicode(b"token") + _short_binunicode(b"value") + b"\x87R."
    )


def _site_addsitedir_payload(site_dir: Path) -> bytes:
    return b"\x80\x04csite\naddsitedir\n" + _binunicode(str(site_dir).encode()) + b"\x85R."


def _site_addpackage_payload(site_dir: Path, pth_name: str) -> bytes:
    return (
        b"\x80\x04csite\naddpackage\n("
        + _binunicode(str(site_dir).encode())
        + _short_binunicode(pth_name.encode())
        + b"N"
        + b"tR."
    )


def _write_executing_pth(pth_path: Path, marker: Path, message: str) -> None:
    pth_path.write_text(
        "import pathlib; pathlib.Path(" + repr(str(marker)) + f").write_text({message!r}, encoding='utf-8')\n",
        encoding="utf-8",
    )


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


def test_scan_bytes_blocks_operator_setitem_copyreg_dispatch_table_poisoning() -> None:
    payload = b"\x80\x02coperator\nsetitem\nccopyreg\ndispatch_table\ncdecimal\nDecimal\ncbuiltins\nstr\n\x87R."
    original_dispatch_table = dict(copyreg.dispatch_table)

    try:
        copyreg.dispatch_table.pop(decimal.Decimal, None)

        report = scan_bytes(payload, source="operator-setitem-copyreg-dispatch-table.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert decimal.Decimal not in copyreg.dispatch_table
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "operator.setitem"
            for finding in report.findings
        )

        assert pickle.loads(payload) is None
        assert copyreg.dispatch_table.get(decimal.Decimal) is str
    finally:
        copyreg.dispatch_table.clear()
        copyreg.dispatch_table.update(original_dispatch_table)


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
    import_references = cast(tuple[dict[str, object], ...], report.metadata.get("import_references", ()))
    assert any(
        reference.get("import_reference") == "torch.FloatStorage"
        and reference.get("pytorch_storage_persistent_id") is True
        for reference in import_references
    )
    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in report.findings)
    assert report.notices == ()


def test_scan_bytes_marks_global_pytorch_storage_persistent_id_import_reference() -> None:
    payload = (
        b"\x80\x02("
        + _binunicode(b"storage")
        + _global(b"torch", b"FloatStorage")
        + _binunicode(b"k")
        + _binunicode(b"cpu")
        + b"K\x01tQ."
    )

    report = scan_bytes(payload, source="global-pytorch-storage.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    import_references = cast(tuple[dict[str, object], ...], report.metadata.get("import_references", ()))
    assert any(
        reference.get("import_reference") == "torch.FloatStorage"
        and reference.get("pytorch_storage_persistent_id") is True
        for reference in import_references
    )
    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in report.findings)
    assert report.notices == ()


def test_scan_bytes_marks_each_pytorch_storage_persistent_id_import_reference() -> None:
    def storage_persistent_id(name: str, key: str, terminator: bytes) -> bytes:
        return (
            b"("
            + _short_binunicode(b"storage")
            + _short_binunicode(b"torch")
            + _short_binunicode(name.encode())
            + b"\x93"
            + _short_binunicode(key.encode())
            + _short_binunicode(b"cpu")
            + b"K\x01tQ"
            + terminator
        )

    storage_names = [f"Synthetic{index}Storage" for index in range(33)]
    payload = b"\x80\x04" + b"".join(
        storage_persistent_id(name, str(index), b"." if index == len(storage_names) - 1 else b"0")
        for index, name in enumerate(storage_names)
    )

    report = scan_bytes(payload, source="many-pytorch-storage-persistent-ids.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH_LIMIT" for finding in report.findings)
    storage_references = [
        reference
        for reference in report.metadata["import_references"]
        if reference.get("module") == "torch" and str(reference.get("name", "")).endswith("Storage")
    ]
    assert len(storage_references) == len(storage_names)
    assert all(reference.get("pytorch_storage_persistent_id") is True for reference in storage_references)


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


def test_scan_file_does_not_route_large_trivial_proto0_text_as_hidden_pickle(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
        archive.writestr("archive/constants", b"I0\n0" * 20_000)

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


def test_scan_bytes_detects_pathlib_mutating_dotted_method_reduce(tmp_path: Path) -> None:
    target = tmp_path / "pickle_touch_bypass_marker"
    expected_reference = f"pathlib.{_concrete_pathlib_class_name()}.touch"
    payload = _pathlib_method_reduce_payload(target, "touch")

    report = scan_bytes(payload, source="pathlib-touch.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert target.exists() is False
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )
    assert any(
        ref["import_reference"] == expected_reference and ref["is_dangerous"] is False
        for ref in report.metadata["import_references"]
    )
    pickle.loads(payload)
    assert target.exists() is True


def test_scan_bytes_detects_pathlib_read_text_dotted_method_reduce(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("modelaudit-secret-8\n", encoding="utf-8")
    expected_reference = f"pathlib.{_concrete_pathlib_class_name()}.read_text"
    payload = _pathlib_method_reduce_payload(secret, "read_text")

    report = scan_bytes(payload, source="pathlib-read-text.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )
    assert pickle.loads(payload) == "modelaudit-secret-8\n"


def test_scan_bytes_detects_pathlib_read_bytes_dotted_method_reduce(tmp_path: Path) -> None:
    secret = tmp_path / "secret.bin"
    secret.write_bytes(b"\x00modelaudit-secret-8\xff")
    expected_reference = f"pathlib.{_concrete_pathlib_class_name()}.read_bytes"
    payload = _pathlib_method_reduce_payload(secret, "read_bytes")

    report = scan_bytes(payload, source="pathlib-read-bytes.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )
    assert pickle.loads(payload) == b"\x00modelaudit-secret-8\xff"


@pytest.mark.parametrize(
    "expected_reference",
    [
        "pathlib._local.PosixPath.iterdir",
        "pathlib._local.PosixPath.read_text",
    ],
)
def test_scan_bytes_detects_python313_pathlib_local_dotted_method_reduce(expected_reference: str) -> None:
    method_name = expected_reference.removeprefix("pathlib._local.")
    payload = b"\x80\x04cpathlib._local\n" + method_name.encode("ascii") + b"\n)R."

    report = scan_bytes(payload, source=f"{expected_reference}-local-method.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )


def test_scan_bytes_allows_benign_pathlib_path_constructor() -> None:
    class_name = _concrete_pathlib_class_name()
    payload = b"\x80\x04" + f"cpathlib\n{class_name}\n".encode("ascii") + _binunicode(b"model.bin") + b"\x85R."

    report = scan_bytes(payload, source="pathlib-constructor.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize(
    ("module", "name", "expected_reference"),
    [
        (b"io", b"open", "io.open"),
        (b"logging", b"FileHandler", "logging.FileHandler"),
    ],
)
def test_scan_bytes_detects_file_truncating_stdlib_reduce(
    tmp_path: Path,
    module: bytes,
    name: bytes,
    expected_reference: str,
) -> None:
    target = tmp_path / f"{module.decode()}-{name.decode()}-should-not-truncate.txt"
    target.write_text("keep this content\n", encoding="utf-8")
    payload = _file_mode_reduce_payload(module, name, target, b"w")

    report = scan_bytes(payload, source=f"{expected_reference}-truncate.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert target.stat().st_size > 0
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )
    result = pickle.loads(payload)
    try:
        assert target.stat().st_size == 0
    finally:
        result.close()


@pytest.mark.parametrize(
    ("module", "mode", "expected_reference", "close_may_fail"),
    [
        ("codecs", b"w", "codecs.open", False),
        ("gzip", b"wb", "gzip.open", False),
        ("bz2", b"wb", "bz2.open", False),
        ("lzma", b"wb", "lzma.open", False),
        ("wave", b"wb", "wave.open", True),
        ("aifc", b"wb", "aifc.open", True),
        ("sunau", b"wb", "sunau.open", True),
    ],
)
def test_scan_bytes_detects_stdlib_file_opening_wrappers(
    tmp_path: Path,
    module: str,
    mode: bytes,
    expected_reference: str,
    close_may_fail: bool,
) -> None:
    pytest.importorskip(module)
    target = tmp_path / f"{expected_reference.replace('.', '-')}-should-not-truncate.dat"
    original = b"keep this content\n" * 2
    target.write_bytes(original)
    payload = _file_mode_reduce_payload(module.encode("ascii"), b"open", target, mode)

    report = scan_bytes(payload, source=f"{expected_reference}-truncate.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert target.read_bytes() == original
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )
    result = pickle.loads(payload)
    close = getattr(result, "close", None)
    if close is not None:
        try:
            close()
        except Exception:
            if not close_may_fail:
                raise
    assert target.read_bytes() != original


def test_scan_bytes_detects_logging_disable_diagnostic_suppression() -> None:
    payload = b"\x80\x04clogging\ndisable\nK2\x85R."
    previous_disable = logging.root.manager.disable

    try:
        logging.disable(logging.NOTSET)
        report = scan_bytes(payload, source="logging-disable.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert logging.root.manager.disable == logging.NOTSET
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "logging.disable"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert logging.root.manager.disable == logging.CRITICAL
    finally:
        logging.disable(previous_disable)


def test_scan_bytes_detects_logging_capture_warnings_diagnostic_reroute() -> None:
    payload = b"\x80\x04clogging\ncaptureWarnings\n\x88\x85R."
    original_showwarning = warnings.showwarning

    try:
        logging.captureWarnings(False)
        baseline_showwarning = warnings.showwarning
        report = scan_bytes(payload, source="logging-capture-warnings.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.showwarning is baseline_showwarning
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "logging.captureWarnings"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert warnings.showwarning is not baseline_showwarning
    finally:
        logging.captureWarnings(False)
        warnings.showwarning = original_showwarning


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (
            b"\x80\x04cwarnings\nsimplefilter\n" + _short_binunicode(b"ignore") + b"\x85R.",
            "warnings.simplefilter",
        ),
        (
            b"\x80\x04cwarnings\nfilterwarnings\n" + _short_binunicode(b"ignore") + b"\x85R.",
            "warnings.filterwarnings",
        ),
    ],
)
def test_scan_bytes_detects_warnings_filter_suppression(payload: bytes, expected_reference: str) -> None:
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        report = scan_bytes(payload, source=f"{expected_reference}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters == []
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == expected_reference
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert warnings.filters[0][0] == "ignore"
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


def test_scan_bytes_detects_warnings_resetwarnings_policy_erasure() -> None:
    payload = b"\x80\x04cwarnings\nresetwarnings\n)R."
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        warnings.simplefilter("error")
        report = scan_bytes(payload, source="warnings-resetwarnings.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters[0][0] == "error"
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "warnings.resetwarnings"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert warnings.filters == []
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


def test_scan_bytes_detects_warnings_filters_list_clear_policy_erasure() -> None:
    payload = _warnings_filters_list_clear_payload()
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        warnings.simplefilter("error")
        report = scan_bytes(payload, source="warnings-filters-list-clear.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters[0][0] == "error"
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.list.clear"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert warnings.filters == []
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


def test_scan_bytes_detects_warnings_filters_operator_imul_policy_erasure() -> None:
    payload = _warnings_filters_operator_imul_payload()
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        warnings.simplefilter("error")
        report = scan_bytes(payload, source="warnings-filters-operator-imul.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters[0][0] == "error"
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "operator.imul"
            and finding.details.get("mutation_target") == "warnings.filters"
            for finding in report.findings
        )
        assert pickle.loads(payload) == []
        assert warnings.filters == []
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


def test_scan_bytes_detects_warnings_filters_list_insert_suppression() -> None:
    payload = _warnings_filters_list_insert_ignore_payload()
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        warnings.simplefilter("error")
        with pytest.raises(UserWarning):
            warnings.warn("before-pickle", UserWarning, stacklevel=2)
        report = scan_bytes(payload, source="warnings-filters-list-insert.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters[0][0] == "error"
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.list.insert"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        warnings.warn("after-pickle", UserWarning, stacklevel=2)
        assert warnings.filters[0][0] == "ignore"
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


def test_scan_bytes_detects_logging_root_handlers_list_clear() -> None:
    payload = _logging_root_handlers_list_clear_payload()
    original_handlers = list(logging.root.handlers)

    try:
        handler = logging.StreamHandler(io.StringIO())
        logging.root.handlers[:] = [handler]
        report = scan_bytes(payload, source="logging-root-handlers-list-clear.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert len(logging.root.handlers) == 1
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.list.clear"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert logging.root.handlers == []
    finally:
        logging.root.handlers[:] = original_handlers


def test_scan_bytes_detects_warnings_filters_list_pop_policy_erasure() -> None:
    payload = _warnings_filters_list_pop_payload()
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        warnings.simplefilter("error")
        report = scan_bytes(payload, source="warnings-filters-list-pop.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters[0][0] == "error"
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.list.pop"
            for finding in report.findings
        )
        removed_filter = pickle.loads(payload)
        assert removed_filter[0] == "error"
        assert warnings.filters == []
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


def test_scan_bytes_detects_warnings_filters_list_setitem_suppression() -> None:
    payload = _warnings_filters_list_setitem_ignore_payload()
    original_filters = list(warnings.filters)

    try:
        warnings.resetwarnings()
        warnings.simplefilter("error")
        report = scan_bytes(payload, source="warnings-filters-list-setitem.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert warnings.filters[0][0] == "error"
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.list.__setitem__"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert warnings.filters[0][0] == "ignore"
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (_logging_root_handlers_list_pop_payload(), "builtins.list.pop"),
        (_logging_root_handlers_list_delitem_payload(), "builtins.list.__delitem__"),
    ],
)
def test_scan_bytes_detects_logging_root_handlers_list_item_removal(
    payload: bytes,
    expected_reference: str,
) -> None:
    original_handlers = list(logging.root.handlers)

    try:
        handler = logging.StreamHandler(io.StringIO())
        logging.root.handlers[:] = [handler]
        report = scan_bytes(payload, source=f"{expected_reference}-logging-root-handler.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert logging.root.handlers == [handler]
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == expected_reference
            for finding in report.findings
        )
        pickle.loads(payload)
        assert logging.root.handlers == []
    finally:
        logging.root.handlers[:] = original_handlers


def test_scan_bytes_detects_faulthandler_disable_diagnostic_suppression() -> None:
    payload = b"\x80\x04cfaulthandler\ndisable\n)R."
    was_enabled = faulthandler.is_enabled()

    try:
        faulthandler.enable()
        report = scan_bytes(payload, source="faulthandler-disable.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert faulthandler.is_enabled() is True
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "faulthandler.disable"
            for finding in report.findings
        )
        assert pickle.loads(payload) is True
        assert faulthandler.is_enabled() is False
    finally:
        if was_enabled:
            faulthandler.enable()
        else:
            faulthandler.disable()


@pytest.mark.parametrize(
    ("helper", "expected_reference"),
    [
        ("addsitedir", "site.addsitedir"),
        ("addpackage", "site.addpackage"),
    ],
)
def test_scan_bytes_detects_site_pth_execution_helpers(
    tmp_path: Path,
    helper: str,
    expected_reference: str,
) -> None:
    site_dir = tmp_path / "attacker_site"
    site_dir.mkdir()
    marker = tmp_path / f"{helper}-pth-executed.txt"
    message = f"{helper}-pth-payload"
    pth_path = site_dir / "payload.pth"
    _write_executing_pth(pth_path, marker, message)
    payload = (
        _site_addsitedir_payload(site_dir)
        if helper == "addsitedir"
        else _site_addpackage_payload(site_dir, pth_path.name)
    )
    site_dir_text = str(site_dir)

    try:
        while site_dir_text in sys.path:
            sys.path.remove(site_dir_text)
        report = scan_bytes(payload, source=f"{expected_reference}-pth.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert marker.exists() is False
        assert site_dir_text not in sys.path
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == expected_reference
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert marker.read_text(encoding="utf-8") == message
        if helper == "addsitedir":
            assert site_dir_text in sys.path
    finally:
        while site_dir_text in sys.path:
            sys.path.remove(site_dir_text)


def test_scan_bytes_detects_dbm_open_resource_creation(tmp_path: Path) -> None:
    base = tmp_path / "payload_dbm"
    payload = _dbm_open_payload(base)

    report = scan_bytes(payload, source="dbm-open-create.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert not list(tmp_path.iterdir())
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "dbm.open"
        for finding in report.findings
    )
    db = pickle.loads(payload)
    try:
        assert any(path.name.startswith("payload_dbm") for path in tmp_path.iterdir())
    finally:
        db.close()


def test_scan_bytes_detects_maildir_resource_creation(tmp_path: Path) -> None:
    maildir = tmp_path / "payload_maildir"
    payload = _maildir_payload(maildir)

    report = scan_bytes(payload, source="maildir-create.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert maildir.exists() is False
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "mailbox.Maildir"
        for finding in report.findings
    )
    pickle.loads(payload)
    assert sorted(path.name for path in maildir.iterdir()) == ["cur", "new", "tmp"]


def test_scan_bytes_detects_named_temporary_file_resource_creation(tmp_path: Path) -> None:
    payload = _named_temporary_file_payload(tmp_path)

    report = scan_bytes(payload, source="named-temporary-file-create.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert not list(tmp_path.iterdir())
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "tempfile.NamedTemporaryFile"
        for finding in report.findings
    )
    created_path: Path | None = None
    wrapper = pickle.loads(payload)
    try:
        created_path = Path(wrapper.name)
        assert created_path.parent == tmp_path
        assert created_path.exists() is True
    finally:
        wrapper.close()
        if created_path is not None:
            created_path.unlink(missing_ok=True)


def test_scan_bytes_detects_temporary_directory_resource_creation(tmp_path: Path) -> None:
    payload = _temporary_directory_payload(tmp_path)

    report = scan_bytes(payload, source="temporary-directory-create.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert not list(tmp_path.iterdir())
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "tempfile.TemporaryDirectory"
        for finding in report.findings
    )
    created_path: Path | None = None
    temporary_directory = pickle.loads(payload)
    try:
        created_path = Path(temporary_directory.name)
        assert created_path.parent == tmp_path
        assert created_path.is_dir()
    finally:
        temporary_directory.cleanup()


@pytest.mark.parametrize(
    ("read_method", "expected_reference"),
    [
        (b"ConfigParser.read", "configparser.ConfigParser.read"),
        (b"RawConfigParser.read", "configparser.RawConfigParser.read"),
    ],
)
def test_scan_bytes_detects_configparser_read_get_disclosure_chain(
    tmp_path: Path,
    read_method: bytes,
    expected_reference: str,
) -> None:
    config_path = tmp_path / "secret.ini"
    config_path.write_text("[secrets]\ntoken = modelaudit-config-secret-10\n", encoding="utf-8")
    payload = _configparser_read_get_payload(config_path, read_method)

    report = scan_bytes(payload, source=f"{expected_reference}-read-get.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == expected_reference
        for finding in report.findings
    )
    assert pickle.loads(payload) == "modelaudit-config-secret-10"


def test_scan_bytes_detects_argparse_filetype_constructed_callable(tmp_path: Path) -> None:
    target = tmp_path / "argparse-filetype-should-not-truncate.txt"
    target.write_text("keep this content\n", encoding="utf-8")
    payload = _argparse_filetype_payload(target)

    report = scan_bytes(payload, source="argparse-filetype.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert target.stat().st_size > 0
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.severity == Severity.CRITICAL
        and finding.details.get("import_reference") == "argparse.FileType"
        for finding in report.findings
    )
    handle = pickle.loads(payload)
    try:
        assert target.stat().st_size == 0
    finally:
        handle.close()


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (_copyreg_pickle_payload(), "copyreg.pickle"),
        (_copyreg_dispatch_table_update_payload(), "builtins.dict.update"),
        (_copyreg_dispatch_table_setitem_payload(), "builtins.dict.__setitem__"),
        (_copyreg_dispatch_table_operator_setitem_payload(), "operator.setitem"),
        (_copyreg_dispatch_table_operator_ior_payload(), "operator.ior"),
        (_copyreg_dispatch_table_setdefault_payload(), "builtins.dict.setdefault"),
        (_copyreg_dispatch_table_ior_payload(), "builtins.dict.__ior__"),
    ],
)
def test_scan_bytes_detects_copyreg_dispatch_table_poisoning(payload: bytes, expected_reference: str) -> None:
    original_dispatch_table = dict(copyreg.dispatch_table)

    try:
        copyreg.dispatch_table.pop(decimal.Decimal, None)
        report = scan_bytes(payload, source=f"{expected_reference}-copyreg-poison.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert decimal.Decimal not in copyreg.dispatch_table
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == expected_reference
            for finding in report.findings
        )
        pickle.loads(payload)
        assert copyreg.dispatch_table.get(decimal.Decimal) is str
        with pytest.raises(pickle.PicklingError):
            pickle.dumps(decimal.Decimal("1.25"), protocol=4)
    finally:
        copyreg.dispatch_table.clear()
        copyreg.dispatch_table.update(original_dispatch_table)


@pytest.mark.parametrize(
    "payload",
    [
        _local_dict_setitem_payload(),
        _local_dict_update_payload(),
        _local_list_append_payload(),
        _local_list_clear_payload(),
        _local_operator_setitem_payload(),
        _local_operator_ior_payload(),
        _local_operator_imul_payload(),
    ],
)
def test_scan_bytes_allows_local_container_mutations(payload: bytes) -> None:
    pickle.loads(payload)

    report = scan_bytes(payload, source="local-container-mutation.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_detects_operator_setitem_constructed_object_protocol() -> None:
    payload = _operator_setitem_constructed_object_payload()
    _PROTOCOL_MUTATION_EVENTS.clear()

    try:
        report = scan_bytes(payload, source="operator-setitem-constructed-object.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _PROTOCOL_MUTATION_EVENTS == []
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "operator.setitem"
            and finding.details.get("mutation_target") == "object.__setitem__"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert _PROTOCOL_MUTATION_EVENTS == [("token", "value")]
    finally:
        _PROTOCOL_MUTATION_EVENTS.clear()


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (_copyreg_dispatch_table_pop_union_payload(), "builtins.dict.pop"),
        (_copyreg_dispatch_table_delitem_union_payload(), "builtins.dict.__delitem__"),
        (_copyreg_dispatch_table_operator_delitem_union_payload(), "operator.delitem"),
    ],
)
def test_scan_bytes_detects_copyreg_dispatch_table_reducer_deletion(
    payload: bytes,
    expected_reference: str,
) -> None:
    original_dispatch_table = dict(copyreg.dispatch_table)
    union_type = type(int | str)

    try:
        assert union_type in copyreg.dispatch_table
        pickle.dumps(int | str, protocol=4)
        report = scan_bytes(payload, source=f"{expected_reference}-copyreg-delete.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == expected_reference
            for finding in report.findings
        )
        pickle.loads(payload)
        assert union_type not in copyreg.dispatch_table
        with pytest.raises(TypeError, match=r"cannot pickle 'types\.UnionType' object"):
            pickle.dumps(int | str, protocol=4)
    finally:
        copyreg.dispatch_table.clear()
        copyreg.dispatch_table.update(original_dispatch_table)


def test_scan_bytes_detects_copyreg_dispatch_table_popitem_erasure() -> None:
    original_dispatch_table = dict(copyreg.dispatch_table)
    payload = _copyreg_dispatch_table_popitem_payload()

    try:
        copyreg.dispatch_table[decimal.Decimal] = str
        report = scan_bytes(payload, source="builtins-dict-popitem-copyreg.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert copyreg.dispatch_table.get(decimal.Decimal) is str
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.dict.popitem"
            for finding in report.findings
        )
        popped_item = pickle.loads(payload)
        assert popped_item == (decimal.Decimal, str)
        assert decimal.Decimal not in copyreg.dispatch_table
    finally:
        copyreg.dispatch_table.clear()
        copyreg.dispatch_table.update(original_dispatch_table)


def test_scan_bytes_detects_copyreg_dispatch_table_erasure() -> None:
    original_dispatch_table = dict(copyreg.dispatch_table)
    payload = _copyreg_dispatch_table_clear_payload()

    try:
        assert copyreg.dispatch_table
        report = scan_bytes(payload, source="builtins-dict-clear-copyreg.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert any(
            finding.rule_code == "DANGEROUS_CALL"
            and finding.severity == Severity.CRITICAL
            and finding.details.get("import_reference") == "builtins.dict.clear"
            for finding in report.findings
        )
        assert pickle.loads(payload) is None
        assert copyreg.dispatch_table == {}
    finally:
        copyreg.dispatch_table.clear()
        copyreg.dispatch_table.update(original_dispatch_table)


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
        (b"cargparse\nFileType\n(tR.", "argparse.FileType"),
        (b"cbase64\nb64decode\n(tR.", "base64.b64decode"),
        (b"cbase64\nb64encode\n(tR.", "base64.b64encode"),
        (b"cbase64\ndecode\n(tR.", "base64.decode"),
        (b"ccodecs\ndecode\n(tR.", "codecs.decode"),
        (b"ccodecs\nencode\n(tR.", "codecs.encode"),
        (b"ccodecs\nopen\n(tR.", "codecs.open"),
        (b"cconfigparser\nConfigParser.read\n(tR.", "configparser.ConfigParser.read"),
        (b"cconfigparser\nRawConfigParser.read\n(tR.", "configparser.RawConfigParser.read"),
        (b"ccopyreg\npickle\n(tR.", "copyreg.pickle"),
        (b"cdbm\nopen\n(tR.", "dbm.open"),
        (b"cfaulthandler\ndisable\n(tR.", "faulthandler.disable"),
        (b"cgzip\nopen\n(tR.", "gzip.open"),
        (b"cbz2\nopen\n(tR.", "bz2.open"),
        (b"cio\nopen\n(tR.", "io.open"),
        (b"clzma\nopen\n(tR.", "lzma.open"),
        (b"cpip\nmain\n(tR.", "pip.main"),
        (b"cnumpy\nload\n(tR.", "numpy.load"),
        (b"clogging\nFileHandler\n(tR.", "logging.FileHandler"),
        (b"clogging\ncaptureWarnings\n(tR.", "logging.captureWarnings"),
        (b"clogging\ndisable\n(tR.", "logging.disable"),
        (b"cmailbox\nMaildir\n(tR.", "mailbox.Maildir"),
        (b"cshutil\nrmtree\n(tR.", "shutil.rmtree"),
        (b"csite\naddpackage\n(tR.", "site.addpackage"),
        (b"csite\naddsitedir\n(tR.", "site.addsitedir"),
        (b"csite\nmain\n(tR.", "site.main"),
        (b"ctarfile\nopen\n(tR.", "tarfile.open"),
        (b"ctempfile\nNamedTemporaryFile\n(tR.", "tempfile.NamedTemporaryFile"),
        (b"ctempfile\nTemporaryDirectory\n(tR.", "tempfile.TemporaryDirectory"),
        (b"cwave\nopen\n(tR.", "wave.open"),
        (b"caifc\nopen\n(tR.", "aifc.open"),
        (b"csunau\nopen\n(tR.", "sunau.open"),
        (b"cwarnings\nfilterwarnings\n(tR.", "warnings.filterwarnings"),
        (b"cwarnings\nresetwarnings\n(tR.", "warnings.resetwarnings"),
        (b"cwarnings\nsimplefilter\n(tR.", "warnings.simplefilter"),
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
        (b"cconfigparser\nConfigParser\n)R.", "configparser.ConfigParser"),
        (b"clogging\ngetLogger\n.", "logging.getLogger"),
        (b"ctempfile\ngettempdir\n.", "tempfile.gettempdir"),
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


def test_with_call_graph_findings_promotes_click_startup_hook_write_paths() -> None:
    pytest.importorskip("click")

    report = PickleReport(
        source="click-startup-hook-write.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            )
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    file_write_findings = [
        finding for finding in updated.findings if finding.rule_code == "DANGEROUS_CALL_GRAPH_FILE_WRITE"
    ]
    assert len(file_write_findings) == 1

    finding = file_write_findings[0]
    assert finding.details["module"] == "click"
    assert finding.details["name"] == "echo"
    assert finding.details["opener_module"] == "click"
    assert finding.details["opener_name"] == "open_file"
    assert finding.details["open_sink"] == "builtins.open"
    assert finding.details["write_sink"] == "binary_file.write"
    assert finding.details["opener_call_path"] == (
        "click.utils.open_file",
        "click.utils.LazyFile.__init__",
        "builtins.open",
    )
    assert finding.details["writer_call_path"] == ("click.utils.echo", "binary_file.write")
    assert finding.details["analysis"] == "python_call_graph_startup_hook_write"


def test_with_call_graph_findings_dedupes_click_startup_hook_write_when_writer_is_already_critical() -> None:
    pytest.importorskip("click")

    existing_finding = Finding(
        message="existing critical writer finding",
        severity=Severity.CRITICAL,
        location="click-startup-hook-write-dedupe.pkl",
        rule_code="DANGEROUS_CALL",
        details={"module": "click", "name": "echo"},
    )
    report = PickleReport(
        source="click-startup-hook-write-dedupe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(existing_finding,),
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            )
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated is report
    assert updated.findings == (existing_finding,)


def test_with_call_graph_findings_dedupes_click_startup_hook_write_when_opener_is_already_critical() -> None:
    pytest.importorskip("click")

    existing_finding = Finding(
        message="existing critical opener finding",
        severity=Severity.CRITICAL,
        location="click-startup-hook-write-dedupe.pkl",
        rule_code="DANGEROUS_CALL",
        details={"module": "click", "name": "open_file"},
    )
    report = PickleReport(
        source="click-startup-hook-write-dedupe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(existing_finding,),
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            )
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated is report
    assert updated.findings == (existing_finding,)


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
