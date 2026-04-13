from __future__ import annotations

import base64
import binascii
import functools
import io
import os
import pickle
import re
import tarfile
import uuid
import zipfile
from pathlib import Path

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


def test_scan_bytes_detects_malicious_stream_after_malformed_prefix() -> None:
    payload = b"\x80\x04\xff" + (b"\x00" * 32) + b"cos\nsystem\n)R."

    report = scan_bytes(payload, source="malformed-prefix-stream.pkl")

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)


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
            }
        ),
        source="dunder-metadata.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(finding.rule_code == "SUSPICIOUS_STRING" for finding in report.findings)


@pytest.mark.parametrize(
    ("literal", "expected_pattern"),
    [
        ("os.popen('id')", "os.popen"),
        ("subprocess.run(['id'])", "subprocess call"),
        ("getattr(os, 'system')('id')", "getattr system"),
        ("base64.b64decode(blob)", "base64.b64decode"),
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


def test_scan_bytes_flags_base64_encoded_code_string_literals() -> None:
    encoded = base64.b64encode(b"os.system('id')").decode("ascii")

    report = scan_bytes(pickle.dumps({"code": encoded}), source="encoded-code-string.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "SUSPICIOUS_STRING" and finding.details.get("pattern") == "base64 os.system"
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


def test_scan_bytes_flags_raw_nested_pickle_payloads() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": nested_payload}, protocol=4),
        source="nested-raw.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)


def test_scan_bytes_flags_raw_nested_pickle_payload_hidden_inside_large_literal() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = b"A" * 64 + nested_payload + b"B" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-raw-nested.pkl",
        options=ScanOptions(max_nested_pickle_bytes=len(nested_payload) + 16),
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S213" for finding in report.findings)


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
    nested_payload = b"\x80\x04" + (b"A" * 64)

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


def test_scan_bytes_flags_base64_encoded_nested_pickle_payloads() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": base64.b64encode(nested_payload).decode("ascii")}, protocol=4),
        source="nested-base64.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S601" for finding in report.findings)


def test_scan_bytes_flags_base64_nested_pickle_payload_hidden_inside_large_literal() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = "A" * 64 + base64.b64encode(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-base64-nested.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S601" for finding in report.findings)


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


def test_scan_bytes_flags_hex_encoded_nested_pickle_payloads() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": binascii.hexlify(nested_payload).decode("ascii")}, protocol=4),
        source="nested-hex.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S602" for finding in report.findings)


def test_scan_bytes_flags_hex_nested_pickle_payload_hidden_inside_large_literal() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    hidden_payload = "A" * 64 + binascii.hexlify(nested_payload).decode("ascii") + "A" * 64

    report = scan_bytes(
        pickle.dumps({"outer": hidden_payload}, protocol=4),
        source="hidden-hex-nested.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S602" for finding in report.findings)


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


def test_scan_bytes_flags_escaped_hex_encoded_nested_pickle_payloads() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    escaped_hex_payload = "".join(f"\\x{byte:02x}" for byte in nested_payload)

    report = scan_bytes(
        pickle.dumps({"outer": escaped_hex_payload}, protocol=4),
        source="nested-escaped-hex.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S602" for finding in report.findings)


def test_scan_bytes_applies_nested_byte_budget_after_unescaping_hex_literals() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    escaped_hex_payload = "".join(f"\\x{byte:02x}" for byte in nested_payload)

    report = scan_bytes(
        pickle.dumps({"outer": escaped_hex_payload}, protocol=4),
        source="nested-escaped-hex-budget.pkl",
        options=ScanOptions(max_nested_pickle_bytes=len(nested_payload)),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(
        finding.rule_code == "S602" and finding.details.get("analysis_incomplete") is not True
        for finding in report.findings
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
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S601" for finding in report.findings)
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
