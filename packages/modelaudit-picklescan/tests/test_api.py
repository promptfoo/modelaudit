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

SYSTEM_GLOBALS = frozenset({"nt.system", "os.system", "posix.system"})


class MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


class UnreadableStream(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        raise OSError("simulated stream read failure")


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
    assert any(any(symbol in finding.message for symbol in SYSTEM_GLOBALS) for finding in report.findings)
    assert any(finding.details.get("import_reference") in SYSTEM_GLOBALS for finding in report.findings)
    assert any(
        ref["import_reference"] in SYSTEM_GLOBALS and ref["is_dangerous"] is True
        for ref in report.metadata["import_references"]
    )


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
    archive_path = tmp_path / "model.bin"
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


def test_scan_file_leaves_generic_data_pickle_zip_as_raw_pickle_input(tmp_path: Path) -> None:
    archive_path = tmp_path / "generic.jpg"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

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


def test_scan_bytes_flags_hex_encoded_nested_pickle_payloads() -> None:
    nested_payload = pickle.dumps({"inner": "data"}, protocol=4)
    report = scan_bytes(
        pickle.dumps({"outer": binascii.hexlify(nested_payload).decode("ascii")}, protocol=4),
        source="nested-hex.pkl",
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "S602" for finding in report.findings)


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


def test_scan_bytes_fails_closed_when_suspicious_literal_content_is_outside_scan_windows() -> None:
    hidden_payload = "A" * 32 + "os.system('id')" + "B" * 32

    report = scan_bytes(
        pickle.dumps({"code": hidden_payload}, protocol=4),
        source="hidden-large-string.pkl",
        options=ScanOptions(max_string_literal_scan_chars=8),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.is_clean is False
    assert not any(finding.rule_code == "SUSPICIOUS_STRING" for finding in report.findings)
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
