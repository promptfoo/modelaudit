"""Stdlib-only Joblib scanner regressions for raw and compressed pickle payloads."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import pickle
import pickletools
import struct
import zipfile
import zlib
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import patch

import modelaudit_picklescan.api as picklescan_api
import pytest
from modelaudit_picklescan.call_graph import _clear_source_sensitive_caches

from modelaudit.cache.cache_policy import should_cache_scan_result
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanner_results import ACTIONABLE_FAILED_CHECKS_METADATA_KEY, INCONCLUSIVE_SCAN_OUTCOME, Issue
from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.compressed_scanner import CompressedScanner, _MissingOptionalDependencyError
from modelaudit.scanners.joblib_scanner import (
    JoblibScanner,
    _is_safe_dtype_metadata,
    _JoblibPickleGlobal,
    _JoblibPickleObject,
    _pickle_without_joblib_numpy_array_data,
    _SafeJoblibUnpickler,
    _validated_numpy_dtype,
    np,
)
from modelaudit.utils.file.detection import _LZ4_FRAME_MAGIC, validate_file_type_with_formats


class _FakeLz4FrameDecompressor:
    def __init__(self, payloads: dict[bytes, bytes]) -> None:
        self.payloads = payloads
        self.remaining: bytes | None = None
        self.trailing = b""
        self.eof = False
        self.needs_input = True
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self.remaining is None:
            if not data.startswith(_LZ4_FRAME_MAGIC):
                raise OSError("Invalid lz4 frame")
            marker_offset = len(_LZ4_FRAME_MAGIC)
            marker = data[marker_offset : marker_offset + 1]
            if marker not in self.payloads:
                raise OSError("Invalid lz4 frame")
            self.remaining = self.payloads[marker]
            self.trailing = data[marker_offset + 1 :]

        output_size = len(self.remaining) if max_length < 0 else min(len(self.remaining), max_length)
        output, self.remaining = self.remaining[:output_size], self.remaining[output_size:]
        self.needs_input = not self.remaining
        if self.needs_input:
            self.eof = True
            self.unused_data = self.trailing
        return output


class _FakeLz4FrameModule:
    def __init__(self, payloads: dict[bytes, bytes]) -> None:
        self.payloads = payloads

    def LZ4FrameDecompressor(self) -> _FakeLz4FrameDecompressor:
        return _FakeLz4FrameDecompressor(self.payloads)


def _install_fake_lz4(
    monkeypatch: pytest.MonkeyPatch,
    payloads: dict[bytes, bytes],
) -> None:
    fake_lz4_frame = _FakeLz4FrameModule(payloads)
    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(lambda: fake_lz4_frame))


class _Payload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        import os

        return (os.system, ("echo owned",))


def _has_system_reduce_failure(result: ScanResult) -> bool:
    return any(
        check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.name == "REDUCE Opcode Safety Check"
        and check.details.get("associated_global") in {"os.system", "posix.system", "nt.system"}
        for check in result.checks
    )


def _scan_payload(
    tmp_path: Path,
    payload: bytes,
    filename: str,
    *,
    trust_numpy_array_wrapper: bool = True,
    trust_numpy_dtype: bool = True,
    picklescan_trust_numpy_dtype: bool | None = None,
) -> ScanResult:
    path = tmp_path / filename
    path.write_bytes(payload)
    original_reference_is_trusted = picklescan_api.import_only_reference_is_proven_trusted
    original_invocation_is_trusted = picklescan_api.import_only_reference_is_proven_trusted_for_pickle_invocation
    original_requires_origin_review = picklescan_api.import_only_module_requires_origin_review
    if picklescan_trust_numpy_dtype is None:
        picklescan_trust_numpy_dtype = trust_numpy_dtype

    def trust_embedded_pickle_reference(
        module: str,
        name: str,
        *,
        pickle_entrypoint_methods: tuple[str, ...] | None = None,
        pickle_invokes_metaclass_call: bool | None = None,
    ) -> bool:
        if (module, name) in {
            ("joblib.numpy_pickle", "NumpyArrayWrapper"),
            ("numpy", "memmap"),
            ("numpy", "matrix"),
            ("numpy", "ndarray"),
        }:
            return trust_numpy_array_wrapper
        if (module, name) == ("numpy", "dtype"):
            return picklescan_trust_numpy_dtype
        return original_reference_is_trusted(
            module,
            name,
            pickle_entrypoint_methods=pickle_entrypoint_methods,
            pickle_invokes_metaclass_call=pickle_invokes_metaclass_call,
        )

    def trust_joblib_validated_reference(module: str, name: str) -> bool:
        if (module, name) in {
            ("joblib.numpy_pickle", "NumpyArrayWrapper"),
            ("numpy", "memmap"),
            ("numpy", "matrix"),
            ("numpy", "ndarray"),
        }:
            return trust_numpy_array_wrapper
        if (module, name) == ("numpy", "dtype"):
            return trust_numpy_dtype
        return original_reference_is_trusted(module, name)

    def trust_embedded_pickle_invocation(module: str, name: str, reference: dict[str, object]) -> bool:
        if (module, name) in {
            ("joblib.numpy_pickle", "NumpyArrayWrapper"),
            ("numpy", "memmap"),
            ("numpy", "matrix"),
            ("numpy", "ndarray"),
        }:
            return trust_numpy_array_wrapper
        if (module, name) == ("numpy", "dtype"):
            return picklescan_trust_numpy_dtype
        return original_invocation_is_trusted(module, name, reference)

    def requires_origin_review(module: str, name: str) -> bool:
        if (module, name) in {
            ("joblib.numpy_pickle", "NumpyArrayWrapper"),
            ("numpy", "memmap"),
            ("numpy", "matrix"),
            ("numpy", "ndarray"),
        }:
            return not trust_numpy_array_wrapper
        if (module, name) == ("numpy", "dtype"):
            return not picklescan_trust_numpy_dtype
        return original_requires_origin_review(module, name)

    _clear_source_sensitive_caches()
    try:
        with (
            patch.object(
                JoblibScanner,
                "_numpy_array_wrapper_origin_is_trusted",
                return_value=trust_numpy_array_wrapper,
            ),
            patch(
                "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
                trust_joblib_validated_reference,
            ),
            patch(
                "modelaudit.scanners.pickle_scanner.import_only_reference_is_proven_trusted",
                trust_embedded_pickle_reference,
            ),
            patch("modelaudit_picklescan.api.import_only_reference_is_proven_trusted", trust_embedded_pickle_reference),
            patch(
                "modelaudit_picklescan.api.import_only_reference_is_proven_trusted_for_pickle_invocation",
                trust_embedded_pickle_invocation,
            ),
            patch("modelaudit_picklescan.api.import_only_module_requires_origin_review", requires_origin_review),
            patch(
                "modelaudit_picklescan.call_graph.import_only_reference_is_proven_trusted",
                trust_embedded_pickle_reference,
            ),
            patch(
                "modelaudit_picklescan.call_graph.import_only_reference_is_proven_trusted_for_pickle_invocation",
                trust_embedded_pickle_invocation,
            ),
            patch(
                "modelaudit_picklescan.call_graph.import_only_module_requires_origin_review",
                requires_origin_review,
            ),
        ):
            return JoblibScanner().scan(str(path))
    finally:
        _clear_source_sensitive_caches()


def _joblib_numpy_wrapper_stop_prefix() -> bytes:
    return b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\ncnumpy\nndarray\ncnumpy\ndtype\n."


def _binunicode(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"X" + struct.pack("<I", len(encoded)) + encoded


def _joblib_numpy_wrapper_control(
    *,
    shape: int = 4,
    dtype: str = "i8",
    subclass: tuple[str, str] = ("numpy", "ndarray"),
) -> bytes:
    subclass_global = b"c" + subclass[0].encode("ascii") + b"\n" + subclass[1].encode("ascii") + b"\n"
    return (
        b"cjoblib.numpy_pickle\nNumpyArrayWrapper\n)\x81}("
        + _binunicode("subclass")
        + subclass_global
        + _binunicode("shape")
        + b"K"
        + bytes([shape])
        + b"\x85"
        + _binunicode("order")
        + _binunicode("C")
        + _binunicode("dtype")
        + b"cnumpy\ndtype\n"
        + _binunicode(dtype)
        + b"\x89\x88\x87R"
        + _binunicode("allow_mmap")
        + b"\x88"
        + _binunicode("numpy_array_alignment_bytes")
        + b"K\x10ub"
    )


def _joblib_structured_object_dtype_control(itemsize: int) -> bytes:
    object_dtype = b"cnumpy\ndtype\n" + _binunicode("O8") + b"\x89\x88\x87R"
    fields = b"}" + _binunicode("x") + b"(" + object_dtype + b"K\x00ts"
    state = (
        b"(K\x03"
        + _binunicode("|")
        + b"N"
        + _binunicode("x")
        + b"\x85"
        + fields
        + b"K"
        + bytes([itemsize])
        + b"K\x01K\x1btb"
    )
    return b"cnumpy\ndtype\n" + _binunicode(f"V{itemsize}") + b"\x89\x88\x87R" + state


def _joblib_numpy_wrapper_with_dtype_control(dtype_control: bytes, *, shape: int = 1) -> bytes:
    return (
        b"cjoblib.numpy_pickle\nNumpyArrayWrapper\n)\x81}("
        + _binunicode("subclass")
        + b"cnumpy\nndarray\n"
        + _binunicode("shape")
        + b"K"
        + bytes([shape])
        + b"\x85"
        + _binunicode("order")
        + _binunicode("C")
        + _binunicode("dtype")
        + dtype_control
        + _binunicode("allow_mmap")
        + b"\x88ub"
    )


def _joblib_datetime_dtype_with_unsafe_codec_payload() -> bytes:
    codec_memo = 30
    unsafe = b"c_codecs\nencode\nq" + bytes([codec_memo]) + _binunicode("payload") + _binunicode("utf-8") + b"\x86R0"
    validated = b"h" + bytes([codec_memo]) + _binunicode("ns") + _binunicode("latin1") + b"\x86R"
    metadata = b"N(" + validated + b"K\x01K\x01K\x01t\x86"
    dtype_state = b"(K\x04" + _binunicode("<") + b"NNNJ\xff\xff\xff\xffJ\xff\xff\xff\xffK\x00" + metadata + b"tb"
    dtype = b"cnumpy\ndtype\n" + _binunicode("M8") + b"\x89\x88\x87R" + dtype_state
    wrapper = (
        b"cjoblib.numpy_pickle\nNumpyArrayWrapper\n)\x81}("
        + _binunicode("subclass")
        + b"cnumpy\nndarray\n"
        + _binunicode("shape")
        + b"K\x01\x85"
        + _binunicode("order")
        + _binunicode("C")
        + _binunicode("dtype")
        + dtype
        + _binunicode("allow_mmap")
        + b"\x88"
        + _binunicode("numpy_array_alignment_bytes")
        + b"K\x10ub"
    )
    prefix = b"\x80\x02](" + unsafe + wrapper
    return prefix + _joblib_numpy_raw_segment(len(prefix), b"\x00" * 8) + b"e."


def _shared_structured_dtype_graph(*, depth: int = 7, fanout: int = 8) -> _JoblibPickleObject:
    child = _JoblibPickleObject(
        _JoblibPickleGlobal("numpy", "dtype"),
        ("V1", False, True),
    )
    for level in range(depth):
        names = tuple(f"f{level}_{index}" for index in range(fanout))
        fields = dict.fromkeys(names, (child, 0))
        parent = _JoblibPickleObject(
            _JoblibPickleGlobal("numpy", "dtype"),
            ("V1", False, True),
        )
        parent.state = (3, "|", None, names, fields, 1, 1, 0)
        child = parent
    return child


def _joblib_numpy_raw_segment(prefix_length: int, raw_data: bytes) -> bytes:
    padding_length = 16 - ((prefix_length + 1) % 16)
    return bytes([padding_length]) + (b"\xff" * padding_length) + raw_data


def _joblib_numpy_list_payload(
    *,
    leading_ops: bytes = b"",
    resumed_ops: bytes = b"",
    raw_data: bytes = b"\x00" * 32,
    shape: int = 4,
    dtype: str = "i8",
    subclass: tuple[str, str] = ("numpy", "ndarray"),
) -> bytes:
    prefix = (
        b"\x80\x02]("
        + leading_ops
        + _joblib_numpy_wrapper_control(
            shape=shape,
            dtype=dtype,
            subclass=subclass,
        )
    )
    raw_segment = _joblib_numpy_raw_segment(len(prefix), raw_data)
    return prefix + raw_segment + resumed_ops + b"e."


def _compression_failures(result: ScanResult) -> list[Check]:
    return [
        check
        for check in result.checks
        if check.name == "Compression Bomb Detection" and check.status == CheckStatus.FAILED
    ]


def test_protocol2_datetime_dtype_metadata_is_bounded_and_safe() -> None:
    encoded_unit = _JoblibPickleObject(
        _JoblibPickleGlobal("_codecs", "encode"),
        ("M", "latin1"),
    )

    assert _is_safe_dtype_metadata((None, (encoded_unit, 1, 1, 1)), depth=0) is True
    assert (
        _is_safe_dtype_metadata(
            _JoblibPickleObject(_JoblibPickleGlobal("_codecs", "encode"), ("M", "utf-8")),
            depth=0,
        )
        is False
    )


def test_plain_numpy_dtype_metadata_is_bounded_and_safe() -> None:
    dtype_object = _JoblibPickleObject(
        _JoblibPickleGlobal("numpy", "dtype"),
        ("i4", False, True),
        state=(3, "<", None, None, None, -1, -1, 0, {"foo": "bar"}),
    )

    assert _validated_numpy_dtype(dtype_object) == np.dtype("i4")
    assert _is_safe_dtype_metadata({"nested": {"value": [1, True, None], "flags": {"a", "b"}}}, depth=0) is True
    unsafe_metadata = {"unsafe": _JoblibPickleObject(_JoblibPickleGlobal("os", "system"), ("echo owned",))}
    assert _is_safe_dtype_metadata(unsafe_metadata, depth=0) is False

    dtype_object.state = (3, "<", None, None, None, -1, -1, 0, unsafe_metadata)
    with pytest.raises(pickle.UnpicklingError, match="dtype metadata"):
        _validated_numpy_dtype(dtype_object)


def test_dtype_validation_bounds_shared_memo_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    real_dtype = np.dtype
    calls = 0

    def bounded_dtype(spec: str) -> object:
        nonlocal calls
        calls += 1
        if calls > 64:
            raise AssertionError("dtype validation exceeded its unique-node budget")
        return real_dtype(spec)

    monkeypatch.setattr(np, "dtype", bounded_dtype)

    _validated_numpy_dtype(_shared_structured_dtype_graph())

    assert calls <= 64


def test_safe_parser_bounds_control_opcode_materialization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("modelaudit.scanners.joblib_scanner._MAX_JOBLIB_CONTROL_OPCODES", 16)
    parser = _SafeJoblibUnpickler(io.BytesIO(b"\x80\x02](" + (b"N" * 32) + b"e."))

    with pytest.raises(pickle.UnpicklingError, match="control stream is too complex"):
        parser.load()


def test_safe_parser_rejects_truncated_bytearray8_before_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    allocation_requests: list[int] = []

    def record_bytearray_allocation(size: int = 0) -> bytearray:
        allocation_requests.append(size)
        return bytearray()

    monkeypatch.setattr(pickle, "bytearray", record_bytearray_allocation, raising=False)
    payload = b"\x80\x05\x96" + struct.pack("<Q", 1 << 40) + b"NumpyArrayWrapper."

    assert _pickle_without_joblib_numpy_array_data(payload) is None
    assert allocation_requests == []


def test_safe_parser_rejects_stop_with_unmatched_mark_after_raw_array() -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=b"\x80\x01K\x01.")
    parser = _SafeJoblibUnpickler(io.BytesIO(payload))

    with pytest.raises(pickle.UnpicklingError, match="unmatched MARK"):
        parser.load()


def test_safe_parser_accepts_bounded_bytearray8_before_numpy_payload(tmp_path: Path) -> None:
    leading_ops = b"\x96" + struct.pack("<Q", 4) + b"data0"
    payload = _joblib_numpy_list_payload(leading_ops=leading_ops).replace(b"\x80\x02", b"\x80\x05", 1)

    result = _scan_payload(tmp_path, payload, "bounded_bytearray8.joblib")

    assert result.success is True
    assert result.metadata["trusted_incomplete_tail"] is True


def test_scan_detects_raw_protocol0_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(_Payload(), protocol=0)

    result = _scan_payload(tmp_path, payload, "raw_protocol0.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_detects_truncated_raw_protocol0_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(_Payload(), protocol=0)[:-1]

    result = _scan_payload(tmp_path, payload, "truncated_raw_protocol0.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert _compression_failures(result) == []


@pytest.mark.parametrize("payload", [b"Pattacker-controlled-id\n", b"Vattacker-controlled-id\nQ"])
def test_scan_detects_truncated_raw_persistent_id_joblib(tmp_path: Path, payload: bytes) -> None:
    result = _scan_payload(tmp_path, payload, "truncated_persistent_id.joblib")

    assert result.success is False
    assert any(issue.rule_code == "S212" for issue in result.issues)
    assert _compression_failures(result) == []


def test_scan_detects_raw_protocol0_pickle_after_large_literal(tmp_path: Path) -> None:
    payload = pickle.dumps(["A" * 5000, _Payload()], protocol=0)

    result = _scan_payload(tmp_path, payload, "large_prefix_raw_protocol0.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert _compression_failures(result) == []


def test_raw_pickle_classifier_skips_large_unicode_operands_without_genops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"V" + (b"A" * (1024 * 1024)) + b"\n0cos\nsystem\n."

    def fail_genops(_payload: object) -> object:
        raise AssertionError("raw pickle classification must not decode opcode operands")

    monkeypatch.setattr(pickletools, "genops", fail_genops)

    assert JoblibScanner()._looks_like_raw_pickle_payload(payload) is True


@pytest.mark.parametrize(
    "leading_operand",
    [
        b"T" + (4).to_bytes(4, "little") + b"safe",
        b"\x8b" + (1).to_bytes(4, "little") + b"\x01",
    ],
)
def test_scan_detects_raw_protocol0_pickle_after_four_byte_length_operand(
    tmp_path: Path,
    leading_operand: bytes,
) -> None:
    payload = leading_operand + b"0cos\nsystem\n(S'echo owned'\ntR."

    assert JoblibScanner()._looks_like_raw_pickle_payload(payload) is True

    result = _scan_payload(tmp_path, payload, "four_byte_length_operand.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert _compression_failures(result) == []


def test_scan_accepts_raw_protocol4_primitive_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(7, protocol=4)

    result = _scan_payload(tmp_path, payload, "raw_protocol4_primitive.joblib")

    assert result.success is True
    assert _compression_failures(result) == []
    assert not _has_system_reduce_failure(result)


def test_scan_accepts_raw_protocol0_int_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(7, protocol=0)

    result = _scan_payload(tmp_path, payload, "raw_protocol0_int.joblib")

    assert result.success is True
    assert _compression_failures(result) == []
    assert not _has_system_reduce_failure(result)


@pytest.mark.parametrize("value", [None, True, 7, 3.5, "safe", b"safe", [1, 2], {"key": "value"}])
def test_raw_protocol0_scalar_and_container_pickles_are_recognized(value: object) -> None:
    payload = pickle.dumps(value, protocol=0)

    assert JoblibScanner()._looks_like_raw_pickle_payload(payload) is True


@pytest.mark.parametrize(
    "payload",
    [
        b"Bogus BINBYTES-like text",
        b"Invalid INT-like text",
        b"Not a pickle",
        b"Routine plain text",
        b"This is not compressed data at all!",
        b"Xylophone BINUNICODE-like text",
        b".not a pickle",
        b"]not a pickle",
        b"}not a pickle",
    ],
)
def test_opcode_looking_text_is_not_recognized_as_raw_pickle(payload: bytes) -> None:
    assert JoblibScanner()._looks_like_raw_pickle_payload(payload) is False


def test_scan_reports_unavailable_joblib_read_as_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "safe.joblib"
    path.write_bytes(pickle.dumps(7, protocol=4))

    def fail_read(_self: JoblibScanner, _path: str) -> bytes:
        raise OSError("simulated joblib read failure")

    monkeypatch.setattr(JoblibScanner, "_read_file_safely", fail_read)

    result = JoblibScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["joblib_read_failed"]
    assert result.metadata["operational_error_reason"] == "joblib_read_failed"
    read_checks = [check for check in result.checks if check.name == "Joblib File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert aggregate.success is False
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


@pytest.mark.parametrize("version_error", [PackageNotFoundError("joblib"), RuntimeError("broken metadata")])
def test_metadata_extraction_with_unavailable_joblib_version_remains_a_safe_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version_error: Exception,
) -> None:
    path = tmp_path / "safe.joblib"
    path.write_bytes(pickle.dumps(7, protocol=4))

    def missing_distribution(_name: str) -> str:
        raise version_error

    monkeypatch.setattr("modelaudit.scanners.joblib_scanner.distribution_version", missing_distribution)

    metadata = JoblibScanner().extract_metadata(str(path))

    assert metadata["deserialization_skipped"] is True
    assert "joblib_version" not in metadata
    assert "extraction_error" not in metadata


def test_scan_fails_closed_when_numpy_wrapper_prefix_has_unknown_tail(tmp_path: Path) -> None:
    payload = b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\ncnumpy\nndarray\ncnumpy\ndtype\n\xff"

    result = _scan_payload(tmp_path, payload, "crafted_unknown_tail.joblib")

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["failure_reason"] == "unknown_opcode_or_format_error"
    assert "first_pickle_end_pos" not in result.metadata
    assert "trusted_incomplete_tail" not in result.metadata
    assert any(
        issue.rule_code == "S901"
        and issue.severity == IssueSeverity.INFO
        and issue.message == "Pickle parsing failed before full scan completion"
        for issue in result.issues
    )
    assert "joblib_numpy_array_wrapper_validation_failed" in result.metadata["scan_outcome_reasons"]


def test_numpy_wrapper_validation_failure_overrides_clean_pickle_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "clean_backend_invalid_wrapper.joblib"
    path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\n\xff")
    scanner = JoblibScanner()
    assert scanner.pickle_scanner is not None

    def clean_scan(*_args: object, **_kwargs: object) -> ScanResult:
        clean_result = ScanResult("pickle")
        clean_result.finish(success=True)
        return clean_result

    monkeypatch.setattr(scanner.pickle_scanner, "scan_stream", clean_scan)

    result = scanner.scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["parsing_failed"] is True
    assert result.metadata["failure_reason"] == "unknown_opcode_or_format_error"
    assert result.metadata["scan_outcome_reasons"] == ["joblib_numpy_array_wrapper_validation_failed"]
    assert any(
        issue.rule_code == "S901"
        and issue.severity == IssueSeverity.INFO
        and issue.details.get("scan_outcome_reason") == "joblib_numpy_array_wrapper_validation_failed"
        for issue in result.issues
    )


def test_scan_fails_closed_when_adapter_trusted_tail_is_not_joblib_array_payload(tmp_path: Path) -> None:
    prefix = b"\x80\x02](" + _joblib_numpy_wrapper_control()
    payload = prefix + b"Abenign-looking-unknown-tail"

    result = _scan_payload(tmp_path, payload, "non_array_tail.joblib")

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert "first_pickle_end_pos" not in result.metadata
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_fails_closed_on_completed_pickle_before_array_like_tail(tmp_path: Path) -> None:
    prefix = _joblib_numpy_wrapper_stop_prefix()
    payload = prefix + b"\x02\xff\xff" + (b"\x00" * 16)

    result = _scan_payload(tmp_path, payload, "completed_pickle_array_like_tail.joblib")

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["first_pickle_end_pos"] == len(prefix)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_trusts_numpy_wrapper_raw_array_tail_after_build_handoff(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=_binunicode("done"))

    result = _scan_payload(tmp_path, payload, "numpy_array_tail.joblib")

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["trusted_incomplete_tail"] is True
    assert result.metadata["trusted_incomplete_tail_reason"] == "joblib_numpy_array_payload"
    assert result.metadata["joblib_numpy_array_payload_count"] == 1
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)


def test_scan_keeps_untrusted_numpy_wrapper_origin_review_after_valid_raw_array(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=_binunicode("done"))

    result = _scan_payload(
        tmp_path,
        payload,
        "untrusted_numpy_array_tail.joblib",
        trust_numpy_array_wrapper=False,
    )

    assert result.metadata["pickle_verdict"] == "suspicious"
    assert "trusted_incomplete_tail" not in result.metadata

    def has_numpy_wrapper_origin_review(finding: object) -> bool:
        details = getattr(finding, "details", None)
        return isinstance(details, dict) and details.get("import_reference") == "joblib.numpy_pickle.NumpyArrayWrapper"

    assert any(has_numpy_wrapper_origin_review(finding) for finding in (*result.issues, *result.checks))


class _StaticEmbeddedPickleScanner:
    def __init__(self, result: ScanResult) -> None:
        self._result = result

    def scan_stream(self, _file_like: object, _file_size: int, *, source: str) -> ScanResult:
        del _file_like, _file_size, source
        return self._result


def test_scan_keeps_untrusted_numpy_dtype_origin_review_after_valid_raw_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=_binunicode("done"))
    embedded_result = ScanResult("pickle")
    embedded_result.metadata["analysis_incomplete"] = True
    embedded_result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    embedded_result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    embedded_result.metadata["pickle_report_status"] = "inconclusive"
    embedded_result.metadata["pickle_verdict"] = "suspicious"
    embedded_result.metadata["import_references"] = [
        {
            "import_reference": "numpy.dtype",
            "module": "numpy",
            "name": "dtype",
            "position": 128,
            "requires_origin_verification": True,
        }
    ]
    embedded_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="validated dtype",
        severity=IssueSeverity.WARNING,
        details={"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": 128},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    embedded_result.finish(success=False)

    def trust_only_wrapper(module: str, name: str) -> bool:
        return (module, name) == ("joblib.numpy_pickle", "NumpyArrayWrapper")

    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        trust_only_wrapper,
    )
    scanner = JoblibScanner()
    scanner.pickle_scanner = _StaticEmbeddedPickleScanner(embedded_result)
    result = ScanResult("joblib", scanner=scanner)

    scanner._scan_pickle_payload(
        payload,
        result,
        "untrusted_numpy_dtype_origin_review.joblib",
    )
    result.finish(success=not result.has_errors)

    assert result.success is False
    assert result.metadata["pickle_verdict"] == "suspicious"
    assert "trusted_incomplete_tail" not in result.metadata

    def has_numpy_dtype_origin_review(finding: object) -> bool:
        details = getattr(finding, "details", None)
        return isinstance(details, dict) and details.get("import_reference") == "numpy.dtype"

    assert any(has_numpy_dtype_origin_review(finding) for finding in (*result.issues, *result.checks))


def test_scan_preserves_unvalidated_numpy_dtype_origin_review_before_valid_raw_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _joblib_numpy_list_payload(
        leading_ops=b"cnumpy\ndtype\n0",
        resumed_ops=_binunicode("done"),
    )
    embedded_result = ScanResult("pickle")
    embedded_result.metadata["analysis_incomplete"] = True
    embedded_result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    embedded_result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    embedded_result.metadata["pickle_report_status"] = "inconclusive"
    embedded_result.metadata["pickle_verdict"] = "suspicious"
    embedded_result.metadata["import_references"] = [
        {
            "import_reference": "numpy.dtype",
            "module": "numpy",
            "name": "dtype",
            "position": 4,
            "requires_origin_verification": True,
        },
        {
            "import_reference": "numpy.dtype",
            "module": "numpy",
            "name": "dtype",
            "position": 128,
            "requires_origin_verification": True,
        },
    ]
    for position in (4, 128):
        embedded_result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="dtype origin review",
            severity=IssueSeverity.WARNING,
            details={"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": position},
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
    embedded_result.finish(success=False)

    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        lambda _module, _name: True,
    )
    scanner = JoblibScanner()
    scanner.pickle_scanner = _StaticEmbeddedPickleScanner(embedded_result)
    result = ScanResult("joblib", scanner=scanner)

    scanner._scan_pickle_payload(
        payload,
        result,
        "unvalidated_numpy_dtype_origin_review.joblib",
    )
    result.finish(success=not result.has_errors)

    assert result.success is False
    assert "trusted_incomplete_tail" not in result.metadata
    assert any(
        check.status == CheckStatus.FAILED
        and check.details.get("import_reference") == "numpy.dtype"
        and check.details.get("position") == 4
        for check in result.checks
    )
    assert not any(
        check.status == CheckStatus.FAILED
        and check.details.get("import_reference") == "numpy.dtype"
        and check.details.get("position") == 128
        for check in result.checks
    )


def test_scan_accepts_numpy_matrix_array_payload(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(subclass=("numpy", "matrix"))

    result = _scan_payload(tmp_path, payload, "numpy_matrix.joblib")

    assert result.success is True
    assert result.metadata["trusted_incomplete_tail"] is True
    assert result.metadata["joblib_numpy_array_payload_count"] == 1


def test_scan_preserves_malicious_pickle_findings_before_joblib_tail(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(leading_ops=b"cposix\nsystem\n(S'echo owned'\ntR0")

    result = _scan_payload(tmp_path, payload, "malicious_with_tail.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_detects_malicious_reduce_after_numpy_array_payload(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=b"cposix\nsystem\n(S'echo owned'\ntR")

    result = _scan_payload(tmp_path, payload, "malicious_after_array.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_preserves_unvalidated_codec_encode_after_numpy_array_payload(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=b"c_codecs\nencode\n(S'payload'\nS'utf-8'\ntR")

    result = _scan_payload(tmp_path, payload, "codec_encode_after_array.joblib")

    assert any(issue.details.get("associated_global") == "_codecs.encode" for issue in result.issues)
    assert "trusted_incomplete_tail" not in result.metadata


def test_sanitized_joblib_payload_records_validated_control_occurrences() -> None:
    sanitized = _pickle_without_joblib_numpy_array_data(_joblib_numpy_list_payload())

    assert sanitized is not None
    assert sanitized.validated_control_occurrences["joblib.numpy_pickle.NumpyArrayWrapper"] == frozenset({1})
    assert sanitized.validated_control_occurrences["numpy.ndarray"] == frozenset({1})
    assert sanitized.validated_control_occurrences["numpy.dtype"] == frozenset({1})


def test_validated_joblib_wrapper_cleanup_preserves_unvalidated_dtype_occurrence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        lambda _module, _name: True,
    )
    result = ScanResult("joblib")
    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_message"] = "Scan analysis incomplete."
    result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    result.metadata["pickle_report_status"] = "inconclusive"
    result.metadata["pickle_verdict"] = "suspicious"
    validated_details = {"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": 10}
    unvalidated_details = {"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": 99}
    result.checks.extend(
        [
            Check(
                name="Standalone Pickle Finding",
                status=CheckStatus.FAILED,
                message="validated dtype",
                severity=IssueSeverity.WARNING,
                details=validated_details,
                rule_code="NON_ALLOWLISTED_GLOBAL",
            ),
            Check(
                name="Standalone Pickle Finding",
                status=CheckStatus.FAILED,
                message="unvalidated dtype",
                severity=IssueSeverity.WARNING,
                details=unvalidated_details,
                rule_code="NON_ALLOWLISTED_GLOBAL",
            ),
        ]
    )
    result.issues.extend(
        [
            Issue(
                message="validated dtype",
                severity=IssueSeverity.WARNING,
                details=validated_details,
                rule_code="NON_ALLOWLISTED_GLOBAL",
            ),
            Issue(
                message="unvalidated dtype",
                severity=IssueSeverity.WARNING,
                details=unvalidated_details,
                rule_code="NON_ALLOWLISTED_GLOBAL",
            ),
        ]
    )

    JoblibScanner._remove_validated_numpy_array_wrapper_findings(result, {"numpy.dtype": frozenset({1})})

    remaining_check_positions = [check.details.get("position") for check in result.checks]
    remaining_issue_positions = [issue.details.get("position") for issue in result.issues]
    assert remaining_check_positions == [99]
    assert remaining_issue_positions == [99]
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["pickle_report_status"] == "inconclusive"
    assert result.metadata["pickle_verdict"] == "suspicious"


def test_validated_joblib_wrapper_cleanup_preserves_ambiguous_no_position_dtype_occurrences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        lambda _module, _name: True,
    )
    result = ScanResult("joblib")
    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_message"] = "Scan analysis incomplete."
    result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    result.metadata["pickle_report_status"] = "inconclusive"
    result.metadata["pickle_verdict"] = "suspicious"
    for message in ("validated dtype", "ambiguous dtype"):
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message=message,
            severity=IssueSeverity.WARNING,
            details={"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype"},
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
    assert len(result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY]) == 2

    JoblibScanner._remove_validated_numpy_array_wrapper_findings(result, {"numpy.dtype": frozenset({1})})

    assert [check.message for check in result.checks] == ["ambiguous dtype"]
    assert [issue.message for issue in result.issues] == ["ambiguous dtype"]
    assert len(result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY]) == 1
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["pickle_report_status"] == "inconclusive"
    assert result.metadata["pickle_verdict"] == "suspicious"
    assert should_cache_scan_result(result.to_dict(include_private_metadata=True)) is False


def test_validated_joblib_wrapper_cleanup_preserves_untrusted_dtype_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def trust_only_wrapper(module: str, name: str) -> bool:
        return (module, name) == ("joblib.numpy_pickle", "NumpyArrayWrapper")

    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        trust_only_wrapper,
    )
    result = ScanResult("joblib")
    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    result.metadata["pickle_report_status"] = "inconclusive"
    result.metadata["pickle_verdict"] = "suspicious"
    result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="validated dtype",
        severity=IssueSeverity.WARNING,
        details={"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": 10},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )

    JoblibScanner._remove_validated_numpy_array_wrapper_findings(result, {"numpy.dtype": frozenset({1})})

    assert [check.details.get("position") for check in result.checks] == [10]
    assert [issue.details.get("position") for issue in result.issues] == [10]
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["pickle_report_status"] == "inconclusive"
    assert result.metadata["pickle_verdict"] == "suspicious"


def test_validated_joblib_wrapper_cleanup_clears_private_actionable_failed_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        lambda _module, _name: True,
    )
    result = ScanResult("joblib")
    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_message"] = "Scan analysis incomplete."
    result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    result.metadata["pickle_report_status"] = "inconclusive"
    result.metadata["pickle_verdict"] = "suspicious"
    result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="validated wrapper",
        severity=IssueSeverity.WARNING,
        details={
            "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
            "module": "joblib.numpy_pickle",
            "name": "NumpyArrayWrapper",
            "position": 10,
        },
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    assert ACTIONABLE_FAILED_CHECKS_METADATA_KEY in result._private_metadata
    result.checks[0].severity = IssueSeverity.INFO
    result.issues[0].severity = IssueSeverity.INFO

    JoblibScanner._remove_validated_numpy_array_wrapper_findings(
        result,
        {"joblib.numpy_pickle.NumpyArrayWrapper": frozenset({1})},
    )

    assert result.issues == []
    assert result.checks == []
    assert ACTIONABLE_FAILED_CHECKS_METADATA_KEY not in result._private_metadata
    assert "scan_outcome" not in result.metadata
    assert result.metadata["pickle_report_status"] == "complete"
    assert result.metadata["pickle_verdict"] == "clean"


def test_validated_joblib_wrapper_cleanup_preserves_bounded_string_analysis_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "modelaudit.scanners.joblib_scanner.import_only_reference_is_proven_trusted",
        lambda _module, _name: True,
    )
    result = ScanResult("joblib")
    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_message"] = "Scan analysis incomplete."
    result.metadata["scan_outcome_reasons"] = ["base64_text_alignment_ambiguous"]
    result.metadata["pickle_report_status"] = "inconclusive"
    result.metadata["pickle_verdict"] = "unknown"
    result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="validated wrapper",
        severity=IssueSeverity.WARNING,
        details={
            "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
            "module": "joblib.numpy_pickle",
            "name": "NumpyArrayWrapper",
            "position": 10,
        },
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )

    JoblibScanner._remove_validated_numpy_array_wrapper_findings(
        result,
        {"joblib.numpy_pickle.NumpyArrayWrapper": frozenset({1})},
    )

    assert result.issues == []
    assert result.checks == []
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["base64_text_alignment_ambiguous"]
    assert result.metadata["pickle_report_status"] == "inconclusive"
    assert result.metadata["pickle_verdict"] == "unknown"


def test_validated_dtype_codec_cleanup_filters_private_actionable_failed_checks() -> None:
    benign_result = ScanResult("joblib")
    benign_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="validated dtype codec",
        severity=IssueSeverity.WARNING,
        details={"associated_global": "_codecs.encode"},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    benign_result.checks[0].severity = IssueSeverity.INFO
    benign_result.issues[0].severity = IssueSeverity.INFO

    result = ScanResult("joblib")
    result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="validated dtype codec",
        severity=IssueSeverity.WARNING,
        details={"associated_global": "_codecs.encode"},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    result.checks[0].severity = IssueSeverity.INFO
    result.issues[0].severity = IssueSeverity.INFO
    result.add_check(
        name="Dangerous Embedded Code",
        passed=False,
        message="dangerous global",
        severity=IssueSeverity.CRITICAL,
        details={"associated_global": "builtins.exec"},
        rule_code="S101",
    )

    JoblibScanner._remove_validated_dtype_codec_findings(benign_result)
    JoblibScanner._remove_validated_dtype_codec_findings(result)

    assert benign_result.checks == []
    assert benign_result.issues == []
    assert ACTIONABLE_FAILED_CHECKS_METADATA_KEY not in benign_result._private_metadata
    assert should_cache_scan_result(benign_result.to_dict(include_private_metadata=True)) is True
    assert [(check.name, check.rule_code) for check in result.checks] == [("Dangerous Embedded Code", "S101")]
    assert [(issue.message, issue.rule_code) for issue in result.issues] == [("dangerous global", "S101")]
    assert result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY] == [
        {"name": "Dangerous Embedded Code", "rule_code": "S101", "severity": "critical"}
    ]


def test_scan_preserves_unrelated_codec_global_before_validated_dtype_use(tmp_path: Path) -> None:
    payload = _joblib_datetime_dtype_with_unsafe_codec_payload()
    start = payload.index(b"c_codecs\nencode\nq\x1e")
    end = payload.index(b"0", start) + 1
    payload = payload[:start] + b"c_codecs\nencode\n0" + b"c_codecs\nencode\nq\x1e" + payload[end:]
    prefix = payload[: payload.rfind(b"ub") + 2]
    payload = prefix + _joblib_numpy_raw_segment(len(prefix), b"\x00" * 8) + b"e."

    parser = _SafeJoblibUnpickler(io.BytesIO(payload))
    parser.load()
    assert len(parser.codec_encode_global_ids) == 2
    assert len(parser.dtype_validation_context.validated_codec_encode_global_ids) == 1

    result = _scan_payload(tmp_path, payload, "unrelated_codec_global.joblib")

    assert any(issue.details.get("associated_global") == "_codecs.encode" for issue in result.issues)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_preserves_unvalidated_codec_when_python_object_ids_collide(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _joblib_datetime_dtype_with_unsafe_codec_payload()
    parser = _SafeJoblibUnpickler(io.BytesIO(payload))
    parser.load()

    assert len(parser.codec_encode_reduction_ids) == 2
    assert len(parser.dtype_validation_context.validated_codec_encode_reduction_ids) == 1

    monkeypatch.setattr("modelaudit.scanners.joblib_scanner.id", lambda _value: 7, raising=False)

    result = _scan_payload(
        tmp_path,
        payload,
        "codec_identity_collision.joblib",
    )

    assert any(issue.details.get("associated_global") == "_codecs.encode" for issue in result.issues)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_revalidates_dtype_when_python_object_ids_collide(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_prefix = b"\x80\x02](" + _joblib_numpy_wrapper_control(shape=1, dtype="i8")
    first_raw = _joblib_numpy_raw_segment(len(first_prefix), b"\x00" * 8)
    nested_pickle = pickle.dumps(_Payload(), protocol=2).ljust(48, b"X")
    second_control = b"0" + _joblib_numpy_wrapper_control(shape=6, dtype="O8")
    second_prefix_length = len(first_prefix) + len(first_raw) + len(second_control)
    payload = (
        first_prefix
        + first_raw
        + second_control
        + _joblib_numpy_raw_segment(second_prefix_length, nested_pickle)
        + b"e."
    )
    monkeypatch.setattr("modelaudit.scanners.joblib_scanner.id", lambda _value: 7, raising=False)

    result = _scan_payload(tmp_path, payload, "dtype_identity_collision.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_revalidates_memoized_dtype_after_build_mutation(tmp_path: Path) -> None:
    base_dtype = b"cnumpy\ndtype\n" + _binunicode("V8") + b"\x89\x88\x87Rq\x1e"
    first_prefix = b"\x80\x02](" + _joblib_numpy_wrapper_with_dtype_control(base_dtype)
    dtype_mutation = (
        b"h\x1e(K\x03"
        + _binunicode("|")
        + b"N"
        + _binunicode("x")
        + b"\x85}"
        + _binunicode("x")
        + b"cnumpy\ndtype\n"
        + _binunicode("O8")
        + b"\x89\x88\x87RK\x00\x86sK\x08K\x01K\x1btb0"
    )
    nested_pickle = pickle.dumps(_Payload(), protocol=2).ljust(48, b"X")
    second_wrapper = _joblib_numpy_wrapper_with_dtype_control(b"h\x1e", shape=6)
    payload = first_prefix + (b"\x00" * 8) + b"0" + dtype_mutation + second_wrapper + nested_pickle + b"e."

    result = _scan_payload(tmp_path, payload, "mutated_cached_dtype.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_rejects_invalid_numpy_wrapper_constructor_hiding_nested_pickle(tmp_path: Path) -> None:
    nested_pickle = pickle.dumps(_Payload(), protocol=2)
    wrapper = _joblib_numpy_wrapper_control(shape=len(nested_pickle), dtype="u1").replace(
        b"NumpyArrayWrapper\n)\x81",
        b"NumpyArrayWrapper\n)R",
        1,
    )
    prefix = b"\x80\x02](" + wrapper
    payload = prefix + _joblib_numpy_raw_segment(len(prefix), nested_pickle) + b"e."

    result = _scan_payload(tmp_path, payload, "invalid_wrapper_constructor.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_rejects_structured_object_dtype_hiding_nested_pickle(tmp_path: Path) -> None:
    nested_pickle = pickle.dumps(_Payload(), protocol=2)
    dtype_control = _joblib_structured_object_dtype_control(len(nested_pickle))
    wrapper_control = _joblib_numpy_wrapper_with_dtype_control(dtype_control)
    payload = b"\x80\x02](" + wrapper_control + nested_pickle + b"e."

    result = _scan_payload(tmp_path, payload, "structured_object_dtype.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_accepts_multiple_numpy_array_payloads_and_resumed_pickle(tmp_path: Path) -> None:
    first_prefix = b"\x80\x02](" + _joblib_numpy_wrapper_control()
    first_raw = _joblib_numpy_raw_segment(len(first_prefix), b"\x00" * 32)
    second_control = _joblib_numpy_wrapper_control(shape=3)
    second_prefix_length = len(first_prefix) + len(first_raw) + len(second_control)
    second_raw = _joblib_numpy_raw_segment(second_prefix_length, b"\x00" * 24)
    payload = first_prefix + first_raw + second_control + second_raw + _binunicode("done") + b"e."

    result = _scan_payload(tmp_path, payload, "multiple_arrays.joblib")

    assert result.success is True
    assert result.metadata["joblib_numpy_array_payload_count"] == 2
    assert not _has_system_reduce_failure(result)


def test_scan_accepts_lzma_compressed_numpy_array_payload(tmp_path: Path) -> None:
    payload = lzma.compress(_joblib_numpy_list_payload(), format=lzma.FORMAT_ALONE)

    result = _scan_payload(tmp_path, payload, "lzma_numpy_array.joblib")

    assert result.success is True
    assert result.metadata["trusted_incomplete_tail"] is True
    assert result.metadata["joblib_numpy_array_payload_count"] == 1


@pytest.mark.parametrize("raw_seed", [b"builtins", b"os.system", b"subprocess", b"pickle.loads"])
def test_scan_accepts_security_like_bytes_inside_numpy_array(tmp_path: Path, raw_seed: bytes) -> None:
    raw_data = raw_seed.ljust(32, b"\x00")
    payload = _joblib_numpy_list_payload(raw_data=raw_data, shape=len(raw_data), dtype="u1")

    result = _scan_payload(tmp_path, payload, "benign_security_like_array_bytes.joblib")

    assert result.success is True
    assert result.metadata["trusted_incomplete_tail"] is True
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_does_not_trust_joblib_tail_when_literal_coverage_is_incomplete(tmp_path: Path) -> None:
    large_literal = b"A" * 128
    payload = _joblib_numpy_list_payload(
        leading_ops=b"X" + struct.pack("<I", len(large_literal)) + large_literal + b"0",
    )
    path = tmp_path / "literal_scan_truncated.joblib"
    path.write_bytes(payload)

    result = JoblibScanner({"max_string_literal_scan_chars": 8}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "literal_scan_truncated" in result.metadata["scan_outcome_reasons"]
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_fails_closed_on_protocol1_pickle_in_numpy_wrapper_tail(tmp_path: Path) -> None:
    payload = _joblib_numpy_list_payload(resumed_ops=b"\x80\x01K\x01.")

    result = _scan_payload(tmp_path, payload, "numpy_array_protocol1_tail.joblib")

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["parsing_failed"] is True
    assert result.metadata["failure_reason"] == "unknown_opcode_or_format_error"
    assert "trusted_incomplete_tail" not in result.metadata


def test_scan_fails_closed_on_invalid_numpy_wrapper_with_origin_warning(tmp_path: Path) -> None:
    path = tmp_path / "numpy_array_protocol1_origin_warning.joblib"
    path.write_bytes(_joblib_numpy_list_payload(resumed_ops=b"\x80\x01K\x01."))

    embedded_result = ScanResult("pickle")
    embedded_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="Joblib NumPy wrapper requires origin verification",
        severity=IssueSeverity.WARNING,
        details={"import_reference": "joblib.numpy_pickle.NumpyArrayWrapper"},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )
    embedded_result.finish(success=True)

    scanner = JoblibScanner()
    scanner.pickle_scanner = _StaticEmbeddedPickleScanner(embedded_result)
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert "joblib_numpy_array_wrapper_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert result.has_warnings is True
    assert "trusted_incomplete_tail" not in result.metadata
    assert should_cache_scan_result(result.to_dict(include_private_metadata=True)) is False


def test_scan_detects_gzip_compressed_pickle_joblib(tmp_path: Path) -> None:
    path = tmp_path / "gzip_protocol4.joblib"
    path.write_bytes(gzip.compress(pickle.dumps(_Payload(), protocol=4)))

    result = JoblibScanner().scan(str(path))

    assert result.success is False
    assert _has_system_reduce_failure(result)
    reduce_failures = [
        check
        for check in result.checks
        if check.name == "REDUCE Opcode Safety Check" and check.status == CheckStatus.FAILED
    ]
    assert reduce_failures
    assert reduce_failures[0].location is not None
    assert reduce_failures[0].location.startswith(f"{path} (decompressed)")


def test_scan_detects_bz2_compressed_pickle_joblib(tmp_path: Path) -> None:
    payload = bz2.compress(pickle.dumps(_Payload(), protocol=4))

    result = _scan_payload(tmp_path, payload, "bz2_protocol4.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_detects_lz4_compressed_pickle_joblib(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_lz4(monkeypatch, {b"M": pickle.dumps(_Payload(), protocol=4)})

    result = _scan_payload(tmp_path, _LZ4_FRAME_MAGIC + b"M", "lz4_malicious.joblib")

    assert result.success is False
    assert result.metadata.get("operational_error") is not True
    assert _has_system_reduce_failure(result)


def test_scan_file_accepts_benign_lz4_joblib_without_format_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_lz4(monkeypatch, {b"S": pickle.dumps({"safe": [1, 2, 3]}, protocol=4)})
    path = tmp_path / "lz4_benign.joblib"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"S")

    result = scan_file(str(path), config={"cache_scan_results": False})

    assert result.scanner_name == "joblib"
    assert result.success is True
    assert not any(check.rule_code == "S901" for check in result.checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_lz4_compressed_joblib_is_valid_but_renamed_pickle_is_not(tmp_path: Path) -> None:
    joblib_path = tmp_path / "model.joblib"
    pickle_path = tmp_path / "model.pkl"
    joblib_path.write_bytes(_LZ4_FRAME_MAGIC + b"S")
    pickle_path.write_bytes(_LZ4_FRAME_MAGIC + b"S")

    assert validate_file_type_with_formats(str(joblib_path), "lz4", "pickle") is True
    assert validate_file_type_with_formats(str(pickle_path), "lz4", "pickle") is False


@pytest.mark.parametrize(
    ("compress", "header_format"),
    [
        (zlib.compress, "zlib"),
        (gzip.compress, "gzip"),
        (bz2.compress, "bzip2"),
        (lzma.compress, "xz"),
    ],
    ids=["zlib", "gzip", "bzip2", "xz"],
)
def test_known_compressed_joblib_codecs_remain_valid_without_format_warnings(
    tmp_path: Path,
    compress: Callable[[bytes], bytes],
    header_format: str,
) -> None:
    path = tmp_path / f"{header_format}_benign.joblib"
    path.write_bytes(compress(pickle.dumps({"safe": [1, 2, 3]}, protocol=4)))

    result = scan_file(str(path), config={"cache_scan_results": False})

    assert validate_file_type_with_formats(str(path), header_format, "pickle") is True
    assert result.success is True
    assert not any(check.rule_code == "S901" for check in result.checks)


def test_lz4_compressed_malicious_joblib_produces_security_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_lz4(monkeypatch, {b"M": pickle.dumps(_Payload(), protocol=4)})
    path = tmp_path / "lz4_malicious.joblib"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"M")

    result = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert determine_exit_code(result) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert not any(issue.rule_code == "S901" and issue.severity == IssueSeverity.WARNING for issue in result.issues)


def test_lz4_compressed_joblib_missing_dependency_fails_closed_and_is_not_cacheable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_lz4_dependency() -> object:
        raise _MissingOptionalDependencyError("Optional dependency 'lz4' is not installed")

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(missing_lz4_dependency))
    path = tmp_path / "missing_lz4.joblib"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"M")

    result = JoblibScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "joblib_wrapper_decode_failed"
    assert any(
        check.severity == IssueSeverity.INFO and "Optional dependency 'lz4'" in check.message for check in result.checks
    )
    assert should_cache_scan_result(result.to_dict(include_private_metadata=True)) is False
    assert determine_exit_code(aggregate) == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)


@pytest.mark.parametrize(
    ("scanner_config", "expected_message"),
    [
        ({"max_decompressed_size": 16, "max_decompression_ratio": 1000.0}, "Decompressed size exceeded limit"),
        ({"max_decompressed_size": 1024, "max_decompression_ratio": 2.0}, "Decompression ratio exceeded limit"),
    ],
    ids=["absolute-size", "compression-ratio"],
)
def test_lz4_compressed_joblib_honors_decompression_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanner_config: dict[str, int | float],
    expected_message: str,
) -> None:
    _install_fake_lz4(monkeypatch, {b"B": pickle.dumps({"safe": "A" * 128}, protocol=4)})
    path = tmp_path / "lz4_bomb.joblib"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"B")

    result = JoblibScanner(scanner_config).scan(str(path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "joblib_wrapper_decode_failed"
    assert any(check.severity == IssueSeverity.INFO and expected_message in check.message for check in result.checks)


def test_lz4_joblib_rejects_unscanned_pickle_trailer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_lz4(monkeypatch, {b"S": pickle.dumps({"safe": True}, protocol=4)})
    path = tmp_path / "lz4_trailer.joblib"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"S" + pickle.dumps(_Payload(), protocol=0))

    result = JoblibScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "joblib_wrapper_decode_failed"
    assert any("Invalid lz4 stream" in check.message for check in result.checks)
    assert not _has_system_reduce_failure(result)


def test_lz4_joblib_does_not_accept_malicious_concatenated_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_lz4(
        monkeypatch,
        {
            b"S": pickle.dumps({"safe": True}, protocol=4),
            b"M": pickle.dumps(_Payload(), protocol=4),
        },
    )
    path = tmp_path / "lz4_concatenated.joblib"
    path.write_bytes(_LZ4_FRAME_MAGIC + b"S" + _LZ4_FRAME_MAGIC + b"M")

    result = JoblibScanner().scan(str(path))

    assert result.success is False
    assert _has_system_reduce_failure(result) or result.metadata.get("operational_error") is True


def test_zip_routes_nested_lz4_joblib_to_embedded_pickle_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_lz4(monkeypatch, {b"M": pickle.dumps(_Payload(), protocol=4)})
    archive_path = tmp_path / "models.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("nested/model.joblib", _LZ4_FRAME_MAGIC + b"M")

    result = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)

    assert determine_exit_code(result) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_detects_bz_prefixed_raw_pickle_joblib(tmp_path: Path) -> None:
    payload = b"B" + struct.pack("<I", 90) + (b"X" * 90) + b"0" + pickle.dumps(_Payload(), protocol=0)
    assert payload.startswith(b"BZ")

    result = _scan_payload(tmp_path, payload, "bz_prefixed_raw_pickle.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)
    assert result.metadata.get("operational_error") is not True


def test_scan_detects_zlib_trailer_after_compressed_joblib_stream(tmp_path: Path) -> None:
    payload = zlib.compress(pickle.dumps({"safe": [1, 2, 3]}, protocol=4)) + pickle.dumps(_Payload(), protocol=0)

    result = _scan_payload(tmp_path, payload, "zlib_trailer.joblib")

    compression_failures = _compression_failures(result)
    assert result.success is False
    assert result.metadata.get("operational_error") is True
    assert result.metadata.get("operational_error_reason") == "joblib_wrapper_decode_failed"
    assert len(compression_failures) == 1
    assert "Trailing data found after compressed joblib stream" in compression_failures[0].message
    assert not _has_system_reduce_failure(result)


def test_scan_reports_plain_text_joblib_without_critical_pickle_noise(tmp_path: Path) -> None:
    result = _scan_payload(tmp_path, b"This is not compressed data at all!", "plain_text.joblib")

    compression_failures = _compression_failures(result)
    assert result.success is False
    assert result.metadata.get("operational_error") is True
    assert result.metadata.get("operational_error_reason") == "joblib_wrapper_decode_failed"
    assert len(compression_failures) == 1
    assert compression_failures[0].severity == IssueSeverity.INFO
    assert not _has_system_reduce_failure(result)


def test_scan_file_routes_gzip_joblib_to_joblib_scanner(tmp_path: Path) -> None:
    path = tmp_path / "gzip_protocol4.joblib"
    path.write_bytes(gzip.compress(pickle.dumps(_Payload(), protocol=4)))

    result = scan_file(str(path), config={"cache_scan_results": False})

    assert result.scanner_name == "joblib"
    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_file_routes_plain_text_joblib_to_joblib_scanner(tmp_path: Path) -> None:
    path = tmp_path / "plain_text.joblib"
    path.write_bytes(b"not a pickle")

    result = scan_file(str(path), config={"cache_scan_results": False})

    assert result.scanner_name == "joblib"
    compression_failures = _compression_failures(result)
    assert result.success is False
    assert result.metadata.get("operational_error") is True
    assert result.metadata.get("operational_error_reason") == "joblib_wrapper_decode_failed"
    assert len(compression_failures) == 1
    assert compression_failures[0].severity == IssueSeverity.INFO
    assert not _has_system_reduce_failure(result)
