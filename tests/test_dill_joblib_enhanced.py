"""Rust-backed dill/joblib pickle scanner regressions."""

from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any

import pytest

from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners import pickle_scanner as pickle_scanner_module
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import ML_SAFE_GLOBALS, PickleScanner, _is_legitimate_serialization_file


class MaliciousPayload:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (os.system, ("id",))


def _write_joblib_like_pickle(path: Path, *, padding: int = 0) -> None:
    path.write_bytes(
        b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00not-joblib-raw-tail" + (b"\x00" * padding),
    )


def _binunicode(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"X" + len(encoded).to_bytes(4, "little") + encoded


def _joblib_numpy_wrapper_control(*, shape: int = 4, dtype: str = "i8") -> bytes:
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
        + b"cnumpy\ndtype\n"
        + _binunicode(dtype)
        + b"\x89\x88\x87R"
        + _binunicode("allow_mmap")
        + b"\x88"
        + _binunicode("numpy_array_alignment_bytes")
        + b"K\x10ub"
    )


def _joblib_numpy_raw_segment(prefix_length: int, raw_data: bytes) -> bytes:
    padding_length = 16 - ((prefix_length + 1) % 16)
    return bytes([padding_length]) + (b"\xff" * padding_length) + raw_data


def _write_valid_joblib_numpy_array_pickle(path: Path) -> None:
    prefix = b"\x80\x02](" + _joblib_numpy_wrapper_control()
    path.write_bytes(prefix + _joblib_numpy_raw_segment(len(prefix), b"\x00" * 32) + b"e.")


def test_malicious_joblib_extension_cannot_bypass_rust_scan(tmp_path: Path) -> None:
    malicious_file = tmp_path / "evil.joblib"
    malicious_file.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))

    result = PickleScanner().scan(str(malicious_file))

    assert result.success is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert _is_legitimate_serialization_file(str(malicious_file)) is False


def test_malicious_dill_extension_cannot_bypass_rust_scan(tmp_path: Path) -> None:
    malicious_file = tmp_path / "evil.dill"
    malicious_file.write_bytes(pickle.dumps(MaliciousPayload(), protocol=4))

    result = PickleScanner().scan(str(malicious_file))

    assert result.success is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_joblib_policy_export_remains_narrow() -> None:
    assert "joblib" not in ML_SAFE_GLOBALS
    assert "dill" not in ML_SAFE_GLOBALS


def test_valid_joblib_like_pickle_has_serialization_span_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    joblib_file = tmp_path / "numpy_arrays.joblib"
    _write_valid_joblib_numpy_array_pickle(joblib_file)

    def trusted_joblib_reference(
        module: str,
        name: str,
        *,
        pickle_entrypoint_methods: tuple[str, ...] | None = None,
        pickle_invokes_metaclass_call: bool | None = None,
    ) -> bool:
        del pickle_entrypoint_methods, pickle_invokes_metaclass_call
        return (module, name) in {
            ("joblib.numpy_pickle", "NumpyArrayWrapper"),
            ("numpy", "ndarray"),
            ("numpy", "dtype"),
        }

    def trusted_joblib_invocation(module: str, name: str, reference: dict[str, object]) -> bool:
        del reference
        return trusted_joblib_reference(module, name)

    def requires_origin_review(module: str, name: str) -> bool:
        return not trusted_joblib_reference(module, name)

    monkeypatch.setattr(
        "modelaudit.scanners.pickle_scanner.import_only_reference_is_proven_trusted",
        trusted_joblib_reference,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.api.import_only_reference_is_proven_trusted",
        trusted_joblib_reference,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.api.import_only_reference_is_proven_trusted_for_pickle_invocation",
        trusted_joblib_invocation,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph.import_only_reference_is_proven_trusted",
        trusted_joblib_reference,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph.import_only_reference_is_proven_trusted_for_pickle_invocation",
        trusted_joblib_invocation,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.api.import_only_module_requires_origin_review",
        requires_origin_review,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph.import_only_module_requires_origin_review",
        requires_origin_review,
    )

    assert _is_legitimate_serialization_file(str(joblib_file)) is True


def test_bare_joblib_like_pickle_requires_span_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    joblib_file = tmp_path / "bare_numpy_arrays.joblib"
    _write_joblib_like_pickle(joblib_file, padding=16)

    def trusted_joblib_reference(module: str, name: str) -> bool:
        return (module, name) in {
            ("joblib.numpy_pickle", "NumpyArrayWrapper"),
            ("numpy", "ndarray"),
            ("numpy", "dtype"),
        }

    monkeypatch.setattr(
        "modelaudit.scanners.pickle_scanner.import_only_reference_is_proven_trusted",
        trusted_joblib_reference,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.api.import_only_reference_is_proven_trusted",
        trusted_joblib_reference,
    )

    result = PickleScanner().scan(str(joblib_file))

    assert _is_legitimate_serialization_file(str(joblib_file)) is False
    assert "trusted_incomplete_tail" not in result.metadata
    assert result.success is False
    assert result.has_warnings or result.metadata.get("scan_outcome") == "inconclusive"


def test_joblib_like_pickle_keeps_wrapper_warning_when_origin_is_untrusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    joblib_file = tmp_path / "numpy_arrays.joblib"
    _write_joblib_like_pickle(joblib_file, padding=16)

    monkeypatch.setattr(pickle_scanner_module, "_is_legitimate_serialization_file", lambda _path: True)
    monkeypatch.setattr(pickle_scanner_module, "_joblib_numpy_array_wrapper_origin_is_trusted", lambda: False)

    scanner = PickleScanner()
    result = scanner._create_result()
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
    result.add_check(
        name="Pickle Global Import",
        passed=False,
        message="Global import joblib.numpy_pickle.NumpyArrayWrapper is not allowlisted",
        severity=IssueSeverity.WARNING,
        location=str(joblib_file),
        details={"import_reference": "joblib.numpy_pickle.NumpyArrayWrapper"},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )

    scanner._apply_legitimate_joblib_like_pickle_cleanup(result, str(joblib_file))

    assert result.success is False
    assert result.has_warnings or result.metadata.get("scan_outcome") == "inconclusive"
    assert "trusted_incomplete_tail" not in result.metadata


def test_legitimate_serialization_file_rejects_empty_text_and_missing_paths(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.joblib"
    empty_file.write_bytes(b"")
    text_file = tmp_path / "text.joblib"
    text_file.write_text("not a pickle", encoding="utf-8")

    assert _is_legitimate_serialization_file(str(empty_file)) is False
    assert _is_legitimate_serialization_file(str(text_file)) is False
    assert _is_legitimate_serialization_file(str(tmp_path / "missing.joblib")) is False
