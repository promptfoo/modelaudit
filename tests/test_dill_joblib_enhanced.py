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
    path.write_bytes(b"\x80\x04cjoblib.numpy_pickle\nNumpyArrayWrapper\nq\x00." + b"\x00" * padding)


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


def test_legitimate_joblib_like_pickle_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    joblib_file = tmp_path / "numpy_arrays.joblib"
    _write_joblib_like_pickle(joblib_file, padding=16)

    def trusted_joblib_wrapper(module: str, name: str) -> bool:
        return (module, name) == ("joblib.numpy_pickle", "NumpyArrayWrapper")

    monkeypatch.setattr(
        "modelaudit.scanners.pickle_scanner.import_only_reference_is_proven_trusted",
        trusted_joblib_wrapper,
    )
    monkeypatch.setattr(
        "modelaudit_picklescan.api.import_only_reference_is_proven_trusted",
        trusted_joblib_wrapper,
    )

    result = PickleScanner().scan(str(joblib_file))

    assert _is_legitimate_serialization_file(str(joblib_file)) is True
    assert result.success is True
    assert result.metadata["trusted_incomplete_tail"] is True
    assert result.metadata["trusted_incomplete_tail_reason"] == "joblib_pickle_tail"
    assert "scan_outcome" not in result.metadata
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]


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

    assert any(
        issue.severity == IssueSeverity.WARNING
        and issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("import_reference") == "joblib.numpy_pickle.NumpyArrayWrapper"
        for issue in result.issues
    )
    assert "trusted_incomplete_tail" not in result.metadata


def test_legitimate_serialization_file_rejects_empty_text_and_missing_paths(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.joblib"
    empty_file.write_bytes(b"")
    text_file = tmp_path / "text.joblib"
    text_file.write_text("not a pickle", encoding="utf-8")

    assert _is_legitimate_serialization_file(str(empty_file)) is False
    assert _is_legitimate_serialization_file(str(text_file)) is False
    assert _is_legitimate_serialization_file(str(tmp_path / "missing.joblib")) is False
