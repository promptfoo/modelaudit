"""Deterministic prerequisites required before Nightly timing is trusted."""

import os
import pickle
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import modelaudit_picklescan._rust as picklescan_rust
import pytest
from modelaudit_picklescan import SafetyVerdict, scan_bytes

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import results_have_inconclusive_outcome
from modelaudit.scanners.pickle_scanner import (
    _JOBLIB_NUMPY_ARRAY_WRAPPER_PICKLE_MARKER,
    _JOBLIB_NUMPY_ARRAY_WRAPPER_REFERENCE,
    _is_legitimate_serialization_file,
    _joblib_numpy_array_validated_raw_span_control_references,
)
from tests.helpers.file_creators import create_malicious_pickle, create_safe_pickle


def _create_safe_pickle_payload() -> bytes:
    return pickle.dumps({"weights": list(range(256))}, protocol=4)


def _create_malicious_pickle_payload() -> bytes:
    class MaliciousReduce:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (os.system, ("echo benchmark",))

    return pickle.dumps(MaliciousReduce(), protocol=4)


def test_nightly_inputs_are_complete_and_security_positive(tmp_path: Path) -> None:
    """Nightly inputs need clean coverage and a real S201 malicious signal."""
    safe_path = create_safe_pickle(tmp_path / "safe.pkl")
    malicious_path = create_malicious_pickle(tmp_path / "malicious.pkl")

    safe_result = scan_model_directory_or_file(str(safe_path), cache_enabled=False)
    malicious_result = scan_model_directory_or_file(str(malicious_path), cache_enabled=False)

    for result in (safe_result, malicious_result):
        assert result.has_errors is False
        assert results_have_inconclusive_outcome(result) is False

    assert determine_exit_code(safe_result) == 0
    assert determine_exit_code(malicious_result) == 1
    assert any(
        issue.rule_code == "S201" and issue.message == "Found REDUCE opcode invoking dangerous global: os.system"
        for issue in malicious_result.issues
    )


def test_real_joblib_fixture_has_trusted_numpy_serialization_proof(tmp_path: Path) -> None:
    """Exercise the marker-gated raw-span proof used for real joblib arrays."""
    joblib = pytest.importorskip("joblib")
    numpy = pytest.importorskip("numpy")
    joblib_file = tmp_path / "real.joblib"
    joblib.dump({"weights": numpy.arange(32, dtype=numpy.float32)}, joblib_file, protocol=2)

    contents = joblib_file.read_bytes()
    assert _JOBLIB_NUMPY_ARRAY_WRAPPER_PICKLE_MARKER in contents
    validated_references = _joblib_numpy_array_validated_raw_span_control_references(joblib_file)
    assert _JOBLIB_NUMPY_ARRAY_WRAPPER_REFERENCE in validated_references
    with patch(
        "modelaudit.scanners.pickle_scanner._joblib_numpy_array_validated_raw_span_control_references",
        return_value=validated_references,
    ) as validator:
        assert _is_legitimate_serialization_file(str(joblib_file)) is True
    validator.assert_called_once_with(joblib_file)


def test_compiled_picklescan_path_classifies_nightly_inputs() -> None:
    """Prove correctness on the compiled path before benchmarking its timing."""
    rust_path = Path(cast(Any, picklescan_rust).__file__)
    assert rust_path.name.startswith("_rust")
    assert any(str(rust_path).endswith(suffix) for suffix in EXTENSION_SUFFIXES)

    safe_report = scan_bytes(_create_safe_pickle_payload(), source="safe.pkl")
    malicious_report = scan_bytes(_create_malicious_pickle_payload(), source="malicious.pkl")

    assert safe_report.verdict == SafetyVerdict.CLEAN
    assert malicious_report.verdict == SafetyVerdict.MALICIOUS
