"""Deterministic proofs required before Nightly performance timing is trusted."""

from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from statistics import median
from time import process_time_ns
from typing import Any, cast

import modelaudit_picklescan._rust as picklescan_rust
import pytest
from modelaudit_picklescan import SafetyVerdict, scan_bytes

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import results_have_inconclusive_outcome
from modelaudit.scanners.pickle_scanner import _is_legitimate_serialization_file
from tests.helpers.file_creators import create_malicious_pickle, create_safe_pickle

_CPU_SCAN_ROUNDS = 9
_SAFE_MEDIAN_SECONDS_MAX = 0.006
_MALICIOUS_MEDIAN_SECONDS_MAX = 0.024


def _scan_cpu_median(payload: bytes, *, source: str) -> tuple[float, SafetyVerdict]:
    for _ in range(2):
        scan_bytes(payload, source=source)

    durations: list[float] = []
    verdict = SafetyVerdict.UNKNOWN
    for _ in range(_CPU_SCAN_ROUNDS):
        start = process_time_ns()
        report = scan_bytes(payload, source=source)
        durations.append((process_time_ns() - start) / 1_000_000_000)
        verdict = report.verdict

    return median(durations), verdict


def test_performance_inputs_are_complete_and_security_positive(tmp_path: Path) -> None:
    """Performance inputs need clean coverage and a real S201 malicious signal."""
    safe_path = create_safe_pickle(tmp_path / "safe.pkl")
    malicious_path = create_malicious_pickle(tmp_path / "malicious.pkl")

    safe_result = scan_model_directory_or_file(str(safe_path), cache_enabled=False)
    malicious_result = scan_model_directory_or_file(str(malicious_path), cache_enabled=False)

    for result in (safe_result, malicious_result):
        assert result.has_errors is False
        assert results_have_inconclusive_outcome(result) is False

    assert determine_exit_code(safe_result) == 0
    assert determine_exit_code(malicious_result) == 1
    assert any(issue.rule_code == "S201" for issue in malicious_result.issues)


def test_real_joblib_fixture_has_trusted_serialization_proof(tmp_path: Path) -> None:
    """Nightly has the existing joblib extra and must exercise its real helper."""
    joblib = pytest.importorskip("joblib")
    joblib_file = tmp_path / "real.joblib"
    joblib.dump({"weights": list(range(32))}, joblib_file)

    assert _is_legitimate_serialization_file(str(joblib_file)) is True


def test_compiled_picklescan_cpu_medians_stay_within_existing_bounds() -> None:
    """Use CPU time and the compiled Rust path for deterministic timing proof."""
    rust_path = Path(cast(Any, picklescan_rust).__file__)
    assert rust_path.name.startswith("_rust")
    assert any(str(rust_path).endswith(suffix) for suffix in EXTENSION_SUFFIXES)

    safe_payload = create_safe_pickle_payload()
    malicious_payload = create_malicious_pickle_payload()
    safe_median, safe_verdict = _scan_cpu_median(safe_payload, source="safe.pkl")
    malicious_median, malicious_verdict = _scan_cpu_median(malicious_payload, source="malicious.pkl")

    assert safe_verdict == SafetyVerdict.CLEAN
    assert malicious_verdict == SafetyVerdict.MALICIOUS
    assert safe_median < _SAFE_MEDIAN_SECONDS_MAX
    assert malicious_median < _MALICIOUS_MEDIAN_SECONDS_MAX


def create_safe_pickle_payload() -> bytes:
    import pickle

    return pickle.dumps({"weights": list(range(256))}, protocol=4)


def create_malicious_pickle_payload() -> bytes:
    import os
    import pickle

    class MaliciousReduce:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (os.system, ("echo benchmark",))

    return pickle.dumps(MaliciousReduce(), protocol=4)
