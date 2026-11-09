"""
Test suite for sklearn/joblib false positive fix.

This test verifies that removing overly broad patterns from CVE_BINARY_PATTERNS
eliminates false positives on legitimate sklearn and joblib models while
maintaining detection of actual CVE exploitation attempts.
"""

import pickle
from pathlib import Path

import pytest

from modelaudit.core import scan_file
from modelaudit.scanners.base import IssueSeverity

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


requires_sklearn = pytest.mark.skipif(not HAS_SKLEARN, reason="sklearn not installed")


def _assert_no_legacy_findings(model_path: Path, *patterns: str) -> None:
    result = scan_file(str(model_path))
    assert result.success
    assert result.bytes_scanned == model_path.stat().st_size
    assert result.metadata.get("opcode_count", 0) > 0

    findings = [
        issue.message
        for issue in result.issues
        if "Legacy" in issue.message
        and issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        and any(pattern.lower() in issue.message.lower() for pattern in patterns)
    ]
    assert not findings, f"{model_path.name}: {findings}"


class TestSklearnJoblibFalsePositive:
    """Test suite for sklearn/joblib false positive fixes."""

    @requires_sklearn
    def test_sklearn_model_no_legacy_pattern_warnings(self, tmp_path: Path) -> None:
        """
        Verify legitimate sklearn models don't trigger legacy pattern WARNINGs.

        Before fix: sklearn models triggered WARNING for "sklearn" pattern
        After fix: sklearn models should not trigger legacy pattern WARNINGs
        """
        # Create a simple sklearn model
        X = np.array([[0, 0], [1, 1], [2, 2]])
        y = np.array([0, 1, 1])
        model = LogisticRegression()
        model.fit(X, y)

        model_path = tmp_path / "sklearn_model.pkl"
        model_path.write_bytes(pickle.dumps(model))
        _assert_no_legacy_findings(model_path, "sklearn")

    @requires_sklearn
    def test_sklearn_pipeline_no_legacy_pattern_warnings(self, tmp_path: Path) -> None:
        """
        Verify sklearn Pipeline models don't trigger legacy pattern WARNINGs.

        Before fix: Pipeline models triggered WARNING for "Pipeline" pattern
        because b"Pipeline" in CVE_BINARY_PATTERNS matched the class name
        sklearn.pipeline.Pipeline present in all serialized Pipeline objects.
        After fix: Pipeline models should not trigger legacy pattern WARNINGs.
        """
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        # Create a Pipeline model (the most common sklearn pattern)
        pipe = Pipeline([("scaler", StandardScaler()), ("clf", LogisticRegression())])
        X = np.array([[0, 0], [1, 1], [2, 2]])
        y = np.array([0, 1, 1])
        pipe.fit(X, y)

        model_path = tmp_path / "pipeline_model.pkl"
        model_path.write_bytes(pickle.dumps(pipe))
        _assert_no_legacy_findings(model_path, "Pipeline")

    @requires_sklearn
    def test_sklearn_model_no_exit_code_1_from_patterns(self, tmp_path: Path) -> None:
        """
        Verify sklearn models don't cause exit code 1 due to legacy patterns.

        Before fix: sklearn pattern triggered WARNING -> exit code 1
        After fix: No legacy pattern WARNINGs -> exit code depends on other checks
        """
        # Create a sklearn model
        X = np.array([[0, 0], [1, 1]])
        y = np.array([0, 1])
        model = RandomForestClassifier(n_estimators=2, max_depth=2, random_state=42)
        model.fit(X, y)

        model_path = tmp_path / "sklearn_rf.pkl"
        model_path.write_bytes(pickle.dumps(model))
        _assert_no_legacy_findings(model_path, "sklearn", "NumpyArrayWrapper", "numpy_pickle")

    @requires_sklearn
    def test_joblib_patterns_not_flagged(self, tmp_path: Path) -> None:
        """
        Verify joblib-specific patterns (NumpyArrayWrapper, numpy_pickle) don't trigger warnings.

        Before fix: NumpyArrayWrapper and numpy_pickle triggered WARNINGs
        After fix: These patterns should not be flagged as they are legitimate joblib internals
        """
        import joblib

        # Create a simple sklearn model
        X = np.array([[0], [1], [2]])
        y = np.array([0, 1, 1])
        model = LogisticRegression()
        model.fit(X, y)

        model_path = tmp_path / "model.pkl"
        model_path.write_bytes(pickle.dumps(model))
        _assert_no_legacy_findings(model_path, "NumpyArrayWrapper", "numpy_pickle")

        joblib_path = tmp_path / "model.joblib"
        joblib.dump(model, joblib_path, compress=0)
        payload = joblib_path.read_bytes()
        assert b"NumpyArrayWrapper" in payload
        assert b"numpy_pickle" in payload
        _assert_no_legacy_findings(joblib_path, "NumpyArrayWrapper", "numpy_pickle")

    def test_malicious_patterns_still_detected(self, tmp_path):
        """
        Security validation: Verify actual malicious patterns are still detected.

        This test ensures that removing sklearn/NumpyArrayWrapper/numpy_pickle patterns
        doesn't weaken security - real threats like os.system should still be caught.
        """
        # Create a malicious pickle with os.system
        malicious_code = b"""cos
system
(S'echo malicious'
tR."""

        malicious_path = tmp_path / "malicious.pkl"
        with open(malicious_path, "wb") as f:
            f.write(malicious_code)

        # Scan the malicious file
        result = scan_file(str(malicious_path))

        # Should still detect os.system as a threat
        has_system_warning = any(
            "system" in issue.message.lower() and issue.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
            for issue in result.issues
        )

        assert has_system_warning, (
            "Malicious os.system pattern should still be detected after removing sklearn patterns"
        )

    def test_scanner_handles_malformed_content(self, tmp_path):
        """
        Robustness check: Verify scanner handles malformed files without crashing.

        This test ensures that removing binary patterns doesn't break the scanner's
        ability to process files, even if they contain suspicious-looking text strings.
        This is NOT a CVE detection test (that would require valid pickle format).
        """
        # Create a file with suspicious text (not a valid pickle)
        suspicious_content = b"""sklearn.linear_model.LogisticRegression joblib.load os.system"""

        test_path = tmp_path / "malformed.pkl"
        with open(test_path, "wb") as f:
            f.write(suspicious_content)

        # Scan the file - should not crash
        result = scan_file(str(test_path))

        # This is a robustness test, not a CVE detection test
        # We just verify the scanner processes the file without errors
        assert result is not None, "Scanner should still process the file without crashing"


@requires_sklearn
def test_false_positive_summary(tmp_path: Path) -> None:
    """
    Integration test: Verify the fix reduces false positives.

    This test documents the improvement from the fix:
    - Before: 10 false positive WARNINGs on sklearn/joblib models
    - After: 0 false positive WARNINGs from legacy pattern detection
    """
    X = np.array([[0, 0], [1, 1], [2, 2]])
    y = np.array([0, 1, 1])

    models = {
        "logistic.pkl": LogisticRegression(),
        "rf.pkl": RandomForestClassifier(n_estimators=2, max_depth=2, random_state=42),
    }

    for filename, model in models.items():
        model.fit(X, y)
        model_path = tmp_path / filename
        model_path.write_bytes(pickle.dumps(model))
        _assert_no_legacy_findings(model_path, "sklearn", "NumpyArrayWrapper", "numpy_pickle", "Pipeline")
