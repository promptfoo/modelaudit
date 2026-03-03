"""
Test suite for sklearn/joblib false positive fix.

This test verifies that removing overly broad patterns from CVE_BINARY_PATTERNS
eliminates false positives on legitimate sklearn and joblib models while
maintaining detection of actual CVE exploitation attempts.
"""

import pickle
import tempfile
from pathlib import Path

import pytest

from modelaudit.core import scan_file
from modelaudit.scanners.base import IssueSeverity

# Skip tests if sklearn is not available
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


@pytest.mark.skipif(not HAS_SKLEARN, reason="sklearn not installed")
class TestSklearnJoblibFalsePositive:
    """Test suite for sklearn/joblib false positive fixes."""

    def test_sklearn_model_no_legacy_pattern_warnings(self, tmp_path):
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

        # Save as pickle
        model_path = tmp_path / "sklearn_model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        # Scan the model
        result = scan_file(str(model_path))

        # Check for legacy pattern WARNINGs
        legacy_warnings = [
            issue for issue in result.issues if "Legacy" in issue.message and issue.severity == IssueSeverity.WARNING
        ]

        # Should NOT have any legacy pattern WARNINGs for "sklearn"
        sklearn_warnings = [issue for issue in legacy_warnings if "sklearn" in issue.message.lower()]

        assert len(sklearn_warnings) == 0, (
            f"Found {len(sklearn_warnings)} false positive sklearn warnings: {[w.message for w in sklearn_warnings]}"
        )

    def test_sklearn_pipeline_no_legacy_pattern_warnings(self, tmp_path):
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

        # Save as pickle
        model_path = tmp_path / "pipeline_model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(pipe, f)

        # Scan the model
        result = scan_file(str(model_path))

        # Check for legacy pattern WARNINGs mentioning Pipeline
        pipeline_warnings = [
            issue
            for issue in result.issues
            if "Legacy" in issue.message and issue.severity == IssueSeverity.WARNING and "Pipeline" in issue.message
        ]

        assert len(pipeline_warnings) == 0, (
            f"Found {len(pipeline_warnings)} false positive Pipeline warnings: {[w.message for w in pipeline_warnings]}"
        )

    def test_sklearn_model_no_exit_code_1_from_patterns(self, tmp_path):
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

        # Save as pickle
        model_path = tmp_path / "sklearn_rf.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        # Scan the model
        result = scan_file(str(model_path))

        # Check for legacy pattern WARNINGs that would cause exit code 1
        legacy_warnings = [
            issue
            for issue in result.issues
            if "Legacy" in issue.message
            and issue.severity == IssueSeverity.WARNING
            and any(pattern in issue.message.lower() for pattern in ["sklearn", "numpyarraywrapper", "numpy_pickle"])
        ]

        assert len(legacy_warnings) == 0, (
            f"Found {len(legacy_warnings)} false positive legacy warnings that would cause exit code 1"
        )

    def test_joblib_patterns_not_flagged(self, tmp_path):
        """
        Verify joblib-specific patterns (NumpyArrayWrapper, numpy_pickle) don't trigger warnings.

        Before fix: NumpyArrayWrapper and numpy_pickle triggered WARNINGs
        After fix: These patterns should not be flagged as they are legitimate joblib internals
        """
        # Create a simple sklearn model
        X = np.array([[0], [1], [2]])
        y = np.array([0, 1, 1])
        model = LogisticRegression()
        model.fit(X, y)

        # Save as pickle (may contain joblib references)
        model_path = tmp_path / "model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        # Scan the model
        result = scan_file(str(model_path))

        # Check for joblib-related legacy pattern WARNINGs
        joblib_warnings = [
            issue
            for issue in result.issues
            if "Legacy" in issue.message
            and issue.severity == IssueSeverity.WARNING
            and any(pattern in issue.message.lower() for pattern in ["numpyarraywrapper", "numpy_pickle"])
        ]

        assert len(joblib_warnings) == 0, (
            f"Found {len(joblib_warnings)} false positive joblib warnings: {[w.message for w in joblib_warnings]}"
        )

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


@pytest.mark.skipif(not HAS_SKLEARN, reason="sklearn not installed")
def test_false_positive_summary():
    """
    Integration test: Verify the fix reduces false positives.

    This test documents the improvement from the fix:
    - Before: 10 false positive WARNINGs on sklearn/joblib models
    - After: 0 false positive WARNINGs from legacy pattern detection
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # Create multiple sklearn models
        X = np.array([[0, 0], [1, 1], [2, 2]])
        y = np.array([0, 1, 1])

        models = {
            "logistic.pkl": LogisticRegression(),
            "rf.pkl": RandomForestClassifier(n_estimators=2, max_depth=2, random_state=42),
        }

        total_legacy_warnings = 0

        for filename, model in models.items():
            model.fit(X, y)
            model_path = tmp_path / filename

            with open(model_path, "wb") as f:
                pickle.dump(model, f)

            # Scan and count legacy pattern WARNINGs
            result = scan_file(str(model_path))

            legacy_warnings = [
                issue
                for issue in result.issues
                if "Legacy" in issue.message
                and issue.severity == IssueSeverity.WARNING
                and any(
                    pattern in issue.message for pattern in ["sklearn", "NumpyArrayWrapper", "numpy_pickle", "Pipeline"]
                )
            ]

            total_legacy_warnings += len(legacy_warnings)

        # After fix: Should have 0 false positive legacy pattern WARNINGs
        assert total_legacy_warnings == 0, (
            f"Expected 0 false positive legacy warnings after fix, but found {total_legacy_warnings}"
        )
