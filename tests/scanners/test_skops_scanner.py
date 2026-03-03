"""Tests for SkopsScanner covering CVE-2025-54412, CVE-2025-54413, CVE-2025-54886."""

import os
import zipfile
from pathlib import Path

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.skops_scanner import SkopsScanner

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "samples")


class TestSkopsScannerCanHandle:
    """Test the can_handle method."""

    def test_can_handle_skops_extension(self, tmp_path: Path) -> None:
        """Test that scanner handles .skops files."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')

        assert SkopsScanner.can_handle(str(skops_file)) is True

    def test_cannot_handle_non_skops_extension(self, tmp_path: Path) -> None:
        """Test that scanner rejects non-.skops files."""
        other_file = tmp_path / "model.pkl"
        other_file.write_bytes(b"not a skops file")

        assert SkopsScanner.can_handle(str(other_file)) is False

    def test_cannot_handle_nonexistent_file(self) -> None:
        """Test that scanner rejects nonexistent files."""
        assert SkopsScanner.can_handle("/nonexistent/path/model.skops") is False

    def test_cannot_handle_directory(self, tmp_path: Path) -> None:
        """Test that scanner rejects directories."""
        skops_dir = tmp_path / "model.skops"
        skops_dir.mkdir()

        assert SkopsScanner.can_handle(str(skops_dir)) is False


class TestSkopsScannerCVE2025_54412:
    """Test CVE-2025-54412: OperatorFuncNode trusted-type confusion detection."""

    def test_detects_operatorfuncnode_pattern(self, tmp_path: Path) -> None:
        """Test detection of OperatorFuncNode pattern in file names."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("OperatorFuncNode_exploit.json", '{"type": "exploit"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_reduce_pattern_no_false_positive(self, tmp_path: Path) -> None:
        """Test that __reduce__ filenames do NOT trigger CVE-2025-54412.

        __reduce__ is a standard Python serialization method used by ALL
        sklearn Cython types (e.g. sklearn.tree._tree.Tree).  It was
        intentionally removed from CVE-2025-54412 pattern matching to
        prevent false positives on legitimate models.
        """
        skops_file = tmp_path / "legitimate.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("__reduce__payload.bin", b"malicious content")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        # __reduce__ alone should NOT trigger CVE-2025-54412
        failed = [c for c in cve_checks if c.status == CheckStatus.FAILED]
        assert len(failed) == 0

    def test_no_false_positive_clean_file(self, tmp_path: Path) -> None:
        """Test that clean skops files don't trigger CVE-2025-54412."""
        skops_file = tmp_path / "clean.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("model.bin", b"model weights")
            zf.writestr("metadata.json", '{"name": "clean_model"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_54412_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        # Should not have any CVE-2025-54412 failed checks
        failed = [c for c in cve_54412_checks if c.status == CheckStatus.FAILED]
        assert len(failed) == 0


class TestSkopsScannerCVE2025_54413:
    """Test CVE-2025-54413: MethodNode inconsistency detection."""

    def test_detects_methodnode_pattern(self, tmp_path: Path) -> None:
        """Test detection of MethodNode pattern in file names."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("MethodNode_accessor.json", '{"type": "method"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_detects_getattr_pattern(self, tmp_path: Path) -> None:
        """Test detection of __getattr__ pattern."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("__getattr__hook.py", "malicious code")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL


class TestSkopsScannerCVE2025_54886:
    """Test CVE-2025-54886: Card.get_model silent joblib fallback detection."""

    def test_detects_card_with_get_model(self, tmp_path: Path) -> None:
        """Test detection of Card.get_model with joblib references."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            card_content = """
            # Model Card
            This model uses get_model() to load the model.
            Fallback to joblib for compatibility.
            """
            zf.writestr("model_card.md", card_content)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54886" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_detects_readme_with_joblib(self, tmp_path: Path) -> None:
        """Test detection of README with joblib fallback pattern."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            readme_content = """
            # Model README
            Load the model using joblib.load() if skops fails.
            """
            zf.writestr("README.md", readme_content)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54886" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL


class TestSkopsScannerJoblibFallback:
    """Test unsafe joblib fallback detection."""

    def test_detects_joblib_load_pattern(self, tmp_path: Path) -> None:
        """Test detection of joblib.load patterns in file content."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("model.pkl", b"joblib.load(model_path)")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name]
        assert len(joblib_checks) > 0
        assert joblib_checks[0].status == CheckStatus.FAILED
        assert joblib_checks[0].severity == IssueSeverity.WARNING

    def test_detects_pickle_load_pattern(self, tmp_path: Path) -> None:
        """Test detection of pickle.load patterns."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("loader.py", b"import pickle\npickle.load(f)")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name]
        assert len(joblib_checks) > 0
        assert joblib_checks[0].status == CheckStatus.FAILED
        assert joblib_checks[0].severity == IssueSeverity.WARNING

    def test_no_false_positive_sklearn_in_schema_json(self, tmp_path: Path) -> None:
        """Regression: schema.json with sklearn type refs must NOT trigger joblib fallback.

        Real .skops files contain a schema.json that references sklearn module
        paths (e.g. "sklearn.linear_model.LogisticRegression"). These are type
        schema references, not pickle/joblib deserialization code.
        """
        skops_file = tmp_path / "legit.skops"
        schema_content = (
            '{"__class__": "sklearn.linear_model._logistic.LogisticRegression",'
            ' "__module__": "sklearn.linear_model._logistic",'
            ' "content": {"C": {"__class__": "float", "content": 1.0}}}'
        )
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", schema_content)
            zf.writestr("step/0/content/0.npy", b"\x93NUMPY\x01\x00model data")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name and c.status == CheckStatus.FAILED]
        assert len(joblib_checks) == 0, (
            f"False positive: schema.json triggered Unsafe Joblib Fallback Detection: {joblib_checks}"
        )

    def test_no_false_positive_sklearn_in_schema_bare(self, tmp_path: Path) -> None:
        """Regression: bare 'schema' file (no .json ext) must also be excluded.

        Some skops archives use a file named just ``schema`` without the
        ``.json`` extension.  The metadata exclusion must cover both variants.
        """
        skops_file = tmp_path / "legit_bare.skops"
        schema_content = (
            '{"__class__": "sklearn.ensemble._forest.RandomForestClassifier",'
            ' "__module__": "sklearn.ensemble._forest",'
            ' "content": {"n_estimators": {"__class__": "int", "content": 100}}}'
        )
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema", schema_content)
            zf.writestr("step/0/content/0.npy", b"\x93NUMPY\x01\x00model data")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name and c.status == CheckStatus.FAILED]
        assert len(joblib_checks) == 0, (
            f"False positive: bare 'schema' file triggered Unsafe Joblib Fallback Detection: {joblib_checks}"
        )

    def test_sklearn_in_data_file_still_detected(self, tmp_path: Path) -> None:
        """Ensure sklearn references in non-metadata files are still flagged."""
        skops_file = tmp_path / "suspicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            # sklearn reference in a data file IS suspicious
            zf.writestr("payload.bin", b"import sklearn; sklearn.externals.joblib.load(f)")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name and c.status == CheckStatus.FAILED]
        assert len(joblib_checks) > 0, "sklearn in a data file should still be flagged"


class TestSkopsScannerEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_empty_archive(self, tmp_path: Path) -> None:
        """Test handling of empty ZIP archive."""
        skops_file = tmp_path / "empty.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            pass  # Create empty archive

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should complete without error
        assert result.success is True

    def test_handles_corrupted_file(self, tmp_path: Path) -> None:
        """Test handling of corrupted/non-ZIP file."""
        skops_file = tmp_path / "corrupted.skops"
        skops_file.write_bytes(b"not a valid zip file content")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should have at least one check about the file
        assert len(result.checks) > 0

    def test_handles_deeply_nested_files(self, tmp_path: Path) -> None:
        """Test handling of deeply nested file paths."""
        skops_file = tmp_path / "nested.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            deep_path = "/".join(["dir"] * 10) + "/model.bin"
            zf.writestr(deep_path, b"model data")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should complete without error
        assert result.success is True

    def test_handles_unicode_filenames(self, tmp_path: Path) -> None:
        """Test handling of unicode characters in filenames."""
        skops_file = tmp_path / "unicode.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("模型_data.json", '{"name": "test"}')
            zf.writestr("données_modèle.bin", b"model data")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should complete without error
        assert result.success is True

    def test_handles_decompression_bomb(self, tmp_path: Path) -> None:
        """Test that archives exceeding max file count are rejected."""
        skops_file = tmp_path / "bomb.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.bin", b"data")

        scanner = SkopsScanner(config={"max_files_in_archive": 5})
        result = scanner.scan(str(skops_file))

        assert result.success is False
        bomb_checks = [c for c in result.checks if "Archive Bomb" in c.name]
        assert len(bomb_checks) > 0
        assert bomb_checks[0].status == CheckStatus.FAILED


class TestSkopsScannerMultipleCVEs:
    """Test detection of multiple CVEs in a single file."""

    def test_detects_multiple_cves(self, tmp_path: Path) -> None:
        """Test that scanner can detect multiple CVEs in one file."""
        skops_file = tmp_path / "multi_exploit.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            # CVE-2025-54412 pattern
            zf.writestr("OperatorFuncNode.json", '{"exploit": true}')
            # CVE-2025-54413 pattern
            zf.writestr("MethodNode_hook.py", "malicious")
            # CVE-2025-54886 pattern
            zf.writestr("model_card.md", "use get_model() with joblib fallback")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should detect all three CVEs
        cve_54412 = [c for c in result.checks if "CVE-2025-54412" in c.name]
        cve_54413 = [c for c in result.checks if "CVE-2025-54413" in c.name]
        cve_54886 = [c for c in result.checks if "CVE-2025-54886" in c.name]

        assert len(cve_54412) > 0
        assert len(cve_54413) > 0
        assert len(cve_54886) > 0

        # All failed checks should be critical
        all_cve_checks = cve_54412 + cve_54413 + cve_54886
        for check in all_cve_checks:
            if check.status == CheckStatus.FAILED:
                assert check.severity == IssueSeverity.CRITICAL


class TestSkopsScannerCVEDetails:
    """Test that CVE details are properly populated."""

    def test_cve_details_include_required_fields(self, tmp_path: Path) -> None:
        """Test that CVE checks include all required detail fields."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("OperatorFuncNode.json", '{"exploit": true}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name and c.status == CheckStatus.FAILED]
        assert len(cve_checks) > 0

        check = cve_checks[0]
        details = check.details

        # Verify required fields
        assert "cve_id" in details
        assert "cvss" in details
        assert "cwe" in details
        assert "affected_versions" in details
        assert "remediation" in details
        assert "skops < 0.12.0" in details["affected_versions"]
        assert "0.12.0" in details["remediation"]


class TestSkopsScannerRealModel:
    """Integration tests using a real .skops model from HuggingFace."""

    REAL_SKOPS = os.path.join(SAMPLES_DIR, "pipeline.skops")

    @pytest.mark.skipif(
        not os.path.isfile(os.path.join(SAMPLES_DIR, "pipeline.skops")),
        reason="Real .skops sample not available",
    )
    def test_can_handle_real_skops_model(self) -> None:
        """Test that scanner recognises a real .skops file (scikit-learn/persistence)."""
        assert SkopsScanner.can_handle(self.REAL_SKOPS) is True

    @pytest.mark.skipif(
        not os.path.isfile(os.path.join(SAMPLES_DIR, "pipeline.skops")),
        reason="Real .skops sample not available",
    )
    def test_scan_real_skops_model_no_cve_false_positives(self) -> None:
        """Test that a legitimate model doesn't trigger CVE detections."""
        scanner = SkopsScanner()
        result = scanner.scan(self.REAL_SKOPS)

        assert result.success is True

        # No CVE checks should fail on a legitimate model
        cve_failed = [
            c
            for c in result.checks
            if any(cve in c.name for cve in ["CVE-2025-54412", "CVE-2025-54413", "CVE-2025-54886"])
            and c.status == CheckStatus.FAILED
        ]
        assert len(cve_failed) == 0, f"False positive CVE detections: {[c.name for c in cve_failed]}"

    @pytest.mark.skipif(
        not os.path.isfile(os.path.join(SAMPLES_DIR, "pipeline.skops")),
        reason="Real .skops sample not available",
    )
    def test_scan_real_skops_model_metadata(self) -> None:
        """Test that scan metadata is populated for a real model."""
        scanner = SkopsScanner()
        result = scanner.scan(self.REAL_SKOPS)

        assert result.metadata.get("file_size", 0) > 0
        assert result.metadata.get("file_count", 0) > 0
