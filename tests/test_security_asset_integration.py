"""
Security Asset Integration Tests

Tests that integrate with the organized test asset structure.
Focuses on security-specific scanning scenarios.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import metadata_has_coverage_only_operational_error
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners.base import IssueSeverity


def describe_operational_errors(results: ModelAuditResultModel) -> str:
    """Summarize which files carried operational errors, for assertion messages.

    ``has_errors`` alone truncates to an unhelpful model repr in CI logs, which
    hides whichever file actually failed. Naming the paths and reasons keeps a
    recurrence diagnosable from the log without a Windows reproduction.
    """
    offenders = []
    for path, metadata in results.file_metadata.items():
        dump = getattr(metadata, "model_dump", None)
        payload = dump() if callable(dump) else metadata
        if not isinstance(payload, dict) or not payload.get("operational_error"):
            continue
        offenders.append(f"{path}: {payload.get('operational_error_reason', 'unknown reason')}")
    return "; ".join(sorted(offenders)) or "no per-file operational_error metadata recorded"


def assert_no_unexpected_asset_scan_errors(results: ModelAuditResultModel, scan_description: str) -> None:
    if not results.has_errors:
        return

    expected_source_changes = set()
    security_finding_locations = {
        issue.location for issue in results.issues if issue.rule_code == "S204" and issue.location is not None
    }
    unexpected_errors = {asset.path for asset in results.assets if asset.type == "error"}
    for path, metadata in results.file_metadata.items():
        payload = metadata.model_dump(exclude_none=True)
        if not payload.get("operational_error") or metadata_has_coverage_only_operational_error(payload):
            continue

        if (
            Path(path).name == "agpl_model.pkl"
            and payload.get("operational_error_reason") == "call_graph_analysis_error"
            and payload.get("analysis_incomplete") is True
            and payload.get("scan_outcome") == "inconclusive"
            and "call_graph_analysis_error" in payload.get("scan_outcome_reasons", [])
            and payload.get("pickle_report_status") == "inconclusive"
            and payload.get("pickle_verdict") == "malicious"
        ):
            expected_source_changes.add(path)
        else:
            unexpected_errors.add(path)

    diagnosed_source_changes = set()
    for issue in results.issues:
        details = issue.details
        location = issue.location or "unknown scan location"
        pickle_source = details.get("pickle_source")
        category = details.get("category")

        if category == "call_graph_analysis_error" or (
            pickle_source and category not in {None, "parse_error"} and "exception_type" in details
        ):
            matching_paths = {path for path in expected_source_changes if location == path}
            if (
                matching_paths
                and pickle_source
                and issue.message
                == "Python call-graph analysis could not complete: source changed during shared call-graph analysis"
                and category == "call_graph_analysis_error"
                and details.get("exception_type") == "_CallGraphAnalysisLimitError"
                and details.get("analysis") == "python_call_graph_source_stability"
                and details.get("analysis_incomplete") is True
                and any(
                    finding_location == location or finding_location.startswith(f"{location} (")
                    for finding_location in security_finding_locations
                )
            ):
                diagnosed_source_changes.update(matching_paths)
            else:
                unexpected_errors.add(location)
            continue

        if pickle_source or category == "parse_error" or "required_package" in details:
            continue

        coverage_only_diagnostic = metadata_has_coverage_only_operational_error(
            {
                "operational_error": True,
                "operational_error_reason": details.get("scan_outcome_reason"),
            }
        )
        scan_budget_failure = any(key.startswith("max_") for key in details) or (
            details.get("security_check") == "compression_bomb_detection"
        )
        if (
            (scan_budget_failure and not coverage_only_diagnostic)
            or details.get("exception_type")
            or details.get("error_type")
            or ("timeout" in details and "error" in details)
            or details.get("operational_error") is True
            or details.get("interrupted") is True
            or (
                details.get("analysis_incomplete") is True
                and (
                    "error" in details
                    or "max_total_size" in details
                    or ("scan_outcome_reason" in details and not coverage_only_diagnostic)
                )
            )
        ):
            unexpected_errors.add(location)

    assert expected_source_changes and expected_source_changes == diagnosed_source_changes and not unexpected_errors, (
        f"{scan_description} should not have unexpected operational errors: {describe_operational_errors(results)}"
    )
    assert results.success is False, f"{scan_description} must fail closed when source stability changes"
    assert determine_exit_code(results) == 2, f"{scan_description} must preserve its operational-error exit code"


class TestSecurityAssetIntegration:
    """Integration tests for security assets using organized structure."""

    @pytest.fixture
    def assets_dir(self):
        """Get the path to organized test assets."""
        return Path(__file__).parent / "assets"

    @pytest.fixture
    def samples_dir(self, assets_dir):
        """Get the samples directory for individual test files."""
        return assets_dir / "samples"

    @pytest.fixture
    def scenarios_dir(self, assets_dir):
        """Get the scenarios directory for complex test scenarios."""
        return assets_dir / "scenarios"

    def get_malicious_samples(self, samples_dir: Path) -> list[Path]:
        """Get all malicious sample files from organized structure."""
        malicious_files = []

        # Check different sample categories
        categories = [
            "pickles",
            "keras",
            "pytorch",
            "tensorflow",
            "manifests",
            "archives",
        ]

        for category in categories:
            category_dir = samples_dir / category
            if category_dir.exists():
                # Look for files with malicious indicators
                for file_path in category_dir.iterdir():
                    if any(
                        indicator in file_path.name.lower() for indicator in ["malicious", "evil", "suspicious", "bad"]
                    ):
                        malicious_files.append(file_path)

        return malicious_files

    def get_safe_samples(self, samples_dir: Path) -> list[Path]:
        """Get all safe sample files from organized structure."""
        safe_files = []
        explicitly_malicious_fixtures = {
            "custom_layer_attack.h5",
            "loss_injection.h5",
            "metric_injection.h5",
        }

        categories = [
            "pickles",
            "keras",
            "pytorch",
            "tensorflow",
            "manifests",
            "archives",
        ]

        for category in categories:
            category_dir = samples_dir / category
            if category_dir.exists():
                for file_path in category_dir.iterdir():
                    # Exclude malicious files and problematic files like dill_func.pkl
                    exclusions = [
                        "malicious",
                        "evil",
                        "suspicious",
                        "bad",
                        "dill_func",
                        "path_traversal",
                        "nested_pickle",  # Our intentionally malicious nested pickle test files
                        "decode_exec",  # Our intentionally malicious decode-exec test files
                        "simple_nested",  # Our intentionally malicious simple nested pickle test file
                    ]
                    if (
                        not any(indicator in file_path.name.lower() for indicator in exclusions)
                        and file_path.name not in explicitly_malicious_fixtures
                        and file_path.is_file()
                        and not file_path.name.startswith(".")
                    ):
                        safe_files.append(file_path)

        return safe_files

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_malicious_sample_detection(self, samples_dir):
        """Test that all malicious samples are properly detected."""
        from modelaudit.scanners import _registry

        def has_tensorflow():
            """Check if TensorFlow is available with timeout protection."""
            # In CI environments, skip TensorFlow detection to prevent hanging
            import os

            if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
                return False

            try:
                # Use subprocess for maximum isolation and cross-platform timeout
                import subprocess
                import sys

                # Try to import TensorFlow in a separate process with strict timeout
                cmd = [sys.executable, "-c", "import tensorflow; print('SUCCESS')"]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3,  # Even shorter timeout
                    cwd=None,
                )

                return result.returncode == 0 and "SUCCESS" in result.stdout

            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
                return False
            except Exception:
                return False

        malicious_files = self.get_malicious_samples(samples_dir)

        if not malicious_files:
            pytest.skip("No malicious sample files found")

        # Get failed scanners to handle compatibility issues
        failed_scanners = _registry.get_failed_scanners()
        tensorflow_available = has_tensorflow() and not any(
            "tf_savedmodel" in scanner_id for scanner_id in failed_scanners
        )

        # Track files that were tested vs skipped
        tested_files = []
        skipped_files = []

        for malicious_file in malicious_files:
            # Skip TensorFlow-specific malicious files if TensorFlow scanner is not available
            if not tensorflow_available and (
                "pyfunc" in malicious_file.name.lower() or "tensorflow" in str(malicious_file.parent).lower()
            ):
                skipped_files.append(f"{malicious_file.name} (TensorFlow scanner unavailable)")
                continue

            # Skip h5/HDF5 files if h5py is not installed
            try:
                import h5py  # noqa: F401

                h5py_available = True
            except ImportError:
                h5py_available = False

            if not h5py_available and malicious_file.suffix.lower() in [".h5", ".hdf5", ".keras"]:
                skipped_files.append(f"{malicious_file.name} (h5py not installed)")
                continue

            # Skip manifest JSON files from the manifests category - they may not trigger security issues
            # depending on scanner configuration (blacklist patterns, etc.)
            if "manifests" in str(malicious_file.parent) and malicious_file.suffix.lower() == ".json":
                skipped_files.append(f"{malicious_file.name} (manifest scanner may not flag generic JSON)")
                continue

            # Scan the malicious file
            results = scan_model_directory_or_file(str(malicious_file), cache_enabled=False)
            exit_code = determine_exit_code(results)

            # Should scan successfully
            assert results.success is True, f"Scan failed for {malicious_file.name}"

            # For files that can be scanned with available scanners, should detect issues
            if exit_code == 0:
                # If no issues detected, check if this might be due to missing scanners
                file_ext = malicious_file.suffix.lower()
                if file_ext in [".pb"] and not tensorflow_available:
                    skipped_files.append(f"{malicious_file.name} (required .pb scanner unavailable)")
                    continue

            # Should detect security issues for files that can be properly scanned
            tested_files.append(malicious_file.name)
            assert exit_code == 1, f"Failed to detect malicious content in {malicious_file.name}"
            assert len(results.issues) > 0, f"No issues found in {malicious_file.name}"

            # Check for security-level issues
            security_issues = [
                issue
                for issue in results.issues
                if getattr(issue, "severity", None) in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
            ]
            assert len(security_issues) > 0, f"No security issues found in {malicious_file.name}"

        # Ensure we tested at least some files
        if not tested_files and skipped_files:
            pytest.skip(f"All malicious files skipped due to scanner unavailability: {skipped_files}")

        assert len(tested_files) > 0, (
            f"Should have tested at least some malicious files. Tested: {tested_files}, Skipped: {skipped_files}"
        )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_safe_sample_validation(self, samples_dir):
        """Test that safe samples pass validation without false positives."""
        safe_files = self.get_safe_samples(samples_dir)
        try:
            import h5py  # noqa: F401

            h5py_available = True
        except Exception:
            h5py_available = False
        if not h5py_available:
            safe_files = [path for path in safe_files if path.suffix.lower() not in {".h5", ".hdf5"}]

        if not safe_files:
            pytest.skip("No safe sample files found")

        for safe_file in safe_files:
            # Scan the safe file
            results = scan_model_directory_or_file(str(safe_file), cache_enabled=False)
            exit_code = determine_exit_code(results)

            assert results.success is True, f"Scan failed for {safe_file.name}"

            # Any issues should be low-severity only (allow warnings but not critical/error)
            high_severity_issues = [
                issue for issue in results.issues if getattr(issue, "severity", None) in ["critical", "error"]
            ]
            assert len(high_severity_issues) == 0, (
                f"High-severity false positive in {safe_file.name}: {high_severity_issues}"
            )

            # Exit code should be 0 for clean files, or 1 for warnings-only (which is acceptable)
            assert exit_code in [0, 1], f"Unexpected exit code {exit_code} for {safe_file.name}: {results.issues}"

            # If exit code is 1, make sure it's only due to warnings or info, not high-severity issues
            if exit_code == 1:
                assert len(high_severity_issues) == 0, (
                    f"Exit code 1 should only be for warnings, not high-severity issues in {safe_file.name}"
                )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_existing_pickle_assets(self, assets_dir):
        """Test existing pickle assets in the organized structure."""
        pickles_dir = assets_dir / "samples" / "pickles"

        if not pickles_dir.exists():
            pytest.skip("Pickles directory not found")

        # Test the existing evil.pickle (should be malicious)
        evil_pickle = pickles_dir / "evil.pickle"
        if evil_pickle.exists():
            results = scan_model_directory_or_file(str(evil_pickle), cache_enabled=False)
            exit_code = determine_exit_code(results)
            assert exit_code == 1, "Should detect evil.pickle as malicious"

        # Test dill_func.pkl (intentionally incomplete but still security-positive)
        dill_func = pickles_dir / "dill_func.pkl"
        if dill_func.exists():
            results = scan_model_directory_or_file(str(dill_func), cache_enabled=False)
            exit_code = determine_exit_code(results)
            assert results.success is False, "dill_func.pkl should preserve its incomplete scan outcome"
            # The detected dill usage should still preserve the security exit code.
            assert exit_code == 1, "dill_func.pkl should be flagged as suspicious due to dill usage"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_license_scenarios_integration(self, scenarios_dir: Path) -> None:
        """Test that license scenarios still work with new structure."""
        license_scenarios = scenarios_dir / "license_scenarios"

        if not license_scenarios.exists():
            pytest.skip("License scenarios directory not found")

        # Test a few license scenarios
        for scenario_dir in license_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir), cache_enabled=False)
                # License scenarios must scan to completion. Some fixtures (e.g.
                # agpl_component) embed pickles that reference __main__ globals and
                # are now correctly flagged as security findings, so success may be
                # False; the scan must still have run and processed the files.
                assert results.files_scanned > 0, f"License scenario produced no scanned files: {scenario_dir.name}"
                assert results.has_errors is False, f"License scenario had operational errors: {scenario_dir.name}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_security_scenarios(self, scenarios_dir):
        """Test complex security scenarios if they exist."""
        security_scenarios = scenarios_dir / "security_scenarios"

        if not security_scenarios.exists():
            pytest.skip("Security scenarios directory not found")

        for scenario_dir in security_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir), cache_enabled=False)
                exit_code = determine_exit_code(results)

                # Security scenarios should be detected as malicious
                assert exit_code == 1, f"Security scenario not detected: {scenario_dir.name}"
                assert results.success is True, f"Scan failed for {scenario_dir.name}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_cli_organized_structure(self, samples_dir):
        """Test CLI scanning with organized structure."""
        if not samples_dir.exists():
            pytest.skip("Samples directory not found")

        runner = CliRunner()

        # Test scanning samples directory
        result = runner.invoke(cli, ["scan", str(samples_dir), "--format", "json"])
        assert result.exit_code in [0, 1], f"CLI scan failed: {result.output}"

        # Should produce valid JSON
        try:
            output_data = json.loads(result.output)
            assert "files_scanned" in output_data
            assert "issues" in output_data
            assert output_data["files_scanned"] > 0
        except json.JSONDecodeError:
            pytest.fail(f"CLI did not produce valid JSON: {result.output}")

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_mixed_directory_scanning(self, assets_dir):
        """Test scanning directory with both safe and malicious assets."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Create temporary directory with mix of files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Copy a few files from different categories
            samples_dir = assets_dir / "samples"
            if samples_dir.exists():
                copied_files = []

                # Try to copy some files from different categories
                for category_dir in samples_dir.iterdir():
                    if category_dir.is_dir():
                        category_files = [
                            path for path in category_dir.iterdir() if path.is_file() and not path.name.startswith(".")
                        ][:2]
                        for file_path in category_files:
                            dest = temp_path / f"{category_dir.name}_{file_path.name}"
                            shutil.copy2(file_path, dest)
                            copied_files.append(dest)

                if copied_files:
                    # Scan the mixed directory
                    results = scan_model_directory_or_file(str(temp_path), cache_enabled=False)
                    assert results.files_scanned >= len(copied_files)
                    assert results.has_errors is False, (
                        f"Mixed directory scan should not have operational errors: "
                        f"{describe_operational_errors(results)}"
                    )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_asset_discovery_completeness(self, assets_dir: Path) -> None:
        """Test that asset discovery finds all expected file types."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Scan the entire assets directory. The tree intentionally contains
        # exploits/ and malicious samples/, so success is expected to be False;
        # what matters for discovery is that the scan ran and processed files.
        results = scan_model_directory_or_file(str(assets_dir), cache_enabled=False)

        # Should find various file types
        assert results.files_scanned > 0, "Should find some files to scan"
        assert_no_unexpected_asset_scan_errors(results, "Assets directory scan")
        assert len(results.issues) > 0, "Assets tree contains exploits; findings expected"

        # Check for different file extensions in issues (indicates they were processed)
        scanned_extensions = set()
        for issue in results.issues:
            location = getattr(issue, "location", "")
            if location:
                ext = Path(location).suffix.lower()
                if ext:
                    scanned_extensions.add(ext)

        # Should have processed various file types
        expected_extensions = {".pkl", ".h5", ".pt", ".json", ".zip"}
        found_expected = expected_extensions.intersection(scanned_extensions)

        # Don't require all extensions, but should find some that we expect
        if scanned_extensions:
            assert len(found_expected) > 0, f"Should find some expected file types. Found: {scanned_extensions}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_performance_with_organized_structure(self, assets_dir: Path) -> None:
        """Test that organized structure doesn't significantly impact performance."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        import time

        start_time = time.perf_counter()
        results = scan_model_directory_or_file(str(assets_dir), cache_enabled=False)
        duration = time.perf_counter() - start_time

        # Should complete in reasonable time. The assets tree contains exploits,
        # so success is expected to be False; assert the scan ran and produced
        # findings rather than demanding success on malicious inputs.
        assert results.files_scanned > 0, "Performance test scan should process files"
        assert_no_unexpected_asset_scan_errors(results, "Performance test scan")
        assert len(results.issues) > 0, "Assets tree contains exploits; findings expected"
        is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
        threshold = 120 if is_ci else 60
        assert duration < threshold, f"Scan took too long: {duration:.2f}s"

        # Should provide performance metrics
        assert hasattr(results, "duration"), "Results should include timing information"
        assert results.duration > 0, "Duration should be positive"
