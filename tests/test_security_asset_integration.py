"""
Security Asset Integration Tests

Tests that integrate with the organized test asset structure.
Focuses on security-specific scanning scenarios.
"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.base import IssueSeverity


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
                        and file_path.is_file()
                        and not file_path.name.startswith(".")
                    ):
                        safe_files.append(file_path)

        return safe_files

    def test_malicious_sample_detection(self, samples_dir):
        """Test that all malicious samples are properly detected."""
        from modelaudit.scanners import _registry

        malicious_files = self.get_malicious_samples(samples_dir)

        if not malicious_files:
            pytest.skip("No malicious sample files found")

        # Get failed scanners to handle compatibility issues
        failed_scanners = _registry.get_failed_scanners()
        tensorflow_available = not any("tf_savedmodel" in scanner_id for scanner_id in failed_scanners)

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

            # Scan the malicious file
            results = scan_model_directory_or_file(str(malicious_file))
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

    def test_safe_sample_validation(self, samples_dir):
        """Test that safe samples pass validation without false positives."""
        safe_files = self.get_safe_samples(samples_dir)

        if not safe_files:
            pytest.skip("No safe sample files found")

        for safe_file in safe_files:
            # Scan the safe file
            results = scan_model_directory_or_file(str(safe_file))
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

    def test_existing_pickle_assets(self, assets_dir):
        """Test existing pickle assets in the organized structure."""
        pickles_dir = assets_dir / "samples" / "pickles"

        if not pickles_dir.exists():
            pytest.skip("Pickles directory not found")

        # Test the existing evil.pickle (should be malicious)
        evil_pickle = pickles_dir / "evil.pickle"
        if evil_pickle.exists():
            results = scan_model_directory_or_file(str(evil_pickle))
            exit_code = determine_exit_code(results)
            assert exit_code == 1, "Should detect evil.pickle as malicious"

        # Test dill_func.pkl (should be suspicious due to dill usage)
        dill_func = pickles_dir / "dill_func.pkl"
        if dill_func.exists():
            results = scan_model_directory_or_file(str(dill_func))
            exit_code = determine_exit_code(results)
            assert results.success is True, "Should scan dill_func.pkl successfully"
            # dill_func.pkl should be flagged as suspicious (exit code 1) due to dill usage
            assert exit_code == 1, "dill_func.pkl should be flagged as suspicious due to dill usage"

    def test_license_scenarios_integration(self, scenarios_dir):
        """Test that license scenarios still work with new structure."""
        license_scenarios = scenarios_dir / "license_scenarios"

        if not license_scenarios.exists():
            pytest.skip("License scenarios directory not found")

        # Test a few license scenarios
        for scenario_dir in license_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir))
                assert results.success is True, f"License scenario scan failed: {scenario_dir.name}"
                # License scenarios might have license issues but should scan successfully

    def test_security_scenarios(self, scenarios_dir):
        """Test complex security scenarios if they exist."""
        security_scenarios = scenarios_dir / "security_scenarios"

        if not security_scenarios.exists():
            pytest.skip("Security scenarios directory not found")

        for scenario_dir in security_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir))
                exit_code = determine_exit_code(results)

                # Security scenarios should be detected as malicious
                assert exit_code == 1, f"Security scenario not detected: {scenario_dir.name}"
                assert results.success is True, f"Scan failed for {scenario_dir.name}"

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
                        for file_path in list(category_dir.iterdir())[:2]:  # Max 2 per category
                            if file_path.is_file():
                                dest = temp_path / f"{category_dir.name}_{file_path.name}"
                                shutil.copy2(file_path, dest)
                                copied_files.append(dest)

                if copied_files:
                    # Scan the mixed directory
                    results = scan_model_directory_or_file(str(temp_path))
                    assert results.success is True, "Mixed directory scan should succeed"
                    assert results.files_scanned >= len(copied_files)

    def test_asset_discovery_completeness(self, assets_dir):
        """Test that asset discovery finds all expected file types."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Scan the entire assets directory
        results = scan_model_directory_or_file(str(assets_dir))
        assert results.success is True, "Assets directory scan should succeed"

        # Should find various file types
        assert results.files_scanned > 0, "Should find some files to scan"

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

    def test_performance_with_organized_structure(self, assets_dir):
        """Test that organized structure doesn't significantly impact performance."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        import time

        start_time = time.time()
        results = scan_model_directory_or_file(str(assets_dir))
        duration = time.time() - start_time

        # Should complete in reasonable time
        assert results.success is True, "Performance test scan should succeed"
        assert duration < 30, f"Scan took too long: {duration:.2f}s"

        # Should provide performance metrics
        assert hasattr(results, "duration"), "Results should include timing information"
        assert results.duration > 0, "Duration should be positive"
