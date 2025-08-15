"""
CLI Integration tests for license detection.

These tests demonstrate the license functionality through actual CLI commands,
showing how users would interact with the license detection features.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


class TestCLILicenseIntegration:
    """Integration tests using the actual CLI commands."""

    @pytest.fixture
    def test_data_dir(self):
        """Return path to integration test data."""
        return Path(__file__).parent / "assets/scenarios/license_scenarios"

    @pytest.fixture
    def cli_command(self):
        """Return the CLI command to run modelaudit."""
        return [sys.executable, "-c", "from modelaudit.cli import main; main()"]

    def test_cli_mit_model_clean_scan(self, test_data_dir, cli_command):
        """Test CLI scanning of MIT licensed model."""
        mit_dir = test_data_dir / "mit_model"

        # Run CLI scan
        result = subprocess.run(
            [*cli_command, "scan", str(mit_dir), "--format", "json"],
            capture_output=True,
            text=True,
        )

        # Should succeed (exit code 0 = no issues found)
        assert result.returncode == 0, f"CLI scan failed: {result.stderr}"

        # Parse JSON output
        output_data = json.loads(result.stdout)

        # Should have scanned files
        assert output_data["files_scanned"] > 0
        assert output_data["bytes_scanned"] > 0

        # Should not have critical license issues
        critical_issues = [
            issue
            for issue in output_data.get("issues", [])
            if issue.get("severity") == "critical" and issue.get("type") == "license_warning"
        ]
        assert len(critical_issues) == 0, "MIT model should not have critical license issues"

    def test_cli_agpl_component_warnings(self, test_data_dir, cli_command):
        """Test CLI scanning of AGPL component triggers warnings."""
        agpl_dir = test_data_dir / "agpl_component"

        # Run CLI scan with --no-skip-files to scan the .py file containing AGPL license
        result = subprocess.run(
            [*cli_command, "scan", str(agpl_dir), "--format", "json", "--no-skip-files"],
            capture_output=True,
            text=True,
        )

        # Should succeed with warnings (exit code 1 = issues found)
        assert result.returncode == 1, f"AGPL scan should trigger warnings. Exit code: {result.returncode}"

        # Parse JSON output
        output_data = json.loads(result.stdout)

        # Should have license warning issues
        license_issues = [issue for issue in output_data.get("issues", []) if issue.get("type") == "license_warning"]
        assert len(license_issues) > 0, "Should have license warning issues"

        # Should have AGPL warning
        agpl_issues = [issue for issue in license_issues if "AGPL" in issue.get("message", "")]

        assert len(agpl_issues) > 0, "Should have AGPL-specific warnings"

        # Verify AGPL warning content
        agpl_issue = agpl_issues[0]
        assert agpl_issue["severity"] == "warning"
        assert "network use restrictions" in agpl_issue["message"]

    def test_cli_unlicensed_dataset_warnings(self, test_data_dir, cli_command):
        """Test CLI scanning of unlicensed datasets."""
        unlicensed_dir = test_data_dir / "unlicensed_dataset"

        # Run CLI scan
        result = subprocess.run(
            [*cli_command, "scan", str(unlicensed_dir), "--format", "json"],
            capture_output=True,
            text=True,
        )

        # Should trigger warnings
        assert result.returncode == 1, "Unlicensed datasets should trigger warnings"

        # Parse JSON output
        output_data = json.loads(result.stdout)

        # Should have dataset license warnings
        dataset_issues = [
            issue
            for issue in output_data.get("issues", [])
            if issue.get("type") == "license_warning" and "unspecified licenses" in issue.get("message", "")
        ]
        assert len(dataset_issues) > 0, "Should warn about unlicensed datasets"

    def test_cli_sbom_generation(self, test_data_dir, cli_command):
        """Test CLI SBOM generation with license metadata."""
        mit_dir = test_data_dir / "mit_model"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            sbom_path = f.name

        try:
            # Run CLI scan with SBOM generation
            result = subprocess.run(
                [*cli_command, "scan", str(mit_dir), "--sbom", sbom_path],
                capture_output=True,
                text=True,
            )

            # Should succeed
            assert result.returncode == 0, f"SBOM generation failed: {result.stderr}"

            # Should create SBOM file
            sbom_file = Path(sbom_path)
            assert sbom_file.exists(), "SBOM file should be created"

            # Parse SBOM content
            with sbom_file.open() as f:
                sbom_data = json.loads(f.read())

            # Should have components
            assert "components" in sbom_data
            components = sbom_data["components"]
            assert len(components) > 0, "SBOM should contain components"

            # Components should have properties
            has_properties = any(
                "properties" in component and len(component["properties"]) > 0 for component in components
            )
            assert has_properties, "Components should have license-related properties"

        finally:
            # Cleanup
            Path(sbom_path).unlink(missing_ok=True)

    def test_cli_verbose_license_output(self, test_data_dir, cli_command):
        """Test CLI verbose output includes license information."""
        agpl_dir = test_data_dir / "agpl_component"

        # Run CLI scan with verbose output
        result = subprocess.run(
            [*cli_command, "scan", str(agpl_dir), "--verbose"],
            capture_output=True,
            text=True,
        )

        # Should have verbose output
        assert len(result.stdout) > 0, "Should produce output"
        assert len(result.stderr) > 0, "Should have verbose logging"

        # Check for license-related content in output
        output_text = result.stdout + result.stderr
        assert "license" in output_text.lower() or "agpl" in output_text.lower(), (
            "Verbose output should mention license-related information"
        )

    def test_cli_mixed_licenses_comprehensive(self, test_data_dir, cli_command):
        """Test CLI scanning of mixed license directory."""
        mixed_dir = test_data_dir / "mixed_licenses"

        # Run CLI scan
        result = subprocess.run(
            [*cli_command, "scan", str(mixed_dir), "--format", "json"],
            capture_output=True,
            text=True,
        )

        # Parse JSON output
        output_data = json.loads(result.stdout)

        # Should have scanned multiple files
        assert output_data["files_scanned"] > 1, "Should scan multiple files in mixed directory"

        # Should detect multiple license types or have warnings
        license_issues = [issue for issue in output_data.get("issues", []) if issue.get("type") == "license_warning"]

        # Print for debugging
        print("Mixed licenses scan results:")
        print(f"Files scanned: {output_data['files_scanned']}")
        print(f"License issues: {len(license_issues)}")
        for issue in license_issues:
            print(f"  - {issue.get('message', 'Unknown')}")

    def test_cli_error_handling(self, cli_command):
        """Test CLI error handling for invalid inputs."""
        # Test scanning non-existent directory
        result = subprocess.run(
            [*cli_command, "scan", "/nonexistent/directory"],
            capture_output=True,
            text=True,
        )

        # Should fail with error code 2 (operational error)
        assert result.returncode == 2, "Should return error code 2 for missing files"

        # Should have error message
        assert len(result.stderr) > 0 or "Error" in result.stdout, "Should show error message"

    def test_cli_help_includes_license_features(self, cli_command):
        """Test that CLI help mentions license-related features."""
        # Test main help
        result = subprocess.run(
            [*cli_command, "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, "Help should work"

        # Test scan help
        result = subprocess.run(
            [*cli_command, "scan", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, "Scan help should work"
        assert "--sbom" in result.stdout, "Help should mention SBOM option"

    def test_cli_comprehensive_real_world_scenario(self, test_data_dir, cli_command):
        """
        Test a comprehensive real-world scenario with all license types.
        This demonstrates the complete license detection workflow.
        """
        # Create a temporary directory with mixed content
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Copy our test files to simulate a real project
            import shutil

            # Copy MIT model
            mit_dest = temp_path / "models" / "mit_model"
            mit_dest.mkdir(parents=True)
            shutil.copytree(test_data_dir / "mit_model", mit_dest, dirs_exist_ok=True)

            # Copy AGPL component
            agpl_dest = temp_path / "components" / "agpl_component"
            agpl_dest.mkdir(parents=True)
            shutil.copytree(
                test_data_dir / "agpl_component",
                agpl_dest,
                dirs_exist_ok=True,
            )

            # Copy unlicensed datasets
            data_dest = temp_path / "data"
            data_dest.mkdir(parents=True)
            shutil.copytree(
                test_data_dir / "unlicensed_dataset",
                data_dest,
                dirs_exist_ok=True,
            )

            # Create SBOM output file
            sbom_path = temp_path / "project_sbom.json"

            # Run comprehensive scan
            result = subprocess.run(
                [*cli_command, "scan", str(temp_path), "--format", "json", "--sbom", str(sbom_path), "--verbose"],
                capture_output=True,
                text=True,
            )

            # Should complete (may have warnings)
            assert result.returncode in [0, 1], f"Scan should complete. Exit code: {result.returncode}"

            # Parse results
            output_data = json.loads(result.stdout)

            # Should scan multiple files
            assert output_data["files_scanned"] > 5, "Should scan many files in comprehensive test"

            # Should have various license warnings
            license_issues = [
                issue for issue in output_data.get("issues", []) if issue.get("type") == "license_warning"
            ]

            # Should detect different types of license issues
            issue_types = set()
            for issue in license_issues:
                message = issue.get("message", "")
                if "AGPL" in message:
                    issue_types.add("agpl")
                elif "unspecified licenses" in message:
                    issue_types.add("unlicensed")
                elif "copyleft" in message:
                    issue_types.add("copyleft")

            # Should create SBOM
            assert sbom_path.exists(), "Should create SBOM file"

            # SBOM should be valid JSON
            with sbom_path.open() as f:
                sbom_data = json.loads(f.read())
            assert "components" in sbom_data

            print("\nComprehensive scan results:")
            print(f"Files scanned: {output_data['files_scanned']}")
            print(f"Bytes scanned: {output_data['bytes_scanned']}")
            print(f"License issues: {len(license_issues)}")
            print(f"Issue types detected: {list(issue_types)}")
            print(f"SBOM components: {len(sbom_data.get('components', []))}")


if __name__ == "__main__":
    # Allow running individual tests for debugging
    pytest.main([__file__, "-v", "-s"])
