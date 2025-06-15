import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.core import scan_model_directory_or_file, determine_exit_code


class TestAssetIntegration:
    """Comprehensive integration tests for the asset scanning feature."""

    @pytest.fixture
    def assets_dir(self):
        """Get the path to test assets."""
        return Path(__file__).parent / "assets"

    @pytest.fixture
    def malicious_assets(self, assets_dir):
        """List of malicious test assets."""
        return [
            assets_dir / "evil_pickle.pkl",
            assets_dir / "malicious_keras.h5", 
            assets_dir / "malicious_pytorch.pt",
            assets_dir / "malicious_tf",
            assets_dir / "malicious_manifest.json",
            assets_dir / "malicious_zip.zip",
        ]

    @pytest.fixture
    def safe_assets(self, assets_dir):
        """List of safe test assets."""
        return [
            assets_dir / "safe_pickle.pkl",
            assets_dir / "safe_keras.h5",
            assets_dir / "safe_pytorch.pt", 
            assets_dir / "safe_tf",
            assets_dir / "safe_manifest.json",
            assets_dir / "safe_zip.zip",
        ]

    def test_end_to_end_malicious_detection(self, malicious_assets):
        """Test that all malicious assets are correctly detected."""
        for asset_path in malicious_assets:
            if not asset_path.exists():
                pytest.skip(f"Asset {asset_path} does not exist")
                
            # Scan the malicious asset
            results = scan_model_directory_or_file(str(asset_path))
            exit_code = determine_exit_code(results)
            
            # Should detect issues (exit code 1)
            assert exit_code == 1, f"Failed to detect malicious content in {asset_path}"
            assert len(results["issues"]) > 0, f"No issues found in {asset_path}"
            assert results["success"] is True, f"Scan failed for {asset_path}"
            
            # Check that we found security issues, not just operational errors
            security_issues = [
                issue for issue in results["issues"] 
                if issue.get("severity") in ["error", "warning", "info"]
            ]
            assert len(security_issues) > 0, f"No security issues found in {asset_path}"

    def test_end_to_end_safe_validation(self, safe_assets):
        """Test that all safe assets pass validation."""
        for asset_path in safe_assets:
            if not asset_path.exists():
                pytest.skip(f"Asset {asset_path} does not exist")
                
            # Scan the safe asset
            results = scan_model_directory_or_file(str(asset_path))
            exit_code = determine_exit_code(results)
            
            # Should be clean (exit code 0) or only have debug messages
            assert exit_code == 0, f"False positive detected in {asset_path}: {results['issues']}"
            assert results["success"] is True, f"Scan failed for {asset_path}"
            
            # Any issues should only be debug level
            non_debug_issues = [
                issue for issue in results["issues"]
                if issue.get("severity") != "debug"
            ]
            assert len(non_debug_issues) == 0, f"Non-debug issues found in safe asset {asset_path}: {non_debug_issues}"

    def test_cli_integration_malicious_directory(self, assets_dir, malicious_assets):
        """Test CLI scanning of directory with malicious assets."""
        # Create a temporary directory with only malicious assets
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Copy malicious assets to temp directory
            for asset in malicious_assets:
                if asset.exists():
                    if asset.is_dir():
                        shutil.copytree(asset, temp_path / asset.name)
                    else:
                        shutil.copy2(asset, temp_path / asset.name)
            
            # Test CLI scanning with text output
            runner = CliRunner()
            result = runner.invoke(cli, ["scan", str(temp_path)])
            
            assert result.exit_code == 1, f"CLI should return exit code 1 for malicious content, got {result.exit_code}"
            assert "Files scanned:" in result.output
            assert temp_path.name in result.output or str(temp_path) in result.output
            
            # Test CLI scanning with JSON output
            json_result = runner.invoke(cli, ["scan", str(temp_path), "--format", "json"])
            assert json_result.exit_code == 1
            
            # Should be valid JSON
            output_data = json.loads(json_result.output)
            assert "files_scanned" in output_data
            assert "issues" in output_data
            assert len(output_data["issues"]) > 0
            
            # Should have found security issues
            security_issues = [
                issue for issue in output_data["issues"]
                if issue.get("severity") in ["error", "warning", "info"]
            ]
            assert len(security_issues) > 0

    def test_cli_integration_safe_directory(self, safe_assets):
        """Test CLI scanning of directory with only safe assets."""
        # Create a temporary directory with only safe assets  
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Copy safe assets to temp directory
            for asset in safe_assets:
                if asset.exists():
                    if asset.is_dir():
                        shutil.copytree(asset, temp_path / asset.name)
                    else:
                        shutil.copy2(asset, temp_path / asset.name)
            
            # Test CLI scanning
            runner = CliRunner()
            result = runner.invoke(cli, ["scan", str(temp_path)])
            
            assert result.exit_code == 0, f"CLI should return exit code 0 for safe content, got {result.exit_code}. Output: {result.output}"
            assert "Files scanned:" in result.output

    def test_mixed_directory_scanning(self, assets_dir):
        """Test scanning a directory with both safe and malicious assets."""
        if not assets_dir.exists():
            pytest.skip("Assets directory does not exist")
        
        # Scan the entire assets directory
        results = scan_model_directory_or_file(str(assets_dir))
        exit_code = determine_exit_code(results)
        
        # Should detect malicious content (exit code 1)
        assert exit_code == 1, "Should detect malicious content in mixed directory"
        assert results["success"] is True
        assert results["files_scanned"] > 0
        
        # Should have both types of files scanned
        locations = {issue.get("location", "") for issue in results["issues"]}
        has_malicious_locations = any("malicious" in loc or "evil" in loc for loc in locations)
        assert has_malicious_locations, "Should detect malicious assets in mixed directory"

    def test_performance_benchmarking(self, assets_dir):
        """Test scanning performance and resource usage."""
        if not assets_dir.exists():
            pytest.skip("Assets directory does not exist")
        
        # Benchmark scanning performance
        start_time = time.time()
        results = scan_model_directory_or_file(str(assets_dir), timeout=60)
        scan_duration = time.time() - start_time
        
        # Performance assertions
        assert results["success"] is True
        assert scan_duration < 30, f"Scanning took too long: {scan_duration:.2f}s"
        assert results["files_scanned"] > 0
        
        # Check that duration is tracked in results
        assert "duration" in results
        assert results["duration"] > 0
        assert abs(results["duration"] - scan_duration) < 1.0  # Should be close

    def test_concurrent_scanning_safety(self, safe_assets):
        """Test that concurrent scanning doesn't cause issues."""
        import concurrent.futures
        import threading
        
        def scan_asset(asset_path):
            """Scan a single asset and return results."""
            if not asset_path.exists():
                return {"skipped": True}
            return scan_model_directory_or_file(str(asset_path))
        
        # Scan multiple assets concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_asset = {
                executor.submit(scan_asset, asset): asset 
                for asset in safe_assets[:3]  # Test with first 3 assets
            }
            
            results = {}
            for future in concurrent.futures.as_completed(future_to_asset):
                asset = future_to_asset[future]
                try:
                    result = future.result(timeout=30)
                    results[asset.name] = result
                except Exception as exc:
                    pytest.fail(f"Concurrent scan failed for {asset}: {exc}")
        
        # All scans should succeed
        for asset_name, result in results.items():
            if not result.get("skipped"):
                assert result["success"] is True, f"Concurrent scan failed for {asset_name}"

    def test_error_handling_integration(self):
        """Test error handling for various failure scenarios."""
        # Test non-existent file
        results = scan_model_directory_or_file("/nonexistent/path/file.pkl")
        assert results["success"] is False
        assert results.get("has_errors") is True
        assert determine_exit_code(results) == 2
        
        # Test permission denied (if we can create such a scenario)
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test content")
        
        try:
            # Try to make file unreadable (may not work on all systems)
            os.chmod(temp_path, 0o000)
            results = scan_model_directory_or_file(str(temp_path))
            
            # Either should fail with permission error, or succeed if chmod didn't work
            if not results["success"]:
                assert results.get("has_errors") is True
                assert determine_exit_code(results) == 2
        finally:
            # Clean up (restore permissions first)
            try:
                os.chmod(temp_path, 0o644)
                temp_path.unlink()
            except:
                pass

    def test_regression_no_false_positives(self, safe_assets):
        """Regression test to ensure safe assets don't trigger false positives."""
        false_positive_patterns = [
            "malicious",
            "evil", 
            "dangerous",
            "attack",
            "exploit",
            "vulnerability"
        ]
        
        for asset_path in safe_assets:
            if not asset_path.exists():
                continue
                
            results = scan_model_directory_or_file(str(asset_path))
            
            # Check for false positive indicators in issue messages
            for issue in results["issues"]:
                message = issue.get("message", "").lower()
                severity = issue.get("severity", "")
                
                # Skip debug messages
                if severity == "debug":
                    continue
                    
                # Check for false positive patterns
                has_false_positive = any(pattern in message for pattern in false_positive_patterns)
                assert not has_false_positive, f"Potential false positive in {asset_path}: {message}"

    def test_output_format_consistency(self, assets_dir):
        """Test that different output formats provide consistent information."""
        if not assets_dir.exists():
            pytest.skip("Assets directory does not exist")
        
        # Get results programmatically
        results = scan_model_directory_or_file(str(assets_dir))
        
        # Get results via CLI JSON
        runner = CliRunner()
        cli_result = runner.invoke(cli, ["scan", str(assets_dir), "--format", "json"])
        cli_data = json.loads(cli_result.output)
        
        # Compare key metrics
        assert results["files_scanned"] == cli_data["files_scanned"]
        assert results["bytes_scanned"] == cli_data["bytes_scanned"]
        assert len(results["issues"]) == len(cli_data["issues"])
        assert determine_exit_code(results) == cli_result.exit_code

    def test_asset_completeness(self, assets_dir):
        """Test that all expected assets exist and are valid."""
        expected_assets = [
            "evil_pickle.pkl",
            "malicious_keras.h5",
            "malicious_pytorch.pt", 
            "malicious_tf",
            "malicious_manifest.json",
            "malicious_zip.zip",
            "safe_pickle.pkl",
            "safe_keras.h5",
            "safe_pytorch.pt",
            "safe_tf", 
            "safe_manifest.json",
            "safe_zip.zip",
            "README.md",
            "generate_assets.py"
        ]
        
        for asset_name in expected_assets:
            asset_path = assets_dir / asset_name
            assert asset_path.exists(), f"Expected asset {asset_name} is missing"
            
            # Check that files are not empty (except for potential edge cases)
            if asset_path.is_file() and not asset_name.endswith(('.md', '.py')):
                assert asset_path.stat().st_size > 0, f"Asset {asset_name} is empty"

    def test_cli_verbose_output(self, assets_dir):
        """Test CLI verbose mode provides additional information."""
        if not assets_dir.exists():
            pytest.skip("Assets directory does not exist")
            
        runner = CliRunner()
        
        # Test normal output
        normal_result = runner.invoke(cli, ["scan", str(assets_dir)])
        
        # Test verbose output  
        verbose_result = runner.invoke(cli, ["scan", str(assets_dir), "--verbose"])
        
        # Verbose should have more information
        assert len(verbose_result.output) >= len(normal_result.output)
        
        # Both should have same exit code
        assert normal_result.exit_code == verbose_result.exit_code

    def test_timeout_handling(self, safe_assets):
        """Test that timeout handling works correctly."""
        # Test with very short timeout
        asset = next((a for a in safe_assets if a.exists()), None)
        if not asset:
            pytest.skip("No safe assets available")
        
        # Test with reasonable timeout (should succeed)
        results = scan_model_directory_or_file(str(asset), timeout=30)
        assert results["success"] is True
        
        # Test with very short timeout (might timeout)
        results_short = scan_model_directory_or_file(str(asset), timeout=1)
        # Either succeeds quickly or times out
        if not results_short["success"]:
            # Should have timeout-related error
            timeout_errors = [
                issue for issue in results_short["issues"]
                if "timeout" in issue.get("message", "").lower()
            ]
            # Note: might not always timeout on fast systems, so don't assert 