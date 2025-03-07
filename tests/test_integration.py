import os
import pytest
import json
from pathlib import Path
from click.testing import CliRunner

from modelaudit.core import scan_model_directory_or_file
from modelaudit.cli import cli

def test_scan_directory_with_multiple_models(temp_model_dir, mock_progress_callback):
    """Test scanning a directory with multiple model types."""
    # Scan the directory with all models
    results = scan_model_directory_or_file(
        str(temp_model_dir),
        progress_callback=mock_progress_callback
    )
    
    # Check basic results
    assert results["success"] is True
    assert results["files_scanned"] >= 4  # At least our 4 test files
    assert results["bytes_scanned"] > 0
    
    # Check progress callback was called
    assert len(mock_progress_callback.messages) > 0
    assert len(mock_progress_callback.percentages) > 0
    assert any("Scanning directory" in msg for msg in mock_progress_callback.messages)
    assert 100.0 in mock_progress_callback.percentages  # Should reach 100%
    
    # Check that issues were found for each model type
    model_paths = [
        str(temp_model_dir / "model1.pkl"),
        str(temp_model_dir / "model2.pt"),
        str(temp_model_dir / "tf_model"),
        str(temp_model_dir / "subdir" / "model3.h5")
    ]
    
    # Each model should have at least one issue (even if just informational)
    for model_path in model_paths:
        model_issues = [issue for issue in results["issues"] 
                       if model_path in issue.get("location", "")]
        assert len(model_issues) > 0, f"No issues found for {model_path}"

def test_cli_scan_directory(temp_model_dir):
    """Test scanning a directory with multiple models using the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(temp_model_dir)])
    
    assert result.exit_code == 0
    assert "Scan Summary" in result.output
    assert str(temp_model_dir) in result.output
    
    # Should mention the number of files scanned
    assert "Files scanned: " in result.output
    
    # Should have found some issues
    assert "Issues found: " in result.output

def test_cli_json_output_parsing(temp_model_dir):
    """Test that the CLI JSON output can be parsed."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(temp_model_dir), "--format", "json"])
    
    assert result.exit_code == 0
    
    # Should be valid JSON
    output_json = json.loads(result.output)
    
    # Check expected fields
    assert "files_scanned" in output_json
    assert "issues" in output_json
    assert "bytes_scanned" in output_json
    assert "duration" in output_json
    
    # Should have found some issues
    assert len(output_json["issues"]) > 0

def test_scan_with_all_options(temp_model_dir, mock_progress_callback):
    """Test scanning with all options enabled."""
    results = scan_model_directory_or_file(
        str(temp_model_dir),
        blacklist_patterns=["suspicious_pattern", "malicious_code"],
        timeout=60,
        max_file_size=1000000,
        progress_callback=mock_progress_callback,
        verbose=True,
        additional_option="test_value"
    )
    
    assert results["success"] is True
    assert results["files_scanned"] > 0
    assert results["bytes_scanned"] > 0
    
    # Check progress callback was called
    assert len(mock_progress_callback.messages) > 0
    assert len(mock_progress_callback.percentages) > 0

def test_cli_with_all_options(temp_model_dir):
    """Test CLI with all options."""
    output_file = Path(temp_model_dir) / "output.json"
    
    runner = CliRunner()
    result = runner.invoke(cli, [
        "scan", 
        str(temp_model_dir),
        "--blacklist", "suspicious_pattern",
        "--blacklist", "malicious_code",
        "--format", "json",
        "--output", str(output_file),
        "--timeout", "60",
        "--max-file-size", "1000000",
        "--verbose"
    ])
    
    assert result.exit_code == 0
    assert output_file.exists()
    
    # Read the output file
    output_content = output_file.read_text()
    output_json = json.loads(output_content)
    
    # Check expected fields
    assert "files_scanned" in output_json
    assert "issues" in output_json
    assert "bytes_scanned" in output_json

def test_scan_multiple_paths_combined_results(temp_model_dir):
    """Test scanning multiple paths and combining results."""
    # Create paths to scan
    path1 = temp_model_dir / "model1.pkl"
    path2 = temp_model_dir / "model2.pt"
    
    # Scan individual files
    results1 = scan_model_directory_or_file(str(path1))
    results2 = scan_model_directory_or_file(str(path2))
    
    # Scan both files using CLI
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(path1), str(path2), "--format", "json"])
    
    assert result.exit_code == 0
    combined_results = json.loads(result.output)
    
    # Combined results should have at least the sum of individual scans
    assert combined_results["files_scanned"] >= results1["files_scanned"] + results2["files_scanned"]
    assert combined_results["bytes_scanned"] >= results1["bytes_scanned"] + results2["bytes_scanned"]
    assert len(combined_results["issues"]) >= len(results1["issues"]) + len(results2["issues"]) 
