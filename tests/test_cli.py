import json
import os
import re

import pytest
from click.testing import CliRunner

from modelaudit import __version__
from modelaudit.cli import cli, format_text_output


def strip_ansi(text):
    """Strip ANSI color codes from text for testing."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_cli_help():
    """Test the CLI help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "scan" in result.output  # Should list the scan command


def test_cli_version():
    """Test the CLI version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_command_help():
    """Test the scan command help."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "--blacklist" in result.output
    assert "--format" in result.output
    assert "--output" in result.output
    assert "--timeout" in result.output
    assert "--verbose" in result.output
    assert "--max-file-size" in result.output


def test_scan_nonexistent_file():
    """Test scanning a nonexistent file."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "nonexistent_file.pkl"])
    # The CLI might exit with a non-zero code for errors
    # But it should mention the error in the output
    assert "Error" in result.output
    assert "not exist" in result.output.lower() or "not found" in result.output.lower()


def test_scan_file(tmp_path):
    """Test scanning a file."""
    # Create a test file
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file)], catch_exceptions=True)

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert str(test_file) in result.output  # Should mention the file path


def test_scan_directory(tmp_path):
    """Test scanning a directory."""
    # Create a test directory with files
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    (test_dir / "file1.txt").write_bytes(b"test content 1")
    (test_dir / "file2.dat").write_bytes(b"test content 2")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_dir)], catch_exceptions=True)

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert str(test_dir) in result.output  # Should mention the directory path


def test_scan_multiple_paths(tmp_path):
    """Test scanning multiple paths."""
    # Create test files
    file1 = tmp_path / "file1.dat"
    file1.write_bytes(b"test content 1")

    file2 = tmp_path / "file2.dat"
    file2.write_bytes(b"test content 2")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(file1), str(file2)], catch_exceptions=True)

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert (
        str(file1) in result.output or str(file2) in result.output
    )  # Should mention at least one file path


def test_scan_with_blacklist(tmp_path):
    """Test scanning with blacklist patterns."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(test_file), "--blacklist", "pattern1", "--blacklist", "pattern2"],
        catch_exceptions=True,
    )

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert str(test_file) in result.output  # Should mention the file path
    assert "pattern1" in result.output  # Should mention the blacklist pattern


def test_scan_json_output(tmp_path):
    """Test scanning with JSON output format."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--format", "json"])

    # For JSON output, we should be able to parse the output as JSON
    # regardless of the exit code
    try:
        output_json = json.loads(result.output)
        assert "files_scanned" in output_json
        assert "issues" in output_json
        assert output_json["files_scanned"] == 1
    except json.JSONDecodeError:
        pytest.fail("Output is not valid JSON")


def test_scan_output_file(tmp_path):
    """Test scanning with output to a file."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    output_file = tmp_path / "output.txt"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file), "--output", str(output_file)])

    # The file should be created regardless of the exit code
    assert output_file.exists()
    assert output_file.read_text()  # Should not be empty
    assert f"Results written to {output_file}" in result.output


def test_scan_sbom_output(tmp_path):
    """Test scanning with SBOM output."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    sbom_file = tmp_path / "sbom.json"

    runner = CliRunner()
    runner.invoke(cli, ["scan", str(test_file), "--sbom", str(sbom_file)])

    assert sbom_file.exists()
    try:
        json.loads(sbom_file.read_text())
    except json.JSONDecodeError:
        pytest.fail("SBOM output is not valid JSON")


def test_scan_verbose_mode(tmp_path):
    """Test scanning in verbose mode."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    # Use catch_exceptions=True to handle any errors in the CLI
    result = runner.invoke(
        cli,
        ["scan", str(test_file), "--verbose"],
        catch_exceptions=True,
    )

    # In verbose mode, we should see more output
    # But we can't guarantee specific output without knowing the implementation
    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert "Scanning" in result.output  # Should mention scanning


def test_scan_max_file_size(tmp_path):
    """Test scanning with max file size limit."""
    # Create a file larger than our limit
    test_file = tmp_path / "large_file.dat"
    test_file.write_bytes(b"x" * 1000)  # 1000 bytes

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(test_file),
            "--max-file-size",
            "500",  # 500 bytes limit
        ],
        catch_exceptions=True,
    )

    # Just check that the command ran and produced some output
    assert result.output  # Should have some output
    assert str(test_file) in result.output  # Should mention the file path
    assert "500" in result.output  # Should mention the max file size


def test_format_text_output():
    """Test the format_text_output function."""
    # Create a sample results dictionary
    results = {
        "path": "/path/to/model",
        "files_scanned": 5,
        "bytes_scanned": 1024,
        "duration": 0.5,
        "issues": [
            {
                "message": "Test issue",
                "severity": "warning",
                "location": "test.pkl",
                "details": {"test": "value"},
            },
        ],
        "has_errors": False,
    }

    # Test normal output
    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "Files:" in clean_output and "5" in clean_output
    assert "Test issue" in clean_output
    assert "warning" in clean_output.lower()

    # Test verbose output
    output = format_text_output(results, verbose=True)
    clean_output = strip_ansi(output)
    assert "Files:" in clean_output and "5" in clean_output
    assert "Test issue" in clean_output
    assert "warning" in clean_output.lower()
    # Verbose might include details, but we can't guarantee it


def test_format_text_output_only_debug_issues():
    """Ensure debug-only issues result in a success status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Debug info", "severity": "debug", "location": "file.pkl"},
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "No security issues detected" in clean_output
    assert "NO ISSUES FOUND" in clean_output


def test_format_text_output_only_info_issues():
    """Ensure info-only issues result in a success status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Info message", "severity": "info", "location": "file.pkl"},
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)
    assert "1 Info" in clean_output
    assert (
        "INFORMATIONAL FINDINGS" in clean_output
    )  # Info issues show INFORMATIONAL FINDINGS
    assert "WARNINGS DETECTED" not in clean_output


def test_format_text_output_debug_and_info_issues():
    """Ensure debug and info issues (no warnings) result in a success status."""
    results = {
        "files_scanned": 1,
        "bytes_scanned": 10,
        "duration": 0.1,
        "issues": [
            {"message": "Debug info", "severity": "debug", "location": "file1.pkl"},
            {"message": "Info message", "severity": "info", "location": "file2.pkl"},
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=True)
    clean_output = strip_ansi(output)
    assert "1 Info" in clean_output
    assert "1 Debug" in clean_output
    assert (
        "INFORMATIONAL FINDINGS" in clean_output
    )  # Info issues show INFORMATIONAL FINDINGS
    assert "WARNINGS DETECTED" not in clean_output


def test_format_text_output_fast_scan_duration():
    """Test duration formatting for very fast scans (< 0.01 seconds)."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 1,
        "bytes_scanned": 512,
        "duration": 0.005,  # Very fast scan < 0.01 seconds
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 3 decimal places for very fast scans
    assert "Duration:" in clean_output and "0.005s" in clean_output
    assert "Files:" in clean_output and "1" in clean_output
    assert "No security issues detected" in clean_output


def test_format_text_output_normal_scan_duration():
    """Test duration formatting for normal scans (>= 0.01 seconds)."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 2,
        "bytes_scanned": 2048,
        "duration": 0.25,  # Normal scan >= 0.01 seconds
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 2 decimal places for normal scans
    assert "Duration:" in clean_output and "0.25s" in clean_output
    assert "Files:" in clean_output and "2" in clean_output
    assert "No security issues detected" in clean_output


def test_format_text_output_edge_case_duration():
    """Test duration formatting for edge case exactly at 0.01 seconds."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 1,
        "bytes_scanned": 1024,
        "duration": 0.01,  # Edge case exactly at threshold
        "issues": [],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 2 decimal places (>= 0.01 branch)
    assert "Duration:" in clean_output and "0.01s" in clean_output
    assert "Files:" in clean_output and "1" in clean_output
    assert "No security issues detected" in clean_output


def test_format_text_output_very_fast_scan_with_issues():
    """Test duration formatting for very fast scan with issues."""
    results = {
        "path": "/path/to/model",
        "files_scanned": 1,
        "bytes_scanned": 256,
        "duration": 0.003,  # Very fast scan with issues
        "issues": [
            {
                "message": "Suspicious pattern detected",
                "severity": "warning",
                "location": "malicious.pkl",
                "details": {"pattern": "eval"},
            },
        ],
        "has_errors": False,
    }

    output = format_text_output(results, verbose=False)
    clean_output = strip_ansi(output)

    # Should show 3 decimal places for very fast scans
    assert "Duration:" in clean_output and "0.003s" in clean_output
    assert "Files:" in clean_output and "1" in clean_output
    assert "Suspicious pattern detected" in clean_output
    assert "warning" in output.lower()


def test_exit_code_clean_scan(tmp_path):
    """Test exit code 0 when scan is clean with no issues."""
    import pickle

    # Create a clean pickle file that should have no security issues
    test_file = tmp_path / "clean_model.pkl"
    data = {
        "weights": [1.0, 2.0, 3.0],
        "biases": [0.1, 0.2, 0.3],
        "model_name": "clean_model",
    }
    with (test_file).open("wb") as f:
        pickle.dump(data, f)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file)])

    # Should exit with code 0 for clean scan
    assert result.exit_code == 0, (
        f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"
    )
    # The output might not say "No issues found" if there are debug messages,
    # so let's be less strict
    assert (
        "scan completed successfully" in result.output.lower()
        or "no issues found" in result.output.lower()
    )


def test_exit_code_security_issues(tmp_path):
    """Test exit code 1 when security issues are found."""
    import pickle

    # Create a malicious pickle file
    evil_pickle_path = tmp_path / "malicious.pkl"

    class MaliciousClass:
        def __reduce__(self):
            return (os.system, ('echo "This is a malicious pickle"',))

    with evil_pickle_path.open("wb") as f:
        pickle.dump(MaliciousClass(), f)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(evil_pickle_path)])

    # Should exit with code 1 for security findings
    assert result.exit_code == 1, (
        f"Expected exit code 1, got {result.exit_code}. Output: {result.output}"
    )
    assert "error" in result.output.lower() or "warning" in result.output.lower()


def test_exit_code_scan_errors(tmp_path):
    """Test exit code 2 when errors occur during scanning."""
    runner = CliRunner()

    # Try to scan a non-existent file
    result = runner.invoke(cli, ["scan", "/path/that/does/not/exist/file.pkl"])

    # Should exit with code 2 for scan errors
    assert result.exit_code == 2
    assert "Error" in result.output
