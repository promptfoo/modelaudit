import json
import os

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli, format_text_output


def test_cli_help():
    """Test the CLI help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "scan" in result.output  # Should list the scan command


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


def test_scan_verbose_mode(tmp_path):
    """Test scanning in verbose mode."""
    test_file = tmp_path / "test_file.dat"
    test_file.write_bytes(b"test content")

    runner = CliRunner()
    # Use catch_exceptions=True to handle any errors in the CLI
    result = runner.invoke(
        cli, ["scan", str(test_file), "--verbose"], catch_exceptions=True
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
            }
        ],
        "has_errors": False,
    }

    # Test normal output
    output = format_text_output(results, verbose=False)
    assert "Files scanned: 5" in output
    assert "Test issue" in output
    assert "warning" in output.lower()

    # Test verbose output
    output = format_text_output(results, verbose=True)
    assert "Files scanned: 5" in output
    assert "Test issue" in output
    assert "warning" in output.lower()
    # Verbose might include details, but we can't guarantee it


def test_exit_code_clean_scan(tmp_path):
    """Test exit code 0 when scan is clean with no issues."""
    # Create a clean file that won't trigger any security issues
    test_file = tmp_path / "clean_file.txt"
    test_file.write_text("This is just a text file with no security issues")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(test_file)])

    # Should exit with code 0 for clean scan
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_exit_code_security_issues():
    """Test exit code 1 when security issues are found."""
    runner = CliRunner()
    # Use the evil.pickle file from tests directory
    evil_pickle_path = os.path.join(os.path.dirname(__file__), "evil.pickle")

    result = runner.invoke(cli, ["scan", evil_pickle_path])

    # Should exit with code 1 for security findings
    assert result.exit_code == 1
    assert "issue" in result.output.lower() or "warning" in result.output.lower()


def test_exit_code_scan_errors(tmp_path):
    """Test exit code 2 when errors occur during scanning."""
    runner = CliRunner()

    # Try to scan a non-existent file
    result = runner.invoke(cli, ["scan", "/path/that/does/not/exist/file.pkl"])

    # Should exit with code 2 for scan errors
    assert result.exit_code == 2
    assert "Error" in result.output
