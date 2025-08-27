import json
import os
import re
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from modelaudit import __version__
from modelaudit.cli import cli, format_text_output
from modelaudit.models import create_initial_audit_result


def strip_ansi(text):
    """Strip ANSI color codes from text for testing."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def create_mock_scan_result(**kwargs):
    """Create a mock ModelAuditResultModel for testing."""
    result = create_initial_audit_result()

    # Set default values
    result.bytes_scanned = kwargs.get("bytes_scanned", 1024)
    result.files_scanned = kwargs.get("files_scanned", 1)
    result.has_errors = kwargs.get("has_errors", False)
    result.success = kwargs.get("success", True)

    # Add issues if provided
    if "issues" in kwargs:
        import time

        from modelaudit.scanners.base import Issue

        issues = []
        for issue_dict in kwargs["issues"]:
            issue = Issue(
                message=issue_dict.get("message", "Test issue"),
                severity=issue_dict.get("severity", "warning"),
                location=issue_dict.get("location"),
                timestamp=time.time(),
                details=issue_dict.get("details", {}),
            )
            issues.append(issue)
        result.issues = issues

    # Add assets if provided
    if "assets" in kwargs:
        from modelaudit.models import AssetModel

        assets = []
        for asset_dict in kwargs["assets"]:
            asset = AssetModel(path=asset_dict.get("path", "/test/path"), type=asset_dict.get("type", "test"))
            assets.append(asset)
        result.assets = assets

    # Add scanners if provided
    if "scanners" in kwargs:
        result.scanner_names = kwargs["scanners"]

    result.finalize_statistics()
    return result


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
    (test_dir / "file1.pkl").write_bytes(b"test content 1")
    (test_dir / "file2.bin").write_bytes(b"test content 2")

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
    assert str(file1) in result.output or str(file2) in result.output  # Should mention at least one file path


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


def test_scan_output_utf8_locale(tmp_path):
    """Ensure output file is valid UTF-8 even with ASCII locale."""
    test_file = tmp_path / "utf8_test.dat"
    test_file.write_bytes(b"test content")

    output_file = tmp_path / "output.txt"

    runner = CliRunner()
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    runner.invoke(cli, ["scan", str(test_file), "--output", str(output_file)], env=env)

    assert output_file.exists()
    try:
        output_file.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        pytest.fail("Output file is not valid UTF-8")


def test_scan_sbom_utf8_locale(tmp_path):
    """Ensure SBOM file is valid UTF-8 even with ASCII locale."""
    test_file = tmp_path / "utf8_test.dat"
    test_file.write_bytes(b"test content")

    sbom_file = tmp_path / "sbom.json"

    runner = CliRunner()
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    runner.invoke(cli, ["scan", str(test_file), "--sbom", str(sbom_file)], env=env)

    assert sbom_file.exists()
    try:
        sbom_file.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        pytest.fail("SBOM file is not valid UTF-8")


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
    assert "INFORMATIONAL FINDINGS" in clean_output  # Info issues show INFORMATIONAL FINDINGS
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
    assert "INFORMATIONAL FINDINGS" in clean_output  # Info issues show INFORMATIONAL FINDINGS
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


def test_scan_huggingface_url_help():
    """Test that HuggingFace URL examples are in the help text."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "https://huggingface.co/user/model" in result.output
    assert "https://pytorch.org/hub/pytorch_vision_resnet/" in result.output
    assert "hf://user/model" in result.output
    assert "s3://my-bucket/models/" in result.output
    assert "models:/MyModel/1" in result.output


def test_scan_jfrog_url_help():
    """Test that JFrog URL example is in the help text."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "jfrog.io" in result.output


def test_scan_mlflow_url_help():
    """Test that MLflow URL examples are in the help text."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "models:/MyModel/1" in result.output
    assert "models:/MyModel/Production" in result.output


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_url_success(mock_rmtree, mock_scan, mock_download, mock_is_hf_url, tmp_path):
    """Test successful scanning of a HuggingFace URL."""
    # Setup mocks
    mock_is_hf_url.return_value = True
    # Create a real temp directory for the test
    test_model_dir = tmp_path / "test_model"
    test_model_dir.mkdir()
    # Create a dummy file inside to make it look like a real model
    (test_model_dir / "model.bin").write_text("dummy model")

    mock_download.return_value = test_model_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=1024, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "https://huggingface.co/test/model"])

    # Should succeed
    assert result.exit_code == 0
    assert (
        "Downloaded" in result.output
        or "Clean" in result.output
        or "Downloaded successfully" in result.output
        or "Downloading from" in result.output
    )

    # Verify download was called
    mock_download.assert_called_once()

    # Verify scan was called with downloaded path
    mock_scan.assert_called_once()
    call_args = mock_scan.call_args
    assert call_args[0][0] == str(test_model_dir)

    # Verify cleanup was attempted (only when not using cache)
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
def test_scan_huggingface_url_download_failure(mock_download, mock_is_hf_url):
    """Test handling of download failure for HuggingFace URL."""
    # Setup mocks
    mock_is_hf_url.return_value = True
    mock_download.side_effect = Exception("Download failed")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://huggingface.co/test/model"])

    # Should fail with error code 2
    assert result.exit_code == 2
    assert "Error downloading model" in result.output
    assert "Download failed" in result.output


@patch("modelaudit.cli.is_huggingface_url")
@patch("modelaudit.cli.download_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_huggingface_url_with_issues(mock_rmtree, mock_scan, mock_download, mock_is_hf_url, tmp_path):
    """Test scanning a HuggingFace URL that has security issues."""
    # Setup mocks
    mock_is_hf_url.return_value = True
    # Create a real temp directory for the test
    test_model_dir = tmp_path / "test_model"
    test_model_dir.mkdir()
    # Create a dummy file inside to make it look like a real model
    (test_model_dir / "model.pkl").write_text("dummy model")

    mock_download.return_value = test_model_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=2048,
        issues=[
            {
                "message": "Dangerous import detected",
                "severity": "critical",
                "location": "model.pkl",
            }
        ],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["pickle_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "hf://test/malicious-model"])

    # Should exit with code 1 (security issues found)
    assert result.exit_code == 1
    assert (
        "Downloaded" in result.output
        or "issue" in result.output.lower()
        or "Downloaded successfully" in result.output
        or "Downloading from" in result.output
    )

    # Verify cleanup was still attempted
    mock_rmtree.assert_called()


@patch("modelaudit.cli.scan_model_directory_or_file")
def test_scan_mixed_paths_and_urls(mock_scan):
    """Test scanning both local paths and HuggingFace URLs in one command."""
    runner = CliRunner()

    with patch("modelaudit.cli.is_huggingface_url") as mock_is_hf, patch("os.path.exists") as mock_exists:
        # Setup mocks - first arg is local path, second is URL
        mock_is_hf.side_effect = [False, True]
        mock_exists.return_value = False  # Local path doesn't exist

        result = runner.invoke(cli, ["scan", "/local/path/model.pkl", "https://huggingface.co/test/model"])

        # Should report error for missing local file
        assert "Path does not exist: /local/path/model.pkl" in result.output


@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_pytorchhub_url_success(mock_rmtree, mock_scan, mock_download, mock_is_ph_url, tmp_path):
    """Test scanning a PyTorch Hub URL successfully."""
    mock_is_ph_url.return_value = True
    test_dir = tmp_path / "hub"
    test_dir.mkdir()
    (test_dir / "model.pt").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=1, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://pytorch.org/hub/pytorch_vision_resnet/"])

    assert result.exit_code == 0
    mock_download.assert_called_once()
    mock_scan.assert_called_once()
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_pytorch_hub_url")
@patch("modelaudit.cli.download_pytorch_hub_model")
def test_scan_pytorchhub_url_download_failure(mock_download, mock_is_ph_url):
    """Test download failure for PyTorch Hub URL."""
    mock_is_ph_url.return_value = True
    mock_download.side_effect = Exception("boom")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://pytorch.org/hub/pytorch_vision_resnet/"])

    assert result.exit_code == 2
    assert "Error downloading model" in result.output


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_cloud_url_success(mock_rmtree, mock_scan, mock_download, mock_is_cloud, tmp_path):
    """Test scanning a cloud storage URL successfully."""
    mock_is_cloud.return_value = True
    test_dir = tmp_path / "cloud"
    test_dir.mkdir()
    (test_dir / "model.bin").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=123, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "s3://bucket/model.bin"])

    assert result.exit_code == 0
    mock_download.assert_called_once()
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
def test_scan_cloud_url_download_failure(mock_download, mock_is_cloud):
    """Test download failure for cloud storage URL."""
    mock_is_cloud.return_value = True
    mock_download.side_effect = Exception("boom")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "s3://bucket/model.bin"])

    assert result.exit_code == 2
    assert "Error downloading" in result.output


@patch("modelaudit.cli.is_cloud_url")
@patch("modelaudit.cli.download_from_cloud")
@patch("modelaudit.cli.scan_model_directory_or_file")
@patch("shutil.rmtree")
def test_scan_cloud_url_with_issues(mock_rmtree, mock_scan, mock_download, mock_is_cloud, tmp_path):
    """Test scanning a cloud storage URL that has issues."""
    mock_is_cloud.return_value = True
    test_dir = tmp_path / "cloud"
    test_dir.mkdir()
    (test_dir / "model.pkl").write_text("dummy")
    mock_download.return_value = test_dir
    mock_scan.return_value = create_mock_scan_result(
        bytes_scanned=123,
        issues=[{"message": "bad", "severity": "critical", "location": "model.pkl"}],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["pickle"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--no-cache", "gs://bucket/model.pkl"])

    assert result.exit_code == 1
    mock_rmtree.assert_called()


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_success(mock_scan_jfrog, mock_is_jfrog):
    """Test scanning a JFrog URL."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://company.jfrog.io/artifactory/repo/model.bin"])

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        api_token=None,
        access_token=None,
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        strict_license=False,
        skip_file_types=True,
    )


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_download_failure(mock_scan_jfrog, mock_is_jfrog):
    """Test handling of JFrog download failures."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.side_effect = Exception("fail")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://company.jfrog.io/artifactory/repo/model.bin"])

    assert result.exit_code == 2
    assert "Error downloading/scanning model" in result.output


@patch("modelaudit.cli.is_jfrog_url")
@patch("modelaudit.cli.scan_jfrog_artifact")
def test_scan_jfrog_url_with_auth(mock_scan_jfrog, mock_is_jfrog):
    """Test scanning a JFrog URL with authentication."""
    mock_is_jfrog.return_value = True
    mock_scan_jfrog.return_value = create_mock_scan_result(
        bytes_scanned=512, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "https://company.jfrog.io/artifactory/repo/model.bin",
            "--jfrog-api-token",
            "test-token",
            "--timeout",
            "600",
        ],
    )

    assert result.exit_code == 0
    mock_scan_jfrog.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.bin",
        api_token="test-token",
        access_token=None,
        timeout=600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        strict_license=False,
        skip_file_types=True,
    )


@patch("modelaudit.mlflow_integration.scan_mlflow_model")
def test_scan_mlflow_uri_success(mock_scan_mlflow):
    """Test successful scanning of an MLflow URI."""
    # Setup mock
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=1024, issues=[], files_scanned=1, assets=[], has_errors=False, scanners=["test_scanner"]
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "models:/TestModel/1", "--registry-uri", "http://localhost:5000"])

    # Should succeed
    assert result.exit_code == 0
    assert (
        "Downloaded & Scanned" in result.output
        or "Clean" in result.output
        or "Downloaded and scanned successfully" in result.output
    )

    # Verify MLflow scan was called with correct parameters
    mock_scan_mlflow.assert_called_once_with(
        "models:/TestModel/1",
        registry_uri="http://localhost:5000",
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
    )


@patch("modelaudit.mlflow_integration.scan_mlflow_model")
def test_scan_mlflow_uri_with_options(mock_scan_mlflow):
    """Test MLflow URI scanning with additional options."""
    # Setup mock
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=2048,
        issues=[{"message": "Test issue", "severity": "warning"}],
        files_scanned=1,
        assets=[],
        has_errors=False,
        scanners=["test_scanner"],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "models:/TestModel/Production",
            "--registry-uri",
            "http://mlflow.example.com",
            "--timeout",
            "600",
            "--blacklist",
            "malicious",
            "--blacklist",
            "unsafe",
            "--max-file-size",
            "1000000",
            "--max-total-size",
            "5000000",
            "--verbose",
        ],
    )

    # Should succeed with findings
    assert result.exit_code == 1  # Exit code 1 indicates issues found

    # Verify MLflow scan was called with all options
    mock_scan_mlflow.assert_called_once_with(
        "models:/TestModel/Production",
        registry_uri="http://mlflow.example.com",
        timeout=600,
        blacklist_patterns=["malicious", "unsafe"],
        max_file_size=1000000,
        max_total_size=5000000,
    )


@patch("modelaudit.mlflow_integration.scan_mlflow_model")
def test_scan_mlflow_uri_error(mock_scan_mlflow):
    """Test error handling for MLflow URI scanning."""
    # Setup mock to raise an error
    mock_scan_mlflow.side_effect = Exception("MLflow connection failed")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "models:/TestModel/1"])

    # Should fail with error code 2
    assert result.exit_code == 2
    assert "Error downloading model" in result.output
    assert "MLflow connection failed" in result.output


@patch("modelaudit.mlflow_integration.scan_mlflow_model")
def test_scan_mlflow_uri_json_format(mock_scan_mlflow):
    """Test MLflow URI scanning with JSON output format."""
    # Setup mock
    mock_scan_mlflow.return_value = create_mock_scan_result(
        bytes_scanned=1024,
        issues=[],
        files_scanned=1,
        assets=[{"path": "model.pkl", "type": "pickle"}],
        has_errors=False,
        scanners=["pickle"],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "models:/TestModel/1", "--format", "json"])

    # Should succeed and output JSON
    assert result.exit_code == 0

    # Should contain JSON output
    assert "bytes_scanned" in result.output
    assert "files_scanned" in result.output
    assert "assets" in result.output


def test_is_mlflow_uri():
    """Test the is_mlflow_uri helper function."""
    from modelaudit.cli import is_mlflow_uri

    # Test valid MLflow URIs
    assert is_mlflow_uri("models:/MyModel/1")
    assert is_mlflow_uri("models:/MyModel/Production")
    assert is_mlflow_uri("models:/MyModel/Staging")

    # Test invalid URIs
    assert not is_mlflow_uri("/path/to/model.pkl")
    assert not is_mlflow_uri("https://huggingface.co/model")
    assert not is_mlflow_uri("hf://model")
    assert not is_mlflow_uri("model.pkl")
    assert not is_mlflow_uri("models:invalid")


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
    assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"
    # The output might not say "No issues found" if there are debug messages,
    # so let's be less strict
    assert "scan completed successfully" in result.output.lower() or "no issues found" in result.output.lower()


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
    assert result.exit_code == 1, f"Expected exit code 1, got {result.exit_code}. Output: {result.output}"
    assert "error" in result.output.lower() or "warning" in result.output.lower()


def test_exit_code_scan_errors(tmp_path):
    """Test exit code 2 when errors occur during scanning."""
    runner = CliRunner()

    # Try to scan a non-existent file
    result = runner.invoke(cli, ["scan", "/path/that/does/not/exist/file.pkl"])

    # Should exit with code 2 for scan errors
    assert result.exit_code == 2
    assert "Error" in result.output


def test_doctor_command():
    """Test the doctor command for scanner diagnostics."""
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 0
    assert "ModelAudit Scanner Diagnostic Report" in result.output
    assert "Python version:" in result.output
    assert "NumPy status:" in result.output
    assert "Total scanners:" in result.output
    assert "Loaded successfully:" in result.output
    assert "Failed to load:" in result.output


def test_doctor_command_with_show_failed():
    """Test the doctor command with --show-failed flag."""
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--show-failed"])

    assert result.exit_code == 0
    assert "ModelAudit Scanner Diagnostic Report" in result.output

    # Should show failed scanners if any exist
    if "Failed to load: 0" not in result.output:
        assert "Failed Scanners:" in result.output or "Recommendations:" in result.output


def test_doctor_command_numpy_status():
    """Test that doctor command provides NumPy compatibility information."""
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 0
    assert "NumPy" in result.output

    # Should provide either success message or recommendations
    success_indicators = ["All scanners loaded successfully!", "Recommendations:"]
    assert any(indicator in result.output for indicator in success_indicators)
