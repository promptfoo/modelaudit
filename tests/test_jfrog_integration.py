from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.jfrog_integration import scan_jfrog_artifact


@patch("modelaudit.jfrog_integration.shutil.rmtree")
@patch("modelaudit.jfrog_integration.tempfile.mkdtemp")
@patch("modelaudit.jfrog_integration.download_artifact")
@patch("modelaudit.jfrog_integration.scan_model_directory_or_file")
def test_scan_jfrog_artifact_success(mock_scan, mock_download, mock_mkdtemp, mock_rmtree):
    """Test successful JFrog artifact scanning."""
    temp_dir = "/tmp/modelaudit_jfrog_test"
    mock_mkdtemp.return_value = temp_dir
    mock_download.return_value = Path(f"{temp_dir}/model.pt")
    expected_results = {
        "bytes_scanned": 512,
        "issues": [],
        "files_scanned": 1,
        "assets": [],
        "has_errors": False,
        "scanners": ["test_scanner"],
    }
    mock_scan.return_value = expected_results

    results = scan_jfrog_artifact(
        "https://company.jfrog.io/artifactory/repo/model.pt",
        api_token="token",
        timeout=200,
        blacklist_patterns=["bad"],
        max_file_size=1000,
        max_total_size=2000,
    )

    mock_download.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.pt",
        cache_dir=Path(temp_dir),
        api_token="token",
        access_token=None,
        timeout=200,
    )
    mock_scan.assert_called_once_with(
        f"{temp_dir}/model.pt",
        blacklist_patterns=["bad"],
        timeout=200,
        max_file_size=1000,
        max_total_size=2000,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)
    assert results == expected_results


@patch("modelaudit.jfrog_integration.shutil.rmtree")
@patch("modelaudit.jfrog_integration.tempfile.mkdtemp")
@patch("modelaudit.jfrog_integration.download_artifact")
def test_scan_jfrog_artifact_download_error(mock_download, mock_mkdtemp, mock_rmtree):
    """Test error handling when JFrog download fails."""
    temp_dir = "/tmp/modelaudit_jfrog_test"
    mock_mkdtemp.return_value = temp_dir
    mock_download.side_effect = Exception("fail")

    with pytest.raises(Exception, match="fail"):
        scan_jfrog_artifact("https://company.jfrog.io/artifactory/repo/model.pt")

    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)
