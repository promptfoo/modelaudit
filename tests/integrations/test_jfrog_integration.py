from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.integrations.jfrog import scan_jfrog_artifact


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.integrations.jfrog.scan_model_directory_or_file")
def test_scan_jfrog_artifact_success(mock_scan, mock_download, mock_detect, mock_mkdtemp, mock_rmtree):
    """Test successful JFrog artifact scanning."""
    temp_dir = "/tmp/modelaudit_jfrog_test"
    mock_mkdtemp.return_value = temp_dir

    # Mock file detection
    mock_detect.return_value = {"type": "file", "repo": "test-repo"}

    mock_download.return_value = Path(f"{temp_dir}/model.pt")

    # Create mock result
    from modelaudit.models import create_initial_audit_result

    mock_result = create_initial_audit_result()
    mock_result.bytes_scanned = 512
    mock_result.files_scanned = 1
    mock_result.scanner_names = ["test_scanner"]
    mock_scan.return_value = mock_result

    results = scan_jfrog_artifact(
        "https://company.jfrog.io/artifactory/repo/model.pt",
        api_token="token",
        timeout=200,
        blacklist_patterns=["bad"],
        max_file_size=1000,
        max_total_size=2000,
    )

    # Verify file detection was called
    mock_detect.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.pt",
        api_token="token",
        access_token=None,
        timeout=30,  # Min of timeout and 30
    )

    mock_download.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/model.pt",
        cache_dir=Path(temp_dir),
        api_token="token",
        access_token=None,
        timeout=200,
    )
    # Check that scan was called with adjusted timeout (should be slightly less than 200 due to download time)
    scan_call = mock_scan.call_args
    assert scan_call[0][0] == f"{temp_dir}/model.pt"
    assert scan_call[1]["blacklist_patterns"] == ["bad"]
    assert 195 <= scan_call[1]["timeout"] <= 200  # Should be close to 200 but slightly reduced
    assert scan_call[1]["max_file_size"] == 1000
    assert scan_call[1]["max_total_size"] == 2000
    assert scan_call[1]["cache_enabled"] is True
    assert scan_call[1]["cache_dir"] is None
    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)
    assert results == mock_result

    # Verify JFrog metadata was added
    assert hasattr(results, "metadata")
    metadata = results.metadata
    assert "jfrog_source" in metadata
    assert metadata["jfrog_source"]["type"] == "file"
    assert metadata["jfrog_source"]["repo"] == "test-repo"


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
def test_scan_jfrog_artifact_download_error(mock_download, mock_detect, mock_mkdtemp, mock_rmtree):
    """Test error handling when JFrog download fails."""
    temp_dir = "/tmp/modelaudit_jfrog_test"
    mock_mkdtemp.return_value = temp_dir

    # Mock file detection (successful)
    mock_detect.return_value = {"type": "file", "repo": "test-repo"}

    # Mock download failure
    mock_download.side_effect = Exception("fail")

    with pytest.raises(Exception, match="fail"):
        scan_jfrog_artifact("https://company.jfrog.io/artifactory/repo/model.pt")

    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_jfrog_folder")
@patch("modelaudit.integrations.jfrog.scan_model_directory_or_file")
def test_scan_jfrog_folder_success(mock_scan, mock_download_folder, mock_detect, mock_mkdtemp, mock_rmtree):
    """Test successful JFrog folder scanning."""
    temp_dir = "/tmp/modelaudit_jfrog_test"
    mock_mkdtemp.return_value = temp_dir

    # Mock folder detection
    mock_detect.return_value = {"type": "folder", "repo": "test-repo", "path": "/models"}

    # Mock folder download
    mock_download_folder.return_value = Path(f"{temp_dir}/models")

    # Create mock result
    from modelaudit.models import create_initial_audit_result

    mock_result = create_initial_audit_result()
    mock_result.bytes_scanned = 2048
    mock_result.files_scanned = 3
    mock_result.scanner_names = ["pickle_scanner", "pytorch_scanner"]
    mock_scan.return_value = mock_result

    results = scan_jfrog_artifact(
        "https://company.jfrog.io/artifactory/repo/models/",
        api_token="token",
        timeout=200,
        blacklist_patterns=["bad"],
        max_file_size=1000,
        max_total_size=2000,
    )

    # Verify folder detection was called
    mock_detect.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/models/",
        api_token="token",
        access_token=None,
        timeout=30,  # Min of timeout and 30
    )

    # Verify folder download was called (not file download)
    mock_download_folder.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/models/",
        cache_dir=Path(temp_dir),
        api_token="token",
        access_token=None,
        timeout=200,
        selective=True,
        show_progress=True,
    )

    # Verify scan was called on the folder with adjusted timeout
    scan_call = mock_scan.call_args
    assert scan_call[0][0] == f"{temp_dir}/models"
    assert scan_call[1]["blacklist_patterns"] == ["bad"]
    assert 195 <= scan_call[1]["timeout"] <= 200  # Should be close to 200 but slightly reduced
    assert scan_call[1]["max_file_size"] == 1000
    assert scan_call[1]["max_total_size"] == 2000
    assert scan_call[1]["cache_enabled"] is True
    assert scan_call[1]["cache_dir"] is None

    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)

    # Verify JFrog metadata was added to results
    assert hasattr(results, "metadata")
    metadata = results.metadata
    assert "jfrog_source" in metadata
    assert metadata["jfrog_source"]["type"] == "folder"
    assert metadata["jfrog_source"]["url"] == "https://company.jfrog.io/artifactory/repo/models/"
    assert metadata["jfrog_source"]["repo"] == "test-repo"


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
def test_scan_jfrog_artifact_detection_error(mock_detect, mock_mkdtemp, mock_rmtree):
    """Test error handling when JFrog target detection fails."""
    temp_dir = "/tmp/modelaudit_jfrog_test"
    mock_mkdtemp.return_value = temp_dir
    mock_detect.side_effect = Exception("Authentication failed")

    with pytest.raises(Exception, match="Authentication failed"):
        scan_jfrog_artifact("https://company.jfrog.io/artifactory/repo/model.pt")

    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)


class TestJFrogIntegrationEndToEnd:
    """Integration tests that would work with a real JFrog instance."""

    @pytest.mark.integration
    @pytest.mark.skipif(True, reason="Integration tests disabled by default - enable with --run-integration-tests")
    def test_scan_real_jfrog_file(self):
        """Test scanning a real JFrog file (requires JFrog instance).

        This test is skipped by default. To run it, you need:
        1. A running JFrog Artifactory instance
        2. Valid credentials in environment variables
        3. A test model file uploaded to your repository
        4. Run with: pytest --run-integration-tests
        """
        import os

        # These should be set in your test environment
        jfrog_url = os.getenv("JFROG_TEST_FILE_URL")
        api_token = os.getenv("JFROG_API_TOKEN")

        if not jfrog_url or not api_token:
            pytest.skip("JFrog integration test credentials not available")

        results = scan_jfrog_artifact(jfrog_url, api_token=api_token)

        # Basic validation
        assert results is not None
        assert results.files_scanned >= 1
        assert hasattr(results, "metadata")
        metadata = results.metadata
        assert "jfrog_source" in metadata
        assert metadata["jfrog_source"]["type"] in ["file", "folder"]

    @pytest.mark.integration
    @pytest.mark.skipif(True, reason="Integration tests disabled by default - enable with --run-integration-tests")
    def test_scan_real_jfrog_folder(self):
        """Test scanning a real JFrog folder (requires JFrog instance).

        This test is skipped by default. To run it, you need:
        1. A running JFrog Artifactory instance
        2. Valid credentials in environment variables
        3. A test folder with model files uploaded to your repository
        4. Run with: pytest --run-integration-tests
        """
        import os

        # These should be set in your test environment
        jfrog_url = os.getenv("JFROG_TEST_FOLDER_URL")
        api_token = os.getenv("JFROG_API_TOKEN")

        if not jfrog_url or not api_token:
            pytest.skip("JFrog integration test credentials not available")

        results = scan_jfrog_artifact(jfrog_url, api_token=api_token)

        # Basic validation for folder scanning
        assert results is not None
        assert results.files_scanned >= 1  # Should find at least one model file
        assert hasattr(results, "metadata")
        metadata = results.metadata
        assert "jfrog_source" in metadata
        assert metadata["jfrog_source"]["type"] == "folder"
