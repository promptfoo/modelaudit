import hashlib
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.integrations.jfrog import scan_jfrog_artifact


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_artifact_success(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test successful JFrog artifact scanning."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir

    # Mock file detection
    mock_detect.return_value = {"type": "file", "repo": "test-repo", "size": 512, "size_known": True}

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
        max_size=1000,
    )
    # Check that scan was called with adjusted timeout (should be slightly less than 200 due to download time)
    scan_call = mock_scan.call_args
    # Normalize paths for cross-platform comparison (Windows uses backslashes)
    # scan_call[0][0] is a string (converted via str(download_path) in jfrog.py)
    expected_path = str(Path(temp_dir) / "model.pt")
    actual_path = str(scan_call[0][0])
    assert Path(actual_path).as_posix() == Path(expected_path).as_posix()
    assert scan_call[1]["blacklist_patterns"] == ["bad"]
    assert 195 <= scan_call[1]["timeout"] <= 200  # Should be close to 200 but slightly reduced
    assert scan_call[1]["max_file_size"] == 1000
    assert scan_call[1]["max_total_size"] == 2000
    assert scan_call[1]["cache_enabled"] is True
    assert scan_call[1]["cache_dir"] is None
    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)
    assert results == mock_result

    # Verify JFrog metadata was added
    assert hasattr(results, "metadata")
    metadata = results.metadata
    assert "jfrog_source" in metadata
    assert metadata["jfrog_source"]["type"] == "file"
    assert metadata["jfrog_source"]["url"] == "https://company.jfrog.io/artifactory/repo/model.pt"
    assert metadata["jfrog_source"]["repo"] == "test-repo"


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_artifact_rejects_oversized_file_before_download(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Storage API metadata should cap direct artifact transfer before body download."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.return_value = {"type": "file", "repo": "test-repo", "size": 6, "size_known": True}

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        scan_jfrog_artifact(
            "https://company.jfrog.io/artifactory/repo/model.pt",
            max_download_size=5,
        )

    mock_download.assert_not_called()
    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_artifact_rejects_huge_declared_size_without_format_overflow(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Attacker-controlled size metadata must not overflow error formatting."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.return_value = {
        "type": "file",
        "repo": "test-repo",
        "size": 10**400,
        "size_known": True,
    }

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        scan_jfrog_artifact(
            "https://company.jfrog.io/artifactory/repo/model.pt",
            max_download_size=5,
        )

    mock_download.assert_not_called()
    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_artifact_rejects_unknown_file_size_when_capped(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Unknown Storage API sizes should fail closed when a download budget is active."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.return_value = {"type": "file", "repo": "test-repo", "size": 0, "size_known": False}

    with pytest.raises(ValueError, match="Cannot verify JFrog artifact size"):
        scan_jfrog_artifact(
            "https://company.jfrog.io/artifactory/repo/model.pt",
            max_download_size=5,
        )

    mock_download.assert_not_called()
    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_artifact_redacts_source_url(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    """JFrog scan logs and metadata should not store URL credentials."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.return_value = {"type": "file", "repo": "test-repo", "size": 512, "size_known": True}
    mock_download.return_value = Path(f"{temp_dir}/model.pt")

    from modelaudit.models import create_initial_audit_result

    mock_result = create_initial_audit_result()
    mock_scan.return_value = mock_result
    raw_url = "https://user:leaky-pass@company.jfrog.io/artifactory/repo/model.pt?token=leaky-token"

    with caplog.at_level(logging.DEBUG, logger="modelaudit.integrations.jfrog"):
        results = scan_jfrog_artifact(raw_url, api_token="token")

    assert results.model_extra is not None
    jfrog_source = results.model_extra["metadata"]["jfrog_source"]
    assert jfrog_source["url"] == "https://<credentials-redacted>@company.jfrog.io/artifactory/repo/model.pt"
    assert "user:leaky-pass" not in caplog.text
    assert "leaky-token" not in caplog.text
    assert "user:leaky-pass" not in jfrog_source["url"]
    assert "leaky-token" not in jfrog_source["url"]
    mock_detect.assert_called_once_with(raw_url, api_token="token", access_token=None, timeout=30)
    mock_download.assert_called_once_with(
        raw_url,
        cache_dir=Path(temp_dir),
        api_token="token",
        access_token=None,
        timeout=3600,
        max_size=None,
    )
    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_artifact_uses_cache_dir_for_downloads(
    mock_scan: MagicMock,
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test JFrog downloads use a dedicated subdirectory under cache_dir."""
    url = "https://company.jfrog.io/artifactory/repo/model.pt"
    cache_dir = tmp_path / "cache"
    cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    expected_download_root = cache_dir / "jfrog"
    expected_download_dir = expected_download_root / f"{cache_key}-run"
    mock_mkdtemp.return_value = str(expected_download_dir)

    mock_detect.return_value = {"type": "file", "repo": "test-repo", "size": 512, "size_known": True}
    mock_download.return_value = expected_download_dir / "model.pt"

    from modelaudit.models import create_initial_audit_result

    mock_result = create_initial_audit_result()
    mock_result.bytes_scanned = 512
    mock_result.files_scanned = 1
    mock_result.scanner_names = ["test_scanner"]
    mock_scan.return_value = mock_result

    results = scan_jfrog_artifact(url, api_token="token", cache_enabled=True, cache_dir=str(cache_dir))

    mock_mkdtemp.assert_called_once_with(prefix=f"{cache_key}-", dir=str(expected_download_root))
    mock_download.assert_called_once_with(
        url,
        cache_dir=expected_download_dir,
        api_token="token",
        access_token=None,
        timeout=3600,
        max_size=None,
    )
    mock_scan.assert_called_once()
    scan_call = mock_scan.call_args
    assert scan_call[0][0] == str(expected_download_dir / "model.pt")
    assert scan_call[1]["blacklist_patterns"] is None
    assert 3599 <= scan_call[1]["timeout"] <= 3600
    assert scan_call[1]["max_file_size"] == 0
    assert scan_call[1]["max_total_size"] == 0
    assert scan_call[1]["cache_enabled"] is True
    assert scan_call[1]["cache_dir"] == str(cache_dir)
    mock_rmtree.assert_called_once_with(expected_download_dir, ignore_errors=True)
    assert results == mock_result


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_artifact")
def test_scan_jfrog_artifact_download_error(
    mock_download: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test error handling when JFrog download fails."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir

    # Mock file detection (successful)
    mock_detect.return_value = {"type": "file", "repo": "test-repo"}

    # Mock download failure
    mock_download.side_effect = Exception("fail")

    with pytest.raises(Exception, match="fail"):
        scan_jfrog_artifact("https://company.jfrog.io/artifactory/repo/model.pt")

    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_jfrog_folder")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_folder_success(
    mock_scan: MagicMock,
    mock_download_folder: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test successful JFrog folder scanning."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
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
        max_size=None,
        max_file_size=1000,
        max_total_size=2000,
    )

    # Verify scan was called on the folder with adjusted timeout
    scan_call = mock_scan.call_args
    # Normalize paths for cross-platform comparison (Windows uses backslashes)
    # scan_call[0][0] is a string (converted via str(download_path) in jfrog.py)
    expected_path = str(Path(temp_dir) / "models")
    actual_path = str(scan_call[0][0])
    assert Path(actual_path).as_posix() == Path(expected_path).as_posix()
    assert scan_call[1]["blacklist_patterns"] == ["bad"]
    assert 195 <= scan_call[1]["timeout"] <= 200  # Should be close to 200 but slightly reduced
    assert scan_call[1]["max_file_size"] == 1000
    assert scan_call[1]["max_total_size"] == 2000
    assert scan_call[1]["cache_enabled"] is True
    assert scan_call[1]["cache_dir"] is None

    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)

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
@patch("modelaudit.integrations.jfrog.download_jfrog_folder")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_folder_download_error_aborts_scan(
    mock_scan: MagicMock,
    mock_download_folder: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test that folder download failures stop before scanning."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.return_value = {"type": "folder", "repo": "test-repo", "path": "/models"}
    mock_download_folder.side_effect = Exception("JFrog folder download failed after 1 of 2 file(s) completed")

    with pytest.raises(Exception, match="JFrog folder download failed"):
        scan_jfrog_artifact("https://company.jfrog.io/artifactory/repo/models/")

    mock_scan.assert_not_called()


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
@patch("modelaudit.integrations.jfrog.download_jfrog_folder")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_jfrog_folder_respects_selective_download(
    mock_scan: MagicMock,
    mock_download_folder: MagicMock,
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Explicit selective_download should flow through to folder downloads."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.return_value = {"type": "folder", "repo": "test-repo", "path": "/models"}
    mock_download_folder.return_value = Path(f"{temp_dir}/models")

    from modelaudit.models import create_initial_audit_result

    mock_result = create_initial_audit_result()
    mock_result.bytes_scanned = 2048
    mock_result.files_scanned = 3
    mock_result.scanner_names = ["pickle_scanner", "pytorch_scanner"]
    mock_scan.return_value = mock_result

    scan_jfrog_artifact(
        "https://company.jfrog.io/artifactory/repo/models/",
        api_token="token",
        timeout=200,
        selective_download=False,
        max_download_size=4096,
    )

    mock_download_folder.assert_called_once_with(
        "https://company.jfrog.io/artifactory/repo/models/",
        cache_dir=Path(temp_dir),
        api_token="token",
        access_token=None,
        timeout=200,
        selective=False,
        show_progress=True,
        max_size=4096,
        max_file_size=0,
        max_total_size=0,
    )
    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.jfrog.shutil.rmtree")
@patch("modelaudit.integrations.jfrog.tempfile.mkdtemp")
@patch("modelaudit.integrations.jfrog.detect_jfrog_target_type")
def test_scan_jfrog_artifact_detection_error(
    mock_detect: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test error handling when JFrog target detection fails."""
    temp_dir = str(tmp_path / "modelaudit_jfrog_test")
    mock_mkdtemp.return_value = temp_dir
    mock_detect.side_effect = Exception("Authentication failed")

    with pytest.raises(Exception, match="Authentication failed"):
        scan_jfrog_artifact("https://company.jfrog.io/artifactory/repo/model.pt")

    mock_rmtree.assert_called_once_with(Path(temp_dir), ignore_errors=True)


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
