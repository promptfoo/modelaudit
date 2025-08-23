import sys
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.mlflow_integration import scan_mlflow_model


def test_scan_mlflow_model_import_error(monkeypatch):
    """scan_mlflow_model should raise ImportError when mlflow is missing."""
    monkeypatch.setitem(sys.modules, "mlflow", None)
    with pytest.raises(ImportError, match="mlflow is not installed"):
        scan_mlflow_model("models:/dummy/1")


@patch("modelaudit.mlflow_integration.shutil.rmtree")
@patch("modelaudit.mlflow_integration.tempfile.mkdtemp")
@patch("modelaudit.mlflow_integration.scan_model_directory_or_file")
def test_scan_mlflow_model_success(mock_scan, mock_mkdtemp, mock_rmtree):
    """Test successful MLflow model scanning."""
    # Mock MLflow
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.download_artifacts.return_value = "/tmp/test_model"

    # Create a temporary directory for the test
    temp_dir = "/tmp/modelaudit_mlflow_test"
    mock_mkdtemp.return_value = temp_dir

    # Mock the scan results
    expected_results = {
        "bytes_scanned": 1024,
        "issues": [],
        "files_scanned": 1,
        "assets": [],
        "has_errors": False,
        "scanners": ["test_scanner"],
    }
    mock_scan.return_value = expected_results

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        results = scan_mlflow_model(
            "models:/TestModel/1",
            registry_uri="http://localhost:5000",
            timeout=300,
            blacklist_patterns=["malicious"],
            max_file_size=1000000,
            max_total_size=5000000,
        )

    # Verify MLflow interactions
    mock_mlflow.set_registry_uri.assert_called_once_with("http://localhost:5000")
    mock_mlflow.artifacts.download_artifacts.assert_called_once_with(
        artifact_uri="models:/TestModel/1", dst_path=temp_dir
    )

    # Verify scan was called with correct parameters
    mock_scan.assert_called_once_with(
        "/tmp/test_model",
        timeout=300,
        blacklist_patterns=["malicious"],
        max_file_size=1000000,
        max_total_size=5000000,
        cache_enabled=True,
        cache_dir=None,
    )

    # Verify cleanup
    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)

    # Verify results
    assert results == expected_results


@patch("modelaudit.mlflow_integration.shutil.rmtree")
@patch("modelaudit.mlflow_integration.tempfile.mkdtemp")
@patch("modelaudit.mlflow_integration.scan_model_directory_or_file")
def test_scan_mlflow_model_file_path(mock_scan, mock_mkdtemp, mock_rmtree):
    """Test MLflow model scanning when download returns a file path."""
    # Mock MLflow
    mock_mlflow = MagicMock()

    # Create a temporary file path (simulating MLflow returning a file)
    temp_dir = "/tmp/modelaudit_mlflow_test"
    temp_file = "/tmp/modelaudit_mlflow_test/model.pkl"
    mock_mlflow.artifacts.download_artifacts.return_value = temp_file
    mock_mkdtemp.return_value = temp_dir

    # Mock os.path.isfile to return True for our temp file
    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.dirname", return_value=temp_dir),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        mock_scan.return_value = {"bytes_scanned": 512, "issues": []}

        scan_mlflow_model("models:/TestModel/1")

        # Verify scan was called with the directory path, not the file path
        mock_scan.assert_called_once()
        args, kwargs = mock_scan.call_args
        assert args[0] == temp_dir  # Should be directory, not file


@patch("modelaudit.mlflow_integration.shutil.rmtree")
@patch("modelaudit.mlflow_integration.tempfile.mkdtemp")
def test_scan_mlflow_model_download_error(mock_mkdtemp, mock_rmtree):
    """Test error handling when MLflow download fails."""
    # Mock MLflow with download error
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.download_artifacts.side_effect = Exception("Download failed")

    temp_dir = "/tmp/modelaudit_mlflow_test"
    mock_mkdtemp.return_value = temp_dir

    with (
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
        pytest.raises(Exception, match="Download failed"),
    ):
        scan_mlflow_model("models:/TestModel/1")

    # Verify cleanup still happens
    mock_rmtree.assert_called_once_with(temp_dir, ignore_errors=True)


def test_scan_mlflow_model_no_registry_uri():
    """Test MLflow model scanning without registry URI."""
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.download_artifacts.return_value = "/tmp/test_model"

    with (
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
        patch("modelaudit.mlflow_integration.tempfile.mkdtemp", return_value="/tmp/test"),
        patch("modelaudit.mlflow_integration.scan_model_directory_or_file", return_value={}),
        patch("modelaudit.mlflow_integration.shutil.rmtree"),
    ):
        scan_mlflow_model("models:/TestModel/1")

        # Verify set_registry_uri was not called
        mock_mlflow.set_registry_uri.assert_not_called()
