import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.core import determine_exit_code
from modelaudit.integrations.mlflow import scan_mlflow_model


def test_scan_mlflow_model_import_error(monkeypatch):
    """scan_mlflow_model should raise ImportError when mlflow is missing."""
    monkeypatch.setitem(sys.modules, "mlflow", None)
    with pytest.raises(ImportError, match="mlflow is not installed"):
        scan_mlflow_model("models:/dummy/1")


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_success(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
) -> None:
    """Test successful MLflow model scanning."""
    # Mock MLflow
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.download_artifacts.return_value = "/tmp/test_model"
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=1024),
    ]
    mock_repo.download_artifacts.return_value = "/tmp/test_model"
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

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
    mock_mlflow.artifacts.get_artifact_repository.assert_called_once_with("models:/TestModel/1")
    mock_repo.list_artifacts.assert_called_once_with(None)
    mock_repo.download_artifacts.assert_called_once_with(artifact_path="", dst_path=temp_dir)
    mock_mlflow.artifacts.download_artifacts.assert_not_called()

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
    assert results == mock_scan.return_value  # Verify the mock was called correctly


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_splits_subpath_and_downloads_from_resolved_repo(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
) -> None:
    """Finite-budget MLflow scans should list and download the same resolved subpath."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="path/to/model/model.pkl", is_dir=False, file_size=1024),
    ]
    mock_repo.download_artifacts.return_value = "/tmp/modelaudit_mlflow_test/path/to/model"
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 1024, "issues": []}
    mock_mkdtemp.return_value = "/tmp/modelaudit_mlflow_test"

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        scan_mlflow_model("models:/TestModel/2/path/to/model", max_file_size=2048)

    mock_mlflow.artifacts.get_artifact_repository.assert_called_once_with("models:/TestModel/2")
    mock_repo.list_artifacts.assert_called_once_with("path/to/model")
    mock_repo.download_artifacts.assert_called_once_with(
        artifact_path="path/to/model",
        dst_path="/tmp/modelaudit_mlflow_test",
    )
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once_with("/tmp/modelaudit_mlflow_test", ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_accepts_single_file_artifact_with_size_metadata(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Finite-budget MLflow scans should accept exact file artifact URIs when parent metadata is bounded."""
    download_dir = tmp_path / "modelaudit_mlflow_test"
    download_dir.mkdir()
    downloaded_file = download_dir / "model.pkl"
    downloaded_file.write_bytes(b"safe")
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.side_effect = [
        [],
        [SimpleNamespace(path="model.pkl", is_dir=False, file_size=1024)],
    ]
    mock_repo.download_artifacts.return_value = str(downloaded_file)
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 1024, "issues": []}
    mock_mkdtemp.return_value = str(download_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        scan_mlflow_model("models:/TestModel/2/model.pkl", max_file_size=2048)

    assert [call.args for call in mock_repo.list_artifacts.call_args_list] == [("model.pkl",), (None,)]
    mock_repo.download_artifacts.assert_called_once_with(
        artifact_path="model.pkl",
        dst_path=str(download_dir),
    )
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_scan.assert_called_once_with(
        str(download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=2048,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_downloads_mutable_ref_from_preflight_repo(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
) -> None:
    """Mutable refs should not be resolved again after the finite-budget preflight."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=1024),
    ]
    mock_repo.download_artifacts.return_value = "/tmp/modelaudit_mlflow_stage"
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 1024, "issues": []}
    mock_mkdtemp.return_value = "/tmp/modelaudit_mlflow_test"

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        scan_mlflow_model("models:/TestModel/Production", max_total_size=2048)

    mock_mlflow.artifacts.get_artifact_repository.assert_called_once_with("models:/TestModel/Production")
    mock_repo.list_artifacts.assert_called_once_with(None)
    mock_repo.download_artifacts.assert_called_once_with(
        artifact_path="",
        dst_path="/tmp/modelaudit_mlflow_test",
    )
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once_with("/tmp/modelaudit_mlflow_test", ignore_errors=True)


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_unknown_size_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Finite budgets should fail closed before MLflow downloads unknown-size artifacts."""
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.get_artifact_repository.side_effect = RuntimeError("size unavailable")

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=1000)

    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.has_errors is True
    assert result.checks[0].name == "MLflow Download Size Check"
    assert result.checks[0].details["reason"] == "artifact_size_unavailable"


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_oversized_artifact_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Finite budgets should reject oversized MLflow artifacts before download."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="large.bin", is_dir=False, file_size=2048),
    ]
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=1024)

    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.checks[0].details["reason"] == "artifact_file_size_exceeded"
    assert result.checks[0].details["artifact_path"] == "large.bin"


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_listing_budget_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Finite-budget preflight should cap remote artifact traversal work."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="a.bin", is_dir=False, file_size=1),
        SimpleNamespace(path="b.bin", is_dir=False, file_size=1),
        SimpleNamespace(path="c.bin", is_dir=False, file_size=1),
    ]
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model(
            "models:/TestModel/1",
            max_file_size=1024,
            max_mlflow_artifact_entries=2,
        )

    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.checks[0].details["reason"] == "artifact_listing_budget_exceeded"
    assert result.checks[0].details["artifact_entry_count"] == 3
    assert result.checks[0].details["max_artifact_entries"] == 2


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_bounds_generator_listing_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Generator-like artifact repositories should not be fully materialized before the listing cap."""
    yielded: list[int] = []

    def _artifact_infos() -> Any:
        for index in range(100):
            yielded.append(index)
            yield SimpleNamespace(path=f"{index}.bin", is_dir=False, file_size=1)

    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = _artifact_infos()
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model(
            "models:/TestModel/1",
            max_file_size=1024,
            max_mlflow_artifact_entries=2,
        )

    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert yielded == [0, 1, 2]
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_listing_budget_exceeded"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_uses_cache_dir_for_downloads(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Test MLflow model downloads use a dedicated subdirectory under cache_dir."""
    mock_mlflow = MagicMock()
    cache_dir = tmp_path / "cache"
    cache_key = hashlib.sha256(b"models:/TestModel/1").hexdigest()[:16]
    expected_download_root = cache_dir / "mlflow"
    expected_download_dir = expected_download_root / f"{cache_key}-run"
    mock_mkdtemp.return_value = str(expected_download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(expected_download_dir)
    mock_scan.return_value = {"bytes_scanned": 256, "issues": []}

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        scan_mlflow_model("models:/TestModel/1", cache_enabled=True, cache_dir=str(cache_dir))

    mock_mkdtemp.assert_called_once_with(prefix=f"{cache_key}-", dir=str(expected_download_root))
    mock_mlflow.artifacts.download_artifacts.assert_called_once_with(
        artifact_uri="models:/TestModel/1",
        dst_path=str(expected_download_dir),
    )
    mock_scan.assert_called_once_with(
        str(expected_download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=str(cache_dir),
    )
    mock_rmtree.assert_called_once_with(str(expected_download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
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
        args, _kwargs = mock_scan.call_args
        assert args[0] == temp_dir  # Should be directory, not file


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
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
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value="/tmp/test"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value={}),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
    ):
        scan_mlflow_model("models:/TestModel/1")

        # Verify set_registry_uri was not called
        mock_mlflow.set_registry_uri.assert_not_called()
