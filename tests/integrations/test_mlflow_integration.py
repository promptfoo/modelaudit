import hashlib
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.core import determine_exit_code
from modelaudit.integrations.mlflow import (
    _copy_local_mlflow_artifact,
    _local_mlflow_artifact_root,
    _MlflowArtifact,
    _MlflowArtifactSizeChangedError,
    scan_mlflow_model,
)


def _write_local_artifacts(source_root: Path, artifact_sizes: dict[str, int]) -> None:
    for artifact_path, artifact_size in artifact_sizes.items():
        source_path = source_root.joinpath(*artifact_path.split("/"))
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(b"x" * artifact_size)


def test_local_mlflow_artifact_root_unwraps_models_repository(tmp_path: Path) -> None:
    """Only MLflow's local repository type should expose a bounded-copy source root."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        def __init__(self, repository: object) -> None:
            self.repo = repository

    mlflow_module = ModuleType("mlflow")
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    source_root = tmp_path / "artifacts"
    source_root.mkdir()

    with patch.dict(
        sys.modules,
        {
            "mlflow": mlflow_module,
            "mlflow.store": store_module,
            "mlflow.store.artifact": artifact_module,
            "mlflow.store.artifact.local_artifact_repo": local_module,
            "mlflow.store.artifact.models_artifact_repo": models_module,
        },
    ):
        assert (
            _local_mlflow_artifact_root(ModelsArtifactRepository(LocalArtifactRepository(source_root))) == source_root
        )
        assert _local_mlflow_artifact_root(object()) is None


def test_copy_local_mlflow_artifact_removes_partial_file_when_source_grows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mutable local source must not write beyond its advertised size."""
    source_root = tmp_path / "source"
    source_root.mkdir()
    source_path = source_root / "model.bin"
    source_path.write_bytes(b"abcd")
    destination = tmp_path / "download" / "model.bin"
    original_read = os.read
    grew = False

    def growing_read(file_descriptor: int, size: int) -> bytes:
        nonlocal grew
        data = original_read(file_descriptor, size)
        if not grew:
            with source_path.open("ab") as output:
                output.write(b"e")
            grew = True
        return data

    monkeypatch.setattr("modelaudit.integrations.mlflow._MLFLOW_COPY_CHUNK_SIZE", 2)
    monkeypatch.setattr(os, "read", growing_read)

    with pytest.raises(_MlflowArtifactSizeChangedError) as exc_info:
        _copy_local_mlflow_artifact(source_root, _MlflowArtifact(path="model.bin", size=4), destination)

    assert exc_info.value.actual_size == 5
    assert not destination.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported on this platform")
def test_copy_local_mlflow_artifact_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    """Special files must be rejected after a nonblocking open."""
    source_root = tmp_path / "source"
    source_root.mkdir()
    os.mkfifo(source_root / "model.bin")
    destination = tmp_path / "download" / "model.bin"

    with pytest.raises(ValueError, match="not a regular file"):
        _copy_local_mlflow_artifact(source_root, _MlflowArtifact(path="model.bin", size=0), destination)

    assert not destination.exists()


@pytest.mark.skipif(
    not getattr(os, "O_NOFOLLOW", 0) or os.open not in os.supports_dir_fd,
    reason="race-resistant descriptor traversal is not supported on this platform",
)
def test_copy_local_mlflow_artifact_rejects_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory swapped to a symlink while opening must fail closed."""
    source_root = tmp_path / "source"
    nested = source_root / "nested"
    nested.mkdir(parents=True)
    (nested / "model.bin").write_bytes(b"SAFE")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "model.bin").write_bytes(b"EVIL")
    destination = tmp_path / "download" / "model.bin"
    original_open = os.open
    swapped = False

    def swapping_open(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal swapped
        if path == "nested" and dir_fd is not None and not swapped:
            preserved = source_root / "preserved"
            nested.rename(preserved)
            nested.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swapping_open)

    with pytest.raises(OSError):
        _copy_local_mlflow_artifact(source_root, _MlflowArtifact(path="nested/model.bin", size=4), destination)

    assert swapped is True
    assert not destination.exists()


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
    tmp_path: Path,
) -> None:
    """Test successful MLflow model scanning."""
    # Mock MLflow
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.download_artifacts.return_value = "/tmp/test_model"
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=1024),
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 1024})
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    # Create a temporary directory for the test
    temp_dir = tmp_path / "modelaudit_mlflow_test"
    temp_dir.mkdir()
    mock_mkdtemp.return_value = str(temp_dir)

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

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
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
    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mlflow.artifacts.download_artifacts.assert_not_called()

    # Verify scan was called with correct parameters
    mock_scan.assert_called_once_with(
        str(temp_dir),
        timeout=300,
        blacklist_patterns=["malicious"],
        max_file_size=1000000,
        max_total_size=5000000,
        cache_enabled=True,
        cache_dir=None,
    )

    # Verify cleanup
    mock_rmtree.assert_called_once_with(str(temp_dir), ignore_errors=True)

    # Verify results
    assert results == mock_scan.return_value  # Verify the mock was called correctly


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_splits_subpath_and_downloads_from_resolved_repo(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Finite-budget MLflow scans should list and download the same resolved subpath."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="path/to/model/model.pkl", is_dir=False, file_size=1024),
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"path/to/model/model.pkl": 1024})
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 1024, "issues": []}
    download_dir = tmp_path / "modelaudit_mlflow_test"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        scan_mlflow_model("models:/TestModel/2/path/to/model", max_file_size=2048)

    mock_mlflow.artifacts.get_artifact_repository.assert_called_once_with("models:/TestModel/2")
    mock_repo.list_artifacts.assert_called_once_with("path/to/model")
    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


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
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.side_effect = [
        [],
        [SimpleNamespace(path="model.pkl", is_dir=False, file_size=1024)],
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 1024})
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 1024, "issues": []}
    mock_mkdtemp.return_value = str(download_dir)

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        scan_mlflow_model("models:/TestModel/2/model.pkl", max_file_size=2048)

    assert [call.args for call in mock_repo.list_artifacts.call_args_list] == [("model.pkl",), (None,)]
    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
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
    tmp_path: Path,
) -> None:
    """Mutable refs should not be resolved again after the finite-budget preflight."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=1024),
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 1024})
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 1024, "issues": []}
    download_dir = tmp_path / "modelaudit_mlflow_test"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        scan_mlflow_model("models:/TestModel/Production", max_total_size=2048)

    mock_mlflow.artifacts.get_artifact_repository.assert_called_once_with("models:/TestModel/Production")
    mock_repo.list_artifacts.assert_called_once_with(None)
    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_accepts_empty_local_artifact_directory(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """An empty local artifact is known to be within every finite byte budget."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = []
    source_root = tmp_path / "mlflow_artifacts"
    source_root.mkdir()
    download_dir = tmp_path / "modelaudit_mlflow_empty"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_scan.return_value = {"bytes_scanned": 0, "issues": []}

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=10)

    assert result == mock_scan.return_value
    mock_scan.assert_called_once_with(
        str(download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=10,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


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
def test_scan_mlflow_model_redacts_size_lookup_error_before_reporting(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Remote size lookup failures should not copy backend credentials into findings."""
    secret_url = "https://user:password@example.com/AKIAIOSFODNN7EXAMPLE?X-Amz-Signature=supersecret"
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.get_artifact_repository.side_effect = RuntimeError(f"size unavailable for {secret_url}")

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=1000)

    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    reported_error = result.checks[0].details["error"]
    serialized_result = result.model_dump_json()
    assert "user:password" not in serialized_result
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized_result
    assert "supersecret" not in serialized_result
    assert reported_error == "size unavailable for https://example.com/<redacted>"
    assert result.issues[0].details["error"] == reported_error


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_redacts_header_credentials_from_size_errors(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Backend authorization values must not be retained in budget findings."""
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.get_artifact_repository.side_effect = RuntimeError(
        "request failed; headers={'Authorization': 'Bearer very-secret-token', \"api_key\": \"another secret\"}"
    )

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=1000)

    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    reported_error = result.checks[0].details["error"]
    assert reported_error == "request failed; headers={'Authorization': '<redacted>', \"api_key\": \"<redacted>\"}"
    assert "very-secret-token" not in result.model_dump_json()
    assert "another secret" not in result.model_dump_json()


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_file_added_after_preflight(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Files added after metadata validation must not be silently omitted from the scan."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=4),
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 4})
    download_dir = tmp_path / "modelaudit_mlflow_changed"

    def add_artifact_before_download(*args: Any, **kwargs: Any) -> str:
        del args, kwargs
        download_dir.mkdir()
        _write_local_artifacts(source_root, {"malicious.pkl": 4})
        return str(download_dir)

    mock_mkdtemp.side_effect = add_artifact_before_download
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=10)

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_set_changed"
    assert result.checks[0].details["added_artifact_paths"] == ["malicious.pkl"]


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
def test_scan_mlflow_model_rejects_repository_without_bounded_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Finite budgets must not call repositories that cannot cap transferred bytes."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=4),
    ]
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=10)

    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_streaming_budget_unavailable"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_artifact_size_change_after_preflight(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """A repository must not grow an artifact between metadata lookup and download."""
    download_dir = tmp_path / "modelaudit_mlflow_changed"
    download_dir.mkdir()
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="model.pkl", is_dir=False, file_size=4),
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 5})
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_mkdtemp.return_value = str(download_dir)

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=10)

    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_size_changed"
    assert result.checks[0].details["expected_artifact_size"] == 4
    assert result.checks[0].details["downloaded_artifact_size"] == 5
    assert not (download_dir / "model.pkl").exists()


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_unsafe_artifact_metadata_path(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Remote artifact metadata must not select a path outside the staging directory."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="../outside.pkl", is_dir=False, file_size=4),
    ]
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=10)

    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_size_unavailable"
    assert "escapes the repository root" in result.checks[0].details["error"]


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_accepts_exact_download_size_boundaries(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
) -> None:
    """Files and totals equal to their configured limits remain accepted."""
    download_dir = tmp_path / "modelaudit_mlflow_boundary"
    download_dir.mkdir()
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="a.bin", is_dir=False, file_size=4),
        SimpleNamespace(path="b.bin", is_dir=False, file_size=3),
    ]
    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"a.bin": 4, "b.bin": 3})
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    mock_mkdtemp.return_value = str(download_dir)
    mock_scan.return_value = {"bytes_scanned": 7, "issues": []}

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        result = scan_mlflow_model(
            "models:/TestModel/1",
            max_file_size=4,
            max_total_size=7,
        )

    assert result == mock_scan.return_value
    mock_repo._download_file.assert_not_called()
    mock_repo.download_artifacts.assert_not_called()
    mock_scan.assert_called_once_with(
        str(download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=4,
        max_total_size=7,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_listing_budget_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    """Finite-budget preflight should reject repository responses over the entry budget."""
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
    mock_repo._download_file.assert_not_called()
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
    mock_repo._download_file.assert_not_called()
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
