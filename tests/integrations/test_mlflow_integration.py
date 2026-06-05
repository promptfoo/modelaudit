import ctypes
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
    _mlflow_budget_failure_result,
    _MlflowArtifact,
    _MlflowArtifactSizeChangedError,
    _MlflowLocalSource,
    _normalize_mlflow_artifact_path,
    _opened_local_mlflow_path,
    _snapshot_local_mlflow_sources,
    scan_mlflow_model,
)


def _write_local_artifacts(source_root: Path, artifact_sizes: dict[str, int]) -> None:
    for artifact_path, artifact_size in artifact_sizes.items():
        source_path = source_root.joinpath(*artifact_path.split("/"))
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(b"x" * artifact_size)


@pytest.mark.parametrize("artifact_path", ["model.pkl:payload", "nested/model.bin:stream"])
def test_normalize_mlflow_artifact_path_rejects_windows_streams(
    artifact_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.integrations.mlflow._IS_WINDOWS", True)

    with pytest.raises(ValueError, match="not relative"):
        _normalize_mlflow_artifact_path(artifact_path)


def test_normalize_mlflow_artifact_path_allows_posix_colons(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("modelaudit.integrations.mlflow._IS_WINDOWS", False)

    assert _normalize_mlflow_artifact_path("checkpoint:1/model.pkl") == "checkpoint:1/model.pkl"


def test_opened_local_mlflow_path_preserves_windows_handle_width(monkeypatch: pytest.MonkeyPatch) -> None:
    from ctypes import wintypes

    handle_value = 1 << 40

    class FakeGetFinalPath:
        argtypes: tuple[Any, ...] | None = None
        restype: Any = None

        def __call__(self, handle: Any, buffer: Any, length: int, flags: int) -> int:
            assert handle.value == handle_value
            assert length == 32768
            assert flags == 0
            buffer.value = r"\\?\C:\artifacts\model.pkl"
            return len(buffer.value)

    get_final_path = FakeGetFinalPath()
    fake_msvcrt = ModuleType("msvcrt")
    fake_msvcrt.get_osfhandle = lambda source_fd: handle_value  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *args, **kwargs: SimpleNamespace(GetFinalPathNameByHandleW=get_final_path),
        raising=False,
    )
    monkeypatch.setattr("modelaudit.integrations.mlflow._IS_WINDOWS", True)

    assert str(_opened_local_mlflow_path(7)) == r"C:\artifacts\model.pkl"
    assert get_final_path.argtypes == (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    assert get_final_path.restype is wintypes.DWORD


def test_snapshot_local_mlflow_sources_accepts_existing_empty_directory(tmp_path: Path) -> None:
    source_root = tmp_path / "artifacts"
    empty_artifact = source_root / "empty"
    empty_artifact.mkdir(parents=True)

    artifacts, entry_count = _snapshot_local_mlflow_sources(
        (_MlflowLocalSource(source_root, "empty", "empty"),),
        max_artifact_entries=10,
    )

    assert artifacts == {}
    assert entry_count == 0


def test_local_mlflow_artifact_root_preserves_runs_repository(tmp_path: Path) -> None:
    """Run adapters must retain their logged-model overlay semantics."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        def __init__(self, repository: object) -> None:
            self.repo = repository

    class RunsArtifactRepository:
        def __init__(self, repository: object) -> None:
            self.repo = repository

    mlflow_module = ModuleType("mlflow")
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]
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
            "mlflow.store.artifact.runs_artifact_repo": runs_module,
        },
    ):
        assert (
            _local_mlflow_artifact_root(ModelsArtifactRepository(LocalArtifactRepository(source_root))) == source_root
        )
        assert (
            _local_mlflow_artifact_root(
                ModelsArtifactRepository(RunsArtifactRepository(LocalArtifactRepository(source_root)))
            )
            is None
        )
        assert _local_mlflow_artifact_root(object()) is None


def test_scan_mlflow_model_unwraps_local_run_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registered run-backed models should use their bounded local repository."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

        def list_artifacts(self, path: str | None) -> list[SimpleNamespace]:
            assert path is None
            return [SimpleNamespace(path="model.pkl", is_dir=False, file_size=4)]

    class RunsArtifactRepository:
        def __init__(self, repository: object) -> None:
            self.repo = repository

        def list_artifacts(self, path: str | None) -> list[SimpleNamespace]:
            raise AssertionError("run wrapper listing should not mix other artifact repositories")

    class ModelsArtifactRepository:
        def __init__(self, repository: object) -> None:
            self.repo = repository

        def list_artifacts(self, path: str | None) -> list[SimpleNamespace]:
            raise AssertionError("model wrapper listing should delegate to the resolved repository")

    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    source_root = tmp_path / "artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 4})
    repository = ModelsArtifactRepository(RunsArtifactRepository(LocalArtifactRepository(source_root)))
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 4, "issues": []}

    with (
        patch.dict(
            sys.modules,
            {
                "mlflow": mlflow_module,
                "mlflow.store": store_module,
                "mlflow.store.artifact": artifact_module,
                "mlflow.store.artifact.local_artifact_repo": local_module,
                "mlflow.store.artifact.models_artifact_repo": models_module,
                "mlflow.store.artifact.runs_artifact_repo": runs_module,
            },
        ),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value=scan_result) as mock_scan,
    ):
        result = scan_mlflow_model("models:/TestModel/1", max_file_size=10)

    assert result == scan_result
    assert (download_dir / "model.pkl").read_bytes() == b"xxxx"
    mock_scan.assert_called_once()


def test_scan_mlflow_model_preserves_local_logged_model_overlay(
    tmp_path: Path,
) -> None:
    """MLflow 3 logged-model artifacts must overlay, not replace, run artifacts."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        pass

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1"

        def __init__(self, run_repository: object, logged_model_repository: object) -> None:
            self.repo = run_repository
            self.logged_model_repository = logged_model_repository

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1"
            return "run-1", None

        def _get_logged_model_artifact_repo(self, run_id: str, name: str) -> object:
            assert (run_id, name) == ("run-1", "model")
            return self.logged_model_repository

    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    run_root = tmp_path / "run-artifacts"
    logged_model_root = tmp_path / "logged-model-artifacts"
    _write_local_artifacts(run_root, {"model/run-only.bin": 3, "model/shared.bin": 4})
    _write_local_artifacts(logged_model_root, {"logged-only.bin": 2, "shared.bin": 5})
    repository = RunsArtifactRepository(
        LocalArtifactRepository(run_root),
        LocalArtifactRepository(logged_model_root),
    )
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "runs:/run-1",
        "model",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 10, "issues": []}

    with (
        patch.dict(
            sys.modules,
            {
                "mlflow": mlflow_module,
                "mlflow.store": store_module,
                "mlflow.store.artifact": artifact_module,
                "mlflow.store.artifact.local_artifact_repo": local_module,
                "mlflow.store.artifact.models_artifact_repo": models_module,
                "mlflow.store.artifact.runs_artifact_repo": runs_module,
            },
        ),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value=scan_result) as mock_scan,
    ):
        result = scan_mlflow_model(
            "runs:/run-1/model",
            max_file_size=5,
            max_total_size=10,
        )

    assert result == scan_result
    assert (download_dir / "model" / "run-only.bin").read_bytes() == b"xxx"
    assert (download_dir / "model" / "logged-only.bin").read_bytes() == b"xx"
    assert (download_dir / "model" / "shared.bin").read_bytes() == b"xxxxx"
    mock_scan.assert_called_once()
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]


def test_scan_mlflow_model_allows_logged_model_without_run_artifact(tmp_path: Path) -> None:
    """A missing run-side path must not hide a bounded logged-model artifact."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        pass

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1"

        def __init__(self, run_repository: object, logged_model_repository: object) -> None:
            self.repo = run_repository
            self.logged_model_repository = logged_model_repository

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1"
            return "run-1", None

        def _get_logged_model_artifact_repo(self, run_id: str, name: str) -> object:
            assert (run_id, name) == ("run-1", "model")
            return self.logged_model_repository

    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    run_root = tmp_path / "run-artifacts"
    run_root.mkdir()
    logged_model_root = tmp_path / "logged-model-artifacts"
    _write_local_artifacts(logged_model_root, {"model.pkl": 4})
    repository = RunsArtifactRepository(
        LocalArtifactRepository(run_root),
        LocalArtifactRepository(logged_model_root),
    )
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "runs:/run-1",
        "model",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 4, "issues": []}

    with (
        patch.dict(
            sys.modules,
            {
                "mlflow": mlflow_module,
                "mlflow.store": store_module,
                "mlflow.store.artifact": artifact_module,
                "mlflow.store.artifact.local_artifact_repo": local_module,
                "mlflow.store.artifact.models_artifact_repo": models_module,
                "mlflow.store.artifact.runs_artifact_repo": runs_module,
            },
        ),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value=scan_result) as mock_scan,
    ):
        result = scan_mlflow_model(
            "runs:/run-1/model",
            max_file_size=4,
            max_total_size=4,
        )

    assert result == scan_result
    assert (download_dir / "model" / "model.pkl").read_bytes() == b"xxxx"
    mock_scan.assert_called_once()
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]


def test_scan_mlflow_model_allows_local_run_when_logged_model_lookup_fails(tmp_path: Path) -> None:
    """Optional logged-model lookup failures must not hide bounded run artifacts."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        pass

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1"

        def __init__(self, run_repository: object) -> None:
            self.repo = run_repository

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1"
            return "run-1", None

        @staticmethod
        def _get_logged_model_artifact_repo(run_id: str, name: str) -> object:
            assert (run_id, name) == ("run-1", "model")
            raise RuntimeError("logged-model search is unsupported")

    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    run_root = tmp_path / "run-artifacts"
    _write_local_artifacts(run_root, {"model/model.pkl": 4})
    repository = RunsArtifactRepository(LocalArtifactRepository(run_root))
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "runs:/run-1",
        "model",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 4, "issues": []}

    with (
        patch.dict(
            sys.modules,
            {
                "mlflow": mlflow_module,
                "mlflow.store": store_module,
                "mlflow.store.artifact": artifact_module,
                "mlflow.store.artifact.local_artifact_repo": local_module,
                "mlflow.store.artifact.models_artifact_repo": models_module,
                "mlflow.store.artifact.runs_artifact_repo": runs_module,
            },
        ),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value=scan_result) as mock_scan,
    ):
        result = scan_mlflow_model(
            "runs:/run-1/model",
            max_file_size=4,
            max_total_size=4,
        )

    assert result == scan_result
    assert (download_dir / "model" / "model.pkl").read_bytes() == b"xxxx"
    mock_scan.assert_called_once()
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.parametrize("repository_scoped", [False, True], ids=["unscoped", "scoped"])
def test_scan_mlflow_model_preserves_runs_subpath_prefix(tmp_path: Path, repository_scoped: bool) -> None:
    """Run repositories must apply the wrapper prefix exactly once."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path, artifact_uri: str | None = None) -> None:
            self.artifact_dir = artifact_dir
            self.artifact_uri = artifact_uri

    class ModelsArtifactRepository:
        pass

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1/model"

        def __init__(self, run_repository: object) -> None:
            self.repo = run_repository

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1/model"
            return "run-1", "model"

        @staticmethod
        def _get_logged_model_artifact_repo(run_id: str, name: str) -> None:
            assert (run_id, name) == ("run-1", "model")
            return None

    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    if repository_scoped:
        run_root = tmp_path / "run-artifacts" / "model"
        artifact_sizes = {
            "subdir/right.bin": 4,
            "model/subdir/wrong.bin": 3,
        }
        artifact_uri = "file:///run-artifacts/model"
    else:
        run_root = tmp_path / "run-artifacts"
        artifact_sizes = {
            "subdir/wrong.bin": 3,
            "model/subdir/right.bin": 4,
        }
        artifact_uri = None
    _write_local_artifacts(run_root, artifact_sizes)
    repository = RunsArtifactRepository(LocalArtifactRepository(run_root, artifact_uri=artifact_uri))
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "runs:/run-1/model",
        "subdir",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 4, "issues": []}

    with (
        patch.dict(
            sys.modules,
            {
                "mlflow": mlflow_module,
                "mlflow.store": store_module,
                "mlflow.store.artifact": artifact_module,
                "mlflow.store.artifact.local_artifact_repo": local_module,
                "mlflow.store.artifact.models_artifact_repo": models_module,
                "mlflow.store.artifact.runs_artifact_repo": runs_module,
            },
        ),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value=scan_result) as mock_scan,
    ):
        result = scan_mlflow_model(
            "runs:/run-1/model/subdir",
            max_file_size=4,
            max_total_size=4,
        )

    assert result == scan_result
    assert (download_dir / "subdir" / "right.bin").read_bytes() == b"xxxx"
    assert not (download_dir / "subdir" / "wrong.bin").exists()
    mock_scan.assert_called_once()
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]


def test_scan_mlflow_model_rejects_nonlocal_logged_model_overlay(tmp_path: Path) -> None:
    """A local run half must not hide an unbounded logged-model repository."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        pass

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1"

        def __init__(self, run_repository: object) -> None:
            self.repo = run_repository

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1"
            return "run-1", None

        @staticmethod
        def _get_logged_model_artifact_repo(run_id: str, name: str) -> object:
            assert (run_id, name) == ("run-1", "model")
            return object()

    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    run_root = tmp_path / "run-artifacts"
    _write_local_artifacts(run_root, {"model/model.pkl": 4})
    repository = RunsArtifactRepository(LocalArtifactRepository(run_root))
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "runs:/run-1",
        "model",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]

    with patch.dict(
        sys.modules,
        {
            "mlflow": mlflow_module,
            "mlflow.store": store_module,
            "mlflow.store.artifact": artifact_module,
            "mlflow.store.artifact.local_artifact_repo": local_module,
            "mlflow.store.artifact.models_artifact_repo": models_module,
            "mlflow.store.artifact.runs_artifact_repo": runs_module,
        },
    ):
        result = scan_mlflow_model("runs:/run-1/model", max_file_size=10)

    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_streaming_budget_unavailable"
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]


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


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="opened file paths are not exposed through procfs")
def test_copy_local_mlflow_artifact_rejects_symlink_swap_without_secure_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fallback opening must verify the handle path after an intermediate-directory swap."""
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
        if Path(path) == source_root / "nested" / "model.bin" and not swapped:
            nested.rename(source_root / "preserved")
            nested.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("modelaudit.integrations.mlflow._OS_OPEN_SUPPORTS_DIR_FD", False)
    monkeypatch.setattr(os, "open", swapping_open)

    with pytest.raises(ValueError, match="escaped the repository root"):
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


def test_mlflow_budget_failure_redacts_uri_and_artifact_path_evidence() -> None:
    """Refused downloads must not serialize credentials from source-controlled paths."""
    model_uri = "https://user:password@example.com/model?token=URI_SECRET"
    result = _mlflow_budget_failure_result(
        model_uri,
        "MLflow artifact download refused",
        {
            "model_uri": model_uri,
            "root_uri": model_uri,
            "artifact_path": "models/token=PATH_SECRET/model.pkl",
            "added_artifact_paths": ["models/client_secret=LIST_SECRET/model.pkl"],
        },
    )

    serialized_result = result.model_dump_json()
    assert "user:password" not in serialized_result
    assert "URI_SECRET" not in serialized_result
    assert "PATH_SECRET" not in serialized_result
    assert "LIST_SECRET" not in serialized_result
    expected_uri = "https://<credentials-redacted>@example.com/model?token=<redacted>"
    assert result.checks[0].location == expected_uri
    assert result.checks[0].details["model_uri"] == expected_uri
    assert result.checks[0].details["artifact_path"] == "models/token=<redacted>"


def test_mlflow_budget_failure_preserves_benign_uri_context() -> None:
    result = _mlflow_budget_failure_result(
        "models:/PublicModel/7",
        "MLflow artifact download refused",
        {
            "model_uri": "models:/PublicModel/7",
            "root_uri": "models:/PublicModel/7",
            "artifact_path": "weights/model.pkl",
        },
    )

    assert result.checks[0].location == "models:/PublicModel/7"
    assert result.checks[0].details == {
        "model_uri": "models:/PublicModel/7",
        "root_uri": "models:/PublicModel/7",
        "artifact_path": "weights/model.pkl",
    }


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
    tmp_path: Path,
) -> None:
    """Finite budgets should reject oversized MLflow artifacts before download."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="large.bin", is_dir=False, file_size=2048),
    ]
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    source_root = tmp_path / "mlflow_artifacts"
    source_root.mkdir()

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
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
    mock_repo.list_artifacts.assert_not_called()
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
    tmp_path: Path,
) -> None:
    """Remote artifact metadata must not select a path outside the staging directory."""
    mock_mlflow = MagicMock()
    mock_repo = MagicMock()
    mock_repo.list_artifacts.return_value = [
        SimpleNamespace(path="../outside.pkl", is_dir=False, file_size=4),
    ]
    mock_mlflow.artifacts.get_artifact_repository.return_value = mock_repo
    source_root = tmp_path / "mlflow_artifacts"
    source_root.mkdir()

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
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
    tmp_path: Path,
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
    source_root = tmp_path / "mlflow_artifacts"
    source_root.mkdir()

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
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
def test_scan_mlflow_model_bounds_real_local_repository_listing(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    """Verified local repositories should be traversed lazily by ModelAudit."""
    pytest.importorskip("mlflow")
    from mlflow.store.artifact.local_artifact_repo import LocalArtifactRepository

    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"a.bin": 1, "b.bin": 1, "c.bin": 1})
    repository = LocalArtifactRepository(source_root.as_uri())
    repository.list_artifacts = MagicMock(side_effect=AssertionError("MLflow listing should not be used"))  # type: ignore[method-assign]
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.get_artifact_repository.return_value = repository

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model(
            "models:/TestModel/1",
            max_file_size=1024,
            max_mlflow_artifact_entries=2,
        )

    repository.list_artifacts.assert_not_called()  # type: ignore[attr-defined]
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_listing_budget_exceeded"
    assert result.checks[0].details["artifact_entry_count"] == 3


def test_scan_mlflow_model_direct_local_file_does_not_enumerate_siblings(tmp_path: Path) -> None:
    """A direct local file request should spend the entry budget only on that file."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        pass

    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(
        source_root,
        {
            "model.pkl": 1,
            "unrelated-a.bin": 1,
            "unrelated-b.bin": 1,
        },
    )
    repository = LocalArtifactRepository(source_root)
    repository.list_artifacts = MagicMock(side_effect=AssertionError("direct local files should not list siblings"))  # type: ignore[attr-defined]
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "models:/TestModel/1",
        "model.pkl",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = repository  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 1, "issues": []}

    with (
        patch.dict(
            sys.modules,
            {
                "mlflow": mlflow_module,
                "mlflow.store": store_module,
                "mlflow.store.artifact": artifact_module,
                "mlflow.store.artifact.local_artifact_repo": local_module,
                "mlflow.store.artifact.models_artifact_repo": models_module,
            },
        ),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
        patch("modelaudit.core.scan_model_directory_or_file", return_value=scan_result) as mock_scan,
    ):
        result = scan_mlflow_model(
            "models:/TestModel/1/model.pkl",
            max_file_size=1,
            max_total_size=1,
            max_mlflow_artifact_entries=1,
        )

    assert result == scan_result
    assert (download_dir / "model.pkl").read_bytes() == b"x"
    repository.list_artifacts.assert_not_called()  # type: ignore[attr-defined]
    mock_scan.assert_called_once()


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_bounds_generator_listing_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
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
    source_root = tmp_path / "mlflow_artifacts"
    source_root.mkdir()

    with (
        patch("modelaudit.integrations.mlflow._local_mlflow_artifact_root", return_value=source_root),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
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
