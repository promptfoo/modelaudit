import ctypes
import ctypes.wintypes
import hashlib
import logging
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest

from modelaudit.core import determine_exit_code
from modelaudit.integrations.mlflow import (
    _capture_mlflow_download_root,
    _copy_local_mlflow_artifact,
    _download_trusted_mlflow_artifacts,
    _local_mlflow_artifact_root,
    _mlflow_artifact_uri_matches_prefix,
    _mlflow_budget_failure_result,
    _mlflow_download_safety_failure_result,
    _MlflowArtifact,
    _MlflowArtifactSizeChangedError,
    _MlflowDelegatedDownloadPlan,
    _MlflowDelegatedDownloadTarget,
    _MlflowDownloadRoot,
    _MlflowLocalSource,
    _normalize_mlflow_artifact_path,
    _normalize_mlflow_delegated_artifact_path,
    _opened_local_mlflow_path,
    _partition_mlflow_delegated_targets,
    _redact_mlflow_error_for_display,
    _runs_mlflow_repository_is_scoped,
    _snapshot_local_mlflow_sources,
    scan_mlflow_model,
)


def _write_local_artifacts(source_root: Path, artifact_sizes: dict[str, int]) -> None:
    for artifact_path, artifact_size in artifact_sizes.items():
        source_path = source_root.joinpath(*artifact_path.split("/"))
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(b"x" * artifact_size)


def _configure_trusted_remote_repository(
    mock_mlflow: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> MagicMock:
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/TestModel"
    artifact_repository.download_artifacts = mock_mlflow.artifacts.download_artifacts
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository
    return artifact_repository


def _download_trusted_plan_for_test(plan: _MlflowDelegatedDownloadPlan, download_dir: Path) -> Any:
    captured_root = _capture_mlflow_download_root("models:/TestModel/1", str(download_dir))
    assert isinstance(captured_root, _MlflowDownloadRoot)
    try:
        return _download_trusted_mlflow_artifacts(
            plan,
            "models:/TestModel/1",
            str(download_dir),
            1_000,
            captured_root,
        )
    finally:
        if captured_root.file_descriptor is not None:
            os.close(captured_root.file_descriptor)


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


@pytest.mark.parametrize("artifact_path", ["C:evil", "z:weights/model.pkl"])
def test_normalize_mlflow_delegated_artifact_path_rejects_windows_drive_relative_paths(
    artifact_path: str,
) -> None:
    with pytest.raises(ValueError, match="not relative"):
        _normalize_mlflow_delegated_artifact_path(artifact_path)


def test_normalize_mlflow_delegated_artifact_path_allows_non_drive_colons() -> None:
    assert _normalize_mlflow_delegated_artifact_path("checkpoint:1/model.pkl") == "checkpoint:1/model.pkl"


def test_opened_local_mlflow_path_preserves_windows_handle_width(monkeypatch: pytest.MonkeyPatch) -> None:
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
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.LPWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
    )
    assert get_final_path.restype is ctypes.wintypes.DWORD


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


def test_local_mlflow_artifact_root_rejects_remote_file_authority(tmp_path: Path) -> None:
    pytest.importorskip("mlflow")
    from mlflow.store.artifact.local_artifact_repo import LocalArtifactRepository

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    repository = LocalArtifactRepository(f"file://attacker.example{artifact_root.as_posix()}")

    assert _local_mlflow_artifact_root(repository) is None


def test_sql_backed_mlflow_model_registry_is_available(tmp_path: Path) -> None:
    mlflow = pytest.importorskip("mlflow")
    registry_uri = f"sqlite:///{tmp_path / 'registry.db'}"
    client = mlflow.MlflowClient(tracking_uri=registry_uri, registry_uri=registry_uri)

    registered_model = client.create_registered_model("ModelAuditRegressionProbe")

    assert registered_model.name == "ModelAuditRegressionProbe"


def test_file_uri_allowlist_accepts_bracketed_ipv6_loopback() -> None:
    assert _mlflow_artifact_uri_matches_prefix(
        "file://[::1]/tmp/models/model.pkl",
        "file://[::1]/tmp/models",
    )


def test_file_uri_allowlist_rejects_malformed_unbracketed_ipv6_loopback() -> None:
    assert not _mlflow_artifact_uri_matches_prefix(
        "file://::1/tmp/models/model.pkl",
        "file://::1/tmp/models",
    )


@pytest.mark.parametrize(
    ("artifact_uri", "allowed_prefix"),
    [
        ("opaque://safe/root/model.pkl", "opaque://SAFE/root"),
        ("opaque://safe./root/model.pkl", "opaque://safe/root"),
    ],
)
def test_custom_mlflow_scheme_preserves_raw_authority_semantics(
    artifact_uri: str,
    allowed_prefix: str,
) -> None:
    assert not _mlflow_artifact_uri_matches_prefix(artifact_uri, allowed_prefix)


def test_local_mlflow_artifact_root_rejects_remote_file_authority_before_path_lookup() -> None:
    class LocalArtifactRepository:
        artifact_uri = "file://attacker.example/share/model"

        @property
        def artifact_dir(self) -> str:
            raise AssertionError("remote file authority must be rejected before path lookup")

    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]

    with patch.dict(sys.modules, {"mlflow.store.artifact.local_artifact_repo": local_module}):
        assert _local_mlflow_artifact_root(LocalArtifactRepository()) is None


@pytest.mark.parametrize("artifact_dir", [r"\\server\share\model", "//server/share/model"])
def test_local_mlflow_artifact_root_rejects_unc_path_before_resolution(artifact_dir: str) -> None:
    class LocalArtifactRepository:
        def __init__(self, path: str) -> None:
            self.artifact_dir = path

    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]

    with (
        patch.dict(sys.modules, {"mlflow.store.artifact.local_artifact_repo": local_module}),
        patch.object(Path, "resolve", side_effect=AssertionError("UNC path must not be resolved")),
    ):
        assert _local_mlflow_artifact_root(LocalArtifactRepository(artifact_dir)) is None


@pytest.mark.parametrize("legacy_resolver", [False, True], ids=["current", "legacy"])
def test_runs_mlflow_repository_scope_supports_mlflow_resolver_versions(legacy_resolver: bool) -> None:
    expected_uri = "file:///artifacts/model"

    class RunRepository:
        artifact_uri = expected_uri

    class CurrentRunsRepository:
        tracking_uri = "sqlite:///tracking.db"

        @staticmethod
        def get_underlying_uri(wrapper_uri: str, tracking_uri: str | None = None) -> str:
            assert wrapper_uri == "runs:/run-1/model"
            assert tracking_uri == "sqlite:///tracking.db"
            return expected_uri

    class LegacyRunsRepository:
        @staticmethod
        def get_underlying_uri(wrapper_uri: str) -> str:
            assert wrapper_uri == "runs:/run-1/model"
            return expected_uri

    artifact_repository = LegacyRunsRepository() if legacy_resolver else CurrentRunsRepository()

    assert _runs_mlflow_repository_is_scoped(
        artifact_repository,
        RunRepository(),
        "runs:/run-1/model",
    )


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


def test_scan_mlflow_model_rejects_local_run_when_logged_model_lookup_fails(tmp_path: Path) -> None:
    """A failed overlay lookup must not silently omit logged-model artifacts."""

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
        patch("modelaudit.core.scan_model_directory_or_file") as mock_scan,
    ):
        result = scan_mlflow_model(
            "runs:/run-1/model",
            max_file_size=4,
            max_total_size=4,
        )

    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_streaming_budget_unavailable"
    assert not (download_dir / "model" / "model.pkl").exists()
    mock_scan.assert_not_called()
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "repository_layout",
    ["unscoped", "scoped", "scoped_resolution_error", "unscoped_matching_suffix"],
)
def test_scan_mlflow_model_preserves_runs_subpath_prefix(tmp_path: Path, repository_layout: str) -> None:
    """Run repositories must apply the wrapper prefix exactly once."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path, artifact_uri: str | None = None) -> None:
            self.artifact_dir = artifact_dir
            self.artifact_uri = artifact_uri

    class ModelsArtifactRepository:
        pass

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1/model"

        def __init__(self, run_repository: object, underlying_uri: str) -> None:
            self.repo = run_repository
            self.underlying_uri = underlying_uri

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1/model"
            return "run-1", "model"

        def get_underlying_uri(self, uri: str, tracking_uri: str | None = None) -> str:
            assert uri == "runs:/run-1/model"
            assert tracking_uri is None
            if repository_layout == "scoped_resolution_error":
                raise RuntimeError("tracking lookup failed")
            return self.underlying_uri

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

    if repository_layout in {"scoped", "scoped_resolution_error"}:
        run_root = tmp_path / "run-artifacts" / "model"
        artifact_sizes = {
            "subdir/right.bin": 4,
            "model/subdir/wrong.bin": 3,
        }
        underlying_uri = run_root.as_uri()
    elif repository_layout == "unscoped_matching_suffix":
        run_root = tmp_path / "run-artifacts" / "model"
        artifact_sizes = {
            "subdir/wrong.bin": 3,
            "model/subdir/right.bin": 4,
        }
        underlying_uri = (run_root / "model").as_uri()
    else:
        run_root = tmp_path / "run-artifacts"
        artifact_sizes = {
            "subdir/wrong.bin": 3,
            "model/subdir/right.bin": 4,
        }
        underlying_uri = (run_root / "model").as_uri()
    _write_local_artifacts(run_root, artifact_sizes)
    repository = RunsArtifactRepository(
        LocalArtifactRepository(run_root, artifact_uri=run_root.as_uri()),
        underlying_uri,
    )
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

    if repository_layout == "scoped_resolution_error":
        assert determine_exit_code(result) == 2
        assert result.checks[0].details["reason"] == "artifact_streaming_budget_unavailable"
        assert not (download_dir / "subdir" / "right.bin").exists()
        assert not (download_dir / "subdir" / "wrong.bin").exists()
        mock_scan.assert_not_called()
    else:
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


@pytest.mark.parametrize(
    ("artifact_uri", "allowed_prefix"),
    [
        ("https://mlflow.example.com:443/artifacts/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/model.pkl", "https://mlflow.example.com:443/artifacts"),
        ("http://mlflow.example.com:80/artifacts/model.pkl", "http://mlflow.example.com/artifacts"),
        ("ftp://mlflow.example.com:21/artifacts/model.pkl", "ftp://mlflow.example.com/artifacts"),
        ("sftp://mlflow.example.com:22/artifacts/model.pkl", "sftp://mlflow.example.com/artifacts"),
        ("dbfs:/trusted/models/model.pkl", "dbfs:/trusted/models"),
        ("s3://trusted-bucket/models//model.pkl", "s3://trusted-bucket/models//"),
        ("s3://trusted-bucket//model.pkl", "s3://trusted-bucket//"),
        ("https://mlflow.example.com/artifacts;v1/model.pkl", "https://mlflow.example.com/artifacts;v1/"),
    ],
)
def test_mlflow_artifact_uri_prefix_matching_accepts_equivalent_safe_uris(
    artifact_uri: str,
    allowed_prefix: str,
) -> None:
    assert _mlflow_artifact_uri_matches_prefix(artifact_uri, allowed_prefix) is True


@pytest.mark.parametrize(
    ("artifact_uri", "allowed_prefix"),
    [
        ("https://mlflow.example.com/artifacts/../evil/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/%2e%2e/evil/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/%252e%252e/evil/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/%2", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/%5c..%5cevil", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com:invalid/artifacts/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/model.pkl;evil", "https://mlflow.example.com/artifacts/model.pkl"),
        ("https://mlflow.example.com/artifacts/model.pkl", "https://mlflow.example.com/artifacts/model.pkl;evil"),
        ("s3://trusted-bucket/%6dodels/model.pkl", "s3://trusted-bucket/models"),
        ("s3://trusted-bucket/models/model.pkl", "s3://trusted-bucket/models//"),
        ("s3://trusted-bucket/model.pkl", "s3://trusted-bucket//"),
        ("ftp:/artifacts/model.pkl", "ftp:/artifacts"),
        ("file://attacker.example/share/model.pkl", "file://attacker.example/share"),
        ("models:/TrustedModel/1", "models:/TrustedModel"),
        ("runs:/run-1/model", "runs:/run-1"),
    ],
)
def test_mlflow_artifact_uri_prefix_matching_rejects_ambiguous_uris(
    artifact_uri: str,
    allowed_prefix: str,
) -> None:
    assert _mlflow_artifact_uri_matches_prefix(artifact_uri, allowed_prefix) is False


@pytest.mark.parametrize(
    ("artifact_uri", "allowed_prefix"),
    [
        ("file:///private/tmp/modelaudit-evil/model.pkl", "file:///private/tmp/modelaudit-trusted"),
        ("file:///private/tmp/modelaudit-trusted/model.pkl", "file:///private/tmp/modelaudit-trusted"),
        ("https://mlflow.example.com/artifacts2/model.pkl", "https://mlflow.example.com/artifacts"),
        ("s3://trusted-bucket/models2/model.pkl", "s3://trusted-bucket/models"),
        ("https://mlflow.example.com/artifacts/../evil/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/%2e%2e/evil/model.pkl", "https://mlflow.example.com/artifacts"),
        ("https://mlflow.example.com/artifacts/model.pkl;evil", "https://mlflow.example.com/artifacts/model.pkl"),
    ],
)
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_unallowlisted_artifact_uri_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    artifact_uri: str,
    allowed_prefix: str,
) -> None:
    """Remote MLflow artifact roots must match the local allowlist before download."""
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", allowed_prefix)
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.get_artifact_repository.return_value = SimpleNamespace(artifact_uri=artifact_uri)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.checks[0].name == "MLflow Artifact Trust Check"
    assert result.checks[0].details["reason"] == "artifact_uri_not_allowlisted"
    assert result.checks[0].details["artifact_repository_uri"] == artifact_uri


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_drive_relative_delegated_artifact_path(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A registry-controlled Windows drive path must not escape the staging directory."""
    artifact_root = "s3://trusted-bucket/models"
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", artifact_root)
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = artifact_root
    artifact_repository.download_artifacts.side_effect = AssertionError("unsafe path reached the downloader")
    mlflow_module = MagicMock()
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (artifact_root, "C:evil")
    mlflow_module.artifacts.get_artifact_repository.return_value = artifact_repository

    with patch.dict(sys.modules, {"mlflow": mlflow_module}):
        result = scan_mlflow_model(f"{artifact_root}/C:evil")

    artifact_repository.download_artifacts.assert_not_called()
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.checks[0].name == "MLflow Artifact Trust Check"
    assert result.checks[0].message == "Unable to verify the MLflow artifact repository before download"
    assert result.checks[0].details["artifact_path"] == "C:evil"


@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_unallowlisted_logged_model_overlay_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A runs:/ adapter must trust both its run and logged-model artifact stores."""

    class RemoteArtifactRepository:
        def __init__(self, artifact_uri: str) -> None:
            self.artifact_uri = artifact_uri

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1/model"

        def __init__(self) -> None:
            self.repo = RemoteArtifactRepository("s3://trusted-bucket/runs/run-1/model")

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1/model"
            return "run-1", "model"

        @staticmethod
        def get_underlying_uri(uri: str, tracking_uri: str | None = None) -> str:
            assert uri == "runs:/run-1/model"
            assert tracking_uri is None
            return "s3://trusted-bucket/runs/run-1/model"

        @staticmethod
        def _get_logged_model_artifact_repo(*, run_id: str, name: str) -> RemoteArtifactRepository:
            assert run_id == "run-1"
            assert name == "model"
            return RemoteArtifactRepository("s3://untrusted-bucket/logged-models/model")

    class ModelsArtifactRepository:
        def __init__(self, repo: Any) -> None:
            self.repo = repo

    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/runs")
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts.get_artifact_repository.return_value = ModelsArtifactRepository(  # type: ignore[attr-defined]
        RunsArtifactRepository()
    )
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]

    with patch.dict(
        sys.modules,
        {
            "mlflow": mlflow_module,
            "mlflow.store": store_module,
            "mlflow.store.artifact": artifact_module,
            "mlflow.store.artifact.models_artifact_repo": models_module,
            "mlflow.store.artifact.runs_artifact_repo": runs_module,
        },
    ):
        result = scan_mlflow_model("models:/TestModel/1")

    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]
    mock_mkdtemp.assert_not_called()
    mock_scan.assert_not_called()
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["artifact_repository_uri"] == "s3://untrusted-bucket/logged-models/model"
    assert result.checks[0].details["artifact_repository_uris"] == [
        "s3://trusted-bucket/runs/run-1/model",
        "s3://untrusted-bucket/logged-models/model",
    ]


@pytest.mark.parametrize("run_artifact_state", ["present", "missing"])
@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_downloads_from_the_validated_logged_model_repository(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    run_artifact_state: str,
) -> None:
    """A runs:/ download must use the validated logged-model backend even without a run overlay."""

    class RemoteArtifactRepository:
        def __init__(self, artifact_uri: str, downloaded_path: Path, marker_name: str) -> None:
            self.artifact_uri = artifact_uri
            self.list_artifacts = MagicMock(return_value=[SimpleNamespace(path=marker_name, is_dir=False)])

            def download_artifacts(*, artifact_path: str, dst_path: str) -> str:
                assert Path(dst_path) == downloaded_path
                downloaded_path.mkdir(parents=True, exist_ok=True)
                (downloaded_path / marker_name).write_bytes(marker_name.encode())
                return str(downloaded_path)

            self.download_artifacts = MagicMock(side_effect=download_artifacts)

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1/model"

        def __init__(self, run_repository: RemoteArtifactRepository) -> None:
            self.repo = run_repository
            self.download_artifacts = MagicMock(side_effect=AssertionError("wrapper download must not be used"))
            self._get_logged_model_artifact_repo = MagicMock()

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1/model"
            return "run-1", "model"

        @staticmethod
        def get_underlying_uri(uri: str, tracking_uri: str | None = None) -> str:
            assert uri == "runs:/run-1/model"
            assert tracking_uri is None
            return "s3://trusted-bucket/runs/run-1/model"

    class ModelsArtifactRepository:
        def __init__(self, repo: Any) -> None:
            self.repo = repo

    monkeypatch.setenv(
        "MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS",
        "s3://trusted-bucket/runs,s3://trusted-bucket/logged-models",
    )
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)
    run_repository = RemoteArtifactRepository("s3://trusted-bucket/runs/run-1/model", download_dir, "run.txt")
    if run_artifact_state == "missing":
        mlflow_exceptions = pytest.importorskip("mlflow.exceptions")
        mlflow_proto = pytest.importorskip("mlflow.protos.databricks_pb2")
        run_repository.download_artifacts.side_effect = mlflow_exceptions.MlflowException(
            "run artifact path is absent",
            error_code=mlflow_proto.RESOURCE_DOES_NOT_EXIST,
        )
    trusted_logged_repository = RemoteArtifactRepository(
        "s3://trusted-bucket/logged-models/model",
        download_dir,
        "logged.txt",
    )
    untrusted_logged_repository = RemoteArtifactRepository(
        "s3://untrusted-bucket/logged-models/model",
        download_dir,
        "untrusted.txt",
    )
    runs_repository = RunsArtifactRepository(run_repository)
    runs_repository._get_logged_model_artifact_repo.side_effect = [
        trusted_logged_repository,
        untrusted_logged_repository,
    ]
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts.get_artifact_repository.return_value = ModelsArtifactRepository(  # type: ignore[attr-defined]
        runs_repository
    )
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]
    scan_result: Any = {"bytes_scanned": 4, "issues": []}
    mock_scan.return_value = scan_result

    with patch.dict(
        sys.modules,
        {
            "mlflow": mlflow_module,
            "mlflow.store": store_module,
            "mlflow.store.artifact": artifact_module,
            "mlflow.store.artifact.models_artifact_repo": models_module,
            "mlflow.store.artifact.runs_artifact_repo": runs_module,
        },
    ):
        result = scan_mlflow_model("models:/TestModel/1")

    assert result == scan_result
    runs_repository._get_logged_model_artifact_repo.assert_called_once_with(run_id="run-1", name="model")
    runs_repository.download_artifacts.assert_not_called()
    run_repository.download_artifacts.assert_called_once_with(artifact_path="", dst_path=str(download_dir))
    trusted_logged_repository.download_artifacts.assert_called_once_with(
        artifact_path="",
        dst_path=str(download_dir),
    )
    untrusted_logged_repository.download_artifacts.assert_not_called()
    assert (download_dir / "logged.txt").is_file()
    mock_scan.assert_called_once_with(
        str(download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@pytest.mark.parametrize("error_kind", ["runtime", "permission_denied"])
def test_delegated_mlflow_download_fails_closed_on_target_error(tmp_path: Path, error_kind: str) -> None:
    """An optional run overlay must fail closed for errors other than absence."""
    if error_kind == "permission_denied":
        mlflow_exceptions = pytest.importorskip("mlflow.exceptions")
        mlflow_proto = pytest.importorskip("mlflow.protos.databricks_pb2")
        error = mlflow_exceptions.MlflowException(
            "run artifact access denied",
            error_code=mlflow_proto.PERMISSION_DENIED,
        )
    else:
        error = RuntimeError("run artifact download failed")
    listed_file = SimpleNamespace(path="artifact.bin", is_dir=False)
    failed_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(side_effect=error),
    )
    later_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(return_value=str(tmp_path / "model")),
    )
    plan = _MlflowDelegatedDownloadPlan(
        (
            _MlflowDelegatedDownloadTarget(failed_repository, None, optional_when_missing=True),
            _MlflowDelegatedDownloadTarget(later_repository, None, "model"),
        )
    )

    with pytest.raises(type(error), match=str(error)):
        _download_trusted_plan_for_test(plan, tmp_path)

    later_repository.download_artifacts.assert_not_called()


def test_delegated_mlflow_download_does_not_skip_missing_mandatory_target(tmp_path: Path) -> None:
    """A direct or sole target remains mandatory even when MLflow reports it missing."""
    mlflow_exceptions = pytest.importorskip("mlflow.exceptions")
    mlflow_proto = pytest.importorskip("mlflow.protos.databricks_pb2")
    missing_error = mlflow_exceptions.MlflowException(
        "artifact path is absent",
        error_code=mlflow_proto.RESOURCE_DOES_NOT_EXIST,
    )
    listed_file = SimpleNamespace(path="artifact.bin", is_dir=False)
    missing_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(side_effect=missing_error),
    )
    later_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(return_value=str(tmp_path / "model")),
    )
    plan = _MlflowDelegatedDownloadPlan(
        (
            _MlflowDelegatedDownloadTarget(missing_repository, None),
            _MlflowDelegatedDownloadTarget(later_repository, None, "model"),
        )
    )

    with pytest.raises(mlflow_exceptions.MlflowException, match="artifact path is absent"):
        _download_trusted_plan_for_test(plan, tmp_path)

    later_repository.download_artifacts.assert_not_called()


def test_delegated_mlflow_download_fails_when_later_target_errors(tmp_path: Path) -> None:
    """A successful run target must not hide a failed logged-model overlay."""
    run_path = tmp_path / "run"
    run_path.mkdir()
    listed_file = SimpleNamespace(path="artifact.bin", is_dir=False)
    run_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(return_value=str(run_path)),
    )
    failed_logged_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(side_effect=RuntimeError("logged-model download failed")),
    )
    plan = _MlflowDelegatedDownloadPlan(
        (
            _MlflowDelegatedDownloadTarget(run_repository, None),
            _MlflowDelegatedDownloadTarget(failed_logged_repository, None, "model"),
        )
    )

    with pytest.raises(RuntimeError, match="logged-model download failed"):
        _download_trusted_plan_for_test(plan, tmp_path)

    run_repository.download_artifacts.assert_called_once()
    failed_logged_repository.download_artifacts.assert_called_once()


@pytest.mark.parametrize("returned_path", [None, ""])
def test_delegated_mlflow_download_rejects_missing_target_path(
    tmp_path: Path,
    returned_path: str | None,
) -> None:
    """An empty repository result is incomplete even if a later target could succeed."""
    listed_file = SimpleNamespace(path="artifact.bin", is_dir=False)
    empty_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(return_value=returned_path),
    )
    later_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(return_value=str(tmp_path / "model")),
    )
    plan = _MlflowDelegatedDownloadPlan(
        (
            _MlflowDelegatedDownloadTarget(empty_repository, None),
            _MlflowDelegatedDownloadTarget(later_repository, None, "model"),
        )
    )

    with pytest.raises(RuntimeError, match="did not return a download path"):
        _download_trusted_plan_for_test(plan, tmp_path)

    later_repository.download_artifacts.assert_not_called()


def test_delegated_mlflow_download_rejects_destination_symlink_before_next_target(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """One backend cannot redirect the next backend's destination outside staging."""
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    def create_destination_symlink(*, artifact_path: str, dst_path: str) -> str:
        assert artifact_path == ""
        run_path = Path(dst_path) / "run"
        run_path.mkdir()
        (Path(dst_path) / "model").symlink_to(outside_dir, target_is_directory=True)
        return str(run_path)

    listed_file = SimpleNamespace(path="artifact.bin", is_dir=False)
    first_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(side_effect=create_destination_symlink),
    )
    second_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[listed_file]),
        download_artifacts=MagicMock(),
    )
    plan = _MlflowDelegatedDownloadPlan(
        (
            _MlflowDelegatedDownloadTarget(first_repository, None),
            _MlflowDelegatedDownloadTarget(second_repository, None, "model"),
        )
    )

    result = _download_trusted_plan_for_test(plan, download_dir)

    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_escape"
    second_repository.download_artifacts.assert_not_called()
    assert list(outside_dir.iterdir()) == []


def test_delegated_mlflow_download_skips_structurally_missing_optional_target(tmp_path: Path) -> None:
    """An absent optional run overlay is skipped without parsing wrapped error text."""
    optional_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[]),
        download_artifacts=MagicMock(side_effect=RuntimeError("wrapped MLflow INTERNAL_ERROR")),
    )

    def download_logged_model(*, artifact_path: str, dst_path: str) -> str:
        assert artifact_path == ""
        destination = Path(dst_path)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "model.pkl").write_bytes(b"model")
        return str(destination)

    logged_repository = SimpleNamespace(
        list_artifacts=MagicMock(return_value=[SimpleNamespace(path="model.pkl", is_dir=False)]),
        download_artifacts=MagicMock(side_effect=download_logged_model),
    )
    plan = _MlflowDelegatedDownloadPlan(
        (
            _MlflowDelegatedDownloadTarget(optional_repository, None, optional_when_missing=True),
            _MlflowDelegatedDownloadTarget(logged_repository, None, "model"),
        )
    )

    result = _download_trusted_plan_for_test(plan, tmp_path)

    assert result == str(tmp_path / "model")
    optional_repository.download_artifacts.assert_not_called()
    logged_repository.download_artifacts.assert_called_once()


def test_delegated_standard_repository_uses_validated_file_plan(tmp_path: Path) -> None:
    """A standard MLflow repository cannot swap in traversal entries during recursive download."""
    pytest.importorskip("mlflow")
    from mlflow.entities import FileInfo
    from mlflow.store.artifact.artifact_repo import ArtifactRepository

    class MutatingArtifactRepository(ArtifactRepository):
        def __init__(self) -> None:
            super().__init__("s3://trusted-bucket/models")
            self.list_calls = 0

        def log_artifact(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("upload path must not be used")

        def log_artifacts(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("upload path must not be used")

        def list_artifacts(self, path: str | None = None) -> list[FileInfo]:
            self.list_calls += 1
            if self.list_calls == 1:
                return [FileInfo("model.pkl", False, 5)]
            return [FileInfo("../escaped.txt", False, 7)]

        def _download_file(self, remote_file_path: str, local_path: str) -> None:
            assert remote_file_path == "model.pkl"
            Path(local_path).write_bytes(b"model")

    repository = MutatingArtifactRepository()
    plan = _MlflowDelegatedDownloadPlan((_MlflowDelegatedDownloadTarget(repository, None),))

    result = _download_trusted_plan_for_test(plan, tmp_path)

    assert result == str(tmp_path)
    assert repository.list_calls == 1
    assert (tmp_path / "model.pkl").read_bytes() == b"model"
    assert not (tmp_path.parent / "escaped.txt").exists()


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_unsafe_remote_listing_before_download(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An allowlisted backend cannot write a traversal key before staging validation."""
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    outside_path = tmp_path / "escaped.txt"
    mock_mkdtemp.return_value = str(download_dir)

    def unsafe_download(*, artifact_path: str, dst_path: str) -> str:
        outside_path.write_bytes(b"escaped")
        return dst_path

    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/TestModel"
    artifact_repository.list_artifacts.return_value = [SimpleNamespace(path="../escaped.txt", is_dir=False)]
    artifact_repository.download_artifacts.side_effect = unsafe_download
    mock_mlflow = MagicMock()
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_listing_unsafe"
    artifact_repository.download_artifacts.assert_not_called()
    mock_scan.assert_not_called()
    assert not outside_path.exists()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_allows_explicitly_allowlisted_remote_artifact_uri(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Explicitly allowlisted remote artifact roots may still use MLflow's downloader."""
    artifact_uri = "s3://trusted-bucket/models/TestModel"
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    download_dir = tmp_path / "modelaudit_mlflow_allowed"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)
    scan_result: Any = {"bytes_scanned": 256, "issues": []}
    mock_scan.return_value = scan_result
    mock_mlflow = MagicMock()
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = artifact_uri
    artifact_repository.download_artifacts.return_value = str(download_dir)
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    assert result == scan_result
    mock_mlflow.artifacts.get_artifact_repository.assert_called_once_with("models:/TestModel/1")
    artifact_repository.download_artifacts.assert_called_once_with(
        artifact_path="",
        dst_path=str(download_dir),
    )
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
    mock_scan.assert_called_once_with(
        str(download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_combines_hardened_local_run_with_allowlisted_remote_overlay(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Mixed overlays must copy local targets safely and allowlist only remote targets."""

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir
            self.artifact_uri = artifact_dir.as_uri()
            self.download_artifacts = MagicMock(side_effect=AssertionError("local target must use hardened copy"))

    class RemoteArtifactRepository:
        def __init__(self, artifact_uri: str, downloaded_path: Path) -> None:
            self.artifact_uri = artifact_uri
            self.list_artifacts = MagicMock(return_value=[SimpleNamespace(path="logged.txt", is_dir=False)])

            def download_artifacts(*, artifact_path: str, dst_path: str) -> str:
                assert artifact_path == ""
                assert Path(dst_path) == downloaded_path
                downloaded_path.mkdir(parents=True, exist_ok=True)
                (downloaded_path / "logged.txt").write_bytes(b"logged")
                return str(downloaded_path)

            self.download_artifacts = MagicMock(side_effect=download_artifacts)

    class RunsArtifactRepository:
        artifact_uri = "runs:/run-1/model"

        def __init__(self, run_repository: LocalArtifactRepository) -> None:
            self.repo = run_repository

        @staticmethod
        def parse_runs_uri(uri: str) -> tuple[str, str | None]:
            assert uri == "runs:/run-1/model"
            return "run-1", "model"

        @staticmethod
        def get_underlying_uri(uri: str, tracking_uri: str | None = None) -> str:
            assert uri == "runs:/run-1/model"
            assert tracking_uri is None
            return run_repository.artifact_uri

        @staticmethod
        def _get_logged_model_artifact_repo(*, run_id: str, name: str) -> RemoteArtifactRepository:
            assert run_id == "run-1"
            assert name == "model"
            return logged_repository

    class ModelsArtifactRepository:
        def __init__(self, repo: Any) -> None:
            self.repo = repo

    monkeypatch.setenv(
        "MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS",
        "s3://trusted-bucket/logged-models/model",
    )
    local_root = tmp_path / "run-artifacts"
    _write_local_artifacts(local_root, {"run.txt": 4})
    download_dir = tmp_path / "mixed-download"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)
    run_repository = LocalArtifactRepository(local_root)
    logged_repository = RemoteArtifactRepository(
        "s3://trusted-bucket/logged-models/model",
        download_dir,
    )
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts.get_artifact_repository.return_value = ModelsArtifactRepository(  # type: ignore[attr-defined]
        RunsArtifactRepository(run_repository)
    )
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    runs_module = ModuleType("mlflow.store.artifact.runs_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]
    runs_module.RunsArtifactRepository = RunsArtifactRepository  # type: ignore[attr-defined]
    scan_result: Any = {"bytes_scanned": 8, "issues": []}
    mock_scan.return_value = scan_result

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
        result = scan_mlflow_model("models:/TestModel/1")

    assert result == scan_result
    assert (download_dir / "run.txt").read_bytes() == b"xxxx"
    run_repository.download_artifacts.assert_not_called()
    logged_repository.download_artifacts.assert_called_once_with(
        artifact_path="",
        dst_path=str(download_dir),
    )
    mock_scan.assert_called_once_with(
        str(download_dir),
        timeout=3600,
        blacklist_patterns=None,
        max_file_size=0,
        max_total_size=0,
        cache_enabled=True,
        cache_dir=None,
    )
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_honors_artifact_path_specific_allowlist(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A direct artifact may be trusted without allowlisting its repository parent."""
    artifact_uri = "s3://trusted-bucket/models/model.pkl"
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", artifact_uri)
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    (download_dir / "model.pkl").write_bytes(b"model")
    mock_mkdtemp.return_value = str(download_dir)
    scan_result: Any = {"bytes_scanned": 4, "issues": []}
    mock_scan.return_value = scan_result
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models"
    artifact_repository.download_artifacts.return_value = str(download_dir / "model.pkl")
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "s3://trusted-bucket/models",
        "model.pkl",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = artifact_repository  # type: ignore[attr-defined]

    with patch.dict(sys.modules, {"mlflow": mlflow_module}):
        result = scan_mlflow_model(artifact_uri)

    assert result == scan_result
    artifact_repository.download_artifacts.assert_called_once_with(
        artifact_path="model.pkl",
        dst_path=str(download_dir),
    )
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


def test_artifact_path_specific_allowlist_does_not_trust_sibling_object() -> None:
    assert (
        _mlflow_artifact_uri_matches_prefix(
            "s3://trusted-bucket/models/other.pkl",
            "s3://trusted-bucket/models/model.pkl",
        )
        is False
    )


def test_mixed_mlflow_overlay_fails_closed_when_local_target_follows_remote(tmp_path: Path) -> None:
    remote_repository = object()
    local_repository = object()
    targets = (
        _MlflowDelegatedDownloadTarget(remote_repository, None),
        _MlflowDelegatedDownloadTarget(local_repository, None, "model"),
    )

    with patch(
        "modelaudit.integrations.mlflow._local_mlflow_artifact_root",
        side_effect=lambda repository: tmp_path if repository is local_repository else None,
    ):
        assert _partition_mlflow_delegated_targets(targets) is None


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_preserves_remote_artifact_key_separators(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Direct object-store keys must not be normalized to a different artifact."""
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    download_dir = tmp_path / "download"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models"
    artifact_repository.download_artifacts.return_value = str(download_dir)
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts._get_root_uri_and_artifact_path.return_value = (  # type: ignore[attr-defined]
        "s3://trusted-bucket/models",
        "weights//model.pkl",
    )
    mlflow_module.artifacts.get_artifact_repository.return_value = artifact_repository  # type: ignore[attr-defined]
    scan_result: Any = {"bytes_scanned": 4, "issues": []}
    mock_scan.return_value = scan_result

    with patch.dict(sys.modules, {"mlflow": mlflow_module}):
        result = scan_mlflow_model("s3://trusted-bucket/models/weights//model.pkl")

    assert result == scan_result
    artifact_repository.download_artifacts.assert_called_once_with(
        artifact_path="weights//model.pkl",
        dst_path=str(download_dir),
    )
    mock_scan.assert_called_once()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


def test_scan_mlflow_model_copies_local_repository_without_remote_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verified local MLflow repositories remain scannable without a remote allowlist."""
    monkeypatch.delenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", raising=False)

    class LocalArtifactRepository:
        def __init__(self, artifact_dir: Path) -> None:
            self.artifact_dir = artifact_dir

    class ModelsArtifactRepository:
        pass

    source_root = tmp_path / "mlflow_artifacts"
    _write_local_artifacts(source_root, {"model.pkl": 4})
    download_dir = tmp_path / "modelaudit_mlflow_local"
    download_dir.mkdir()
    scan_result: Any = {"bytes_scanned": 4, "issues": []}
    mlflow_module = ModuleType("mlflow")
    mlflow_module.artifacts = MagicMock()  # type: ignore[attr-defined]
    mlflow_module.artifacts.get_artifact_repository.return_value = LocalArtifactRepository(source_root)  # type: ignore[attr-defined]
    store_module = ModuleType("mlflow.store")
    artifact_module = ModuleType("mlflow.store.artifact")
    local_module = ModuleType("mlflow.store.artifact.local_artifact_repo")
    models_module = ModuleType("mlflow.store.artifact.models_artifact_repo")
    local_module.LocalArtifactRepository = LocalArtifactRepository  # type: ignore[attr-defined]
    models_module.ModelsArtifactRepository = ModelsArtifactRepository  # type: ignore[attr-defined]

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
        result = scan_mlflow_model("models:/TestModel/1")

    assert result == scan_result
    assert (download_dir / "model.pkl").read_bytes() == b"xxxx"
    mlflow_module.artifacts.download_artifacts.assert_not_called()  # type: ignore[attr-defined]
    mock_scan.assert_called_once()


def test_mlflow_budget_failure_redacts_mlflow_query_credentials_recursively() -> None:
    model_uri = "models:/PublicModel/1?auth=QUERYSECRET123&session=SESSIONSECRET123"
    boundary_error = "x" * 470 + " artifact_uri=///user:BUDGETPARTIALSECRET1234567890@host/model"
    result = _mlflow_budget_failure_result(
        model_uri,
        "MLflow artifact download refused",
        {
            "model_uri": model_uri,
            "nested": {"source": "models:/OtherModel/2?code=CODESECRET123&jwt=JWTSECRET123"},
            "boundary_error": boundary_error,
        },
    )

    serialized_result = result.model_dump_json()
    for secret in ("QUERYSECRET123", "SESSIONSECRET123", "CODESECRET123", "JWTSECRET123"):
        assert secret not in serialized_result
    assert "BUDGETPARTIAL" not in serialized_result
    assert result.checks[0].location == "models:/PublicModel/1?auth=<redacted>&session=<redacted>"
    assert result.checks[0].details["nested"]["source"] == ("models:/OtherModel/2?code=<redacted>&jwt=<redacted>")


def test_mlflow_download_safety_failure_redacts_source_and_artifact_credentials() -> None:
    result = _mlflow_download_safety_failure_result(
        "models:/PublicModel/1?auth=MODELSECRET123",
        "MLflow staging contains an unsupported filesystem object",
        {
            "reason": "artifact_download_path_unsupported",
            "artifact_path": "model/access_token=PATHSECRET123.pkl",
        },
    )

    serialized_result = result.model_dump_json()
    assert "MODELSECRET123" not in serialized_result
    assert "PATHSECRET123" not in serialized_result
    assert result.checks[0].location == "models:/PublicModel/1?auth=<redacted>"
    assert result.checks[0].details["artifact_path"] == "model/access_token=<redacted>"


@pytest.mark.parametrize(
    "source",
    [
        "//user:RELATIVEPASS123@mlflow.example/model?token=QUERYSECRET123",
        "///user:RELATIVEPASS123@mlflow.example/model?token=QUERYSECRET123",
        "\\\\user:RELATIVEPASS123@mlflow.example\\model?token=QUERYSECRET123",
        "\\/\\/user:RELATIVEPASS123@mlflow.example\\/model?token=QUERYSECRET123",
        "%2F%2F%2Fuser%3ARELATIVEPASS123%40mlflow.example%2Fmodel%3Ftoken%3DQUERYSECRET123",
        "%252F%252Fuser%253ARELATIVEPASS123%2540mlflow.example%252Fmodel%253Ftoken%253DQUERYSECRET123",
    ],
)
def test_redact_mlflow_error_handles_protocol_relative_userinfo(source: str) -> None:
    redacted = _redact_mlflow_error_for_display(f"artifact_uri={source}")

    assert "mlflow.example/model" in redacted
    assert "RELATIVEPASS123" not in redacted
    assert "QUERYSECRET123" not in redacted


@pytest.mark.parametrize(
    "source",
    [
        "///folder/user@mlflow.example/model",
        "\\\\mlflow.example\\folder\\user@label",
    ],
)
def test_redact_mlflow_error_preserves_non_authority_at_signs(source: str) -> None:
    assert _redact_mlflow_error_for_display(f"artifact_uri={source}") == f"artifact_uri={source}"


def test_redact_mlflow_error_handles_deeply_encoded_protocol_relative_userinfo() -> None:
    source = "//user:RELATIVEPASS123@mlflow.example/model?token=QUERYSECRET123"
    for _ in range(4):
        source = quote(source, safe="")

    redacted = _redact_mlflow_error_for_display(f"artifact_uri={source}")

    assert "mlflow.example/model" in redacted
    assert "RELATIVEPASS123" not in redacted
    assert "QUERYSECRET123" not in redacted


@pytest.mark.parametrize(
    "details",
    [
        "credentials=('user', 'CONTAINERSECRET123')",
        "credentials=['user', 'CONTAINERSECRET123']",
        "credentials={'username': 'user', 'password': 'CONTAINERSECRET123'}",
        "credentials=[['user'], 'CONTAINERSECRET123']",
        "credentials={'primary': {'username': 'user'}, 'value': 'CONTAINERSECRET123'}",
        "credentials={'username': 'user', 'password': 'CONTAINERSECRET123'",
    ],
)
def test_redact_mlflow_error_handles_credential_containers(details: str) -> None:
    redacted = _redact_mlflow_error_for_display(details)

    assert redacted == "credentials=<redacted>"
    assert "CONTAINERSECRET123" not in redacted


@pytest.mark.parametrize(
    "message",
    [
        "Permission denied while calling token endpoint",
        "OAuth token endpoint returned HTTP 401",
        "Token refresh failed",
        "Bearer authentication failed",
        "Basic authentication is required",
    ],
)
def test_redact_mlflow_error_preserves_benign_auth_diagnostics(message: str) -> None:
    assert _redact_mlflow_error_for_display(message) == message


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("client_secret='CLIENTSECRET123'", "client_secret='<redacted>'"),
        ("refresh-token=REFRESHSECRET123", "refresh-token=<redacted>"),
        ("private_key=PRIVATESECRET123", "private_key=<redacted>"),
        ("cookie=COOKIESECRET123", "cookie=<redacted>"),
        ("session=SESSIONSECRET123", "session=<redacted>"),
        ("jwt=JWTSECRET123", "jwt=<redacted>"),
        (
            "auth=AUTHSECRET123&session=SESSIONSECRET123",
            "auth=<redacted>&session=<redacted>",
        ),
        (
            "credentials=TOPSECRET123&region=us-east-1",
            "credentials=<redacted>&region=us-east-1",
        ),
        (
            "C:/models auth=AUTHSECRET123&session=SESSIONSECRET123",
            "C:/models auth=<redacted>&session=<redacted>",
        ),
    ],
)
def test_redact_mlflow_error_handles_sensitive_aliases(message: str, expected: str) -> None:
    assert _redact_mlflow_error_for_display(message) == expected


@pytest.mark.parametrize(
    "message",
    [
        "Cookie policy rejected request",
        "JWT validation failed",
        "Private key file missing",
        "Client secret provider unavailable",
        "Refresh token endpoint failed",
        "monkey=value",
        "key=value",
        "session state changed",
        "tokenizer=bert",
    ],
)
def test_redact_mlflow_error_preserves_benign_sensitive_key_near_matches(message: str) -> None:
    assert _redact_mlflow_error_for_display(message) == message


@pytest.mark.parametrize(
    "message",
    [
        "headers[Authorization]=BRACKETSECRET123",
        "request.headers[proxy-authorization]=Bearer SHORT",
        "headers[proxy_authorization]=PROXYSECRET123",
        "headers[X-Api-Key]=HEADERSECRET123",
        "headers[Credentials]=CREDENTIALSECRET123",
        "headers[auth]=AUTHSECRET123",
        "headers[Cookie]=COOKIESECRET123",
        "headers[session]=SESSIONSECRET123",
        "headers[jwt]=JWTSECRET123",
        "headers[key]=KEYSECRET123",
        "params[api_key]='PARAMSECRET123'",
        "params[client_secret]=CLIENTSECRET123",
        "query[refresh_token]=REFRESHSECRET123",
    ],
)
def test_redact_mlflow_error_handles_bracketed_sensitive_keys(message: str) -> None:
    redacted = _redact_mlflow_error_for_display(message)

    assert "<redacted>" in redacted
    assert "SECRET" not in redacted
    assert "Bearer SHORT" not in redacted


def test_redact_mlflow_error_preserves_benign_bracketed_keys() -> None:
    for message in (
        "headers[Content-Type]=application/json",
        "headers[X-Api-Version]=2026-06-08",
        "params[region]=us-east-1",
    ):
        assert _redact_mlflow_error_for_display(message) == message


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test MLflow model downloads use a dedicated subdirectory under cache_dir."""
    mock_mlflow = MagicMock()
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    cache_dir = tmp_path / "cache"
    cache_key = hashlib.sha256(b"models:/TestModel/1").hexdigest()[:16]
    expected_download_root = cache_dir / "mlflow"
    expected_download_dir = expected_download_root / f"{cache_key}-run"
    expected_download_dir.mkdir(parents=True)
    mock_mkdtemp.return_value = str(expected_download_dir)
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/TestModel"
    artifact_repository.download_artifacts.return_value = str(expected_download_dir)
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository
    mock_scan.return_value = {"bytes_scanned": 256, "issues": []}

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        scan_mlflow_model("models:/TestModel/1", cache_enabled=True, cache_dir=str(cache_dir))

    mock_mkdtemp.assert_called_once_with(prefix=f"{cache_key}-", dir=str(expected_download_root))
    artifact_repository.download_artifacts.assert_called_once_with(
        artifact_path="",
        dst_path=str(expected_download_dir),
    )
    mock_mlflow.artifacts.download_artifacts.assert_not_called()
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
def test_scan_mlflow_model_file_path(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test MLflow model scanning when download returns a file path."""
    # Mock MLflow
    mock_mlflow = MagicMock()
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")

    # Create a temporary file path (simulating MLflow returning a file)
    temp_dir = tmp_path / "modelaudit_mlflow_test"
    temp_dir.mkdir()
    temp_file = temp_dir / "model.pkl"
    temp_file.write_bytes(b"model")
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/TestModel"
    artifact_repository.download_artifacts.return_value = str(temp_file)
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository
    mock_mkdtemp.return_value = str(temp_dir)

    with (
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
    ):
        mock_scan.return_value = {"bytes_scanned": 512, "issues": []}

        scan_mlflow_model("models:/TestModel/1")

        # Verify scan was called with the directory path, not the file path
        mock_scan.assert_called_once()
        args, _kwargs = mock_scan.call_args
        assert args[0] == str(temp_dir.resolve())  # Should be directory, not file


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_download_return_outside_staging(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MLflow backends must not redirect scanning outside ModelAudit's staging directory."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "modelaudit_mlflow_test"
    download_dir.mkdir()
    outside_model = tmp_path / "outside" / "model.pkl"
    outside_model.parent.mkdir()
    outside_model.write_bytes(b"model")
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(outside_model)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.has_errors is True
    assert result.checks[0].name == "MLflow Download Path Check"
    assert result.checks[0].details["reason"] == "artifact_download_path_escape"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_staging_root_symlink_swap(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backend must not replace the private staging root with an outside link."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_model = outside_dir / "model.pkl"
    outside_model.write_bytes(b"model")
    mock_mkdtemp.return_value = str(download_dir)

    def replace_staging_root(*, artifact_path: str, dst_path: str) -> str:
        assert artifact_path == ""
        assert dst_path == str(download_dir)
        download_dir.rmdir()
        download_dir.symlink_to(outside_dir, target_is_directory=True)
        return str(download_dir / outside_model.name)

    mock_mlflow.artifacts.download_artifacts.side_effect = replace_staging_root

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_root_changed"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_staging_root_directory_swap(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new directory at the same path is not the private staging root ModelAudit created."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    mock_mkdtemp.return_value = str(download_dir)

    def replace_staging_root(*, artifact_path: str, dst_path: str) -> str:
        assert artifact_path == ""
        assert dst_path == str(download_dir)
        download_dir.rmdir()
        download_dir.mkdir()
        replacement_model = download_dir / "model.pkl"
        replacement_model.write_bytes(b"replacement")
        return str(replacement_model)

    mock_mlflow.artifacts.download_artifacts.side_effect = replace_staging_root

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_root_changed"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_staged_symlink_to_outside_file(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged symlink must not redirect scanning to an outside file."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    outside_model = tmp_path / "outside" / "model.pkl"
    outside_model.parent.mkdir()
    outside_model.write_bytes(b"model")
    returned_link = download_dir / "model.pkl"
    returned_link.symlink_to(outside_model)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(returned_link)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_escape"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_accepts_staged_symlink_to_staged_file(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An in-staging symlink to an in-staging regular file remains scannable."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    target_dir = download_dir / "artifacts"
    target_dir.mkdir(parents=True)
    target_file = target_dir / "model.pkl"
    target_file.write_bytes(b"model")
    returned_link = download_dir / "model-link.pkl"
    returned_link.symlink_to(target_file)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(returned_link)
    mock_scan.return_value = {"bytes_scanned": 5, "issues": []}

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    assert result == mock_scan.return_value
    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(target_dir.resolve())
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported on this platform")
@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_fifo_without_blocking(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A returned FIFO is rejected by metadata without opening the pipe."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    fifo_path = download_dir / "model.pkl"
    os.mkfifo(fifo_path)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(fifo_path)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_unsupported"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_symlink_loop(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A returned symlink loop fails closed instead of escaping the CLI error contract."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    first_link = download_dir / "first.pkl"
    second_link = download_dir / "second.pkl"
    first_link.symlink_to(second_link.name)
    second_link.symlink_to(first_link.name)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(first_link)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_unavailable"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported on this platform")
@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_nested_fifo_without_blocking(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A special file nested below an accepted directory must be rejected before core hashing."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    model_dir = download_dir / "model"
    model_dir.mkdir(parents=True)
    os.mkfifo(model_dir / "nested.pkl")
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(model_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_unsupported"
    assert result.checks[0].details["artifact_path"] == "model/nested.pkl"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_nested_file_symlink_escape(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nested file symlink must not redirect core to a target outside staging."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    model_dir = download_dir / "model"
    model_dir.mkdir(parents=True)
    outside_file = tmp_path / "outside.pkl"
    outside_file.write_bytes(b"outside")
    (model_dir / "linked.pkl").symlink_to(outside_file)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(model_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_escape"
    assert result.checks[0].details["artifact_path"] == "model/linked.pkl"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_nested_directory_symlink(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directory links are rejected because core's non-following walk would omit their contents."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    model_dir = download_dir / "model"
    target_dir = download_dir / "target"
    model_dir.mkdir(parents=True)
    target_dir.mkdir()
    (target_dir / "hidden.pkl").write_bytes(b"payload")
    (model_dir / "linked").symlink_to(target_dir, target_is_directory=True)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(model_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_directory_link_unsupported"
    assert result.checks[0].details["artifact_path"] == "model/linked"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_nested_directory_junction(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows junctions are rejected even when pathlib does not classify them as symlinks."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    model_dir = download_dir / "model"
    junction_dir = model_dir / "junction"
    junction_dir.mkdir(parents=True)
    (junction_dir / "hidden.pkl").write_bytes(b"payload")
    monkeypatch.setattr(Path, "is_junction", lambda self: self == junction_dir, raising=False)
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(model_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_directory_link_unsupported"
    assert result.checks[0].details["artifact_path"] == "model/junction"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_regular_file_reparse_point(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file reparse point must not be treated as an ordinary staged regular file."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    reparse_file = download_dir / "model.pkl"
    reparse_file.write_bytes(b"model")
    monkeypatch.setattr(
        "modelaudit.integrations.mlflow._mlflow_entry_is_reparse_point",
        lambda path, _path_stat: path == reparse_file,
    )
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(download_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_unsupported"
    assert result.checks[0].details["artifact_path"] == "model.pkl"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_rejects_hardlink_alias_outside_staging(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged file with an alias outside the private directory remains replaceable by that alias."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    staged_file = download_dir / "model.pkl"
    staged_file.write_bytes(b"model")
    try:
        os.link(staged_file, tmp_path / "outside.pkl")
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(download_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_hardlink_escape"


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_accepts_hardlinks_contained_in_staging(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hardlinks are safe when every alias remains inside the private staging directory."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    staged_file = download_dir / "model.pkl"
    staged_file.write_bytes(b"model")
    try:
        os.link(staged_file, download_dir / "model-alias.pkl")
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(download_dir)
    mock_scan.return_value = {"bytes_scanned": 5, "issues": []}

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1")

    assert result == mock_scan.return_value
    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(download_dir.resolve())
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
@patch("modelaudit.core.scan_model_directory_or_file")
def test_scan_mlflow_model_bounds_staging_tree_validation(
    mock_scan: MagicMock,
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recursive validation uses the same configurable artifact-entry budget as preflight."""
    mock_mlflow = MagicMock()
    _configure_trusted_remote_repository(mock_mlflow, monkeypatch)
    download_dir = tmp_path / "staging"
    download_dir.mkdir()
    (download_dir / "first.pkl").write_bytes(b"one")
    (download_dir / "second.pkl").write_bytes(b"two")
    mock_mkdtemp.return_value = str(download_dir)
    mock_mlflow.artifacts.download_artifacts.return_value = str(download_dir)

    with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
        result = scan_mlflow_model("models:/TestModel/1", max_mlflow_artifact_entries=1)

    mock_scan.assert_not_called()
    mock_rmtree.assert_called_once_with(str(download_dir), ignore_errors=True)
    assert determine_exit_code(result) == 2
    assert result.checks[0].details["reason"] == "artifact_download_path_entry_limit"
    assert result.checks[0].details["max_artifact_entries"] == 1


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
def test_scan_mlflow_model_download_error(
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test error handling when MLflow download fails."""
    # Mock MLflow with download error
    mock_mlflow = MagicMock()
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/TestModel"
    artifact_repository.download_artifacts.side_effect = Exception("Download failed")
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository

    temp_dir = tmp_path / "modelaudit_mlflow_test"
    temp_dir.mkdir()
    mock_mkdtemp.return_value = str(temp_dir)

    with (
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
        pytest.raises(Exception, match="Download failed"),
    ):
        scan_mlflow_model("models:/TestModel/1")

    # Verify cleanup still happens
    mock_rmtree.assert_called_once_with(str(temp_dir), ignore_errors=True)


@patch("modelaudit.integrations.mlflow.shutil.rmtree")
@patch("modelaudit.integrations.mlflow.tempfile.mkdtemp")
def test_scan_mlflow_model_debug_log_redacts_source_uri(
    mock_mkdtemp: MagicMock,
    mock_rmtree: MagicMock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_uri = "models:/PrivateModel/access_token=DEBUGSECRET123"
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    mock_mlflow = MagicMock()
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/PrivateModel"
    artifact_repository.download_artifacts.side_effect = RuntimeError("Download failed")
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository
    temp_dir = tmp_path / "modelaudit_mlflow_test"
    temp_dir.mkdir()
    mock_mkdtemp.return_value = str(temp_dir)

    with (
        caplog.at_level(logging.DEBUG, logger="modelaudit.integrations.mlflow"),
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
        pytest.raises(RuntimeError, match="Download failed"),
    ):
        scan_mlflow_model(model_uri)

    assert "models:/PrivateModel/access_token=<redacted>" in caplog.text
    assert "DEBUGSECRET123" not in caplog.text
    mock_rmtree.assert_called_once_with(str(temp_dir), ignore_errors=True)


def test_scan_mlflow_model_no_registry_uri(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test MLflow model scanning without registry URI."""
    mock_mlflow = MagicMock()
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "s3://trusted-bucket/models")
    download_dir = tmp_path / "test"
    download_dir.mkdir()
    artifact_repository = MagicMock()
    artifact_repository.artifact_uri = "s3://trusted-bucket/models/TestModel"
    artifact_repository.download_artifacts.return_value = str(download_dir)
    mock_mlflow.artifacts.get_artifact_repository.return_value = artifact_repository

    with (
        patch.dict(sys.modules, {"mlflow": mock_mlflow}),
        patch("modelaudit.integrations.mlflow.tempfile.mkdtemp", return_value=str(download_dir)),
        patch("modelaudit.core.scan_model_directory_or_file", return_value={}),
        patch("modelaudit.integrations.mlflow.shutil.rmtree"),
    ):
        scan_mlflow_model("models:/TestModel/1")

        # Verify set_registry_uri was not called
        mock_mlflow.set_registry_uri.assert_not_called()
