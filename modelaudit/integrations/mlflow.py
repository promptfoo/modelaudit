import hashlib
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import Check, CheckStatus, Issue, IssueSeverity, ModelAuditResultModel, create_initial_audit_result

logger = logging.getLogger(__name__)

_MLFLOW_DOWNLOAD_BUDGET_CHECK = "MLflow Download Size Check"
_DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES = 10000


@dataclass(frozen=True)
class _MlflowDownloadPlan:
    artifact_repository: Any
    artifact_path: str | None
    root_uri: str


def _finite_budget(max_file_size: int, max_total_size: int) -> bool:
    return max_file_size > 0 or max_total_size > 0


def _normalize_max_artifact_entries(value: Any) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return _DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES
    if normalized <= 0:
        return _DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES
    return normalized


def _split_mlflow_artifact_uri(mlflow_module: Any, model_uri: str) -> tuple[str, str | None]:
    splitter = getattr(getattr(mlflow_module, "artifacts", None), "_get_root_uri_and_artifact_path", None)
    if callable(splitter):
        try:
            split_result = splitter(model_uri)
        except Exception:
            split_result = None
        if isinstance(split_result, tuple) and len(split_result) == 2:
            root_uri, artifact_path = split_result
            if isinstance(root_uri, str):
                return root_uri, str(artifact_path) if artifact_path else None

    if not model_uri.startswith("models:/"):
        return model_uri, None

    model_ref = model_uri[len("models:/") :].lstrip("/")
    if not model_ref:
        return model_uri, None

    if "@" in model_ref:
        root_ref, separator, artifact_path = model_ref.partition("/")
        return f"models:/{root_ref}", artifact_path if separator and artifact_path else None

    parts = model_ref.split("/")
    if len(parts) <= 2:
        return model_uri, None
    return f"models:/{parts[0]}/{parts[1]}", "/".join(parts[2:])


def _mlflow_budget_failure_result(model_uri: str, message: str, details: dict[str, Any]) -> ModelAuditResultModel:
    result = create_initial_audit_result()
    result.scanner_names = ["mlflow"]
    result.has_errors = True
    result.success = False

    why = (
        "ModelAudit cannot safely acquire this MLflow artifact within the configured scan budget. "
        "Refusing the download avoids unbounded network, disk, or elapsed-time use before scanning begins."
    )
    result.checks.append(
        Check(
            name=_MLFLOW_DOWNLOAD_BUDGET_CHECK,
            status=CheckStatus.FAILED,
            message=message,
            severity=IssueSeverity.INFO,
            location=model_uri,
            details=details,
            why=why,
        )
    )
    result.issues.append(
        Issue(
            message=message,
            severity=IssueSeverity.INFO,
            location=model_uri,
            details=details,
            why=why,
            type="mlflow_download_budget",
        )
    )
    result.finalize_statistics()
    return result


def _preflight_mlflow_download_budget(
    mlflow_module: Any,
    model_uri: str,
    *,
    max_file_size: int,
    max_total_size: int,
    max_artifact_entries: int,
) -> _MlflowDownloadPlan | ModelAuditResultModel | None:
    if not _finite_budget(max_file_size, max_total_size):
        return None

    root_uri, initial_artifact_path = _split_mlflow_artifact_uri(mlflow_module, model_uri)
    details: dict[str, Any] = {
        "model_uri": model_uri,
        "root_uri": root_uri,
        "artifact_path": initial_artifact_path,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "max_artifact_entries": max_artifact_entries,
    }
    try:
        artifact_repository = mlflow_module.artifacts.get_artifact_repository(root_uri)
        list_artifacts = artifact_repository.list_artifacts
    except Exception as e:
        details["reason"] = "artifact_size_unavailable"
        details["error"] = str(e)
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    total_size = 0
    file_count = 0
    entry_count = 0
    pending_dirs: list[str | None] = [initial_artifact_path]
    visited_dirs: set[str | None] = set()
    try:
        while pending_dirs:
            current_path = pending_dirs.pop()
            if current_path in visited_dirs:
                continue
            visited_dirs.add(current_path)
            artifact_infos = list_artifacts(current_path)
            if artifact_infos is None:
                raise ValueError(f"Artifact listing returned no size information for {current_path or '<root>'}")

            for artifact_info in artifact_infos:
                entry_count += 1
                if entry_count > max_artifact_entries:
                    details.update(
                        {
                            "reason": "artifact_listing_budget_exceeded",
                            "artifact_entry_count": entry_count,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                        details,
                    )

                artifact_path = getattr(artifact_info, "path", None)
                if getattr(artifact_info, "is_dir", False):
                    if isinstance(artifact_path, str):
                        pending_dirs.append(artifact_path)
                    else:
                        raise ValueError("Artifact directory entry did not include a path")
                    continue

                file_size = getattr(artifact_info, "file_size", None)
                if not isinstance(file_size, int) or file_size < 0:
                    raise ValueError(f"Artifact file size unavailable for {artifact_path or '<unknown>'}")

                file_count += 1
                total_size += file_size
                if max_file_size > 0 and file_size > max_file_size:
                    details.update(
                        {
                            "reason": "artifact_file_size_exceeded",
                            "artifact_path": artifact_path,
                            "artifact_file_size": file_size,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact file too large to download: {file_size} bytes (max: {max_file_size})",
                        details,
                    )
                if max_total_size > 0 and total_size > max_total_size:
                    details.update(
                        {
                            "reason": "artifact_total_size_exceeded",
                            "artifact_total_size": total_size,
                            "artifact_file_count": file_count,
                            "artifact_entry_count": entry_count,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact total size too large to download: {total_size} bytes (max: {max_total_size})",
                        details,
                    )
    except Exception as e:
        details["reason"] = "artifact_size_unavailable"
        details["error"] = str(e)
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    if file_count == 0:
        details["reason"] = "artifact_size_unavailable"
        details["artifact_file_count"] = 0
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    return _MlflowDownloadPlan(
        artifact_repository=artifact_repository,
        artifact_path=initial_artifact_path,
        root_uri=root_uri,
    )


def _prepare_download_dir(model_uri: str, cache_dir: str | None) -> tuple[str, bool]:
    """Return an ephemeral per-run staging directory under the configured cache root."""
    if not cache_dir:
        return tempfile.mkdtemp(prefix="modelaudit_mlflow_"), True

    cache_key = hashlib.sha256(model_uri.encode("utf-8")).hexdigest()[:16]
    download_root = Path(cache_dir).expanduser() / "mlflow"
    download_root.mkdir(parents=True, exist_ok=True)
    # Use a unique staging directory for this run. ``cache_dir`` controls where
    # temporary downloads live, while scan-result caching is still handled by core.
    return tempfile.mkdtemp(prefix=f"{cache_key}-", dir=str(download_root)), True


def scan_mlflow_model(
    model_uri: str,
    *,
    registry_uri: str | None = None,
    timeout: int = 3600,
    blacklist_patterns: list[str] | None = None,
    max_file_size: int = 0,
    max_total_size: int = 0,
    **kwargs: Any,
) -> ModelAuditResultModel:
    """Download and scan a model from the MLflow model registry.

    Parameters
    ----------
    model_uri:
        URI of the model in MLflow, e.g. ``"models:/MyModel/1"`` or
        ``"models:/MyModel/Production"``.
    registry_uri:
        Optional MLflow registry URI. If provided, ``mlflow.set_registry_uri`` is
        called before downloading the model.
    timeout:
        Maximum time in seconds to spend scanning.
    blacklist_patterns:
        Optional list of blacklist patterns to check against model names.
    max_file_size:
        Maximum file size to scan in bytes (0 = unlimited).
    max_total_size:
        Maximum total bytes to scan before stopping (0 = unlimited).
    **kwargs:
        Additional arguments passed to :func:`scan_model_directory_or_file`.

    Returns
    -------
    ModelAuditResultModel
        Scan results as returned by
        :func:`scan_model_directory_or_file`.

    Raises
    ------
    ImportError
        If the ``mlflow`` package is not installed.
    """
    try:
        import mlflow
    except Exception as e:  # pragma: no cover - handled in tests
        raise ImportError("mlflow is not installed, cannot scan MLflow models") from e

    if registry_uri:
        mlflow.set_registry_uri(registry_uri)  # type: ignore[possibly-unbound-attribute]

    scan_kwargs = kwargs.copy()
    cache_enabled = scan_kwargs.pop("cache_enabled", True)
    raw_cache_dir = scan_kwargs.pop("cache_dir", None)
    max_artifact_entries = _normalize_max_artifact_entries(
        scan_kwargs.pop("max_mlflow_artifact_entries", _DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES)
    )
    scan_cache_dir = str(Path(raw_cache_dir).expanduser()) if cache_enabled and raw_cache_dir else None

    download_plan = _preflight_mlflow_download_budget(
        mlflow,
        model_uri,
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_artifact_entries=max_artifact_entries,
    )
    if isinstance(download_plan, ModelAuditResultModel):
        return download_plan

    download_dir, cleanup_download_dir = _prepare_download_dir(model_uri, scan_cache_dir)

    try:
        logger.debug(f"Downloading MLflow model {model_uri} to {download_dir}")
        if isinstance(download_plan, _MlflowDownloadPlan):
            local_path = download_plan.artifact_repository.download_artifacts(
                artifact_path=download_plan.artifact_path or "",
                dst_path=download_dir,
            )
        else:
            local_path = mlflow.artifacts.download_artifacts(artifact_uri=model_uri, dst_path=download_dir)  # type: ignore[possibly-unbound-attribute]
        # mlflow may return a file within the download directory; ensure directory path
        download_path = os.path.dirname(local_path) if os.path.isfile(local_path) else local_path
        cache_config = {"cache_enabled": cache_enabled, "cache_dir": scan_cache_dir}

        # Import here to avoid circular dependency
        from ..core import scan_model_directory_or_file

        return scan_model_directory_or_file(
            download_path,
            timeout=timeout,
            blacklist_patterns=blacklist_patterns,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            **cache_config,
            **scan_kwargs,
        )
    finally:
        if cleanup_download_dir:
            shutil.rmtree(download_dir, ignore_errors=True)
