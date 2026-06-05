import hashlib
import logging
import ntpath
import os
import posixpath
import re
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any

from ..detectors.network_comm import _redact_urls_in_text
from ..models import Check, CheckStatus, Issue, IssueSeverity, ModelAuditResultModel, create_initial_audit_result
from ..utils.sources.cloud_storage import redact_cloud_error_for_display

logger = logging.getLogger(__name__)

_MLFLOW_DOWNLOAD_BUDGET_CHECK = "MLflow Download Size Check"
_DEFAULT_MLFLOW_MAX_ARTIFACT_ENTRIES = 10000
_MAX_MLFLOW_ERROR_DISPLAY_CHARS = 512
_MLFLOW_AUTH_VALUE_RE = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization)\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?[^\s,;]+"
)
_MLFLOW_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:access[_-]?key|access[_-]?token|api[_-]?key|credential|password|secret|token)"
    r"\s*[:=]\s*)[^\s,;]+"
)


@dataclass(frozen=True)
class _MlflowArtifact:
    path: str
    size: int


@dataclass(frozen=True)
class _MlflowDownloadPlan:
    artifact_repository: Any
    artifacts: tuple[_MlflowArtifact, ...]
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


def _redact_mlflow_error_for_display(error: object) -> str:
    redacted = redact_cloud_error_for_display(_redact_urls_in_text(str(error)))
    redacted = _MLFLOW_AUTH_VALUE_RE.sub(r"\1<redacted>", redacted)
    redacted = _MLFLOW_SENSITIVE_ASSIGNMENT_RE.sub(r"\1<redacted>", redacted)
    if len(redacted) <= _MAX_MLFLOW_ERROR_DISPLAY_CHARS:
        return redacted
    return f"{redacted[: _MAX_MLFLOW_ERROR_DISPLAY_CHARS - 3]}..."


def _bounded_artifact_listing(
    list_artifacts: Any,
    artifact_path: str | None,
    remaining_entries: int,
) -> tuple[list[Any], bool]:
    """Bound local listing consumption after the repository returns each response.

    Standard MLflow repositories return a materialized sequence, so their own
    pagination and response allocation cannot be interrupted through this API.
    Iterable repository plugins are consumed lazily here.
    """
    artifact_infos = list_artifacts(artifact_path)
    if artifact_infos is None:
        raise ValueError(f"Artifact listing returned no size information for {artifact_path or '<root>'}")

    if isinstance(artifact_infos, Sequence):
        return list(artifact_infos[: remaining_entries + 1]), len(artifact_infos) > remaining_entries

    bounded_infos = list(islice(iter(artifact_infos), remaining_entries + 1))
    return bounded_infos, len(bounded_infos) > remaining_entries


def _artifact_path_matches(artifact_path: str | None, requested_path: str) -> bool:
    if artifact_path == requested_path:
        return True
    return artifact_path == posixpath.basename(requested_path)


def _normalize_mlflow_artifact_path(artifact_path: object) -> str:
    if not isinstance(artifact_path, str) or not artifact_path or "\x00" in artifact_path:
        raise ValueError("Artifact entry did not include a valid path")
    if "\\" in artifact_path or posixpath.isabs(artifact_path) or ntpath.isabs(artifact_path):
        raise ValueError(f"Artifact entry path is not relative: {artifact_path}")
    normalized = posixpath.normpath(artifact_path)
    if normalized in {"", ".", ".."} or normalized.startswith("../") or ntpath.splitdrive(normalized)[0]:
        raise ValueError(f"Artifact entry path escapes the repository root: {artifact_path}")
    return normalized


def _artifact_path_is_within(path: str, parent: str | None) -> bool:
    if parent is None:
        return True
    return path == parent or path.startswith(f"{parent}/")


def _find_single_file_artifact_info(
    list_artifacts: Any,
    requested_path: str,
    remaining_entries: int,
) -> tuple[Any | None, int, bool]:
    parent_path = posixpath.dirname(requested_path) or None
    artifact_infos, listing_exceeded = _bounded_artifact_listing(list_artifacts, parent_path, remaining_entries)
    for artifact_info in artifact_infos:
        artifact_path = getattr(artifact_info, "path", None)
        if not getattr(artifact_info, "is_dir", False) and _artifact_path_matches(artifact_path, requested_path):
            return artifact_info, len(artifact_infos), listing_exceeded
    return None, len(artifact_infos), listing_exceeded


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
        details["error"] = _redact_mlflow_error_for_display(e)
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to determine MLflow artifact size before download",
            details,
        )

    total_size = 0
    file_count = 0
    entry_count = 0
    normalized_initial_path: str | None = None
    pending_dirs: list[str | None] = []
    visited_dirs: set[str | None] = set()
    planned_artifacts: dict[str, _MlflowArtifact] = {}
    try:
        normalized_initial_path = (
            _normalize_mlflow_artifact_path(initial_artifact_path) if initial_artifact_path is not None else None
        )
        pending_dirs.append(normalized_initial_path)
        while pending_dirs:
            current_path = pending_dirs.pop()
            if current_path in visited_dirs:
                continue
            visited_dirs.add(current_path)
            artifact_infos, listing_exceeded = _bounded_artifact_listing(
                list_artifacts,
                current_path,
                max_artifact_entries - entry_count,
            )
            if listing_exceeded:
                details.update(
                    {
                        "reason": "artifact_listing_budget_exceeded",
                        "artifact_entry_count": max_artifact_entries + 1,
                    }
                )
                return _mlflow_budget_failure_result(
                    model_uri,
                    f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                    details,
                )

            artifact_infos_already_counted = False
            if not artifact_infos and current_path == normalized_initial_path and current_path:
                artifact_info, parent_entry_count, parent_listing_exceeded = _find_single_file_artifact_info(
                    list_artifacts,
                    current_path,
                    max_artifact_entries - entry_count,
                )
                if parent_listing_exceeded:
                    details.update(
                        {
                            "reason": "artifact_listing_budget_exceeded",
                            "artifact_entry_count": max_artifact_entries + 1,
                        }
                    )
                    return _mlflow_budget_failure_result(
                        model_uri,
                        f"MLflow artifact listing exceeded {max_artifact_entries} entries before download",
                        details,
                    )
                entry_count += parent_entry_count
                artifact_infos = [artifact_info] if artifact_info is not None else []
                artifact_infos_already_counted = artifact_info is not None

            for artifact_info in artifact_infos:
                if not artifact_infos_already_counted:
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

                raw_artifact_path = getattr(artifact_info, "path", None)
                artifact_path = (
                    current_path
                    if artifact_infos_already_counted and current_path is not None
                    else _normalize_mlflow_artifact_path(raw_artifact_path)
                )
                if not _artifact_path_is_within(artifact_path, current_path):
                    raise ValueError(f"Artifact entry path escaped listed directory: {artifact_path}")
                if getattr(artifact_info, "is_dir", False):
                    pending_dirs.append(artifact_path)
                    continue

                file_size = getattr(artifact_info, "file_size", None)
                if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
                    raise ValueError(f"Artifact file size unavailable for {artifact_path or '<unknown>'}")
                if artifact_path in planned_artifacts:
                    raise ValueError(f"Artifact listing returned a duplicate file path: {artifact_path}")

                file_count += 1
                total_size += file_size
                planned_artifacts[artifact_path] = _MlflowArtifact(path=artifact_path, size=file_size)
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
        details["error"] = _redact_mlflow_error_for_display(e)
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
        artifacts=tuple(planned_artifacts.values()),
        root_uri=root_uri,
    )


def _download_preflighted_mlflow_artifacts(
    plan: _MlflowDownloadPlan,
    model_uri: str,
    download_dir: str,
    *,
    max_file_size: int,
    max_total_size: int,
) -> str | ModelAuditResultModel:
    download_file = getattr(plan.artifact_repository, "_download_file", None)
    details: dict[str, Any] = {
        "model_uri": model_uri,
        "root_uri": plan.root_uri,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "artifact_file_count": len(plan.artifacts),
    }
    if not callable(download_file):
        details["reason"] = "artifact_download_unavailable"
        return _mlflow_budget_failure_result(
            model_uri,
            "Unable to download preflighted MLflow artifacts safely",
            details,
        )

    download_root = Path(download_dir).resolve()
    actual_total_size = 0
    for artifact in plan.artifacts:
        local_path = download_root.joinpath(*PurePosixPath(artifact.path).parts)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if not local_path.parent.resolve().is_relative_to(download_root):
            details.update({"reason": "artifact_path_escape", "artifact_path": artifact.path})
            return _mlflow_budget_failure_result(
                model_uri,
                "MLflow artifact path escaped the download directory",
                details,
            )

        download_file(artifact.path, str(local_path))
        try:
            if local_path.is_symlink() or not local_path.is_file():
                raise ValueError("downloaded path is not a regular file")
            if not local_path.resolve().is_relative_to(download_root):
                raise ValueError("downloaded path escaped the download directory")
            actual_size = local_path.stat().st_size
        except OSError as exc:
            details.update(
                {
                    "reason": "artifact_download_verification_failed",
                    "artifact_path": artifact.path,
                    "error": _redact_mlflow_error_for_display(exc),
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to verify downloaded MLflow artifact",
                details,
            )
        except ValueError as exc:
            details.update(
                {
                    "reason": "artifact_download_verification_failed",
                    "artifact_path": artifact.path,
                    "error": str(exc),
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "Unable to verify downloaded MLflow artifact",
                details,
            )

        actual_total_size += actual_size
        if actual_size != artifact.size:
            details.update(
                {
                    "reason": "artifact_download_size_changed",
                    "artifact_path": artifact.path,
                    "expected_artifact_size": artifact.size,
                    "downloaded_artifact_size": actual_size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                "MLflow artifact size changed after preflight",
                details,
            )
        if max_file_size > 0 and actual_size > max_file_size:
            details.update(
                {
                    "reason": "artifact_file_size_exceeded",
                    "artifact_path": artifact.path,
                    "artifact_file_size": actual_size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"Downloaded MLflow artifact exceeds the file size budget: {actual_size} bytes (max: {max_file_size})",
                details,
            )
        if max_total_size > 0 and actual_total_size > max_total_size:
            details.update(
                {
                    "reason": "artifact_total_size_exceeded",
                    "artifact_total_size": actual_total_size,
                }
            )
            return _mlflow_budget_failure_result(
                model_uri,
                f"Downloaded MLflow artifacts exceed the total size budget: {actual_total_size} bytes "
                f"(max: {max_total_size})",
                details,
            )

    return str(download_root)


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
        Maximum artifact file size to download and scan in bytes (0 = unlimited).
    max_total_size:
        Maximum total artifact bytes to download and scan (0 = unlimited).
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
            download_result = _download_preflighted_mlflow_artifacts(
                download_plan,
                model_uri,
                download_dir,
                max_file_size=max_file_size,
                max_total_size=max_total_size,
            )
            if isinstance(download_result, ModelAuditResultModel):
                return download_result
            local_path = download_result
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
