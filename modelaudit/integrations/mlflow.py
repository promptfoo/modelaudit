import hashlib
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..models import ModelAuditResultModel

logger = logging.getLogger(__name__)


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
    scan_cache_dir = str(Path(raw_cache_dir).expanduser()) if cache_enabled and raw_cache_dir else None
    download_dir, cleanup_download_dir = _prepare_download_dir(model_uri, scan_cache_dir)

    try:
        logger.debug(f"Downloading MLflow model {model_uri} to {download_dir}")
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
