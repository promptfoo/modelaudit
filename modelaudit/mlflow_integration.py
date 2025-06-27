import logging
import os
import shutil
import tempfile
from typing import Any, Optional

from .core import scan_model_directory_or_file

logger = logging.getLogger(__name__)


def scan_mlflow_model(
    model_uri: str,
    *,
    registry_uri: Optional[str] = None,
    timeout: int = 300,
    blacklist_patterns: Optional[list[str]] = None,
    max_file_size: int = 0,
    max_total_size: int = 0,
    **kwargs: Any,
) -> dict[str, Any]:
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
    dict
        Scan results dictionary as returned by
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
        mlflow.set_registry_uri(registry_uri)

    tmp_dir = tempfile.mkdtemp(prefix="modelaudit_mlflow_")
    try:
        logger.debug("Downloading MLflow model %s to %s", model_uri, tmp_dir)
        local_path = mlflow.artifacts.download_artifacts(artifact_uri=model_uri, dst_path=tmp_dir)
        # mlflow may return a file within tmp_dir; ensure directory path
        download_path = os.path.dirname(local_path) if os.path.isfile(local_path) else local_path
        return scan_model_directory_or_file(
            download_path,
            timeout=timeout,
            blacklist_patterns=blacklist_patterns,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            **kwargs,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
