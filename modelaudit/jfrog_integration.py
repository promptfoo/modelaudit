"""Integration helpers for scanning JFrog Artifactory artifacts."""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any, Union

from .core import scan_model_directory_or_file
from .models import ModelAuditResultModel
from .utils.jfrog import download_artifact

logger = logging.getLogger(__name__)


def scan_jfrog_artifact(
    url: str,
    *,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 3600,
    blacklist_patterns: list[str] | None = None,
    max_file_size: int = 0,
    max_total_size: int = 0,
    return_download_path: bool = False,
    **kwargs: Any,
) -> Union[ModelAuditResultModel, tuple[ModelAuditResultModel, str]]:  # noqa: UP007
    """Download and scan an artifact from JFrog Artifactory.

    Parameters
    ----------
    url:
        JFrog Artifactory URL to download.
    api_token:
        API token used for authentication via ``X-JFrog-Art-Api`` header.
    access_token:
        Access token used for authentication via ``Authorization`` header.
    timeout:
        Maximum time in seconds to spend scanning.
    blacklist_patterns:
        Optional list of blacklist patterns to check against model names.
    max_file_size:
        Maximum file size to scan in bytes (0 = unlimited).
    max_total_size:
        Maximum total bytes to scan before stopping (0 = unlimited).
    return_download_path:
        If True, return a tuple of (scan_results, download_path).
    **kwargs:
        Additional arguments passed to :func:`scan_model_directory_or_file`.

    Returns
    -------
    ModelAuditResultModel or tuple[ModelAuditResultModel, str]
        Scan results, or tuple of (scan_results, download_path) if return_download_path=True.
    """

    tmp_dir = tempfile.mkdtemp(prefix="modelaudit_jfrog_")
    try:
        logger.debug(f"Downloading JFrog artifact {url} to {tmp_dir}")
        download_path = download_artifact(
            url,
            cache_dir=Path(tmp_dir),
            api_token=api_token,
            access_token=access_token,
            timeout=timeout,
        )

        # Ensure cache configuration is passed through from kwargs
        # Remove cache config from kwargs to avoid conflicts
        scan_kwargs = kwargs.copy()
        cache_config = {
            "cache_enabled": scan_kwargs.pop("cache_enabled", True),
            "cache_dir": scan_kwargs.pop("cache_dir", None),
        }

        results = scan_model_directory_or_file(
            str(download_path),
            blacklist_patterns=blacklist_patterns,
            timeout=timeout,
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            **cache_config,
            **scan_kwargs,
        )

        if return_download_path:
            # Defer cleanup - caller must handle temp directory cleanup
            return results, str(download_path)
        return results
    finally:
        if not return_download_path:
            shutil.rmtree(tmp_dir, ignore_errors=True)
