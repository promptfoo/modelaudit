"""Integration helpers for scanning JFrog Artifactory artifacts and folders."""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from ..models import ModelAuditResultModel
from ..utils.sources.jfrog import detect_jfrog_target_type, download_artifact, download_jfrog_folder

logger = logging.getLogger(__name__)


def _prepare_download_dir(url: str, cache_dir: str | None) -> tuple[Path, bool]:
    """Return an ephemeral per-run staging directory under the configured cache root."""
    if not cache_dir:
        return Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_")), True

    cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    download_root = Path(cache_dir).expanduser() / "jfrog"
    download_root.mkdir(parents=True, exist_ok=True)
    # Use a unique staging directory for this run. ``cache_dir`` controls where
    # temporary downloads live, while scan-result caching is still handled by core.
    return Path(tempfile.mkdtemp(prefix=f"{cache_key}-", dir=str(download_root))), True


def scan_jfrog_artifact(
    url: str,
    *,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 3600,
    blacklist_patterns: list[str] | None = None,
    max_file_size: int = 0,
    max_total_size: int = 0,
    selective_download: bool = True,
    **kwargs: Any,
) -> ModelAuditResultModel:
    """Download and scan an artifact or folder from JFrog Artifactory.

    This function now supports both individual files and entire folders/repositories.
    For folders, it will recursively discover and download all scannable model files.

    Parameters
    ----------
    url:
        JFrog Artifactory URL to download (file or folder).
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
    selective_download:
        Whether folder downloads should prefilter to scannable model files.
    **kwargs:
        Additional arguments passed to :func:`scan_model_directory_or_file`.

    Returns
    -------
    ModelAuditResultModel
        Scan results as returned by :func:`scan_model_directory_or_file`.

    Examples
    --------
    Scan a single file:
        >>> scan_jfrog_artifact(
        ...     "https://company.jfrog.io/artifactory/models/model.pkl",
        ...     api_token="your-token"
        ... )

    Scan an entire folder:
        >>> scan_jfrog_artifact(
        ...     "https://company.jfrog.io/artifactory/models/pytorch-models/",
        ...     api_token="your-token"
        ... )
    """

    scan_kwargs = kwargs.copy()
    cache_enabled = scan_kwargs.pop("cache_enabled", True)
    raw_cache_dir = scan_kwargs.pop("cache_dir", None)
    scan_cache_dir = str(Path(raw_cache_dir).expanduser()) if cache_enabled and raw_cache_dir else None
    download_dir, cleanup_download_dir = _prepare_download_dir(url, scan_cache_dir)
    start_time = time.time()

    try:
        # Detect if URL points to a file or folder
        logger.debug(f"Analyzing JFrog target {url}")
        target_info = detect_jfrog_target_type(
            url,
            api_token=api_token,
            access_token=access_token,
            timeout=min(timeout, 30),  # Use shorter timeout for detection
        )

        if target_info["type"] == "file":
            logger.debug(f"Downloading JFrog file {url} to {download_dir}")
            download_path = download_artifact(
                url,
                cache_dir=download_dir,
                api_token=api_token,
                access_token=access_token,
                timeout=timeout,
            )
        else:
            logger.debug(f"Downloading JFrog folder {url} to {download_dir}")
            download_path = download_jfrog_folder(
                url,
                cache_dir=download_dir,
                api_token=api_token,
                access_token=access_token,
                timeout=timeout,
                selective=selective_download,
                show_progress=True,
            )

        # Calculate remaining timeout for scanning phase
        elapsed_time = time.time() - start_time
        remaining_timeout = max(timeout - elapsed_time, 30)  # Ensure at least 30 seconds for scanning
        logger.debug(f"Spent {elapsed_time:.1f}s on download, {remaining_timeout:.1f}s remaining for scan")

        cache_config = {"cache_enabled": cache_enabled, "cache_dir": scan_cache_dir}

        # Import here to avoid circular dependency
        from ..core import scan_model_directory_or_file

        # Scan the downloaded file or directory with remaining timeout
        result = scan_model_directory_or_file(
            str(download_path),
            blacklist_patterns=blacklist_patterns,
            timeout=int(remaining_timeout),
            max_file_size=max_file_size,
            max_total_size=max_total_size,
            **cache_config,
            **scan_kwargs,
        )

        # Add metadata about the JFrog source
        # Ensure metadata field exists as dict
        if not hasattr(result, "metadata") or result.metadata is None:
            result.metadata = {}  # type: ignore[attr-defined]

        # Add JFrog source information
        result.metadata["jfrog_source"] = {  # type: ignore[attr-defined]
            "url": url,
            "type": target_info["type"],
            "repo": target_info.get("repo", ""),
        }

        return result
    finally:
        if cleanup_download_dir:
            shutil.rmtree(download_dir, ignore_errors=True)
