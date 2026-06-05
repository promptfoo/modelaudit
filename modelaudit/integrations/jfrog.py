"""Integration helpers for scanning JFrog Artifactory artifacts and folders."""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
import time
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from ..models import ModelAuditResultModel
from ..scanner_selection import SCANNER_SELECTION_CONFIG_KEY
from ..utils.sources.jfrog import (
    detect_jfrog_target_type,
    download_artifact,
    download_jfrog_folder,
    format_size,
    redact_jfrog_url_for_display,
)

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


def _positive_limit(*limits: int | None) -> int | None:
    positive_limits = [limit for limit in limits if limit is not None and limit > 0]
    return min(positive_limits) if positive_limits else None


def _known_file_size(target_info: Mapping[str, Any]) -> int | None:
    if target_info.get("size_known") is False:
        return None
    size = target_info.get("size")
    if isinstance(size, bool):
        return None
    if isinstance(size, int) and size >= 0:
        return size
    return None


def _require_known_file_size_within_limit(
    target_info: Mapping[str, Any],
    *,
    limit: int | None,
    display_url: str,
) -> None:
    if limit is None:
        return

    size = _known_file_size(target_info)
    if size is None:
        raise ValueError(
            f"Cannot verify JFrog artifact size for {display_url}; refusing to download with maximum allowed size "
            f"{format_size(limit)}"
        )
    if size > limit:
        raise ValueError(
            f"JFrog artifact size ({format_size(size)}) exceeds maximum allowed size ({format_size(limit)}) "
            f"for {display_url}"
        )


def scan_jfrog_artifact(
    url: str,
    *,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 3600,
    blacklist_patterns: list[str] | None = None,
    max_file_size: int = 0,
    max_total_size: int = 0,
    max_download_size: int | None = None,
    selective_download: bool = True,
    scannable_extensions: Collection[str] | None = None,
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
    max_download_size:
        Maximum bytes to download before scan-time checks run (None or 0 = unlimited).
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
    display_url = redact_jfrog_url_for_display(url)

    try:
        # Detect if URL points to a file or folder
        logger.debug(f"Analyzing JFrog target {display_url}")
        target_info = detect_jfrog_target_type(
            url,
            api_token=api_token,
            access_token=access_token,
            timeout=min(timeout, 30),  # Use shorter timeout for detection
        )

        if target_info["type"] == "file":
            file_download_limit = _positive_limit(max_download_size, max_file_size, max_total_size)
            _require_known_file_size_within_limit(target_info, limit=file_download_limit, display_url=display_url)
            logger.debug(f"Downloading JFrog file {display_url} to {download_dir}")
            download_path = download_artifact(
                url,
                cache_dir=download_dir,
                api_token=api_token,
                access_token=access_token,
                timeout=timeout,
                max_size=file_download_limit,
            )
        else:
            logger.debug(f"Downloading JFrog folder {display_url} to {download_dir}")
            folder_download_kwargs: dict[str, Any] = {}
            if scannable_extensions is not None:
                folder_download_kwargs["scannable_extensions"] = scannable_extensions
            scanner_selection = scan_kwargs.get(SCANNER_SELECTION_CONFIG_KEY)
            if isinstance(scanner_selection, dict):
                folder_download_kwargs["scanner_selection"] = scanner_selection
            download_path = download_jfrog_folder(
                url,
                cache_dir=download_dir,
                api_token=api_token,
                access_token=access_token,
                timeout=timeout,
                selective=selective_download,
                show_progress=True,
                max_size=max_download_size,
                max_file_size=max_file_size,
                max_total_size=max_total_size,
                **folder_download_kwargs,
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
            "url": display_url,
            "type": target_info["type"],
            "repo": target_info.get("repo", ""),
        }

        return result
    finally:
        if cleanup_download_dir:
            shutil.rmtree(download_dir, ignore_errors=True)
