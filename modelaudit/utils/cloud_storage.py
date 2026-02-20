"""Backward-compatible cloud storage helpers.

This module is retained for compatibility with older import paths.
The canonical implementation lives in :mod:`modelaudit.utils.sources.cloud_storage`.
"""

from modelaudit.utils.sources.cloud_storage import (
    GCSCache,
    analyze_cloud_target,
    download_from_cloud,
    estimate_download_time,
    filter_scannable_files,
    format_size,
    get_cloud_object_size,
    get_fs_protocol,
    is_cloud_url,
    prompt_for_large_download,
)

__all__ = [
    "GCSCache",
    "analyze_cloud_target",
    "download_from_cloud",
    "estimate_download_time",
    "filter_scannable_files",
    "format_size",
    "get_cloud_object_size",
    "get_fs_protocol",
    "is_cloud_url",
    "prompt_for_large_download",
]
