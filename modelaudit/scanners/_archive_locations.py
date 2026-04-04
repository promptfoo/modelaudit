"""Shared helpers for rewriting nested scan locations to archive provenance."""

from __future__ import annotations

import os


def rewrite_extracted_member_location(
    location: str | None,
    extracted_path: str,
    archive_location: str,
    *,
    preserve_non_delimited_suffix: bool,
) -> str:
    """Replace a temporary extraction path with the originating archive member location."""
    if not location:
        return archive_location

    if location == extracted_path:
        return archive_location

    if location.startswith(extracted_path):
        suffix = location[len(extracted_path) :]
        suffix_prefix = suffix[:1]
        if suffix_prefix in {":", ".", " ", os.sep, os.altsep}:
            if preserve_non_delimited_suffix or suffix.startswith(":"):
                return f"{archive_location}{suffix}"
            return archive_location

    return f"{archive_location} {location}"
