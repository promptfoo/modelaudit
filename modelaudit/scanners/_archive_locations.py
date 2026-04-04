"""Shared helpers for rewriting nested scan locations to archive provenance."""

from __future__ import annotations


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

    if location.startswith(extracted_path):
        suffix = location[len(extracted_path) :]
        if preserve_non_delimited_suffix or suffix.startswith(":"):
            return f"{archive_location}{suffix}"
        return archive_location

    return f"{archive_location} {location}"
