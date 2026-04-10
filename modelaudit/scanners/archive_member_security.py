"""Shared security helpers for archive member names."""

import re

_EXECUTABLE_ARCHIVE_MEMBER_SUFFIXES = (
    ".sh",
    ".bash",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".scr",
    ".com",
    ".bat",
    ".ps1",
)
_VERSIONED_SHARED_OBJECT_SUFFIX_RE = re.compile(r"\.so(?:\.[0-9]+)+$")


def is_executable_archive_member_name(member_name: str) -> bool:
    """Return True when an archive member name has an executable/native-library suffix."""
    normalized_name = member_name.lower()
    return normalized_name.endswith(_EXECUTABLE_ARCHIVE_MEMBER_SUFFIXES) or bool(
        _VERSIONED_SHARED_OBJECT_SUFFIX_RE.search(normalized_name)
    )
