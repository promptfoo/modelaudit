# Utils package for ModelAudit
import os
from pathlib import Path

from .dvc_utils import resolve_dvc_file
from .file_filter import DEFAULT_SKIP_EXTENSIONS, DEFAULT_SKIP_FILENAMES, should_skip_file


def is_within_directory(base_dir: str, target: str) -> bool:
    """Return True if the target path is within the given base directory."""
    base_path = Path(base_dir).resolve()
    target_path = Path(target).resolve()
    try:
        return target_path.is_relative_to(base_path)
    except AttributeError:  # Python < 3.9
        try:
            return os.path.commonpath([target_path, base_path]) == str(base_path)
        except ValueError:
            return False


def sanitize_archive_path(entry_name: str, base_dir: str) -> tuple[str, bool]:
    """Return normalized path for archive entry and whether it stays within base.

    Parameters
    ----------
    entry_name: str
        Name of the entry in the archive.
    base_dir: str
        Intended extraction directory used for normalization.

    Returns
    -------
    tuple[str, bool]
        (resolved_path, is_safe) where ``is_safe`` is ``False`` if the entry
        would escape ``base_dir`` when extracted.
    """
    base_path = Path(base_dir).resolve()
    # Normalize separators
    entry = entry_name.replace("\\", "/")
    if entry.startswith("/") or (len(entry) > 1 and entry[1] == ":"):
        # Absolute paths are not allowed
        return str((base_path / entry.lstrip("/")).resolve()), False
    entry = entry.lstrip("/")
    resolved = (base_path / entry).resolve()
    try:
        is_safe = resolved.is_relative_to(base_path)
    except AttributeError:  # Python < 3.9
        try:
            is_safe = os.path.commonpath([resolved, base_path]) == str(base_path)
        except ValueError:  # Windows: different drives
            is_safe = False
    return str(resolved), is_safe
