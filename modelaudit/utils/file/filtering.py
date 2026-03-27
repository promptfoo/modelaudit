"""File filtering utilities for ModelAudit."""

import os
import zipfile
from pathlib import Path

# Default extensions to skip when scanning directories
DEFAULT_SKIP_EXTENSIONS = {
    # Documentation and text files
    ".md",
    ".txt",
    ".rst",
    ".doc",
    ".docx",
    ".pdf",
    # Source code files
    ".py",
    ".js",
    ".ts",
    ".java",
    ".cpp",
    ".c",
    ".h",
    ".go",
    ".rs",
    # Web files
    ".html",
    ".css",
    ".scss",
    ".sass",
    ".less",
    # Configuration files (but keep .json, .yaml, .yml as they can be model configs)
    ".ini",
    ".cfg",
    ".conf",
    ".toml",
    # Build and package files
    ".lock",
    ".log",
    ".pid",
    # Version control
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    # IDE files
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dylib",
    ".dll",
    # Archives (but keep .zip as it can contain models)
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    # Media files
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wmv",
    ".flv",
    # Temporary files
    ".tmp",
    ".temp",
    ".swp",
    ".bak",
    "~",
}

# Default filenames to skip
DEFAULT_SKIP_FILENAMES = {
    "README",
    "CHANGELOG",
    "AUTHORS",
    "CONTRIBUTORS",
    "Makefile",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "package.json",
    "package-lock.json",
    "yarn.lock",
}

DEFAULT_SCANNABLE_SKIP_OVERRIDES = {
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
}

_ARCHIVE_SIGNAL_EXTENSION_EXCLUSIONS = frozenset(
    {
        ".json",
        ".xml",
        ".txt",
        ".md",
        ".markdown",
        ".rst",
        ".yaml",
        ".yml",
        ".cfg",
        ".conf",
        ".ini",
        ".toml",
        ".py",
        ".js",
        ".ts",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".html",
    }
)


def _get_scannable_extensions() -> set[str]:
    """Lazy-load scannable extensions to avoid circular imports."""
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _get_candidate_extensions(filename: str) -> list[str]:
    """Return suffix candidates from most specific to least specific."""
    suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
    candidates: list[str] = []
    for i in range(len(suffixes), 0, -1):
        candidate = "".join(suffixes[-i:])
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _has_scannable_content(path: str) -> bool:
    """Return whether on-disk file contents map to a supported format."""
    if not os.path.isfile(path):
        return False

    try:
        from .detection import detect_file_format

        detected_format = detect_file_format(path)
        if detected_format == "unknown":
            return False

        if detected_format != "zip":
            return True

        with zipfile.ZipFile(path, "r") as archive:
            member_names = {
                member.filename.replace("\\", "/").strip("/")
                for member in archive.infolist()
                if member.filename and not member.is_dir()
            }

            # Preserve Keras, TorchServe, and PyTorch ZIP containers even when
            # the outer filename uses a skipped suffix.
            if "MAR-INF/MANIFEST.json" in member_names:
                return True
            if "config.json" in member_names and any(
                marker in member_names for marker in {"metadata.json", "model.weights.h5", "variables.h5"}
            ):
                return True
            if any(name == "data.pkl" or name.endswith("/data.pkl") for name in member_names):
                return True

            scannable_extensions = _get_scannable_extensions() - _ARCHIVE_SIGNAL_EXTENSION_EXCLUSIONS
            for member_name in member_names:
                candidate_extensions = _get_candidate_extensions(member_name)
                if any(candidate in scannable_extensions for candidate in candidate_extensions):
                    return True

        return False
    except OSError:
        return False
    except zipfile.BadZipFile:
        return False


def should_skip_file(
    path: str,
    skip_extensions: set[str] | None = None,
    skip_filenames: set[str] | None = None,
    skip_hidden: bool = True,
    metadata_scanner_available: bool = True,
) -> bool:
    """
    Check if a file should be skipped based on its extension or name.

    Args:
        path: File path to check
        skip_extensions: Set of extensions to skip (defaults to DEFAULT_SKIP_EXTENSIONS)
        skip_filenames: Set of filenames to skip (defaults to DEFAULT_SKIP_FILENAMES)
        skip_hidden: Whether to skip hidden files (starting with .)
        metadata_scanner_available: Whether metadata scanner is available to handle metadata files

    Returns:
        True if the file should be skipped
    """
    use_default_skip_extensions = skip_extensions is None
    if skip_extensions is None:
        skip_extensions = DEFAULT_SKIP_EXTENSIONS
    if skip_filenames is None:
        skip_filenames = DEFAULT_SKIP_FILENAMES

    filename = os.path.basename(path)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    candidate_extensions = _get_candidate_extensions(filename)
    scannable_extensions = _get_scannable_extensions()

    # Special handling for metadata files that scanners can handle
    metadata_extensions = {".md", ".yml", ".yaml"}
    metadata_filenames = {"readme", "model_card", "model-index"}

    # Special handling for specific .txt files that are README-like
    is_readme_txt = ext == ".txt" and (filename.lower() in metadata_filenames or filename.lower().startswith("readme."))

    # If metadata scanner is available, don't skip metadata files
    if metadata_scanner_available and (
        ext in metadata_extensions or filename.lower() in metadata_filenames or is_readme_txt
    ):
        return False

    # Preserve scanner coverage for archive/metadata formats that are otherwise
    # part of the default skip list.
    if use_default_skip_extensions and any(
        candidate in DEFAULT_SCANNABLE_SKIP_OVERRIDES and candidate in scannable_extensions
        for candidate in candidate_extensions
    ):
        return False

    if ext in skip_extensions and _has_scannable_content(path):
        return False

    # Skip based on extension
    if ext in skip_extensions:
        return True

    # Preserve hidden DVC pointers so directory scans can expand them before
    # applying normal scanner selection to their targets.
    if (
        skip_hidden
        and filename.startswith(".")
        and ext != ".dvc"
        and not any(candidate in scannable_extensions for candidate in candidate_extensions)
    ):
        return True

    # Skip specific filenames
    return filename in skip_filenames
