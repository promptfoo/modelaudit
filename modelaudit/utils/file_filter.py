"""File filtering utilities for ModelAudit."""

import os
from typing import Optional

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


def should_skip_file(
    path: str,
    skip_extensions: Optional[set[str]] = None,
    skip_filenames: Optional[set[str]] = None,
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
    if skip_extensions is None:
        skip_extensions = DEFAULT_SKIP_EXTENSIONS
    if skip_filenames is None:
        skip_filenames = DEFAULT_SKIP_FILENAMES

    filename = os.path.basename(path)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

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

    # Skip based on extension
    if ext in skip_extensions:
        return True

    # Skip hidden files (starting with .) except for specific model extensions
    if (
        skip_hidden
        and filename.startswith(".")
        and ext not in {".pkl", ".pt", ".pth", ".h5", ".ckpt", ".npz", ".dvc", ".safetensors"}
    ):
        return True

    # Skip specific filenames
    return filename in skip_filenames
