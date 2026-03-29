"""File filtering utilities for ModelAudit."""

import logging
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

_ARCHIVE_SIGNAL_EXTENSION_EXCLUSIONS: frozenset[str] = frozenset(
    {
        ".bin",
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

_ZIP_MEMBER_SNIFF_LIMIT: int = 256
_OFFICE_ARCHIVE_PREFIXES: tuple[str, ...] = ("word/", "xl/", "ppt/")
_OFFICE_ARCHIVE_MARKER_FILES: frozenset[str] = frozenset(
    {
        "word/document.xml",
        "xl/workbook.xml",
        "ppt/presentation.xml",
    }
)
_MODEL_ARCHIVE_SIGNAL_BASENAMES: frozenset[str] = frozenset(
    {
        "pytorch_model.bin",
        "adapter_model.bin",
        "diffusion_pytorch_model.bin",
        "flax_model.msgpack",
    }
)


def _get_scannable_extensions() -> set[str]:
    """Lazy-load scannable extensions to avoid circular imports."""
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _get_model_archive_signal_extensions() -> frozenset[str]:
    """Return model-bearing archive member suffixes that should promote skipped ZIP containers."""
    return frozenset(
        extension for extension in _get_scannable_extensions() if extension not in _ARCHIVE_SIGNAL_EXTENSION_EXCLUSIONS
    )


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
            model_archive_signal_extensions = _get_model_archive_signal_extensions()
            has_keras_config = False
            has_keras_marker = False
            has_pytorch_data = False
            has_pytorch_marker = False
            processed_members = 0
            archive_names = archive.NameToInfo
            saw_content_types = "[Content_Types].xml" in archive_names
            saw_office_prefix = any(marker in archive_names for marker in _OFFICE_ARCHIVE_MARKER_FILES)
            for member in archive.filelist:
                if processed_members >= _ZIP_MEMBER_SNIFF_LIMIT:
                    # If we cannot finish classifying the archive within the
                    # prefilter budget, preserve it for full scanning unless it
                    # already looks like a standard Office document container.
                    return not (saw_content_types and saw_office_prefix)

                if not member.filename or member.is_dir():
                    continue

                processed_members += 1
                member_name = member.filename.replace("\\", "/").strip("/")
                member_basename = Path(member_name).name.lower()

                if member_name == "[Content_Types].xml":
                    saw_content_types = True
                    continue

                if member_name.startswith(_OFFICE_ARCHIVE_PREFIXES):
                    saw_office_prefix = True

                # Preserve Keras, TorchServe, and PyTorch ZIP containers even
                # when the outer filename uses a skipped suffix.
                if member_name == "MAR-INF/MANIFEST.json":
                    return True

                if member_name == "config.json":
                    has_keras_config = True
                    continue

                if member_name in {"metadata.json", "model.weights.h5", "variables.h5"}:
                    has_keras_marker = True
                    continue

                if member_name == "data.pkl" or member_name.endswith("/data.pkl"):
                    has_pytorch_data = True
                    continue

                if (
                    member_name == "version"
                    or member_name.endswith("/version")
                    or member_name == "byteorder"
                    or member_name.endswith("/byteorder")
                    or member_name.startswith("data/")
                    or "/data/" in member_name
                ):
                    has_pytorch_marker = True

                candidate_extensions = _get_candidate_extensions(member_name)
                if any(candidate in model_archive_signal_extensions for candidate in candidate_extensions):
                    return True

                if member_basename in _MODEL_ARCHIVE_SIGNAL_BASENAMES:
                    return True

            if has_keras_config and has_keras_marker:
                return True

            if has_pytorch_data and has_pytorch_marker:
                return True

        return False
    except Exception as exc:
        logger.debug("Content sniffing failed for %s; preserving file for full scan: %s", path, exc)
        return True


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

    if use_default_skip_extensions and ext in skip_extensions and _has_scannable_content(path):
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


logger = logging.getLogger(__name__)
