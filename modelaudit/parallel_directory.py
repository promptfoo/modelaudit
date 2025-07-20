"""
Simple wrapper to add parallel directory scanning to ModelAudit.
"""

import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from modelaudit.core import _is_huggingface_cache_file
from modelaudit.parallel_scanner import ParallelScanner
from modelaudit.utils import is_within_directory

logger = logging.getLogger("modelaudit.parallel_directory")


def _should_skip_file(file_path: str) -> bool:
    """Check if a file should be skipped based on common non-model file patterns."""
    # Get file extension
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    # Skip common non-model file extensions
    skip_extensions = {
        # Documentation
        ".md",
        ".rst",
        ".doc",
        ".docx",
        ".pdf",
        # Code
        ".py",
        ".js",
        ".java",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".sh",
        ".bash",
        ".bat",
        ".ps1",
        # Web
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".sass",
        ".less",
        # Data files (but not model formats)
        ".csv",
        ".tsv",
        ".xlsx",
        ".xls",
        # Media
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
        ".wav",
        # Archives (we'll scan specific model archives)
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        # System
        ".lock",
        ".log",
        ".cache",
        ".tmp",
        ".temp",
        ".git",
        ".gitignore",
        ".gitattributes",
        ".DS_Store",
        ".env",
        ".venv",
        # Build artifacts
        ".o",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".class",
        # IDE
        ".idea",
        ".vscode",
        ".project",
        ".classpath",
    }

    if ext in skip_extensions:
        return True

    # Skip specific filenames
    skip_filenames = {
        "LICENSE",
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
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
    }

    basename = os.path.basename(file_path)
    if basename in skip_filenames:
        return True

    # Skip hidden files and directories
    return basename.startswith(".")


def scan_directory_parallel(
    path: str,
    config: dict[str, Any],
    progress_callback: Optional[Callable[[str, float], None]] = None,
    max_workers: Optional[int] = None,
) -> dict[str, Any]:
    """
    Scan a directory using parallel processing.

    Args:
        path: Directory path to scan
        config: Scanner configuration
        progress_callback: Progress callback function
        max_workers: Number of worker processes

    Returns:
        Scan results dictionary
    """
    base_dir = Path(path).resolve()
    files_to_scan = []

    # Collect all files to scan
    for root, _, files in os.walk(path, followlinks=False):
        for file in files:
            file_path = os.path.join(root, file)

            # Skip non-model files
            if _should_skip_file(file_path):
                continue

            # Skip HuggingFace cache files
            if _is_huggingface_cache_file(file_path):
                continue

            # Check file is within base directory
            resolved_file = Path(file_path).resolve()
            if not is_within_directory(str(base_dir), str(resolved_file)):
                continue

            files_to_scan.append(str(resolved_file))

    if not files_to_scan:
        # Return empty results
        return {
            "bytes_scanned": 0,
            "issues": [],
            "files_scanned": 0,
            "scanners": [],
            "assets": [],
            "file_metadata": {},
            "has_errors": False,
            "success": True,
        }

    # Use parallel scanner
    scanner = ParallelScanner(
        max_workers=max_workers,
        timeout_per_file=config.get("timeout", 300),
        progress_callback=progress_callback,
    )

    # Run parallel scan
    results = scanner.scan_files(files_to_scan, config)

    # Add parallel scan markers
    results["parallel_scan"] = True
    results["worker_count"] = scanner.max_workers

    logger.debug(f"Parallel scan returning results with keys: {list(results.keys())}")
    logger.debug(f"parallel_scan={results.get('parallel_scan')}, worker_count={results.get('worker_count')}")

    return results
