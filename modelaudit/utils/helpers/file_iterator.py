"""File iterator utility for streaming mode across all sources."""

import logging
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)


def iterate_files_streaming(path: Path | str, pattern: str = "**/*") -> Iterator[tuple[Path, bool]]:
    """
    Generate (file_path, is_last) tuples from a directory or single file.

    This generator iterates through files in a directory (or yields a single file)
    and yields tuples of (file_path, is_last) where is_last indicates if this
    is the final file in the iteration.

    Args:
        path: Path to file or directory
        pattern: Glob pattern for matching files (default: "**/*")

    Yields:
        Tuples of (file_path, is_last)
    """
    path = Path(path)

    # If it's a single file, yield it directly
    if path.is_file():
        yield (path, True)
        return

    # If it's a directory, iterate through all files
    if not path.is_dir():
        logger.warning(f"Path {path} is neither a file nor directory")
        return

    files = (matched_path for matched_path in path.glob(pattern) if matched_path.is_file())

    try:
        current_file = next(files)
    except StopIteration:
        logger.warning(f"No files found in {path} matching pattern {pattern}")
        return

    # Hold a single item of lookahead so we can preserve the is_last flag
    # without materializing the entire directory listing.
    for next_file in files:
        yield (current_file, False)
        current_file = next_file

    yield (current_file, True)
