"""File handling utilities.

This package contains utilities for file operations:
- detection.py - File type detection and format identification
- filtering.py - File filtering and pattern matching
- handlers.py - Advanced file handling strategies
- large_file_handler.py - Large file optimization
- streaming.py - Streaming file processing
"""

from modelaudit.utils.file import detection, filtering, handlers, large_file_handler, streaming

__all__ = [
    "detection",
    "filtering",
    "handlers",
    "large_file_handler",
    "streaming",
]
