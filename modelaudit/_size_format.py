"""Preserve established byte-count formatting conventions."""


def _format_size_absolute(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    absolute_size = abs(size_bytes)
    for index, unit in enumerate(units):
        divisor = 1024**index
        if absolute_size < divisor * 1024:
            return f"{size_bytes / divisor:.1f} {unit}"
    return f"{size_bytes} B"


def _format_size_scaled(size_bytes: int) -> str:
    """Format a byte count for user-facing download budget errors."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"
