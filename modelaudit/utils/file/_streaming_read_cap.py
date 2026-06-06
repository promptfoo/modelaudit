from __future__ import annotations

from typing import Any, cast

STREAMING_ANALYSIS_DEFAULT_MAX_BYTES = 512 * 1024 * 1024


def resolve_streaming_max_bytes(max_bytes: Any = None) -> int:
    """Resolve the maximum streamed bytes to materialize for scanner-backed analysis."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        return STREAMING_ANALYSIS_DEFAULT_MAX_BYTES
    return int(max_bytes)


def _streaming_max_bytes_from_scanner_config(scanner: object) -> Any:
    config = getattr(scanner, "config", None)
    if not isinstance(config, dict):
        return None
    configured_stream_max = config.get("streaming_max_bytes")
    if configured_stream_max is not None:
        return configured_stream_max
    return config.get("max_file_size")


def apply_streaming_read_cap(streaming_module: object) -> None:
    streaming = cast(Any, streaming_module)
    if getattr(streaming, "_modelaudit_streaming_read_cap_applied", False):
        return

    original_stream_analyze_file = streaming.stream_analyze_file

    def capped_stream_analyze_file(
        url: str,
        scanner: object,
        max_bytes: int | None = None,
    ) -> tuple[object | None, bool]:
        configured_max_bytes: Any = max_bytes
        if configured_max_bytes is None:
            configured_max_bytes = _streaming_max_bytes_from_scanner_config(scanner)
        resolved_max_bytes = resolve_streaming_max_bytes(configured_max_bytes)
        result, analysis_complete = original_stream_analyze_file(url, scanner, max_bytes=resolved_max_bytes)
        if result is not None:
            result.metadata.setdefault("max_bytes", resolved_max_bytes)
        return result, analysis_complete

    streaming.STREAMING_ANALYSIS_DEFAULT_MAX_BYTES = STREAMING_ANALYSIS_DEFAULT_MAX_BYTES
    streaming.resolve_streaming_max_bytes = resolve_streaming_max_bytes
    streaming.stream_analyze_file = capped_stream_analyze_file
    streaming._modelaudit_streaming_read_cap_applied = True
