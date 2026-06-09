"""Scanner configuration for standalone pickle analysis."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Real

DEFAULT_TIMEOUT_S = 3600.0
MAX_TIMEOUT_S = 86_400.0
DEFAULT_MAX_OPCODES = 1_000_000
DEFAULT_POST_BUDGET_SCAN_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_KNOWN_STREAM_READ_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_UNBOUNDED_STREAM_READ_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS = 8 * 1024 * 1024
DEFAULT_MAX_NESTED_PICKLE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_NESTED_DEPTH = 2


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Resource and metadata controls for a pickle scan."""

    timeout_s: float = DEFAULT_TIMEOUT_S
    max_opcodes: int = DEFAULT_MAX_OPCODES
    post_budget_scan_bytes: int = DEFAULT_POST_BUDGET_SCAN_BYTES
    max_known_stream_read_bytes: int = DEFAULT_MAX_KNOWN_STREAM_READ_BYTES
    max_unbounded_stream_read_bytes: int = DEFAULT_MAX_UNBOUNDED_STREAM_READ_BYTES
    max_string_literal_scan_chars: int = DEFAULT_MAX_STRING_LITERAL_SCAN_CHARS
    max_nested_pickle_bytes: int = DEFAULT_MAX_NESTED_PICKLE_BYTES
    max_nested_depth: int = DEFAULT_MAX_NESTED_DEPTH

    def __post_init__(self) -> None:
        timeout_s: object = self.timeout_s
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, Real) or not isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError(f"timeout_s must be greater than 0 and finite, got {timeout_s!r}")
        object.__setattr__(self, "timeout_s", min(float(timeout_s), MAX_TIMEOUT_S))

        max_opcodes: object = self.max_opcodes
        if isinstance(max_opcodes, bool) or not isinstance(max_opcodes, int) or max_opcodes <= 0:
            raise ValueError(f"max_opcodes must be greater than 0 and an integer, got {max_opcodes!r}")

        post_budget_scan_bytes: object = self.post_budget_scan_bytes
        if (
            isinstance(post_budget_scan_bytes, bool)
            or not isinstance(post_budget_scan_bytes, int)
            or post_budget_scan_bytes < 0
        ):
            raise ValueError(
                "post_budget_scan_bytes must be greater than or equal to 0 and an integer, "
                f"got {post_budget_scan_bytes!r}",
            )

        max_known_stream_read_bytes: object = self.max_known_stream_read_bytes
        if (
            isinstance(max_known_stream_read_bytes, bool)
            or not isinstance(max_known_stream_read_bytes, int)
            or max_known_stream_read_bytes <= 0
        ):
            raise ValueError(
                "max_known_stream_read_bytes must be greater than 0 and an integer, "
                f"got {max_known_stream_read_bytes!r}",
            )

        max_unbounded_stream_read_bytes: object = self.max_unbounded_stream_read_bytes
        if (
            isinstance(max_unbounded_stream_read_bytes, bool)
            or not isinstance(max_unbounded_stream_read_bytes, int)
            or max_unbounded_stream_read_bytes <= 0
        ):
            raise ValueError(
                "max_unbounded_stream_read_bytes must be greater than 0 and an integer, "
                f"got {max_unbounded_stream_read_bytes!r}",
            )

        max_string_literal_scan_chars: object = self.max_string_literal_scan_chars
        if (
            isinstance(max_string_literal_scan_chars, bool)
            or not isinstance(max_string_literal_scan_chars, int)
            or max_string_literal_scan_chars < 0
        ):
            raise ValueError(
                "max_string_literal_scan_chars must be greater than or equal to 0 and an integer, "
                f"got {max_string_literal_scan_chars!r}",
            )

        max_nested_pickle_bytes: object = self.max_nested_pickle_bytes
        if (
            isinstance(max_nested_pickle_bytes, bool)
            or not isinstance(max_nested_pickle_bytes, int)
            or max_nested_pickle_bytes < 2
        ):
            raise ValueError(
                f"max_nested_pickle_bytes must be at least 2 and an integer, got {max_nested_pickle_bytes!r}",
            )

        max_nested_depth: object = self.max_nested_depth
        if isinstance(max_nested_depth, bool) or not isinstance(max_nested_depth, int) or max_nested_depth < 0:
            raise ValueError(
                f"max_nested_depth must be greater than or equal to 0 and an integer, got {max_nested_depth!r}",
            )
