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


def _validate_integer(value: object, name: str, minimum: int) -> None:
    # Preserve the established comparison operators for integer subclasses.
    if isinstance(value, bool) or not isinstance(value, int) or (value <= 0 if minimum == 1 else value < minimum):
        requirement = {0: "greater than or equal to 0", 1: "greater than 0", 2: "at least 2"}[minimum]
        raise ValueError(f"{name} must be {requirement} and an integer, got {value!r}")


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
        _validate_integer(max_opcodes, "max_opcodes", 1)

        post_budget_scan_bytes: object = self.post_budget_scan_bytes
        _validate_integer(post_budget_scan_bytes, "post_budget_scan_bytes", 0)

        max_known_stream_read_bytes: object = self.max_known_stream_read_bytes
        _validate_integer(max_known_stream_read_bytes, "max_known_stream_read_bytes", 1)

        max_unbounded_stream_read_bytes: object = self.max_unbounded_stream_read_bytes
        _validate_integer(max_unbounded_stream_read_bytes, "max_unbounded_stream_read_bytes", 1)

        max_string_literal_scan_chars: object = self.max_string_literal_scan_chars
        _validate_integer(max_string_literal_scan_chars, "max_string_literal_scan_chars", 0)

        max_nested_pickle_bytes: object = self.max_nested_pickle_bytes
        _validate_integer(max_nested_pickle_bytes, "max_nested_pickle_bytes", 2)

        max_nested_depth: object = self.max_nested_depth
        _validate_integer(max_nested_depth, "max_nested_depth", 0)
