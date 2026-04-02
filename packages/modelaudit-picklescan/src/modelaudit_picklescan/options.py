"""Scanner configuration for standalone pickle analysis."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Real

DEFAULT_TIMEOUT_S = 3600.0
DEFAULT_MAX_OPCODES = 1_000_000
DEFAULT_POST_BUDGET_SCAN_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Resource and metadata controls for a pickle scan."""

    timeout_s: float = DEFAULT_TIMEOUT_S
    max_opcodes: int = DEFAULT_MAX_OPCODES
    post_budget_scan_bytes: int = DEFAULT_POST_BUDGET_SCAN_BYTES

    def __post_init__(self) -> None:
        timeout_s: object = self.timeout_s
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, Real) or not isfinite(timeout_s) or timeout_s <= 0:
            raise ValueError(f"timeout_s must be greater than 0 and finite, got {timeout_s!r}")

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
