"""Shared coercion for scanner pickle memo operands."""

from typing import Any


def _coerce_memo_key(value: Any) -> int | None:
    """Coerce a memo opcode argument to an integer key."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
