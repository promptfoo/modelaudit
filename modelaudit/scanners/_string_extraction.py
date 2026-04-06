"""Shared bounded printable-string extraction helpers."""

from __future__ import annotations

import re


def extract_bounded_printable_strings(
    payload: bytes,
    pattern: re.Pattern[bytes],
    max_strings: int,
) -> list[str]:
    """Extract decoded printable string candidates up to the configured cap."""
    strings: list[str] = []
    for match in pattern.finditer(payload):
        text = match.group(0).decode("utf-8", errors="ignore").strip()
        if not text:
            continue

        strings.append(text)
        if len(strings) >= max_strings:
            break

    return strings
