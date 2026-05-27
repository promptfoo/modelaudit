"""Shared bounded printable-string extraction helpers."""

from __future__ import annotations

import re


def extract_bounded_printable_strings(
    payload: bytes,
    pattern: re.Pattern[bytes],
    max_strings: int,
) -> tuple[list[str], bool]:
    """Extract candidates and report whether qualifying strings remain uninspected."""
    strings: list[str] = []
    for match in pattern.finditer(payload):
        text = match.group(0).decode("utf-8", errors="ignore").strip()
        if not text:
            continue

        if len(strings) >= max_strings:
            return strings, True
        strings.append(text)

    return strings, False
