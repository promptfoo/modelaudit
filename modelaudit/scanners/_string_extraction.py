"""Shared bounded printable-string extraction helpers."""

from __future__ import annotations

import re


def extract_bounded_printable_strings(
    payload: bytes,
    pattern: re.Pattern[bytes],
    max_strings: int,
    *,
    overlap_chars: int = 0,
) -> tuple[list[str], bool]:
    """Extract candidates and report whether qualifying strings remain uninspected."""
    strings: list[str] = []
    previous_end: int | None = None
    previous_tail = b""
    for match in pattern.finditer(payload):
        raw_text = match.group(0)
        if overlap_chars > 0 and previous_end == match.start():
            raw_text = previous_tail + raw_text
        text = raw_text.decode("utf-8", errors="ignore").strip()
        previous_end = match.end()
        previous_tail = match.group(0)[-overlap_chars:] if overlap_chars > 0 else b""
        if not text:
            continue

        if len(strings) >= max_strings:
            return strings, True
        strings.append(text)

    return strings, False
