"""Bounded rendering of model-controlled evidence without credential masking."""

import unicodedata
from collections.abc import Collection
from typing import Any


def format_evidence_string(text: str, max_chars: int | None = 180) -> str:
    """Remove unsafe controls and retain the caller's evidence preview limit."""
    limit = max(0, max_chars) if max_chars is not None else None
    # Match the former preview's bounded normalization window for control-heavy input.
    source = text if limit is None else text[: limit + 4097]
    safe_text = "".join(
        char for char in source if char in "\r\n\t" or unicodedata.category(char) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
    )
    if limit is None or len(text) <= limit:
        return safe_text
    return safe_text[:limit] if limit <= 3 else safe_text[: limit - 3] + "..."


def format_terminal_text(text: str) -> str:
    """Keep untrusted diagnostics on one line without changing saved evidence."""
    return format_evidence_string(text, max_chars=None).translate(
        {ord("\r"): r"\r", ord("\n"): r"\n", ord("\t"): r"\t"}
    )


def format_evidence_mapping_key(
    key: object,
    existing_keys: Collection[object],
    max_string_chars: int = 180,
    *,
    next_occurrences: dict[str, int] | None = None,
) -> str:
    """Format a key while preserving entries whose previews or types collide."""
    formatted = format_evidence_string(key, max_string_chars) if isinstance(key, str) else f"<{type(key).__name__}-key>"
    if formatted not in existing_keys:
        if next_occurrences is not None:
            next_occurrences.setdefault(formatted, 2)
        return formatted
    occurrence = next_occurrences.get(formatted, 2) if next_occurrences is not None else 2
    while f"{formatted}[{occurrence}]" in existing_keys:
        occurrence += 1
    if next_occurrences is not None:
        next_occurrences[formatted] = occurrence + 1
    return f"{formatted}[{occurrence}]"


def format_evidence_value(value: Any, max_string_chars: int = 180, *, _depth: int = 0) -> Any:
    """Format nested evidence, preserving scalar types and bounded recursion."""
    if _depth >= 100:
        return "<redacted>"
    if isinstance(value, str):
        return format_evidence_string(value, max_string_chars)
    if isinstance(value, (bytes, bytearray)):
        return format_evidence_string(repr(value[: max(0, max_string_chars) + 4097]), max_string_chars)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        occurrences: dict[str, int] = {}
        for key, child in value.items():
            formatted_key = format_evidence_mapping_key(key, result, max_string_chars, next_occurrences=occurrences)
            result[formatted_key] = format_evidence_value(child, max_string_chars, _depth=_depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        children = sorted(value, key=repr) if isinstance(value, set) else value
        result_items = [format_evidence_value(child, max_string_chars, _depth=_depth + 1) for child in children]
        return tuple(result_items) if isinstance(value, tuple) else result_items
    return value
