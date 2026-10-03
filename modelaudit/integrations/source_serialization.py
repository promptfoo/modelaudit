"""Bounded conversion of report values without changing their evidence."""

from typing import Any

from pydantic import AnyUrl, BaseModel

_MAX_DEPTH = 32
_MAX_STRING_CHARS = 256 * 1024


def serialize_source_identifier(value: str) -> str:
    return value if len(value) <= _MAX_STRING_CHARS else "<source redacted>"


def serialize_source_text(value: str) -> str:
    return value if len(value) <= _MAX_STRING_CHARS else "<redacted oversized value>"


def serialize_source_value(value: Any) -> Any:
    """Preserve report shapes and JSON-compatible keys, bounding recursive values."""
    return _serialize(value, set(), 0)


def _serialize(value: Any, seen: set[int], depth: int) -> Any:
    if depth > _MAX_DEPTH:
        return "<redacted>"
    if isinstance(value, BaseModel):
        return _serialize(value.model_dump(mode="python"), seen, depth + 1)
    if isinstance(value, AnyUrl):
        value = str(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return "<binary data>"
    if isinstance(value, str):
        return serialize_source_text(value)
    if not isinstance(value, (dict, list, tuple, set, frozenset)):
        return value
    if id(value) in seen:
        return "<redacted recursive value>"
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            result: dict[Any, Any] = {}
            occurrences: dict[str, int] = {}
            for key, item in value.items():
                key = _serialize(key, set(), 0)
                if not isinstance(key, (str, int, float, bool)) and key is not None:
                    key = serialize_source_text(str(key))
                if key in result:
                    base_key = str(key)
                    occurrence = occurrences.get(base_key, 2)
                    candidate = f"{base_key}#modelaudit-redacted-key-{occurrence}"
                    while candidate in result:
                        occurrence += 1
                        candidate = f"{base_key}#modelaudit-redacted-key-{occurrence}"
                    occurrences[base_key] = occurrence + 1
                    key = candidate
                result[key] = _serialize(item, seen, depth + 1)
            return result
        items = [_serialize(item, seen, depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(items)
        return sorted(items, key=repr) if isinstance(value, (set, frozenset)) else items
    finally:
        seen.remove(id(value))
