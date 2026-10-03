"""Bounded conversion of report values without changing their evidence."""

import hashlib
from collections.abc import Callable
from typing import Any

from pydantic import AnyUrl, BaseModel

_MAX_DEPTH = 32
_MAX_STRING_CHARS = 256 * 1024


def serialize_source_identifier(value: str) -> str:
    if len(value) <= _MAX_STRING_CHARS:
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
    preview = value[:256].encode("utf-8", errors="backslashreplace").decode("utf-8")
    return f"modelaudit-source:{preview}...<source sha256:{digest}>"


def serialize_source_text(value: str) -> str:
    return value if len(value) <= _MAX_STRING_CHARS else "<redacted oversized value>"


def serialize_source_value(value: Any, *, identifier_key: Callable[[str], str] | None = None) -> Any:
    """Preserve report shapes and JSON-compatible keys, bounding recursive values."""
    return serialize_source_values([value], identifier_key=identifier_key)[0]


def serialize_source_values(values: list[Any], *, identifier_key: Callable[[str], str] | None = None) -> list[Any]:
    """Share identifier allocation while retaining each value's depth budget."""
    identifiers: dict[str, str] = {}
    reserved: set[str] = set()

    def reserve(text: str) -> str:
        if len(text) <= _MAX_STRING_CHARS:
            reserved.add(text)
            return text
        if text not in identifiers:
            identifiers[text] = serialize_source_identifier(text)
        return text

    # Materialize each model/key once; strings remain references until IDs are allocated.
    converted = [_serialize(value, set(), 0, reserve) for value in values]
    reserved_identifiers = (
        {identifier_key(text) for text in reserved} if identifiers and identifier_key is not None else set()
    )
    for text in sorted(identifiers, key=identifiers.__getitem__):
        base = candidate = identifiers[text]
        occurrence = 1
        while candidate in reserved or (
            identifier_key is not None and identifier_key(candidate) in reserved_identifiers
        ):
            occurrence += 1
            candidate = f"{base}#{occurrence}"
        reserved.add(candidate)
        if identifier_key is not None:
            reserved_identifiers.add(identifier_key(candidate))
        identifiers[text] = candidate
    return [_serialize(value, set(), 0, lambda text: identifiers.get(text, text)) for value in converted]


def _serialize(value: Any, seen: set[int], depth: int, transform: Callable[[str], str]) -> Any:
    if depth > _MAX_DEPTH:
        return "<redacted>"
    if isinstance(value, BaseModel):
        return _serialize(value.model_dump(mode="python"), seen, depth + 1, transform)
    if isinstance(value, AnyUrl):
        value = str(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return "<binary data>"
    if isinstance(value, str):
        return transform(value)
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
                key = _serialize(key, set(), 0, transform)
                if not isinstance(key, (str, int, float, bool)) and key is not None:
                    key = transform(str(key))
                if key in result:
                    base_key = str(key)
                    occurrence = occurrences.get(base_key, 2)
                    candidate = f"{base_key}#modelaudit-redacted-key-{occurrence}"
                    while candidate in result:
                        occurrence += 1
                        candidate = f"{base_key}#modelaudit-redacted-key-{occurrence}"
                    occurrences[base_key] = occurrence + 1
                    key = candidate
                result[key] = _serialize(item, seen, depth + 1, transform)
            return result
        items = [_serialize(item, seen, depth + 1, transform) for item in value]
        if isinstance(value, tuple):
            return tuple(items)
        return sorted(items, key=repr) if isinstance(value, (set, frozenset)) else items
    finally:
        seen.remove(id(value))
