from typing import Any

import pytest

from modelaudit.utils.helpers.evidence import (
    format_evidence_mapping_key,
    format_evidence_string,
    format_evidence_value,
)


@pytest.mark.parametrize(
    ("text", "limit", "expected"),
    [
        ("abcdef", -1, ""),
        ("abcdef", 0, ""),
        ("abcdef", 1, "a"),
        ("abcdef", 3, "abc"),
        ("abcdef", 4, "a..."),
        ("abcdef", 6, "abcdef"),
        ("x" * 100_000, 160, "x" * 157 + "..."),
        ("api_key=SECRET", None, "api_key=SECRET"),
        ("a\x00\x1b\x7f\u202e\ud800\u2028\u2029b\r\n\t", None, "ab\r\n\t"),
        ("\x00" * 5000 + "hidden tail", 4, "..."),
    ],
)
def test_evidence_preview(text: str, limit: int | None, expected: str) -> None:
    assert format_evidence_string(text, limit) == expected


def test_evidence_values_preserve_types_and_secret_contents() -> None:
    value = {"password": "raw secret", "tuple": (b"\xff", bytearray(b"ab")), "set": {"b", "a"}, "scalar": 3}
    assert format_evidence_value(value) == {
        "password": "raw secret",
        "tuple": ("b'\\xff'", "bytearray(b'ab')"),
        "set": ["a", "b"],
        "scalar": 3,
    }
    assert format_evidence_value(["secret", "password"], 4) == ["s...", "p..."]
    assert format_evidence_value(b"x" * 100_000, 10) == "b'xxxxx..."


def test_evidence_mapping_key_collisions_preserve_all_values() -> None:
    value = {"<int-key>": 1, 1: 2, 2: 3, "abc1": 4, "abc2": 5}
    assert format_evidence_value(value, 3) == {
        "<in": 1,
        "<int-key>": 2,
        "<int-key>[2]": 3,
        "abc": 4,
        "abc[2]": 5,
    }
    keys = {"key", "key[2]"}
    occurrences: dict[str, int] = {}
    assert format_evidence_mapping_key("key", keys, next_occurrences=occurrences) == "key[3]"
    keys.add("key[3]")
    assert format_evidence_mapping_key("key", keys, next_occurrences=occurrences) == "key[4]"


@pytest.mark.parametrize("cyclic", [False, True])
def test_evidence_traversal_stops_at_existing_depth_limit(cyclic: bool) -> None:
    value: list[Any] = []
    if cyclic:
        value.append(value)
    else:
        for _ in range(101):
            value = [value]
    formatted = format_evidence_value(value)
    for _ in range(100):
        assert isinstance(formatted, list) and len(formatted) == 1
        formatted = formatted[0]
    assert formatted == "<redacted>"
