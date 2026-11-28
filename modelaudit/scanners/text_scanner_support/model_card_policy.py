"""Read model-card policy text and recognize prohibited-use language."""

import re
from collections.abc import Callable

from .documentation_examples import MAX_DOCUMENTATION_BYTES

_EMPHASIS_DELIMITER = re.compile(rb"(?<!\w)[*_]{1,3}(?=\w)|(?<=\w)[*_]{1,3}(?!\w)")
_FIELD = re.compile(rb'(?m)^extra_gated_prompt:[ \t]+(?:"|[>|][-+]?[ \t]*\r?$)')
_NEXT_KEY = re.compile(rb"(?m)^\S")
_OPENING = re.compile(rb"\A---[ \t]*\r?\n")
_DELIMITER = re.compile(rb"(?m)^---[ \t]*\r?$")
_PROHIBITED = re.compile(rb"(?im)^[ \t]*#{1,6} +(?:Prohibited|Disallowed) Uses?[ \t]*\r?$")
_SECTION_END = re.compile(rb"(?m)^[ \t]*(?:#{1,6}[ \t]+|`{3,}|~{3,})")
_PROHIBITION = re.compile(rb"\b(?:(?:will|may|must|do)\s+not|never)\s+use\b", re.I)
_ACTION = rb"(?:generate|create|distribute|facilitate|produce|deploy|install)"
_MALWARE_ITEM = re.compile(
    rb"^[ \t]*(?:\d{1,3}[.)]|[-*+])[ \t]+(?P<negation>(?:do not|never)\s+)?"
    + _ACTION
    + rb"\b(?:[, \t]+(?:"
    + _ACTION
    + rb"|and|or|the|creation|of|malicious|code)){0,16}"
    rb"[, \t]+(?P<term>malware)\b",
    re.I | re.M,
)


def displayed_license(payload: bytes) -> tuple[int, bytes]:
    """Unfold the two common HF display scalar styles while preserving raw byte offsets."""
    opening = _OPENING.match(payload)
    if not opening or not (close := _DELIMITER.search(payload, opening.end())):
        return 0, b""
    field = _FIELD.search(payload, opening.end(), close.start())
    if not field:
        return 0, b""
    start = field.end()
    following_key = _NEXT_KEY.search(payload, payload.find(b"\n", start) + 1, close.start())
    body = payload[start : following_key.start() if following_key else close.start()].rstrip()
    if not field[0].endswith(b'"'):
        return start, body
    # Reject unsupported quoting/escapes rather than interpret arbitrary YAML.
    if not body.endswith(b'"') or re.search(rb'(?<!\\)"|\\(?!["n ]|\r?\n)', body[:-1]):
        return 0, b""
    body = re.sub(
        rb'\\\r?\n[ \t]*|\\[" n]',
        lambda match: {b"\\n": b" \n", b'\\"': b' "'}.get(match[0], b" " * len(match[0])),
        body[:-1],
    )
    return start, body


def disclosure_has_harmful_claim(payload: bytes, harmful_claim: re.Pattern[bytes]) -> bool:
    """Check the source and displayed license, including claims split by Markdown emphasis."""
    _, license_body = displayed_license(payload)
    return any(
        harmful_claim.search(source) or harmful_claim.search(_EMPHASIS_DELIMITER.sub(b"", source))
        for source in (payload, license_body)
    )


def model_card_prohibited_terms(
    payload: bytes, harmful_claim: re.Pattern[bytes], actionability: Callable[[bytes, int], bool | None]
) -> frozenset[int]:
    if len(payload) > MAX_DOCUMENTATION_BYTES:
        return frozenset()
    start, body = displayed_license(payload)
    positions: set[int] = set()
    for heading in _PROHIBITED.finditer(body):
        boundary = _SECTION_END.search(body, heading.end())
        end = boundary.start() if boundary else len(body)
        lead = _PROHIBITION.search(body, heading.end(), end)
        positions.update(
            start + item.start("term")
            for item in _MALWARE_ITEM.finditer(body, heading.end(), end)
            if (item["negation"] or (lead and lead.end() <= item.start()))
            and actionability(body, item.start("term")) is False
        )
    if positions and (harmful_claim.search(payload) or harmful_claim.search(body)):
        positions.clear()
    return frozenset(positions)
