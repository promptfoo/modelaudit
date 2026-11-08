"""Locate passive references in a model card's displayed license and attribution."""

import re
from collections.abc import Callable
from urllib.parse import parse_qsl, urlsplit

from .documentation_examples import MAX_DOCUMENTATION_BYTES, _plain_url

_FIELD = re.compile(rb'(?m)^extra_gated_prompt:[ \t]+(?:"|[>|][-+]?[ \t]*\r?$)')
_NEXT_KEY = re.compile(rb"(?m)^\S")
_OPENING = re.compile(rb"\A---[ \t]*\r?\n")
_DELIMITER = re.compile(rb"(?m)^---[ \t]*\r?$")
_EMAIL = rb"[A-Za-z0-9._+-]+@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,63})"
_CREDIT_VERB = rb"(?:converted|quantized|validated|maintained|published|prepared)"
_CREDIT = re.compile(
    rb"^(?:"
    + _CREDIT_VERB
    + rb" and )?"
    + _CREDIT_VERB
    + rb" by \*\*[^*\r\n]{1,100}\*\* (?:\xe2\x80\x94|-) "
    + _EMAIL
    + rb"[ \t]*\r?$",
    re.I | re.M,
)
_TOOL_CREDIT = re.compile(
    rb"^(?:[\w-]+ )?(?:quantization|conversion):[ \t]+(?:done |performed )?by [\w .-]{1,128} with "
    rb"(?P<tool>[\w.-]+)(?: by (?P<author>[\w-]+))? \((?P<url>https://github\.com/"
    rb"(?P<owner>[\w-]+)/(?P<repo>[\w.-]+)/?)\)",
    re.I | re.M,
)
_REPORT_LABEL = (
    rb"^[ \t]*[-*][ \t]+(?:report(?:ing)?[ \t]+(?:violations?|risky[ \t]+content|bugs?|issues?|security[ \t]+issues)"
    rb"|(?:support|license|security) contact)(?:[ \t]+[\w.-]+){0,24}:[ \t]*(?:\r?\n[ \t]+)?"
)
_REPORT_CONTACT = re.compile(
    _REPORT_LABEL + rb"(?:" + _EMAIL + rb"|(?P<site>[A-Za-z0-9.-]+\.[A-Za-z]{2,63}/[\w/-]+))[ \t]*\r?$",
    re.I | re.M,
)
_REFERENCE = rb"(?:polic(?:y|ies)|guidelines|terms)\s+(?:(?:can be found|(?:is |are )?available)\s+)?at\s+"
_PLAIN_REFERENCE = re.compile(
    rb"\b(?:polic(?:y|ies)|guidelines|terms)\s*\((?:currently\s+)?(?:accessible|available)\s+at\s+"
    rb"(?P<url>https://[A-Za-z0-9./_-]{1,2048})\s*\)",
    re.I,
)
_LINK = re.compile(
    rb"(?:\b" + _REFERENCE + rb"|" + _REPORT_LABEL + rb")"
    rb"\[(?P<label>[^\[\]\r\n]{1,2048})\]\((?P<target>https://[^()\s]{1,2048})\)",
    re.I | re.M,
)
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


def _displayed_license(payload: bytes) -> tuple[int, bytes]:
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


def _same_displayed_destination(label: bytes, target: bytes) -> bool:
    try:
        if b"https://" + label == target or re.fullmatch(rb"(?:[a-z]+ ){0,5}(?:policy|guidelines|terms)", label, re.I):
            return _plain_url(target.decode("ascii"))
        visible = label.decode("ascii")
        if not _plain_url(visible):
            return False
        if label == target:
            return True
        wrapper = urlsplit(target.decode("ascii"))
        if (wrapper.scheme, wrapper.netloc, wrapper.path, wrapper.fragment) != (
            "https",
            "l.workplace.com",
            "/l.php",
            "",
        ):
            return False
        # The wrapper must point to the issue tracker shown to the reader.
        if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/issues", visible):
            return False
        params = dict(parse_qsl(wrapper.query, strict_parsing=True, keep_blank_values=True, max_num_fields=2))
        return params.get("u") == visible and re.fullmatch(r"[\w-]+", params.get("h", "")) is not None
    except (ValueError, UnicodeDecodeError):
        return False


def model_card_policy_evidence(
    payload: bytes, harmful_claim: re.Pattern[bytes], actionability: Callable[[bytes, int], bool | None]
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], frozenset[int]]:
    if len(payload) > MAX_DOCUMENTATION_BYTES:
        return [], [], frozenset()
    spans: list[tuple[int, int]] = []
    active_spans: list[tuple[int, int]] = []

    def record(source: bytes, offset: int, position: int, left: int, right: int) -> None:
        active = actionability(source, position)
        if active is not None:
            destination = active_spans if active else spans
            destination.append((offset + left, offset + right))

    for credit in _CREDIT.finditer(payload):
        if credit.start() == 0 or payload.endswith((b"\n\n", b"\r\n\r\n"), 0, credit.start()):
            record(payload, 0, credit.start(), *credit.span("domain"))
    for credit in _TOOL_CREDIT.finditer(payload):
        if (
            (credit.start() == 0 or payload.endswith((b"\n\n", b"\r\n\r\n"), 0, credit.start()))
            and credit["tool"].lower() == credit["repo"].lower()
            and (not credit["author"] or credit["author"].lower() == credit["owner"].lower())
            and _plain_url(credit["url"].decode("ascii"))
        ):
            record(payload, 0, credit.start(), *credit.span("url"))
    start, body = _displayed_license(payload)
    for match in _REPORT_CONTACT.finditer(body):
        if match["site"] and not _plain_url("https://" + match["site"].decode("ascii")):
            continue
        left, right = match.span("site" if match["site"] else "domain")
        record(body, start, match.start(), left, right)
    for match in _PLAIN_REFERENCE.finditer(body):
        if _plain_url(match["url"].decode("ascii")):
            record(body, start, match.start(), *match.span("url"))
    for match in _LINK.finditer(body):
        if _same_displayed_destination(match["label"], match["target"]):
            record(body, start, match.start(), match.start("label"), match.end("target"))
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
    return spans, sorted(active_spans), frozenset(positions)
