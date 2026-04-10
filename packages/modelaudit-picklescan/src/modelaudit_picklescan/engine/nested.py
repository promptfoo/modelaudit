"""Nested pickle literal detection helpers."""

from __future__ import annotations

import base64
import binascii
import pickletools
import re
from io import BytesIO, StringIO

_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_HEX_CANDIDATE_RE = re.compile(r"(?:\\x)?[0-9a-fA-F]+")
_PICKLE_PREFIX_BYTES = frozenset({b"(", b"c", b"d", b"l", b"i", b"I", b"S", b"V"})


def _decode_possible_encoded_pickle(value: str, *, max_nested_pickle_bytes: int) -> list[tuple[str, bytes]]:
    stripped = value.strip()
    if len(stripped) < 16:
        return []

    decoded_values: list[tuple[str, bytes]] = []
    max_base64_nested_pickle_chars = ((max_nested_pickle_bytes + 2) // 3) * 4
    max_hex_nested_pickle_chars = max_nested_pickle_bytes * 2

    if _BASE64_CANDIDATE_RE.fullmatch(stripped):
        bounded = stripped[:max_base64_nested_pickle_chars]
        padded = bounded + ("=" * (-len(bounded) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if _looks_like_pickle_payload(decoded, max_bytes=max_nested_pickle_bytes):
            decoded_values.append(("base64", decoded))

    hex_candidate = stripped[:max_hex_nested_pickle_chars].replace("\\x", "")
    if (
        len(hex_candidate) >= 16
        and len(hex_candidate) % 2 == 0
        and _HEX_CANDIDATE_RE.fullmatch(hex_candidate)
        and not re.fullmatch(r"(.)\1*", hex_candidate)
    ):
        bounded_hex_candidate = hex_candidate[:max_hex_nested_pickle_chars]
        try:
            decoded = binascii.unhexlify(bounded_hex_candidate)
        except (binascii.Error, ValueError):
            decoded = b""
        if _looks_like_pickle_payload(decoded, max_bytes=max_nested_pickle_bytes):
            decoded_values.append(("hex", decoded))

    return decoded_values


def _detect_oversized_encoded_pickle_prefixes(
    value: str,
    *,
    max_nested_pickle_bytes: int,
) -> list[tuple[str, int]]:
    stripped = value.strip()
    if len(stripped) < 16:
        return []

    detected: list[tuple[str, int]] = []
    probe_decoded_bytes = max(max_nested_pickle_bytes + 1, 2)

    if _BASE64_CANDIDATE_RE.fullmatch(stripped):
        max_base64_probe_chars = max(16, ((probe_decoded_bytes + 2) // 3) * 4)
        bounded = stripped[:max_base64_probe_chars]
        padded = bounded + ("=" * (-len(bounded) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) > max_nested_pickle_bytes and _has_pickle_prefix(decoded):
            detected.append(("base64", _estimate_base64_decoded_size(stripped)))

    max_hex_probe_chars = max(16, probe_decoded_bytes * 4)
    hex_candidate = stripped[:max_hex_probe_chars].replace("\\x", "")
    if len(hex_candidate) % 2:
        hex_candidate = hex_candidate[:-1]
    if (
        len(hex_candidate) >= 16
        and _HEX_CANDIDATE_RE.fullmatch(hex_candidate)
        and not re.fullmatch(r"(.)\1*", hex_candidate)
    ):
        try:
            decoded = binascii.unhexlify(hex_candidate)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) > max_nested_pickle_bytes and _has_pickle_prefix(decoded):
            detected.append(("hex", _estimate_hex_decoded_size(stripped)))

    return detected


def _estimate_base64_decoded_size(value: str) -> int:
    padding_chars = len(value) - len(value.rstrip("="))
    return max(0, (len(value) * 3) // 4 - padding_chars)


def _estimate_hex_decoded_size(value: str) -> int:
    return max(0, len(value.replace("\\x", "")) // 2)


def _has_pickle_prefix(value: bytes) -> bool:
    return len(value) >= 2 and (value[:1] == b"\x80" or value[:1] in _PICKLE_PREFIX_BYTES)


def _looks_like_pickle_payload(value: bytes, *, max_bytes: int) -> bool:
    if len(value) < 2 or len(value) > max_bytes:
        return False
    if not _has_pickle_prefix(value):
        return False

    try:
        saw_stop = False
        for opcode, _arg, _pos in pickletools.genops(BytesIO(value)):
            if opcode.name == "STOP":
                saw_stop = True
                break
        if not saw_stop:
            return False
        pickletools.dis(value, out=StringIO())
    except Exception:
        return False
    return True
