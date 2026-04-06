"""Shared compression-format helpers."""

from __future__ import annotations


def is_zlib_header(prefix: bytes) -> bool:
    """Return True when the two-byte prefix is a valid zlib stream header."""
    if len(prefix) < 2:
        return False

    cmf = prefix[0]
    flg = prefix[1]

    if (cmf & 0x0F) != 8:
        return False
    if (cmf >> 4) > 7:
        return False

    return ((cmf << 8) + flg) % 31 == 0
