"""Bounded helpers for identifying HDF5 superblocks."""

import os

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
HDF5_USERBLOCK_FIRST_OFFSET = 512
HDF5_SIGNATURE_SCAN_MAX_BYTES = 10 * 1024 * 1024
HDF5_SUPERBLOCK_PROBE_BYTES = 144
_HDF5_SUPPORTED_FIELD_WIDTHS = frozenset({2, 4, 8, 16, 32})
_HDF5_SUPERBLOCK_STATUS_FLAGS = 0x07
_UINT32_MASK = (1 << 32) - 1


def _rotate_left_32(value: int, bits: int) -> int:
    return ((value << bits) ^ (value >> (32 - bits))) & _UINT32_MASK


def _lookup3_mix(a: int, b: int, c: int) -> tuple[int, int, int]:
    """Apply HDF5's lookup3 block mixing operations."""
    a = ((a - c) ^ _rotate_left_32(c, 4)) & _UINT32_MASK
    c = (c + b) & _UINT32_MASK
    b = ((b - a) ^ _rotate_left_32(a, 6)) & _UINT32_MASK
    a = (a + c) & _UINT32_MASK
    c = ((c - b) ^ _rotate_left_32(b, 8)) & _UINT32_MASK
    b = (b + a) & _UINT32_MASK
    a = ((a - c) ^ _rotate_left_32(c, 16)) & _UINT32_MASK
    c = (c + b) & _UINT32_MASK
    b = ((b - a) ^ _rotate_left_32(a, 19)) & _UINT32_MASK
    a = (a + c) & _UINT32_MASK
    c = ((c - b) ^ _rotate_left_32(b, 4)) & _UINT32_MASK
    b = (b + a) & _UINT32_MASK
    return a, b, c


def _lookup3_finalize(a: int, b: int, c: int) -> int:
    """Finalize HDF5's lookup3 metadata checksum."""
    c = ((c ^ b) - _rotate_left_32(b, 14)) & _UINT32_MASK
    a = ((a ^ c) - _rotate_left_32(c, 11)) & _UINT32_MASK
    b = ((b ^ a) - _rotate_left_32(a, 25)) & _UINT32_MASK
    c = ((c ^ b) - _rotate_left_32(b, 16)) & _UINT32_MASK
    a = ((a ^ c) - _rotate_left_32(c, 4)) & _UINT32_MASK
    b = ((b ^ a) - _rotate_left_32(a, 14)) & _UINT32_MASK
    return ((c ^ b) - _rotate_left_32(b, 24)) & _UINT32_MASK


def hdf5_metadata_checksum(data: bytes, initval: int = 0) -> int:
    """Return the lookup3 checksum used for HDF5 metadata blocks."""
    length = len(data)
    a = b = c = (0xDEADBEEF + length + initval) & _UINT32_MASK
    offset = 0

    while length - offset > 12:
        a = (a + int.from_bytes(data[offset : offset + 4], "little")) & _UINT32_MASK
        b = (b + int.from_bytes(data[offset + 4 : offset + 8], "little")) & _UINT32_MASK
        c = (c + int.from_bytes(data[offset + 8 : offset + 12], "little")) & _UINT32_MASK
        a, b, c = _lookup3_mix(a, b, c)
        offset += 12

    tail = data[offset:]
    if not tail:
        return c

    if len(tail) > 8:
        c = (c + int.from_bytes(tail[8:], "little")) & _UINT32_MASK
    if len(tail) > 4:
        b = (b + int.from_bytes(tail[4:8], "little")) & _UINT32_MASK
    a = (a + int.from_bytes(tail[:4], "little")) & _UINT32_MASK
    return _lookup3_finalize(a, b, c)


def hdf5_signature_offsets(
    file_size: int,
    max_signature_scan_bytes: int | None = HDF5_SIGNATURE_SCAN_MAX_BYTES,
) -> list[int]:
    """Return legal HDF5 signature offsets within the requested search bound."""
    max_signature_end = file_size
    if max_signature_scan_bytes is not None:
        max_signature_end = min(max_signature_end, max_signature_scan_bytes)

    offsets: list[int] = []
    if len(HDF5_MAGIC) <= max_signature_end:
        offsets.append(0)

    offset = HDF5_USERBLOCK_FIRST_OFFSET
    while offset + len(HDF5_MAGIC) <= max_signature_end:
        offsets.append(offset)
        offset *= 2
    return offsets


def is_hdf5_signature_probe_complete(
    file_size: int,
    max_signature_scan_bytes: int | None = HDF5_SIGNATURE_SCAN_MAX_BYTES,
) -> bool:
    """Return whether the bounded probe covers every legal signature offset."""
    return hdf5_signature_offsets(file_size, max_signature_scan_bytes) == hdf5_signature_offsets(
        file_size,
        max_signature_scan_bytes=None,
    )


def has_plausible_hdf5_superblock(superblock: bytes, signature_offset: int, file_size: int) -> bool:
    """Validate bounded HDF5 superblock invariants after a candidate signature."""
    if superblock[: len(HDF5_MAGIC)] != HDF5_MAGIC:
        return False
    if len(superblock) <= len(HDF5_MAGIC):
        return False

    superblock_version = superblock[8]
    if superblock_version in (0, 1):
        fixed_header_bytes = 24 if superblock_version == 0 else 28
        if len(superblock) < fixed_header_bytes:
            return False
        if any(superblock[field_offset] != 0 for field_offset in (9, 10, 11, 12, 15)):
            return False
        if int.from_bytes(superblock[16:18], "little") == 0:
            return False
        if int.from_bytes(superblock[18:20], "little") == 0:
            return False
        if superblock_version == 1:
            if int.from_bytes(superblock[24:26], "little") == 0:
                return False
            if superblock[26:28] != b"\x00\x00":
                return False
        offset_size = superblock[13]
        length_size = superblock[14]
        status_flags = int.from_bytes(superblock[20:24], "little")
        base_address_offset = fixed_header_bytes
    elif superblock_version in (2, 3):
        if len(superblock) < 12:
            return False
        offset_size = superblock[9]
        length_size = superblock[10]
        status_flags = superblock[11]
        base_address_offset = 12
    else:
        return False

    if (
        offset_size not in _HDF5_SUPPORTED_FIELD_WIDTHS
        or length_size not in _HDF5_SUPPORTED_FIELD_WIDTHS
        or status_flags & ~_HDF5_SUPERBLOCK_STATUS_FLAGS
    ):
        return False

    if superblock_version in (2, 3):
        checksum_offset = base_address_offset + (4 * offset_size)
        if len(superblock) < checksum_offset + 4:
            return False
        stored_checksum = int.from_bytes(superblock[checksum_offset : checksum_offset + 4], "little")
        if hdf5_metadata_checksum(superblock[:checksum_offset]) != stored_checksum:
            return False

    end_of_file_offset = base_address_offset + (2 * offset_size)
    if len(superblock) < end_of_file_offset + offset_size:
        return False

    undefined_address = (1 << (offset_size * 8)) - 1
    base_address = int.from_bytes(superblock[base_address_offset : base_address_offset + offset_size], "little")
    end_of_file_address = int.from_bytes(
        superblock[end_of_file_offset : end_of_file_offset + offset_size],
        "little",
    )
    if base_address == undefined_address or end_of_file_address == undefined_address:
        return False

    adjusted_end_of_file = end_of_file_address + (signature_offset - base_address)
    return signature_offset < adjusted_end_of_file <= file_size


def find_hdf5_signature_offset(file_path: str) -> int | None:
    """Return a validated HDF5 signature offset using sparse bounded reads."""
    try:
        file_size = os.stat(file_path).st_size
        with open(file_path, "rb") as handle:
            for offset in hdf5_signature_offsets(file_size, max_signature_scan_bytes=None):
                handle.seek(offset)
                superblock = handle.read(min(HDF5_SUPERBLOCK_PROBE_BYTES, file_size - offset))
                if has_plausible_hdf5_superblock(superblock, offset, file_size):
                    return offset
    except OSError:
        return None

    return None
