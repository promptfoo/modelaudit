"""Bounded helpers for identifying HDF5 superblocks."""

import os

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
HDF5_USERBLOCK_FIRST_OFFSET = 512
HDF5_SIGNATURE_SCAN_MAX_BYTES = 10 * 1024 * 1024
HDF5_SUPERBLOCK_PROBE_BYTES = 96


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
        base_address_offset = fixed_header_bytes
    elif superblock_version in (2, 3):
        if len(superblock) < 12:
            return False
        offset_size = superblock[9]
        length_size = superblock[10]
        base_address_offset = 12
    else:
        return False

    if not 1 <= offset_size <= 16 or not 1 <= length_size <= 16:
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
