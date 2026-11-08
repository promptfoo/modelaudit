"""Shared test fixture writers for ordinary TAR members."""

import io
import tarfile


def add_tar_bytes(archive: tarfile.TarFile, name: str, payload: bytes | bytearray) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))


def make_tar_link(name: str, target: str, link_type: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = link_type
    info.linkname = target
    return info
