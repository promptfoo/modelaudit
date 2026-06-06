"""Import-time hardening for known-size pickle stream scans."""

from __future__ import annotations

import os
import zipfile
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

from . import api as _api
from .report import PickleReport

_ORIGINAL_READ_STREAM_PAYLOAD = _api._read_stream_payload
_ORIGINAL_SCAN_FILE = _api.PickleScanner.scan_file


def _stream_has_trailing_data(stream: BinaryIO) -> bool:
    try:
        position = stream.tell()
    except (AttributeError, OSError, ValueError):
        position = None

    try:
        return bool(stream.read(1))
    finally:
        if position is not None:
            with suppress(AttributeError, OSError, ValueError):
                stream.seek(position)


def _read_stream_payload(
    stream: BinaryIO,
    size: int | None,
    *,
    max_known_read_bytes: int,
    max_unbounded_read_bytes: int,
) -> tuple[bytes, bool]:
    payload, stream_truncated = _ORIGINAL_READ_STREAM_PAYLOAD(
        stream,
        size,
        max_known_read_bytes=max_known_read_bytes,
        max_unbounded_read_bytes=max_unbounded_read_bytes,
    )
    if size is not None and size >= 0 and not stream_truncated and _stream_has_trailing_data(stream):
        stream_truncated = True
    return payload, stream_truncated


def _scan_file(
    self: _api.PickleScanner,
    path: str | Path,
    *,
    enrich_call_graph: bool = True,
) -> PickleReport:
    source = str(path)
    path_obj = Path(path)
    size: int | None = None
    try:
        with path_obj.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if zipfile.is_zipfile(handle):
                return _ORIGINAL_SCAN_FILE(self, path_obj, enrich_call_graph=enrich_call_graph)
            handle.seek(0)
            return self.scan_stream(
                handle,
                source=source,
                size=size,
                enrich_call_graph=enrich_call_graph,
            )
    except OSError as error:
        return _api._io_error_report(
            source=source,
            message=f"Could not read pickle file: {error!s}",
            category="io_error",
            exception=error,
            bytes_scanned=0,
            bytes_total=None,
        )
    except zipfile.BadZipFile as error:
        return _api._io_error_report(
            source=source,
            message=f"Could not read PyTorch ZIP file: {error!s}",
            category="zip_error",
            exception=error,
            bytes_scanned=0,
            bytes_total=size,
        )


def install() -> None:
    if getattr(_api, "_known_size_stream_security_installed", False):
        return
    _api._read_stream_payload = _read_stream_payload
    _api.PickleScanner.scan_file = _scan_file  # type: ignore[method-assign]
    _api._known_size_stream_security_installed = True  # type: ignore[attr-defined]
