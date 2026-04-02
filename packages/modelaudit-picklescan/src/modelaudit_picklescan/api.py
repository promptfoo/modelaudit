"""Public scanner entrypoints for standalone pickle analysis."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from .engine import scan_pickle_payload, scan_pickle_stream
from .options import ScanOptions
from .report import CoverageSummary, PickleReport, SafetyVerdict, ScanError, ScanStatus


class PickleScanner:
    """State-light scanner facade configured only by scan options.

    The concrete engine will be wired behind this facade during extraction from
    `modelaudit.scanners.pickle_scanner`. Keeping this API in place first makes
    the package boundary explicit before detector logic moves.
    """

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = ScanOptions() if options is None else options

    def scan_bytes(self, data: bytes | bytearray | memoryview, *, source: str = "<bytes>") -> PickleReport:
        """Scan a raw pickle byte payload."""
        return scan_pickle_payload(bytes(data), source=source, options=self.options)

    def scan_stream(
        self,
        stream: BinaryIO,
        *,
        source: str = "<stream>",
        size: int | None = None,
    ) -> PickleReport:
        """Scan pickle bytes from the current position of a binary stream."""
        try:
            position_offset = stream.tell()
        except (AttributeError, OSError, ValueError):
            position_offset = 0

        return scan_pickle_stream(
            stream,
            source=source,
            options=self.options,
            bytes_total=size,
            position_offset=position_offset,
        )

    def scan_file(self, path: str | Path) -> PickleReport:
        """Scan a strict pickle file path.

        Container-aware artifact routing stays in `modelaudit`, not this
        standalone package.
        """
        source = str(path)
        path_obj = Path(path)
        try:
            size = path_obj.stat().st_size
            with path_obj.open("rb") as handle:
                return self.scan_stream(handle, source=source, size=size)
        except OSError as error:
            return _io_error_report(
                source=source,
                message=f"Could not read pickle file: {error!s}",
                category="io_error",
                exception=error,
                bytes_scanned=0,
                bytes_total=None,
            )


def scan_bytes(
    data: bytes | bytearray | memoryview,
    *,
    source: str = "<bytes>",
    options: ScanOptions | None = None,
) -> PickleReport:
    """Convenience wrapper around :meth:`PickleScanner.scan_bytes`."""
    return PickleScanner(options=options).scan_bytes(data, source=source)


def scan_stream(
    stream: BinaryIO,
    *,
    source: str = "<stream>",
    size: int | None = None,
    options: ScanOptions | None = None,
) -> PickleReport:
    """Convenience wrapper around :meth:`PickleScanner.scan_stream`."""
    return PickleScanner(options=options).scan_stream(stream, source=source, size=size)


def scan_file(path: str | Path, *, options: ScanOptions | None = None) -> PickleReport:
    """Convenience wrapper around :meth:`PickleScanner.scan_file`."""
    return PickleScanner(options=options).scan_file(path)


def _io_error_report(
    *,
    source: str,
    message: str,
    category: str,
    exception: Exception,
    bytes_scanned: int,
    bytes_total: int | None,
) -> PickleReport:
    return PickleReport(
        source=source,
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message=message,
                category=category,
                location=source,
                exception_type=type(exception).__name__,
            ),
        ),
        coverage=CoverageSummary(
            bytes_scanned=bytes_scanned,
            bytes_total=bytes_total,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
    )
