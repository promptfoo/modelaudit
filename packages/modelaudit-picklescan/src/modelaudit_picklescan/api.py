"""Public scanner entrypoints for standalone pickle analysis."""

from __future__ import annotations

import tempfile
import zipfile
from collections.abc import Mapping
from importlib import import_module
from pathlib import Path
from typing import Any, BinaryIO, cast

from .options import ScanOptions
from .report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity

_RUST_STREAM_READ_CHUNK_SIZE = 1024 * 1024
_PYTORCH_ZIP_EXTENSIONS = frozenset({".pt", ".pth", ".ckpt", ".pkl", ".bin"})
_PYTORCH_ZIP_METADATA_BASENAMES = frozenset({"version", "byteorder"})
_PICKLE_MEMBER_SUFFIXES = (".pkl", ".pickle")
_MAX_PYTORCH_ZIP_ENTRIES = 10_000
_MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES = 512 * 1024 * 1024
_RUST_EXTENSION_MODULE = "modelaudit_picklescan._rust"


class _StreamShortReadError(ValueError):
    def __init__(self, *, expected_size: int, bytes_read: int) -> None:
        super().__init__("Stream ended before the declared size was read")
        self.expected_size = expected_size
        self.bytes_read = bytes_read


class PickleScanner:
    """State-light scanner facade configured only by scan options.

    The standalone package uses the Rust scanner directly; there is no Python
    engine selector or runtime fallback behind this facade.
    """

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = ScanOptions() if options is None else options

    def scan_bytes(self, data: bytes | bytearray | memoryview, *, source: str = "<bytes>") -> PickleReport:
        """Scan a raw pickle byte payload."""
        payload = bytes(data)
        return _scan_pickle_payload_native(payload, source=source, options=self.options, bytes_total=len(payload))

    def scan_stream(
        self,
        stream: BinaryIO,
        *,
        source: str = "<stream>",
        size: int | None = None,
    ) -> PickleReport:
        """Scan pickle bytes from the current position of a binary stream."""
        normalized_size = _normalize_stream_size(size)
        try:
            position_offset = stream.tell()
        except (AttributeError, OSError, ValueError):
            position_offset = 0

        try:
            payload = _read_stream_payload(
                stream,
                normalized_size,
                max_unbounded_read_bytes=self.options.max_unbounded_stream_read_bytes,
            )
        except _StreamShortReadError as error:
            return _io_error_report(
                source=source,
                message=f"Could not read pickle stream: {error!s}",
                category="short_read",
                exception=error,
                bytes_scanned=error.bytes_read,
                bytes_total=error.expected_size,
            )
        except Exception as error:
            return _io_error_report(
                source=source,
                message=f"Could not read pickle stream: {error!s}",
                category="io_error",
                exception=error,
                bytes_scanned=0,
                bytes_total=normalized_size,
            )
        return _scan_pickle_payload_native(
            payload,
            source=source,
            options=self.options,
            bytes_total=normalized_size,
            position_offset=position_offset,
        )

    def scan_file(self, path: str | Path) -> PickleReport:
        """Scan a pickle file path, including pickle members in PyTorch ZIP containers."""
        source = str(path)
        path_obj = Path(path)
        try:
            size = path_obj.stat().st_size
            if zipfile.is_zipfile(path_obj):
                container_report = self._scan_pytorch_zip_file(path_obj, source=source, size=size)
                if container_report is not None:
                    return container_report
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
        except zipfile.BadZipFile as error:
            return _io_error_report(
                source=source,
                message=f"Could not read PyTorch ZIP file: {error!s}",
                category="zip_error",
                exception=error,
                bytes_scanned=0,
                bytes_total=size if "size" in locals() else None,
            )

    def _scan_pytorch_zip_file(self, path: Path, *, source: str, size: int) -> PickleReport | None:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if not _is_pytorch_zip_archive(path, entries):
                return None
            if len(entries) > _MAX_PYTORCH_ZIP_ENTRIES:
                return _pytorch_zip_notice_report(
                    source=source,
                    size=size,
                    message=(
                        "PyTorch ZIP analysis stopped because the archive contains too many entries "
                        f"({len(entries)} > {_MAX_PYTORCH_ZIP_ENTRIES})"
                    ),
                    code="pytorch_zip_entry_limit",
                    details={
                        "entry_count": len(entries),
                        "max_entries": _MAX_PYTORCH_ZIP_ENTRIES,
                        "analysis_incomplete": True,
                    },
                )

            pickle_entries = _discover_pytorch_zip_pickle_entries(entries)
            if not pickle_entries:
                return _pytorch_zip_notice_report(
                    source=source,
                    size=size,
                    message="PyTorch ZIP archive does not contain pickle members to scan",
                    code="pytorch_zip_no_pickle_members",
                    details={"analysis_incomplete": True},
                )

            reports: list[PickleReport] = []
            skipped_notices: list[Notice] = []
            for entry in pickle_entries:
                member_name = entry.filename
                member_source = f"{source}:{member_name}"
                if entry.file_size > _MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES:
                    skipped_notices.append(
                        Notice(
                            message=(
                                "PyTorch ZIP pickle member skipped because it exceeds the standalone member scan limit"
                            ),
                            severity=Severity.INFO,
                            location=member_source,
                            code="pytorch_zip_member_size_limit",
                            details={
                                "member_name": member_name,
                                "member_size": entry.file_size,
                                "max_member_size": _MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES,
                                "analysis_incomplete": True,
                            },
                        )
                    )
                    continue
                try:
                    with archive.open(entry, "r") as member_stream:
                        reports.append(
                            self.scan_stream(
                                cast(BinaryIO, member_stream),
                                source=member_source,
                                size=entry.file_size,
                            )
                        )
                except Exception as error:
                    reports.append(
                        _io_error_report(
                            source=member_source,
                            message=f"Could not read PyTorch ZIP pickle member: {error!s}",
                            category="zip_error",
                            exception=error,
                            bytes_scanned=0,
                            bytes_total=entry.file_size,
                        )
                    )

            return _combine_pytorch_zip_reports(
                source=source,
                size=size,
                entries=entries,
                pickle_entries=pickle_entries,
                member_reports=reports,
                extra_notices=tuple(skipped_notices),
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


def _is_pytorch_zip_archive(path: Path, entries: list[zipfile.ZipInfo]) -> bool:
    names = [entry.filename for entry in entries if not entry.is_dir()]
    has_data_pickle = any(_is_data_pickle_member(name) for name in names)
    if not has_data_pickle:
        return False
    has_metadata_marker = any(Path(name).name in _PYTORCH_ZIP_METADATA_BASENAMES for name in names)
    return has_metadata_marker or path.suffix.lower() in _PYTORCH_ZIP_EXTENSIONS


def _discover_pytorch_zip_pickle_entries(entries: list[zipfile.ZipInfo]) -> list[zipfile.ZipInfo]:
    pickle_entries: list[zipfile.ZipInfo] = []
    for entry in entries:
        if entry.is_dir():
            continue
        name = entry.filename
        lowered = name.lower()
        if _is_data_pickle_member(lowered) or lowered.endswith(_PICKLE_MEMBER_SUFFIXES):
            pickle_entries.append(entry)
    return pickle_entries


def _is_data_pickle_member(name: str) -> bool:
    normalized = name.replace("\\", "/").lower()
    return normalized == "data.pkl" or normalized.endswith("/data.pkl")


def _pytorch_zip_notice_report(
    *,
    source: str,
    size: int,
    message: str,
    code: str,
    details: dict[str, Any],
) -> PickleReport:
    return PickleReport(
        source=source,
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message=message,
                severity=Severity.INFO,
                location=source,
                code=code,
                details={"container_type": "pytorch_zip", **details},
            ),
        ),
        coverage=CoverageSummary(
            bytes_scanned=0,
            bytes_total=size,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
        metadata={"container_type": "pytorch_zip", "archive_size_bytes": size},
    )


def _combine_pytorch_zip_reports(
    *,
    source: str,
    size: int,
    entries: list[zipfile.ZipInfo],
    pickle_entries: list[zipfile.ZipInfo],
    member_reports: list[PickleReport],
    extra_notices: tuple[Notice, ...],
) -> PickleReport:
    findings = tuple(finding for report in member_reports for finding in report.findings)
    notices = (*extra_notices, *(notice for report in member_reports for notice in report.notices))
    errors = tuple(error for report in member_reports for error in report.errors)
    status = _combine_status(member_reports, extra_notices)
    verdict = _combine_verdict(member_reports, status, findings)
    opcode_counts = [
        report.coverage.opcode_count for report in member_reports if report.coverage.opcode_count is not None
    ]
    return PickleReport(
        source=source,
        status=status,
        verdict=verdict,
        findings=findings,
        notices=notices,
        errors=errors,
        coverage=CoverageSummary(
            bytes_scanned=sum(report.coverage.bytes_scanned for report in member_reports),
            bytes_total=size,
            opcode_count=sum(opcode_counts) if opcode_counts else None,
            raw_scan_complete=status == ScanStatus.COMPLETE,
            opcode_scan_complete=status == ScanStatus.COMPLETE,
        ),
        metadata={
            "container_type": "pytorch_zip",
            "archive_size_bytes": size,
            "archive_entry_count": len(entries),
            "pickle_files": [entry.filename for entry in pickle_entries],
            "member_reports": [
                {
                    "source": report.source,
                    "status": report.status.value,
                    "verdict": report.verdict.value,
                    "finding_count": len(report.findings),
                    "notice_count": len(report.notices),
                    "error_count": len(report.errors),
                    "bytes_scanned": report.coverage.bytes_scanned,
                    "opcode_count": report.coverage.opcode_count,
                }
                for report in member_reports
            ],
        },
        duration_s=sum(report.duration_s for report in member_reports),
    )


def _combine_status(member_reports: list[PickleReport], notices: tuple[Notice, ...]) -> ScanStatus:
    if not member_reports:
        return ScanStatus.INCONCLUSIVE
    if any(report.status == ScanStatus.ERROR for report in member_reports):
        return ScanStatus.ERROR
    if notices or any(report.status != ScanStatus.COMPLETE for report in member_reports):
        return ScanStatus.INCONCLUSIVE
    return ScanStatus.COMPLETE


def _combine_verdict(
    member_reports: list[PickleReport],
    status: ScanStatus,
    findings: tuple[Finding, ...],
) -> SafetyVerdict:
    if any(report.verdict == SafetyVerdict.MALICIOUS for report in member_reports):
        return SafetyVerdict.MALICIOUS
    if any(report.verdict == SafetyVerdict.SUSPICIOUS for report in member_reports):
        return SafetyVerdict.SUSPICIOUS
    if findings:
        return SafetyVerdict.MALICIOUS
    if status == ScanStatus.COMPLETE and member_reports:
        return SafetyVerdict.CLEAN
    return SafetyVerdict.UNKNOWN


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


def _scan_pickle_payload_native(
    payload: bytes,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
) -> PickleReport:
    native_bytes_total = _normalize_stream_size(bytes_total)
    native_position_offset = max(position_offset, 0)
    try:
        native_module = import_module(_RUST_EXTENSION_MODULE)
        raw_report = native_module.scan_bytes(
            payload,
            source,
            _options_to_native_dict(options),
            native_bytes_total,
            native_position_offset,
            0,
        )
        if not isinstance(raw_report, Mapping):
            raise TypeError(f"Rust scanner returned {type(raw_report).__name__}, expected mapping")
        return _report_from_native_dict(raw_report)
    except Exception as error:
        return _engine_error_report(
            source=source,
            error=error,
            bytes_total=native_bytes_total,
        )


def _options_to_native_dict(options: ScanOptions) -> dict[str, int | float]:
    return {
        "timeout_s": options.timeout_s,
        "max_opcodes": options.max_opcodes,
        "post_budget_scan_bytes": options.post_budget_scan_bytes,
        "max_string_literal_scan_chars": options.max_string_literal_scan_chars,
        "max_nested_pickle_bytes": options.max_nested_pickle_bytes,
        "max_nested_depth": options.max_nested_depth,
    }


def _report_from_native_dict(raw_report: Mapping[str, Any]) -> PickleReport:
    coverage = _mapping(raw_report.get("coverage", {}))
    return PickleReport(
        source=str(raw_report["source"]),
        status=ScanStatus(str(raw_report["status"])),
        verdict=SafetyVerdict(str(raw_report["verdict"])),
        findings=tuple(_finding_from_native_dict(_mapping(item)) for item in _sequence(raw_report.get("findings"))),
        notices=tuple(_notice_from_native_dict(_mapping(item)) for item in _sequence(raw_report.get("notices"))),
        errors=tuple(_error_from_native_dict(_mapping(item)) for item in _sequence(raw_report.get("errors"))),
        coverage=CoverageSummary(
            bytes_scanned=int(coverage.get("bytes_scanned", 0)),
            bytes_total=_optional_int(coverage.get("bytes_total")),
            opcode_count=_optional_int(coverage.get("opcode_count")),
            raw_scan_complete=_optional_bool(coverage.get("raw_scan_complete")),
            opcode_scan_complete=_optional_bool(coverage.get("opcode_scan_complete")),
        ),
        metadata=dict(_mapping(raw_report.get("metadata", {}))),
        duration_s=float(raw_report.get("duration_s", 0.0)),
    )


def _finding_from_native_dict(raw_finding: Mapping[str, Any]) -> Finding:
    return Finding(
        message=str(raw_finding["message"]),
        severity=Severity(str(raw_finding["severity"])),
        location=_optional_str(raw_finding.get("location")),
        rule_code=_optional_str(raw_finding.get("rule_code")),
        details=dict(_mapping(raw_finding.get("details", {}))),
        why=_optional_str(raw_finding.get("why")),
    )


def _notice_from_native_dict(raw_notice: Mapping[str, Any]) -> Notice:
    return Notice(
        message=str(raw_notice["message"]),
        severity=Severity(str(raw_notice.get("severity", Severity.INFO.value))),
        location=_optional_str(raw_notice.get("location")),
        code=_optional_str(raw_notice.get("code")),
        details=dict(_mapping(raw_notice.get("details", {}))),
    )


def _error_from_native_dict(raw_error: Mapping[str, Any]) -> ScanError:
    return ScanError(
        message=str(raw_error["message"]),
        category=str(raw_error["category"]),
        location=_optional_str(raw_error.get("location")),
        exception_type=_optional_str(raw_error.get("exception_type")),
        details=dict(_mapping(raw_error.get("details", {}))),
    )


def _mapping(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise TypeError(f"expected mapping, got {type(value).__name__}")


def _sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    raise TypeError(f"expected sequence, got {type(value).__name__}")


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str | bytes | bytearray):
        return int(value)
    raise TypeError(f"expected int-compatible value, got {type(value).__name__}")


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise TypeError(f"expected bool or None, got {type(value).__name__}")


def _normalize_stream_size(size: int | None) -> int | None:
    if size is None or size < 0:
        return None
    return size


def _read_stream_payload(
    stream: BinaryIO,
    size: int | None,
    *,
    max_unbounded_read_bytes: int,
) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=max_unbounded_read_bytes, mode="w+b") as spool:
        if size is None:
            remaining = max_unbounded_read_bytes
            while remaining > 0:
                chunk = stream.read(min(_RUST_STREAM_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                spool.write(chunk)
                remaining -= len(chunk)
            if remaining == 0 and stream.read(1):
                raise ValueError("Unbounded stream exceeded max_unbounded_stream_read_bytes")
        else:
            remaining = size
            bytes_read = 0
            while remaining > 0:
                chunk = stream.read(min(_RUST_STREAM_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    raise _StreamShortReadError(expected_size=size, bytes_read=bytes_read)
                spool.write(chunk)
                bytes_read += len(chunk)
                remaining -= len(chunk)

        spool.seek(0)
        return spool.read()


def _engine_error_report(
    *,
    source: str,
    error: Exception,
    bytes_total: int | None,
) -> PickleReport:
    return PickleReport(
        source=source,
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message=f"Rust pickle scanner failed: {error!s}",
                category="rust_engine_error",
                location=source,
                exception_type=type(error).__name__,
            ),
        ),
        coverage=CoverageSummary(
            bytes_scanned=0,
            bytes_total=bytes_total,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
    )
