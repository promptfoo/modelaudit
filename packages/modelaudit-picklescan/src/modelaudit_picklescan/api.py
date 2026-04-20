"""Public scanner entrypoints for standalone pickle analysis."""

from __future__ import annotations

import pickletools
import tempfile
import zipfile
from collections.abc import Mapping
from importlib import import_module
from pathlib import Path
from typing import Any, BinaryIO, cast

from .call_graph import (
    CallGraphFinding,
    StartupHookWriteFinding,
    find_dangerous_call_graphs,
    find_startup_hook_write_call_graphs,
)
from .options import ScanOptions
from .report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity

_RUST_STREAM_READ_CHUNK_SIZE = 1024 * 1024
_PYTORCH_ZIP_METADATA_BASENAMES = frozenset({"version", "byteorder"})
_PICKLE_MEMBER_SUFFIXES = (".pkl", ".pickle")
_PICKLE_BINARY_PROTOCOL_PREFIXES = (b"\x80\x01", b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
_PICKLE_DISCOVERY_SHORT_PROBE_BYTES = 16
_PICKLE_DISCOVERY_LONG_PROBE_BYTES = 64 * 1024
_PROTO0_1_START_BYTES = b"()]}cilp0FGIJKLMNSTUVX"
_PROTO0_1_MAX_PROBE_OPCODES = _PICKLE_DISCOVERY_LONG_PROBE_BYTES
_PROTO0_1_IGNORABLE_TRAILING_BYTES = b" \t\r\n\x00"
_PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES = (
    "pickle exhausted before seeing STOP",
    "no newline found when trying to read ",
)
_PROTO0_1_TRIVIAL_LEADING_OPCODES = frozenset(
    {
        "MARK",
        "POP",
        "PUT",
        "EMPTY_TUPLE",
        "EMPTY_LIST",
        "EMPTY_DICT",
        "LIST",
        "INT",
        "BININT",
        "BININT1",
        "BININT2",
        "LONG",
        "LONG1",
        "LONG4",
        "FLOAT",
        "BINFLOAT",
        "NONE",
        "NEWTRUE",
        "NEWFALSE",
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "UNICODE",
        "BINUNICODE",
        "SHORT_BINUNICODE",
    }
)
_MAX_PYTORCH_ZIP_ENTRIES = 10_000
_MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES = 512 * 1024 * 1024
_RUST_EXTENSION_MODULE = "modelaudit_picklescan._rust"
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_MIN_SIZE = 22
_ZIP_MAX_COMMENT_SIZE = 0xFFFF
_ZIP64_EOCD_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_EOCD_LOCATOR_SIZE = 20
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_EOCD_MIN_SIZE = 56
_ZIP64_SENTINEL_ENTRY_COUNT = 0xFFFF


class _StreamShortReadError(ValueError):
    def __init__(self, *, expected_size: int, bytes_read: int, partial_payload: bytes) -> None:
        super().__init__("Stream ended before the declared size was read")
        self.expected_size = expected_size
        self.bytes_read = bytes_read
        self.partial_payload = partial_payload


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
            payload, stream_truncated = _read_stream_payload(
                stream,
                normalized_size,
                max_known_read_bytes=self.options.max_known_stream_read_bytes,
                max_unbounded_read_bytes=self.options.max_unbounded_stream_read_bytes,
            )
        except _StreamShortReadError as error:
            if error.partial_payload:
                partial_report = _scan_pickle_payload_native(
                    error.partial_payload,
                    source=source,
                    options=self.options,
                    bytes_total=error.bytes_read,
                    position_offset=position_offset,
                )
                return _with_short_read_error(
                    partial_report,
                    source=source,
                    error=error,
                )
            return _io_error_report(
                source=source,
                message=f"Could not read pickle stream: {error!s}",
                category="short_read",
                exception=error,
                bytes_scanned=0,
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
        native_bytes_total = len(payload) if stream_truncated and normalized_size is not None else normalized_size
        report = _scan_pickle_payload_native(
            payload,
            source=source,
            options=self.options,
            bytes_total=native_bytes_total,
            position_offset=position_offset,
        )
        if stream_truncated:
            if normalized_size is None:
                return _with_unbounded_stream_notice(
                    report,
                    source=source,
                    bytes_scanned=len(payload),
                    max_unbounded_read_bytes=self.options.max_unbounded_stream_read_bytes,
                )
            return _with_known_stream_notice(
                report,
                source=source,
                bytes_scanned=len(payload),
                bytes_total=normalized_size,
                max_known_read_bytes=self.options.max_known_stream_read_bytes,
            )
        return report

    def scan_file(self, path: str | Path) -> PickleReport:
        """Scan a pickle file path, including pickle members in PyTorch ZIP containers."""
        source = str(path)
        path_obj = Path(path)
        size: int | None = None
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
                bytes_total=size,
            )

    def _scan_pytorch_zip_file(self, path: Path, *, source: str, size: int) -> PickleReport | None:
        preflight_entry_count = _read_zip_entry_count(path, size)
        if preflight_entry_count is not None and preflight_entry_count > _MAX_PYTORCH_ZIP_ENTRIES:
            return _pytorch_zip_entry_limit_report(
                source=source,
                size=size,
                entry_count=preflight_entry_count,
            )

        with zipfile.ZipFile(path, "r") as archive:
            entries = _bounded_zip_entries(archive, source=source, size=size)
            if isinstance(entries, PickleReport):
                return entries
            if not _is_pytorch_zip_archive(entries):
                return None

            pickle_entries, discovery_notices = _discover_pytorch_zip_pickle_entries(archive, entries, source=source)
            if not pickle_entries:
                return _pytorch_zip_notice_report(
                    source=source,
                    size=size,
                    message="PyTorch ZIP archive does not contain pickle members to scan",
                    code="pytorch_zip_no_pickle_members",
                    details={"analysis_incomplete": True},
                )

            reports: list[PickleReport] = []
            skipped_notices: list[Notice] = list(discovery_notices)
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
                entry_count=len(entries),
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


def _read_zip_entry_count(path: Path, file_size: int) -> int | None:
    if file_size < _ZIP_EOCD_MIN_SIZE:
        return None

    tail_size = min(file_size, _ZIP_EOCD_MIN_SIZE + _ZIP_MAX_COMMENT_SIZE)
    try:
        with path.open("rb") as handle:
            handle.seek(file_size - tail_size)
            tail = handle.read(tail_size)
            eocd_index = _find_zip_eocd_index(tail)
            if eocd_index is None:
                return None

            entry_count = int.from_bytes(tail[eocd_index + 10 : eocd_index + 12], "little")
            if entry_count != _ZIP64_SENTINEL_ENTRY_COUNT:
                return entry_count

            eocd_offset = file_size - tail_size + eocd_index
            locator_offset = eocd_offset - _ZIP64_EOCD_LOCATOR_SIZE
            if locator_offset < 0:
                return None
            handle.seek(locator_offset)
            locator = handle.read(_ZIP64_EOCD_LOCATOR_SIZE)
            if not locator.startswith(_ZIP64_EOCD_LOCATOR_SIGNATURE):
                return None
            zip64_eocd_offset = int.from_bytes(locator[8:16], "little")
            handle.seek(zip64_eocd_offset)
            zip64_eocd = handle.read(_ZIP64_EOCD_MIN_SIZE)
            if len(zip64_eocd) < _ZIP64_EOCD_MIN_SIZE or not zip64_eocd.startswith(_ZIP64_EOCD_SIGNATURE):
                return None
            return int.from_bytes(zip64_eocd[32:40], "little")
    except OSError:
        return None


def _find_zip_eocd_index(tail: bytes) -> int | None:
    search_end = len(tail)
    while True:
        eocd_index = tail.rfind(_ZIP_EOCD_SIGNATURE, 0, search_end)
        if eocd_index < 0 or eocd_index + _ZIP_EOCD_MIN_SIZE > len(tail):
            return None
        comment_length = int.from_bytes(tail[eocd_index + 20 : eocd_index + 22], "little")
        if eocd_index + _ZIP_EOCD_MIN_SIZE + comment_length == len(tail):
            return eocd_index
        search_end = eocd_index


def _bounded_zip_entries(
    archive: zipfile.ZipFile,
    *,
    source: str,
    size: int,
) -> list[zipfile.ZipInfo] | PickleReport:
    filelist = getattr(archive, "filelist", None)
    if isinstance(filelist, list):
        entry_count = len(filelist)
        if entry_count > _MAX_PYTORCH_ZIP_ENTRIES:
            return _pytorch_zip_entry_limit_report(source=source, size=size, entry_count=entry_count)
        return cast(list[zipfile.ZipInfo], filelist)

    entries = archive.infolist()
    entry_count = len(entries)
    if entry_count > _MAX_PYTORCH_ZIP_ENTRIES:
        return _pytorch_zip_entry_limit_report(source=source, size=size, entry_count=entry_count)
    return entries


def _is_pytorch_zip_archive(entries: list[zipfile.ZipInfo]) -> bool:
    names = [entry.filename for entry in entries if not entry.is_dir()]
    has_data_pickle = any(_is_data_pickle_member(name) for name in names)
    has_metadata_marker = any(Path(name).name in _PYTORCH_ZIP_METADATA_BASENAMES for name in names)
    if not has_metadata_marker:
        return False
    if has_data_pickle:
        return True
    has_pickle_members = any(name.lower().endswith(_PICKLE_MEMBER_SUFFIXES) for name in names)
    return has_pickle_members


def _discover_pytorch_zip_pickle_entries(
    archive: zipfile.ZipFile,
    entries: list[zipfile.ZipInfo],
    *,
    source: str,
) -> tuple[list[zipfile.ZipInfo], tuple[Notice, ...]]:
    pickle_entries: list[zipfile.ZipInfo] = []
    notices: list[Notice] = []
    seen_entries: set[int] = set()

    def add_entry(entry: zipfile.ZipInfo) -> None:
        entry_id = id(entry)
        if entry_id in seen_entries:
            return
        pickle_entries.append(entry)
        seen_entries.add(entry_id)

    for entry in entries:
        if entry.is_dir():
            continue
        name = entry.filename
        lowered = name.lower()
        if _is_data_pickle_member(lowered) or lowered.endswith(_PICKLE_MEMBER_SUFFIXES):
            add_entry(entry)

    for entry in entries:
        if entry.is_dir() or id(entry) in seen_entries:
            continue
        try:
            if _zip_entry_looks_like_pickle(archive, entry):
                add_entry(entry)
        except Exception as error:
            notices.append(_pytorch_zip_member_probe_notice(source=source, entry=entry, error=error))

    return pickle_entries, tuple(notices)


def _zip_entry_looks_like_pickle(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> bool:
    with archive.open(entry, "r") as member:
        prefix = member.read(_PICKLE_DISCOVERY_SHORT_PROBE_BYTES)
    if not prefix:
        return False

    if prefix.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES):
        with archive.open(entry, "r") as member:
            sample = member.read(_PICKLE_DISCOVERY_LONG_PROBE_BYTES)
        return _looks_like_binary_pickle_prefix(sample, sample_is_prefix=entry.file_size > len(sample))

    if prefix[0] not in _PROTO0_1_START_BYTES:
        return False

    sample = prefix
    if entry.file_size > len(prefix):
        with archive.open(entry, "r") as member:
            sample = member.read(_PICKLE_DISCOVERY_LONG_PROBE_BYTES)
    return _looks_like_proto0_or_1_pickle(sample, sample_is_prefix=entry.file_size > len(sample))


def _looks_like_binary_pickle_prefix(sample: bytes, *, sample_is_prefix: bool) -> bool:
    # Keep structurally in sync with
    # ``modelaudit.scanners.pytorch_zip_scanner.PyTorchZipScanner._looks_like_binary_pickle_prefix``.
    # The two copies exist because ``modelaudit-picklescan`` ships as a
    # standalone package with no dependency on the main ``modelaudit`` tree.
    if not sample.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES):
        return False

    # Thresholds: ``>= 4`` clean opcodes is enough evidence on a complete
    # probe, ``>= 2`` when the sample is a prefix of a larger member and
    # ``genops`` either ran out of bytes or raised a truncation-style error.
    op_count = 0
    try:
        for opcode, _arg, _pos in pickletools.genops(sample):
            op_count += 1
            if opcode.name == "STOP":
                return True
            if op_count >= 4:
                return True
    except ValueError as exc:
        message = str(exc).lower()
        return (
            sample_is_prefix
            and op_count >= 2
            and ("exhausted before seeing stop" in message or "not enough data" in message or "expected" in message)
        )

    return sample_is_prefix and op_count >= 2


def _looks_like_proto0_or_1_pickle(sample: bytes, *, sample_is_prefix: bool) -> bool:
    # Keep structurally in sync with
    # ``modelaudit.utils.file.detection._looks_like_proto0_or_1_pickle``.
    # Duplicated for the standalone package (see comment on
    # ``_looks_like_binary_pickle_prefix``).
    if len(sample) < 2:
        return False

    def matches_proto_stream(candidate: bytes) -> bool:
        if len(candidate) < 2 or candidate[0] not in _PROTO0_1_START_BYTES:
            return False

        opcode_count = 0
        has_non_trivial_opcode = False
        try:
            for opcode, _arg, pos in pickletools.genops(candidate):
                opcode_count += 1
                if opcode.name == "STOP":
                    stop_pos = 0 if pos is None else pos
                    trailing = candidate[stop_pos + 1 :]
                    if not trailing or not trailing.strip(_PROTO0_1_IGNORABLE_TRAILING_BYTES):
                        return opcode_count >= 2
                    if has_non_trivial_opcode:
                        return opcode_count >= 2
                    stripped_trailing = trailing.lstrip(_PROTO0_1_IGNORABLE_TRAILING_BYTES)
                    return bool(stripped_trailing) and _looks_like_proto0_or_1_pickle(
                        stripped_trailing,
                        sample_is_prefix=sample_is_prefix,
                    )
                if opcode.name not in _PROTO0_1_TRIVIAL_LEADING_OPCODES:
                    has_non_trivial_opcode = True
                if opcode_count >= _PROTO0_1_MAX_PROBE_OPCODES:
                    return False
        except ValueError as exc:
            exc_message = str(exc)
            return (
                sample_is_prefix
                and opcode_count >= 2
                and has_non_trivial_opcode
                and any(
                    exc_message.startswith(error_prefix) for error_prefix in _PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES
                )
            )
        except Exception:
            return False

        return sample_is_prefix and opcode_count >= 2 and has_non_trivial_opcode

    if matches_proto_stream(sample):
        return True

    return sample.startswith(b"#") and matches_proto_stream(sample[1:])


def _is_data_pickle_member(name: str) -> bool:
    normalized = name.replace("\\", "/").lower()
    return normalized == "data.pkl" or normalized.endswith("/data.pkl")


def _pytorch_zip_member_probe_notice(*, source: str, entry: zipfile.ZipInfo, error: Exception) -> Notice:
    return Notice(
        message=f"Could not inspect PyTorch ZIP member for hidden pickle payloads: {error!s}",
        severity=Severity.INFO,
        location=f"{source}:{entry.filename}",
        code="pytorch_zip_member_probe_failed",
        details={
            "member_name": entry.filename,
            "member_size": entry.file_size,
            "exception_type": type(error).__name__,
            "analysis_incomplete": True,
        },
    )


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


def _pytorch_zip_entry_limit_report(*, source: str, size: int, entry_count: int) -> PickleReport:
    return _pytorch_zip_notice_report(
        source=source,
        size=size,
        message=(
            "PyTorch ZIP analysis stopped because the archive contains too many entries "
            f"({entry_count} > {_MAX_PYTORCH_ZIP_ENTRIES})"
        ),
        code="pytorch_zip_entry_limit",
        details={
            "entry_count": entry_count,
            "max_entries": _MAX_PYTORCH_ZIP_ENTRIES,
            "analysis_incomplete": True,
        },
    )


def _combine_pytorch_zip_reports(
    *,
    source: str,
    size: int,
    entry_count: int,
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
            "archive_entry_count": entry_count,
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


def _with_unbounded_stream_notice(
    report: PickleReport,
    *,
    source: str,
    bytes_scanned: int,
    max_unbounded_read_bytes: int,
) -> PickleReport:
    notices = (
        *report.notices,
        Notice(
            message="Unbounded pickle stream scan stopped at configured byte limit",
            severity=Severity.INFO,
            location=source,
            code="unbounded_stream_truncated",
            details={
                "bytes_scanned": bytes_scanned,
                "max_unbounded_stream_read_bytes": max_unbounded_read_bytes,
                "analysis_incomplete": True,
            },
        ),
    )
    status = ScanStatus.INCONCLUSIVE
    verdict = SafetyVerdict.UNKNOWN if report.verdict == SafetyVerdict.CLEAN else report.verdict
    metadata = {**report.to_dict()["metadata"], "analysis_incomplete": True}
    return PickleReport(
        source=report.source,
        status=status,
        verdict=verdict,
        findings=report.findings,
        notices=notices,
        errors=report.errors,
        coverage=CoverageSummary(
            bytes_scanned=report.coverage.bytes_scanned,
            bytes_total=None,
            opcode_count=report.coverage.opcode_count,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
        metadata=metadata,
        duration_s=report.duration_s,
    )


def _with_known_stream_notice(
    report: PickleReport,
    *,
    source: str,
    bytes_scanned: int,
    bytes_total: int,
    max_known_read_bytes: int,
) -> PickleReport:
    notices = (
        *report.notices,
        Notice(
            message="Known-size pickle stream scan stopped at configured byte limit",
            severity=Severity.INFO,
            location=source,
            code="known_stream_truncated",
            details={
                "bytes_scanned": bytes_scanned,
                "bytes_total": bytes_total,
                "max_known_stream_read_bytes": max_known_read_bytes,
                "analysis_incomplete": True,
            },
        ),
    )
    status = ScanStatus.INCONCLUSIVE
    verdict = SafetyVerdict.UNKNOWN if report.verdict == SafetyVerdict.CLEAN else report.verdict
    metadata = {**report.to_dict()["metadata"], "analysis_incomplete": True}
    return PickleReport(
        source=report.source,
        status=status,
        verdict=verdict,
        findings=report.findings,
        notices=notices,
        errors=report.errors,
        coverage=CoverageSummary(
            bytes_scanned=report.coverage.bytes_scanned,
            bytes_total=bytes_total,
            opcode_count=report.coverage.opcode_count,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
        metadata=metadata,
        duration_s=report.duration_s,
    )


def _with_short_read_error(
    report: PickleReport,
    *,
    source: str,
    error: _StreamShortReadError,
) -> PickleReport:
    errors = (
        *report.errors,
        ScanError(
            message=f"Could not read pickle stream: {error!s}",
            category="short_read",
            location=source,
            exception_type=type(error).__name__,
            details={
                "bytes_read": error.bytes_read,
                "expected_size": error.expected_size,
                "analysis_incomplete": True,
            },
        ),
    )
    verdict = SafetyVerdict.UNKNOWN if report.verdict == SafetyVerdict.CLEAN else report.verdict
    metadata = {
        **report.to_dict()["metadata"],
        "analysis_incomplete": True,
        "stream_short_read": True,
        "stream_bytes_read": error.bytes_read,
        "stream_expected_size": error.expected_size,
    }
    return PickleReport(
        source=report.source,
        status=ScanStatus.ERROR,
        verdict=verdict,
        findings=report.findings,
        notices=report.notices,
        errors=errors,
        coverage=CoverageSummary(
            bytes_scanned=max(report.coverage.bytes_scanned, error.bytes_read),
            bytes_total=error.expected_size,
            opcode_count=report.coverage.opcode_count,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
        metadata=metadata,
        duration_s=report.duration_s,
    )


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
        return _with_call_graph_findings(_report_from_native_dict(raw_report))
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


def _with_call_graph_findings(report: PickleReport) -> PickleReport:
    import_references = report.metadata.get("import_references")
    try:
        call_graph_findings = find_dangerous_call_graphs(import_references)
    except Exception:
        call_graph_findings = ()
    try:
        startup_hook_write_findings = find_startup_hook_write_call_graphs(import_references)
    except Exception:
        startup_hook_write_findings = ()
    if not call_graph_findings and not startup_hook_write_findings:
        return report

    existing_critical_globals = {
        (str(finding.details.get("module", "")), str(finding.details.get("name", "")))
        for finding in report.findings
        if finding.severity == Severity.CRITICAL
    }
    rce_findings = tuple(
        _call_graph_finding_to_report_finding(report, finding)
        for finding in call_graph_findings
        if (finding.module, finding.name) not in existing_critical_globals
    )
    startup_findings = tuple(
        _startup_hook_write_finding_to_report_finding(report, finding)
        for finding in startup_hook_write_findings
        if (finding.writer_module, finding.writer_name) not in existing_critical_globals
        and (finding.opener_module, finding.opener_name) not in existing_critical_globals
    )
    additional_findings = (*rce_findings, *startup_findings)
    if not additional_findings:
        return report

    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(*report.findings, *additional_findings),
        notices=report.notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=report.to_dict()["metadata"],
        duration_s=report.duration_s,
    )


def _startup_hook_write_finding_to_report_finding(report: PickleReport, finding: StartupHookWriteFinding) -> Finding:
    return Finding(
        message=(
            f"Pickle globals '{finding.opener_import_reference}' and "
            f"'{finding.writer_import_reference}' can open and write "
            "attacker-controlled files through the installed call graph"
        ),
        severity=Severity.CRITICAL,
        location=report.source,
        rule_code="DANGEROUS_CALL_GRAPH_FILE_WRITE",
        details={
            "module": finding.writer_module,
            "name": finding.writer_name,
            "import_reference": finding.writer_import_reference,
            "opener_module": finding.opener_module,
            "opener_name": finding.opener_name,
            "opener_import_reference": finding.opener_import_reference,
            "open_sink": finding.open_sink,
            "write_sink": finding.write_sink,
            "opener_call_path": list(finding.opener_call_path),
            "writer_call_path": list(finding.writer_call_path),
            "analysis": "python_call_graph_startup_hook_write",
        },
        why=(
            "The pickle imports Python wrappers that can open a pickle-controlled path and write "
            "pickle-controlled content, which can create executable Python startup hooks."
        ),
    )


def _call_graph_finding_to_report_finding(report: PickleReport, finding: CallGraphFinding) -> Finding:
    return Finding(
        message=(
            f"Pickle global '{finding.import_reference}' reaches dangerous Python "
            f"primitive '{finding.sink}' through the installed call graph"
        ),
        severity=Severity.CRITICAL,
        location=report.source,
        rule_code="DANGEROUS_CALL_GRAPH",
        details={
            "module": finding.module,
            "name": finding.name,
            "import_reference": finding.import_reference,
            "sink": finding.sink,
            "call_path": list(finding.call_path),
            "analysis": "python_call_graph",
        },
        why=(
            "The pickle imports a Python wrapper whose source code reaches a known RCE-capable primitive when invoked."
        ),
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
    if type(value) is int:
        return value
    raise TypeError(f"expected int or None, got {type(value).__name__}")


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


def _stream_is_seekable(stream: BinaryIO) -> bool:
    try:
        return bool(stream.seekable())
    except (AttributeError, OSError, ValueError):
        return False


def _read_stream_payload(
    stream: BinaryIO,
    size: int | None,
    *,
    max_known_read_bytes: int,
    max_unbounded_read_bytes: int,
) -> tuple[bytes, bool]:
    with tempfile.SpooledTemporaryFile(max_size=max_unbounded_read_bytes, mode="w+b") as spool:
        stream_truncated = False
        if size is None:
            remaining = max_unbounded_read_bytes
            while remaining > 0:
                chunk = stream.read(min(_RUST_STREAM_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                spool.write(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                stream_truncated = bool(stream.read(1)) if _stream_is_seekable(stream) else True
        else:
            remaining = min(size, max_known_read_bytes)
            stream_truncated = size > max_known_read_bytes
            bytes_read = 0
            while remaining > 0:
                chunk = stream.read(min(_RUST_STREAM_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    spool.seek(0)
                    raise _StreamShortReadError(
                        expected_size=size,
                        bytes_read=bytes_read,
                        partial_payload=spool.read(),
                    )
                spool.write(chunk)
                bytes_read += len(chunk)
                remaining -= len(chunk)

        spool.seek(0)
        return spool.read(), stream_truncated


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
