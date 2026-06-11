"""Public scanner entrypoints for standalone pickle analysis."""

from __future__ import annotations

import os
import pickletools
import tempfile
import zipfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, BinaryIO, cast

from .call_graph import (
    CallGraphFinding,
    StartupHookWriteFinding,
    UnanalyzedCallGraphReference,
    _begin_shared_source_report,
    _CallGraphAnalysisLimitError,
    _ensure_shared_source_snapshot_stable,
    find_analyzed_callable_call_graph_global_positions,
    find_dangerous_call_graphs,
    find_startup_hook_write_call_graphs,
    find_unanalyzed_callable_call_graph_references,
    has_unanalyzed_call_graph_import_references,
    import_only_module_requires_origin_review,
    import_only_reference_is_proven_trusted,
    module_initialization_is_proven_inert,
    shared_source_fingerprint_metadata,
    shared_source_sensitive_caches,
)
from .options import ScanOptions
from .report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity

_RUST_STREAM_READ_CHUNK_SIZE = 1024 * 1024
_CALL_GRAPH_SOURCE_FINGERPRINTS_KEY = "call_graph_source_fingerprints"
_PYTORCH_ZIP_METADATA_BASENAMES = frozenset({"version", "byteorder"})
_PYTORCH_CHECKPOINT_SUFFIXES = frozenset({".pt", ".pth", ".ckpt"})
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
_PICKLE_FRAME_OPCODE_BYTES = 9
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
_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES = 4 * 1024 * 1024
_MAX_PYTORCH_ZIP_PICKLE_MEMBERS = 256
_MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_PYTORCH_ZIP_PICKLE_TOTAL_MEMBER_BYTES = 512 * 1024 * 1024
_RUST_EXTENSION_MODULE = "modelaudit_picklescan._rust"
_MAX_INERT_INITIALIZATION_MODULES = 32
_TRUSTED_REFERENCE_RECONSTRUCTION_OPCODES = frozenset({"BUILD", "NEWOBJ", "NEWOBJ_EX"})
_TRUSTED_FRAMEWORK_IMPORT_ONLY_METADATA_REFERENCES = frozenset(
    {
        ("accelerate.state", "PartialState"),
        ("accelerate.utils.dataclasses", "DeepSpeedPlugin"),
        ("accelerate.utils.dataclasses", "DistributedType"),
        ("torch", "bfloat16"),
        ("torch", "device"),
        ("transformers.integrations.deepspeed", "HfDeepSpeedConfig"),
        ("transformers.integrations.deepspeed", "HfTrainerDeepSpeedConfig"),
        ("transformers.trainer_pt_utils", "AcceleratorConfig"),
        ("transformers.trainer_utils", "HubStrategy"),
        ("transformers.trainer_utils", "IntervalStrategy"),
        ("transformers.trainer_utils", "SaveStrategy"),
        ("transformers.trainer_utils", "SchedulerType"),
        ("transformers.training_args", "OptimizerNames"),
        ("transformers.training_args", "TrainingArguments"),
    }
)
_TRUSTED_FRAMEWORK_REDUCE_REFERENCES = frozenset(
    {
        ("accelerate.utils.dataclasses", "DistributedType"),
        ("torch", "device"),
        ("transformers.trainer_utils", "HubStrategy"),
        ("transformers.trainer_utils", "IntervalStrategy"),
        ("transformers.trainer_utils", "SaveStrategy"),
        ("transformers.trainer_utils", "SchedulerType"),
        ("transformers.training_args", "OptimizerNames"),
    }
)
_TRUSTED_REDUCE_REFERENCES = (
    frozenset(
        {
            ("string", "Formatter"),
            ("weakref", "proxy"),
            ("weakref", "ref"),
        }
    )
    | _TRUSTED_FRAMEWORK_REDUCE_REFERENCES
)
_TRUSTED_RECONSTRUCTION_WITHOUT_SOURCE_ANALYSIS_REFERENCES = frozenset(
    {
        ("_frozen_importlib", "ModuleSpec"),
        ("string", "Formatter"),
        ("weakref", "proxy"),
        ("weakref", "ref"),
    }
)
_TRUSTED_REDUCE_WITHOUT_SOURCE_ANALYSIS_REFERENCES = _TRUSTED_REDUCE_REFERENCES - _TRUSTED_FRAMEWORK_REDUCE_REFERENCES
_NUMPY_RECONSTRUCT_REFERENCES = frozenset(
    {
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy.core.multiarray", "_reconstruct"),
    }
)
_NUMPY_NDARRAY_REFERENCES = frozenset({("numpy", "ndarray")})
_NUMPY_DTYPE_REFERENCES = frozenset({("numpy", "dtype")})
_CODECS_ENCODE_REFERENCES = frozenset({("_codecs", "encode")})
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


class _PickleDiscoveryProbeBudgetExceeded(ValueError):
    """Raised when another hidden ZIP-member probe would exceed the byte budget."""


@dataclass(frozen=True)
class _AbstractGlobal:
    module: str
    name: str


@dataclass(frozen=True)
class _AbstractBytes:
    pass


@dataclass(frozen=True)
class _AbstractNumpyDType:
    pass


@dataclass(frozen=True)
class _AbstractNumpyArraySeed:
    pass


@dataclass(frozen=True)
class _AbstractNumpyArray:
    pass


@dataclass(frozen=True)
class _AbstractCallResult:
    function: object
    args: object


_ABSTRACT_MARK = object()
_ABSTRACT_UNKNOWN = object()


class PickleScanner:
    """State-light scanner facade configured only by scan options.

    The standalone package uses the Rust scanner directly; there is no Python
    engine selector or runtime fallback behind this facade.
    """

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = ScanOptions() if options is None else options

    def scan_bytes(
        self,
        data: bytes | bytearray | memoryview,
        *,
        source: str = "<bytes>",
        enrich_call_graph: bool = True,
    ) -> PickleReport:
        """Scan a raw pickle byte payload."""
        payload = bytes(data)
        return _scan_pickle_payload_native(
            payload,
            source=source,
            options=self.options,
            bytes_total=len(payload),
            enrich_call_graph=enrich_call_graph,
        )

    def scan_stream(
        self,
        stream: BinaryIO,
        *,
        source: str = "<stream>",
        size: int | None = None,
        enrich_call_graph: bool = True,
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
                    enrich_call_graph=enrich_call_graph,
                )
                return _with_short_read_error(
                    partial_report,
                    source=source,
                    error=error,
                    stream_start_offset=position_offset,
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
            enrich_call_graph=enrich_call_graph,
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
                stream_start_offset=position_offset,
            )
        return report

    def scan_file(self, path: str | Path, *, enrich_call_graph: bool = True) -> PickleReport:
        """Scan a pickle file path, including pickle members in PyTorch ZIP containers."""
        source = str(path)
        path_obj = Path(path)
        size: int | None = None
        try:
            with path_obj.open("rb") as handle:
                size = os.fstat(handle.fileno()).st_size
                if zipfile.is_zipfile(handle):
                    handle.seek(0)
                    container_report = self._scan_pytorch_zip_file(
                        handle,
                        source=source,
                        size=size,
                        enrich_call_graph=enrich_call_graph,
                    )
                    if container_report is not None:
                        return container_report
                    if _has_pytorch_checkpoint_suffix(path_obj):
                        return _unsupported_zip_report(source=source, size=size)
                handle.seek(0)
                return self.scan_stream(
                    handle,
                    source=source,
                    size=size,
                    enrich_call_graph=enrich_call_graph,
                )
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

    def _scan_pytorch_zip_file(
        self,
        path_or_stream: Path | BinaryIO,
        *,
        source: str,
        size: int,
        enrich_call_graph: bool = True,
    ) -> PickleReport | None:
        preflight_entry_count = _read_zip_entry_count(path_or_stream, size)
        if preflight_entry_count is not None and preflight_entry_count > _MAX_PYTORCH_ZIP_ENTRIES:
            return _pytorch_zip_entry_limit_report(
                source=source,
                size=size,
                entry_count=preflight_entry_count,
            )

        with zipfile.ZipFile(path_or_stream, "r") as archive:
            entries = _bounded_zip_entries(archive, source=source, size=size)
            if isinstance(entries, PickleReport):
                return entries
            if not _has_pytorch_zip_metadata(entries):
                return None

            pickle_entries, discovery_notices = _discover_pytorch_zip_pickle_entries(archive, entries, source=source)
            probe_budget_exhausted = any(
                notice.code == "pytorch_zip_pickle_discovery_probe_budget" for notice in discovery_notices
            )
            if (
                not _is_pytorch_zip_archive(
                    entries,
                    discovered_pickle_entries=pickle_entries,
                )
                and not probe_budget_exhausted
            ):
                return None
            if not pickle_entries:
                if probe_budget_exhausted:
                    return _combine_pytorch_zip_reports(
                        source=source,
                        size=size,
                        entry_count=len(entries),
                        pickle_entries=[],
                        member_reports=[],
                        extra_notices=discovery_notices,
                    )
                return _pytorch_zip_notice_report(
                    source=source,
                    size=size,
                    message="PyTorch ZIP archive does not contain pickle members to scan",
                    code="pytorch_zip_no_pickle_members",
                    details={"analysis_incomplete": True},
                )

            reports: list[PickleReport] = []
            skipped_notices: list[Notice] = list(discovery_notices)
            scanned_pickle_member_count = 0
            scanned_pickle_member_bytes = 0
            budget_skipped_entries: list[zipfile.ZipInfo] = []
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
                if (
                    scanned_pickle_member_count >= _MAX_PYTORCH_ZIP_PICKLE_MEMBERS
                    or scanned_pickle_member_bytes + entry.file_size > _MAX_PYTORCH_ZIP_PICKLE_TOTAL_MEMBER_BYTES
                ):
                    budget_skipped_entries.append(entry)
                    continue
                scanned_pickle_member_count += 1
                scanned_pickle_member_bytes += entry.file_size
                try:
                    with archive.open(entry, "r") as member_stream:
                        reports.append(
                            self.scan_stream(
                                cast(BinaryIO, member_stream),
                                source=member_source,
                                size=entry.file_size,
                                enrich_call_graph=enrich_call_graph,
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

            if budget_skipped_entries:
                skipped_notices.append(
                    _pytorch_zip_pickle_member_budget_notice(
                        source=source,
                        pickle_member_count=len(pickle_entries),
                        scanned_pickle_member_count=scanned_pickle_member_count,
                        total_pickle_member_bytes=sum(entry.file_size for entry in pickle_entries),
                        scanned_pickle_member_bytes=scanned_pickle_member_bytes,
                        skipped_entries=budget_skipped_entries,
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
    enrich_call_graph: bool = True,
) -> PickleReport:
    """Convenience wrapper around :meth:`PickleScanner.scan_bytes`."""
    return PickleScanner(options=options).scan_bytes(data, source=source, enrich_call_graph=enrich_call_graph)


def scan_stream(
    stream: BinaryIO,
    *,
    source: str = "<stream>",
    size: int | None = None,
    options: ScanOptions | None = None,
    enrich_call_graph: bool = True,
) -> PickleReport:
    """Convenience wrapper around :meth:`PickleScanner.scan_stream`."""
    return PickleScanner(options=options).scan_stream(
        stream,
        source=source,
        size=size,
        enrich_call_graph=enrich_call_graph,
    )


def scan_file(
    path: str | Path,
    *,
    options: ScanOptions | None = None,
    enrich_call_graph: bool = True,
) -> PickleReport:
    """Convenience wrapper around :meth:`PickleScanner.scan_file`."""
    return PickleScanner(options=options).scan_file(path, enrich_call_graph=enrich_call_graph)


def _read_zip_entry_count(path_or_stream: Path | BinaryIO, file_size: int) -> int | None:
    if file_size < _ZIP_EOCD_MIN_SIZE:
        return None

    if isinstance(path_or_stream, Path):
        try:
            with path_or_stream.open("rb") as handle:
                return _read_zip_entry_count_from_stream(handle, file_size)
        except OSError:
            return None

    try:
        position = path_or_stream.tell()
    except (AttributeError, OSError, ValueError):
        return None
    try:
        return _read_zip_entry_count_from_stream(path_or_stream, file_size)
    finally:
        with suppress(AttributeError, OSError, ValueError):
            path_or_stream.seek(position)


def _read_zip_entry_count_from_stream(handle: BinaryIO, file_size: int) -> int | None:
    tail_size = min(file_size, _ZIP_EOCD_MIN_SIZE + _ZIP_MAX_COMMENT_SIZE)
    try:
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


def _has_pytorch_zip_metadata(entries: list[zipfile.ZipInfo]) -> bool:
    names = [entry.filename for entry in entries if not entry.is_dir()]
    return any(Path(name).name in _PYTORCH_ZIP_METADATA_BASENAMES for name in names)


def _is_pytorch_zip_archive(
    entries: list[zipfile.ZipInfo],
    *,
    discovered_pickle_entries: list[zipfile.ZipInfo] | None = None,
) -> bool:
    names = [entry.filename for entry in entries if not entry.is_dir()]
    has_data_pickle = any(_is_data_pickle_member(name) for name in names)
    if not _has_pytorch_zip_metadata(entries):
        return False
    if has_data_pickle:
        return True
    has_pickle_members = any(name.lower().endswith(_PICKLE_MEMBER_SUFFIXES) for name in names)
    return has_pickle_members or bool(discovered_pickle_entries)


def _discover_pytorch_zip_pickle_entries(
    archive: zipfile.ZipFile,
    entries: list[zipfile.ZipInfo],
    *,
    source: str,
) -> tuple[list[zipfile.ZipInfo], tuple[Notice, ...]]:
    pickle_entries: list[zipfile.ZipInfo] = []
    notices: list[Notice] = []
    seen_entries: set[int] = set()
    candidates: list[zipfile.ZipInfo] = []

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
        candidates.append(entry)

    probe_bytes_remaining = [_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES]
    probed_member_count = 0
    for candidate_index, entry in enumerate(candidates):
        try:
            if _zip_entry_looks_like_pickle(archive, entry, probe_bytes_remaining):
                add_entry(entry)
            probed_member_count += 1
        except _PickleDiscoveryProbeBudgetExceeded:
            notices.append(
                _pytorch_zip_pickle_discovery_probe_budget_notice(
                    source=source,
                    probe_bytes_read=(_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES - probe_bytes_remaining[0]),
                    probed_member_count=probed_member_count,
                    skipped_entries=candidates[candidate_index:],
                )
            )
            break
        except Exception as error:
            notices.append(_pytorch_zip_member_probe_notice(source=source, entry=entry, error=error))

    return pickle_entries, tuple(notices)


def _read_zip_entry_probe(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    max_bytes: int,
    probe_bytes_remaining: list[int],
) -> bytes:
    expected_bytes = min(max(entry.file_size, 0), max_bytes)
    if expected_bytes == 0:
        return b""
    if expected_bytes > probe_bytes_remaining[0]:
        raise _PickleDiscoveryProbeBudgetExceeded

    with archive.open(entry, "r") as member:
        sample = member.read(min(max_bytes, probe_bytes_remaining[0]))
    probe_bytes_remaining[0] -= len(sample)
    return sample


def _zip_entry_looks_like_pickle(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    probe_bytes_remaining: list[int],
) -> bool:
    prefix = _read_zip_entry_probe(
        archive,
        entry,
        _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
        probe_bytes_remaining,
    )
    if not prefix:
        return False

    if prefix.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES):
        sample = _read_zip_entry_probe(
            archive,
            entry,
            _PICKLE_DISCOVERY_LONG_PROBE_BYTES,
            probe_bytes_remaining,
        )
        return _looks_like_binary_pickle_prefix(sample, sample_is_prefix=entry.file_size > len(sample))

    if prefix[0] not in _PROTO0_1_START_BYTES:
        return False

    sample = prefix
    if entry.file_size > len(prefix):
        sample = _read_zip_entry_probe(
            archive,
            entry,
            _PICKLE_DISCOVERY_LONG_PROBE_BYTES,
            probe_bytes_remaining,
        )
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


def _pytorch_zip_pickle_discovery_probe_budget_notice(
    *,
    source: str,
    probe_bytes_read: int,
    probed_member_count: int,
    skipped_entries: list[zipfile.ZipInfo],
) -> Notice:
    return Notice(
        message=(
            "PyTorch ZIP analysis stopped hidden pickle-member discovery because the archive exceeds the "
            "standalone aggregate decompressed probe-byte budget"
        ),
        severity=Severity.INFO,
        location=source,
        code="pytorch_zip_pickle_discovery_probe_budget",
        details={
            "probe_bytes_read": probe_bytes_read,
            "max_probe_bytes": _MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES,
            "probed_member_count": probed_member_count,
            "skipped_member_count": len(skipped_entries),
            "skipped_members": [entry.filename for entry in skipped_entries[:10]],
            "analysis_incomplete": True,
        },
    )


def _pytorch_zip_pickle_member_budget_notice(
    *,
    source: str,
    pickle_member_count: int,
    scanned_pickle_member_count: int,
    total_pickle_member_bytes: int,
    scanned_pickle_member_bytes: int,
    skipped_entries: list[zipfile.ZipInfo],
) -> Notice:
    return Notice(
        message=(
            "PyTorch ZIP analysis stopped scanning pickle members because the archive exceeds the standalone "
            "aggregate pickle-member budget"
        ),
        severity=Severity.INFO,
        location=source,
        code="pytorch_zip_pickle_member_budget",
        details={
            "pickle_member_count": pickle_member_count,
            "scanned_pickle_member_count": scanned_pickle_member_count,
            "skipped_pickle_member_count": len(skipped_entries),
            "max_pickle_members": _MAX_PYTORCH_ZIP_PICKLE_MEMBERS,
            "total_pickle_member_bytes": total_pickle_member_bytes,
            "scanned_pickle_member_bytes": scanned_pickle_member_bytes,
            "max_total_pickle_member_bytes": _MAX_PYTORCH_ZIP_PICKLE_TOTAL_MEMBER_BYTES,
            "skipped_pickle_members": [entry.filename for entry in skipped_entries[:10]],
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
    private_metadata = _combine_call_graph_source_fingerprint_private_metadata(member_reports)
    metadata: dict[str, Any] = {
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
    }
    for metadata_key in (
        "analysis_incomplete",
        "import_references_truncated",
        "callable_invocations_truncated",
        "non_allowlisted_global_imports_truncated",
    ):
        if any(report.metadata.get(metadata_key) is True for report in member_reports):
            metadata[metadata_key] = True
    if any(notice.details.get("analysis_incomplete") is True for notice in extra_notices):
        metadata["analysis_incomplete"] = True
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
        metadata=metadata,
        private_metadata=private_metadata,
        duration_s=sum(report.duration_s for report in member_reports),
    )


def _combine_call_graph_source_fingerprint_private_metadata(
    member_reports: list[PickleReport],
) -> dict[str, Any]:
    combined: dict[str, Any] | None = None
    missing_member_fingerprints = False
    for report in member_reports:
        fingerprint_metadata = report.private_metadata.get(_CALL_GRAPH_SOURCE_FINGERPRINTS_KEY)
        if not isinstance(fingerprint_metadata, Mapping):
            missing_member_fingerprints = True
            continue
        combined = _merge_call_graph_source_fingerprint_metadata(combined, fingerprint_metadata)
    if missing_member_fingerprints:
        combined = dict(combined or {})
        combined.pop("source_independent", None)
        combined["reusable"] = False
    return {_CALL_GRAPH_SOURCE_FINGERPRINTS_KEY: combined} if combined is not None else {}


def _merge_call_graph_source_fingerprint_metadata(
    existing: Mapping[str, Any] | None,
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    if _is_source_independent_call_graph_fingerprint_metadata(incoming):
        return dict(existing) if existing is not None else dict(incoming)
    if existing is not None and _is_source_independent_call_graph_fingerprint_metadata(existing):
        return dict(incoming)

    merged = dict(existing or {})
    existing_fingerprints = existing.get("fingerprints") if existing is not None else None
    incoming_fingerprints = incoming.get("fingerprints")
    fingerprints = dict(existing_fingerprints) if isinstance(existing_fingerprints, Mapping) else {}
    fingerprint_conflict = False
    if isinstance(incoming_fingerprints, Mapping):
        for path, fingerprint in incoming_fingerprints.items():
            if path in fingerprints and fingerprints[path] != fingerprint:
                fingerprint_conflict = True
                continue
            fingerprints[path] = fingerprint
    merged["fingerprints"] = fingerprints

    existing_read_fingerprints = existing.get("read_fingerprints") if existing is not None else None
    incoming_read_fingerprints = incoming.get("read_fingerprints")
    read_fingerprints = dict(existing_read_fingerprints) if isinstance(existing_read_fingerprints, Mapping) else {}
    read_fingerprint_conflict = False
    if isinstance(incoming_read_fingerprints, Mapping):
        for path, fingerprint_record in incoming_read_fingerprints.items():
            if path in read_fingerprints and read_fingerprints[path] != fingerprint_record:
                read_fingerprint_conflict = True
                continue
            read_fingerprints[path] = fingerprint_record
    merged["read_fingerprints"] = read_fingerprints

    existing_module_sources = existing.get("module_sources") if existing is not None else None
    incoming_module_sources = incoming.get("module_sources")
    module_sources = dict(existing_module_sources) if isinstance(existing_module_sources, Mapping) else {}
    module_source_conflict = False
    if isinstance(incoming_module_sources, Mapping):
        for module_name, source_path in incoming_module_sources.items():
            if module_name in module_sources and module_sources[module_name] != source_path:
                module_source_conflict = True
                continue
            module_sources[module_name] = source_path
    merged["module_sources"] = module_sources

    existing_loaded_sources = existing.get("loaded_module_sources") if existing is not None else None
    incoming_loaded_sources = incoming.get("loaded_module_sources")
    loaded_sources = dict(existing_loaded_sources) if isinstance(existing_loaded_sources, Mapping) else {}
    loaded_source_conflict = False
    if isinstance(incoming_loaded_sources, Mapping):
        for module_name, source_path in incoming_loaded_sources.items():
            if module_name in loaded_sources and loaded_sources[module_name] != source_path:
                loaded_source_conflict = True
                continue
            loaded_sources[module_name] = source_path
    merged["loaded_module_sources"] = loaded_sources

    existing_loaded_package_paths = existing.get("loaded_package_paths") if existing is not None else None
    incoming_loaded_package_paths = incoming.get("loaded_package_paths")
    loaded_package_paths = (
        dict(existing_loaded_package_paths) if isinstance(existing_loaded_package_paths, Mapping) else {}
    )
    loaded_package_path_conflict = False
    if isinstance(incoming_loaded_package_paths, Mapping):
        for module_name, search_path in incoming_loaded_package_paths.items():
            if module_name in loaded_package_paths and loaded_package_paths[module_name] != search_path:
                loaded_package_path_conflict = True
                continue
            loaded_package_paths[module_name] = search_path
    merged["loaded_package_paths"] = loaded_package_paths

    existing_search_context = existing.get("search_context") if existing is not None else incoming.get("search_context")
    incoming_search_context = incoming.get("search_context")
    existing_resolution_context = (
        existing.get("resolution_context") if existing is not None else incoming.get("resolution_context")
    )
    incoming_resolution_context = incoming.get("resolution_context")
    context_conflict = existing is not None and (
        existing_search_context != incoming_search_context or existing_resolution_context != incoming_resolution_context
    )
    if context_conflict:
        merged["reusable"] = False
    else:
        merged["search_context"] = incoming_search_context
        merged["resolution_context"] = incoming_resolution_context
        merged["reusable"] = (
            incoming.get("reusable") is True
            and not fingerprint_conflict
            and not read_fingerprint_conflict
            and not module_source_conflict
            and not loaded_source_conflict
            and not loaded_package_path_conflict
        )
        if existing is not None:
            merged["reusable"] = merged["reusable"] and existing.get("reusable") is True
    if (
        fingerprint_conflict
        or read_fingerprint_conflict
        or module_source_conflict
        or loaded_source_conflict
        or loaded_package_path_conflict
    ):
        merged["reusable"] = False
    return merged


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


def _without_unproven_oversized_frame_tamper(
    report: PickleReport,
    *,
    bytes_total: int | None,
    stream_start_offset: int,
) -> PickleReport:
    normalized_stream_start_offset = max(stream_start_offset, 0)

    def oversized_frame_is_proven(details: Mapping[str, Any]) -> bool:
        if details.get("overrun_boundary") in {"stop", "next_frame"}:
            return True
        if bytes_total is None:
            return False
        position = details.get("position")
        stream_offset = details.get("stream_offset")
        frame_length = details.get("frame_length")
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or isinstance(stream_offset, bool)
            or not isinstance(stream_offset, int)
            or isinstance(frame_length, bool)
            or not isinstance(frame_length, int)
        ):
            return True
        frame_payload_offset = position - normalized_stream_start_offset + _PICKLE_FRAME_OPCODE_BYTES
        if frame_payload_offset < 0:
            return True
        return frame_length > max(bytes_total - frame_payload_offset, 0)

    findings = tuple(
        finding
        for finding in report.findings
        if not (
            finding.rule_code == "STRUCTURAL_TAMPER"
            and finding.details.get("tamper_type") == "oversized_frame"
            and not oversized_frame_is_proven(finding.details)
        )
    )
    notices = tuple(
        notice
        for notice in report.notices
        if not (notice.code == "oversized_frame" and not oversized_frame_is_proven(notice.details))
    )
    if findings == report.findings and notices == report.notices:
        return report
    verdict = report.verdict
    if verdict == SafetyVerdict.SUSPICIOUS and not findings:
        verdict = SafetyVerdict.CLEAN
    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=verdict,
        findings=findings,
        notices=notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=report.to_dict()["metadata"],
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _with_unbounded_stream_notice(
    report: PickleReport,
    *,
    source: str,
    bytes_scanned: int,
    max_unbounded_read_bytes: int,
) -> PickleReport:
    report = _without_unproven_oversized_frame_tamper(report, bytes_total=None, stream_start_offset=0)
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
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _with_known_stream_notice(
    report: PickleReport,
    *,
    source: str,
    bytes_scanned: int,
    bytes_total: int,
    max_known_read_bytes: int,
    stream_start_offset: int,
) -> PickleReport:
    report = _without_unproven_oversized_frame_tamper(
        report,
        bytes_total=bytes_total,
        stream_start_offset=stream_start_offset,
    )
    notices = (
        *report.notices,
        Notice(
            message="Known-size pickle stream coverage could not be proven complete",
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
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _with_short_read_error(
    report: PickleReport,
    *,
    source: str,
    error: _StreamShortReadError,
    stream_start_offset: int,
) -> PickleReport:
    report = _without_unproven_oversized_frame_tamper(
        report,
        bytes_total=error.expected_size,
        stream_start_offset=stream_start_offset,
    )
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
        private_metadata=report.private_metadata,
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


def _has_pytorch_checkpoint_suffix(path: Path) -> bool:
    return path.suffix.lower() in _PYTORCH_CHECKPOINT_SUFFIXES


def _unsupported_zip_report(*, source: str, size: int) -> PickleReport:
    return PickleReport(
        source=source,
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message="ZIP archive is not a PyTorch checkpoint and cannot be scanned as a pickle stream",
                category="unsupported_zip_container",
                location=source,
                exception_type="ValueError",
                details={"analysis_incomplete": True},
            ),
        ),
        coverage=CoverageSummary(
            bytes_scanned=0,
            bytes_total=size,
            raw_scan_complete=False,
            opcode_scan_complete=False,
        ),
        metadata={
            "container_type": "zip",
            "analysis_incomplete": True,
        },
    )


def _scan_pickle_payload_native(
    payload: bytes,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
    enrich_call_graph: bool = True,
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
        report = _report_from_native_dict(raw_report)
        if enrich_call_graph:
            if _call_graph_enrichment_is_redundant(report):
                if _call_graph_has_no_source_inputs(report):
                    return _with_call_graph_source_fingerprint_metadata(
                        report,
                        _source_independent_call_graph_fingerprint_metadata(),
                    )
                with shared_source_sensitive_caches():
                    source_fingerprints = shared_source_fingerprint_metadata()
                return _with_call_graph_source_fingerprint_metadata(report, source_fingerprints)
            return _with_call_graph_findings(report, payload=payload)
        return _with_import_origin_findings(report)
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
        private_metadata=dict(_mapping(raw_report.get("private_metadata", {}))),
        duration_s=float(raw_report.get("duration_s", 0.0)),
    )


def _call_graph_enrichment_is_redundant(report: PickleReport) -> bool:
    if any(
        report.metadata.get(key)
        for key in (
            "import_references_truncated",
            "callable_invocations_truncated",
            "non_allowlisted_global_imports_truncated",
        )
    ):
        return False

    references = {
        (str(reference.get("module", "")), str(reference.get("name", "")))
        for raw_reference in (
            *_sequence(report.metadata.get("import_references")),
            *_sequence(report.metadata.get("callable_invocations")),
        )
        if (reference := _mapping(raw_reference))
        and str(reference.get("module", ""))
        and str(reference.get("name", ""))
    }
    if not references:
        return True

    critical_references = {
        (str(finding.details.get("module", "")), str(finding.details.get("name", "")))
        for finding in report.findings
        if finding.severity == Severity.CRITICAL
    }
    return references <= critical_references


def _call_graph_has_no_source_inputs(report: PickleReport) -> bool:
    return not any(
        report.metadata.get(key)
        for key in (
            "import_references",
            "callable_invocations",
            "import_references_truncated",
            "callable_invocations_truncated",
            "non_allowlisted_global_imports_truncated",
        )
    )


def _source_independent_call_graph_fingerprint_metadata() -> dict[str, Any]:
    return {
        "reusable": True,
        "source_independent": True,
        "fingerprints": {},
        "read_fingerprints": {},
        "module_sources": {},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
    }


def _is_source_independent_call_graph_fingerprint_metadata(metadata: Mapping[str, Any]) -> bool:
    return dict(metadata) == _source_independent_call_graph_fingerprint_metadata()


def _with_call_graph_findings(report: PickleReport, *, payload: bytes | None = None) -> PickleReport:
    import_references = report.metadata.get("import_references")
    callable_invocations = report.metadata.get("callable_invocations", ())
    enrichment_errors: list[tuple[str, Exception]] = []
    source_fingerprints: Mapping[str, Any] | None = None
    inert_initialization_modules: frozenset[str] = frozenset()
    trusted_import_references: frozenset[tuple[str, str]] = frozenset()
    analyzed_invocation_global_positions: frozenset[int] = frozenset()
    analyzed_invocation_references: frozenset[tuple[str, str]] = frozenset()
    source_snapshot_stable = True
    callable_invocations_complete = not bool(report.metadata.get("callable_invocations_truncated"))
    non_allowlisted_global_imports_complete = not bool(report.metadata.get("non_allowlisted_global_imports_truncated"))
    invocation_classification: (
        tuple[
            frozenset[int],
            frozenset[int],
            frozenset[tuple[str, str]],
        ]
        | None
    )
    try:
        invocation_classification = (
            _invoked_global_positions(callable_invocations),
            _trusted_reconstruction_global_positions(callable_invocations),
            _trusted_reconstruction_references(callable_invocations),
        )
    except Exception as error:
        invocation_classification = None
        callable_invocations_complete = False
        enrichment_errors.append(("python_import_invocation_classification", error))
    with shared_source_sensitive_caches():
        report_generation = _begin_shared_source_report()
        call_graph_limit_exceeded = has_unanalyzed_call_graph_import_references(import_references)
        try:
            report = _with_untrusted_allowlisted_import_findings(report, import_references)
        except Exception as error:
            enrichment_errors.append(("python_import_allowlist_origin", error))
        try:
            call_graph_findings = find_dangerous_call_graphs(import_references, callable_invocations)
        except _CallGraphAnalysisLimitError as error:
            call_graph_findings = error.partial_findings
            enrichment_errors.append(("python_call_graph", error))
        except Exception as error:
            call_graph_findings = ()
            enrichment_errors.append(("python_call_graph", error))
        try:
            startup_hook_write_findings = find_startup_hook_write_call_graphs(
                import_references,
                callable_invocations,
                callable_invocations_complete=callable_invocations_complete,
            )
        except _CallGraphAnalysisLimitError as error:
            startup_hook_write_findings = error.partial_startup_hook_write_findings
            enrichment_errors.append(("python_call_graph_startup_hook_write", error))
        except Exception as error:
            startup_hook_write_findings = ()
            enrichment_errors.append(("python_call_graph_startup_hook_write", error))
        try:
            unanalyzed_references = find_unanalyzed_callable_call_graph_references(callable_invocations)
        except Exception as error:
            unanalyzed_references = ()
            enrichment_errors.append(("python_call_graph_source_unavailable", error))
        try:
            analyzed_invocation_global_positions = find_analyzed_callable_call_graph_global_positions(
                callable_invocations
            )
            analyzed_invocation_references = _invocation_references_for_positions(
                callable_invocations,
                analyzed_invocation_global_positions,
            )
        except Exception as error:
            enrichment_errors.append(("python_import_invocation_analysis", error))
        try:
            inert_initialization_modules = _proven_inert_initialization_modules(report)
        except Exception as error:
            enrichment_errors.append(("python_import_initialization", error))
        try:
            trusted_import_references = _proven_trusted_import_references(report)
        except Exception as error:
            enrichment_errors.append(("python_import_reference_trust", error))
        try:
            _ensure_shared_source_snapshot_stable(report_generation)
        except _CallGraphAnalysisLimitError as error:
            source_snapshot_stable = False
            enrichment_errors.append(("python_call_graph_source_stability", error))
        source_fingerprints = shared_source_fingerprint_metadata()

    if (
        source_snapshot_stable
        and callable_invocations_complete
        and non_allowlisted_global_imports_complete
        and invocation_classification is not None
        and (
            inert_initialization_modules
            or trusted_import_references
            or _has_trusted_framework_import_only_metadata_findings(report)
        )
    ):
        (
            invoked_global_positions,
            trusted_reconstruction_global_positions,
            trusted_reconstruction_references,
        ) = invocation_classification
        report = _without_proven_safe_import_findings(
            report,
            inert_initialization_modules,
            trusted_import_references,
            invoked_global_positions,
            analyzed_invocation_global_positions,
            analyzed_invocation_references,
            trusted_reconstruction_global_positions,
            trusted_reconstruction_references,
        )
    updated_report = _with_call_graph_source_fingerprint_metadata(report, source_fingerprints)
    updated_report = (
        _with_unanalyzed_call_graph_notices(updated_report, unanalyzed_references)
        if unanalyzed_references
        else updated_report
    )
    if (
        not call_graph_findings
        and not startup_hook_write_findings
        and not call_graph_limit_exceeded
        and not enrichment_errors
    ):
        return updated_report

    existing_critical_globals = {
        (str(finding.details.get("module", "")), str(finding.details.get("name", "")))
        for finding in updated_report.findings
        if finding.severity == Severity.CRITICAL
    }
    suppress_safe_numpy_reconstruct = _pickle_payload_has_only_safe_numpy_ndarray_reconstruction(payload)
    rce_findings = tuple(
        _call_graph_finding_to_report_finding(updated_report, finding)
        for finding in call_graph_findings
        if (finding.module, finding.name) not in existing_critical_globals
        and not _call_graph_finding_is_safe_numpy_reconstruction_noise(
            finding,
            suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
        )
    )
    startup_findings = tuple(
        _startup_hook_write_finding_to_report_finding(updated_report, finding)
        for finding in startup_hook_write_findings
        if (finding.writer_module, finding.writer_name) not in existing_critical_globals
        and (finding.opener_module, finding.opener_name) not in existing_critical_globals
    )
    limit_findings = (
        (_call_graph_import_reference_limit_finding_to_report_finding(updated_report),)
        if call_graph_limit_exceeded and not rce_findings and not startup_findings
        else ()
    )
    additional_findings = (*rce_findings, *startup_findings, *limit_findings)
    updated_report = (
        PickleReport(
            source=updated_report.source,
            status=updated_report.status,
            verdict=SafetyVerdict.MALICIOUS,
            findings=(*updated_report.findings, *additional_findings),
            notices=updated_report.notices,
            errors=updated_report.errors,
            coverage=updated_report.coverage,
            metadata=updated_report.to_dict()["metadata"],
            private_metadata=updated_report.private_metadata,
            duration_s=updated_report.duration_s,
        )
        if additional_findings
        else updated_report
    )
    return (
        _with_call_graph_enrichment_errors(updated_report, tuple(enrichment_errors))
        if enrichment_errors
        else updated_report
    )


def _with_import_origin_findings(report: PickleReport) -> PickleReport:
    enrichment_errors: list[tuple[str, Exception]] = []
    source_fingerprints: Mapping[str, Any] | None = None
    with shared_source_sensitive_caches():
        report_generation = _begin_shared_source_report()
        try:
            report = _with_untrusted_allowlisted_import_findings(
                report,
                report.metadata.get("import_references"),
            )
        except Exception as error:
            enrichment_errors.append(("python_import_allowlist_origin", error))
        try:
            _ensure_shared_source_snapshot_stable(report_generation)
        except _CallGraphAnalysisLimitError as error:
            enrichment_errors.append(("python_import_origin_stability", error))
        source_fingerprints = shared_source_fingerprint_metadata()
    updated_report = _with_call_graph_source_fingerprint_metadata(report, source_fingerprints)
    return (
        _with_call_graph_enrichment_errors(updated_report, tuple(enrichment_errors))
        if enrichment_errors
        else updated_report
    )


def _proven_inert_initialization_modules(report: PickleReport) -> frozenset[str]:
    modules: list[str] = []
    seen: set[str] = set()
    for finding in report.findings:
        if finding.rule_code != "NON_ALLOWLISTED_GLOBAL":
            continue
        module = str(finding.details.get("module", ""))
        if not module or module in seen:
            continue
        seen.add(module)
        modules.append(module)
        if len(modules) >= _MAX_INERT_INITIALIZATION_MODULES:
            break
    return frozenset(module for module in modules if module_initialization_is_proven_inert(module))


def _with_untrusted_allowlisted_import_findings(
    report: PickleReport,
    import_references: object,
) -> PickleReport:
    existing_references = {
        (
            str(finding.details.get("import_reference", "")),
            finding.details.get("position"),
        )
        for finding in report.findings
    }
    additional_findings: list[Finding] = []
    for raw_reference in _sequence(import_references):
        reference = _mapping(raw_reference)
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        import_reference = str(reference.get("import_reference", ""))
        raw_position = reference.get("position")
        position = raw_position if type(raw_position) is int else None
        key = (import_reference, position)
        if (
            not module
            or not name
            or not import_reference
            or bool(reference.get("is_dangerous"))
            or not bool(reference.get("requires_origin_verification"))
            or key in existing_references
            or not import_only_module_requires_origin_review(module, name)
        ):
            continue
        additional_findings.append(
            Finding(
                message=f"Found allowlisted global reference from an untrusted module origin: {import_reference}",
                severity=Severity.WARNING,
                location=f"{report.source} (pos {position})" if position is not None else report.source,
                rule_code="NON_ALLOWLISTED_GLOBAL",
                details={
                    "opcode": str(reference.get("opcode", "")),
                    "module": module,
                    "name": name,
                    "import_reference": import_reference,
                    "position": position,
                },
                why=(
                    "Allowlisted modules are safe only when they resolve from the standard library or installed "
                    "site-packages; a project-local shadow module can execute arbitrary import-time code."
                ),
            )
        )
        existing_references.add(key)
    if not additional_findings:
        return report
    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=SafetyVerdict.MALICIOUS if report.verdict == SafetyVerdict.MALICIOUS else SafetyVerdict.SUSPICIOUS,
        findings=(*report.findings, *additional_findings),
        notices=report.notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=report.to_dict()["metadata"],
        duration_s=report.duration_s,
    )


def _proven_trusted_import_references(report: PickleReport) -> frozenset[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for finding in report.findings:
        if finding.rule_code != "NON_ALLOWLISTED_GLOBAL":
            continue
        module = str(finding.details.get("module", ""))
        name = str(finding.details.get("name", ""))
        if not module or not name or not import_only_reference_is_proven_trusted(module, name):
            continue
        references.append((module, name))
        if len(references) >= _MAX_INERT_INITIALIZATION_MODULES:
            break
    return frozenset(references)


def _has_trusted_framework_import_only_metadata_findings(report: PickleReport) -> bool:
    return any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and (
            str(finding.details.get("module", "")),
            str(finding.details.get("name", "")),
        )
        in _TRUSTED_FRAMEWORK_IMPORT_ONLY_METADATA_REFERENCES
        for finding in report.findings
    )


def _without_proven_safe_import_findings(
    report: PickleReport,
    inert_initialization_modules: frozenset[str],
    trusted_import_references: frozenset[tuple[str, str]],
    invoked_global_positions: frozenset[int],
    analyzed_invocation_global_positions: frozenset[int],
    analyzed_invocation_references: frozenset[tuple[str, str]],
    trusted_reconstruction_global_positions: frozenset[int],
    trusted_reconstruction_references: frozenset[tuple[str, str]],
) -> PickleReport:
    findings = tuple(
        finding
        for finding in report.findings
        if finding.rule_code != "NON_ALLOWLISTED_GLOBAL"
        or not _non_allowlisted_import_finding_is_proven_safe(
            finding,
            inert_initialization_modules,
            trusted_import_references,
            invoked_global_positions,
            analyzed_invocation_global_positions,
            analyzed_invocation_references,
            trusted_reconstruction_global_positions,
            trusted_reconstruction_references,
        )
    )
    if len(findings) == len(report.findings):
        return report
    verdict = report.verdict
    if verdict == SafetyVerdict.SUSPICIOUS:
        if findings:
            verdict = SafetyVerdict.SUSPICIOUS
        elif report.status == ScanStatus.COMPLETE:
            verdict = SafetyVerdict.CLEAN
        else:
            verdict = SafetyVerdict.UNKNOWN
    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=verdict,
        findings=findings,
        notices=report.notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=report.to_dict()["metadata"],
        duration_s=report.duration_s,
    )


def _non_allowlisted_import_finding_is_proven_safe(
    finding: Finding,
    inert_initialization_modules: frozenset[str],
    trusted_import_references: frozenset[tuple[str, str]],
    invoked_global_positions: frozenset[int],
    analyzed_invocation_global_positions: frozenset[int],
    analyzed_invocation_references: frozenset[tuple[str, str]],
    trusted_reconstruction_global_positions: frozenset[int],
    trusted_reconstruction_references: frozenset[tuple[str, str]],
) -> bool:
    module = str(finding.details.get("module", ""))
    name = str(finding.details.get("name", ""))
    raw_position = finding.details.get("position")
    position = raw_position if type(raw_position) is int else None
    reference = (module, name)
    finding_is_invoked = position is not None and _finding_is_invoked(
        finding,
        position,
        invoked_global_positions,
    )
    invocation_is_analyzed = (
        position in analyzed_invocation_global_positions
        if position is not None
        else reference in analyzed_invocation_references
    )
    invocation_is_trusted_reconstruction = (
        position in trusted_reconstruction_global_positions
        if position is not None
        else reference in trusted_reconstruction_references
    )
    inert_reference_is_proven_safe = position is not None and not finding_is_invoked
    trusted_reference_is_proven_safe = position is not None and (
        not finding_is_invoked or invocation_is_analyzed or invocation_is_trusted_reconstruction
    )
    framework_import_only_metadata_is_proven_safe = (
        position is not None
        and not finding_is_invoked
        and reference in _TRUSTED_FRAMEWORK_IMPORT_ONLY_METADATA_REFERENCES
    )
    return (
        framework_import_only_metadata_is_proven_safe
        or (trusted_reference_is_proven_safe and (module, name) in trusted_import_references)
        or (inert_reference_is_proven_safe and module in inert_initialization_modules)
    )


def _finding_is_invoked(
    finding: Finding,
    position: int,
    invoked_global_positions: frozenset[int],
) -> bool:
    return finding.details.get("invoked") is True or position in invoked_global_positions


def _invoked_global_positions(callable_invocations: object) -> frozenset[int]:
    positions: set[int] = set()
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        position = _optional_int(invocation.get("global_position"))
        if position is not None:
            positions.add(position)
    return frozenset(positions)


def _invocation_references_for_positions(
    callable_invocations: object,
    positions: frozenset[int],
) -> frozenset[tuple[str, str]]:
    references: set[tuple[str, str]] = set()
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        position = _optional_int(invocation.get("global_position"))
        module = str(invocation.get("module", ""))
        name = str(invocation.get("name", ""))
        if position in positions and module and name:
            references.add((module, name))
    return frozenset(references)


def _trusted_reconstruction_global_positions(callable_invocations: object) -> frozenset[int]:
    opcodes_by_position: dict[int, set[str]] = {}
    references_by_position: dict[int, set[tuple[str, str]]] = {}
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        position = _optional_int(invocation.get("global_position"))
        if position is None:
            continue
        opcodes_by_position.setdefault(position, set()).add(str(invocation.get("opcode", "")))
        module = str(invocation.get("module", ""))
        name = str(invocation.get("name", ""))
        if module and name:
            references_by_position.setdefault(position, set()).add((module, name))
    return frozenset(
        position
        for position, opcodes in opcodes_by_position.items()
        if opcodes
        and (
            (
                opcodes <= _TRUSTED_REFERENCE_RECONSTRUCTION_OPCODES
                and references_by_position.get(position)
                and references_by_position[position] <= _TRUSTED_RECONSTRUCTION_WITHOUT_SOURCE_ANALYSIS_REFERENCES
            )
            or (
                opcodes <= {"REDUCE"}
                and references_by_position.get(position)
                and references_by_position[position] <= _TRUSTED_REDUCE_WITHOUT_SOURCE_ANALYSIS_REFERENCES
            )
        )
    )


def _trusted_reconstruction_references(callable_invocations: object) -> frozenset[tuple[str, str]]:
    opcodes_by_reference: dict[tuple[str, str], set[str]] = {}
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        module = str(invocation.get("module", ""))
        name = str(invocation.get("name", ""))
        if not module or not name:
            continue
        opcodes_by_reference.setdefault((module, name), set()).add(str(invocation.get("opcode", "")))
    return frozenset(
        reference
        for reference, opcodes in opcodes_by_reference.items()
        if opcodes
        and (
            (
                opcodes <= _TRUSTED_REFERENCE_RECONSTRUCTION_OPCODES
                and reference in _TRUSTED_RECONSTRUCTION_WITHOUT_SOURCE_ANALYSIS_REFERENCES
            )
            or (opcodes <= {"REDUCE"} and reference in _TRUSTED_REDUCE_WITHOUT_SOURCE_ANALYSIS_REFERENCES)
        )
    )


def _call_graph_finding_is_safe_numpy_reconstruction_noise(
    finding: CallGraphFinding,
    *,
    suppress_safe_numpy_reconstruct: bool,
) -> bool:
    return (
        suppress_safe_numpy_reconstruct
        and (finding.module, finding.name) in _NUMPY_RECONSTRUCT_REFERENCES
        and finding.sink == "builtins.__import__"
        and finding.invocation_opcode in {None, "BUILD", "REDUCE"}
        and (
            not finding.call_path
            or finding.call_path[0]
            in {
                "numpy._core.multiarray.__getattr__",
                "numpy.core.multiarray.__getattr__",
            }
        )
    )


def _pickle_payload_has_only_safe_numpy_ndarray_reconstruction(payload: bytes | None) -> bool:
    if not payload:
        return False

    stack: list[object] = []
    memo: dict[int, object] = {}
    saw_numpy_reconstruct = False
    unsafe_numpy_reconstruct = False

    def pop_value() -> object:
        return stack.pop() if stack else _ABSTRACT_UNKNOWN

    def memo_key(value: object) -> int | None:
        if type(value) is int:
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return None

    def pop_marked_items() -> list[object] | None:
        items: list[object] = []
        while stack:
            item = stack.pop()
            if item is _ABSTRACT_MARK:
                return list(reversed(items))
            items.append(item)
        return None

    try:
        opcodes = tuple(pickletools.genops(payload))
    except Exception:
        return False

    for opcode, arg, _pos in opcodes:
        opcode_name = opcode.name
        if opcode_name in {"EXT1", "EXT2", "EXT4", "NEXT_BUFFER", "READONLY_BUFFER"}:
            return False
        if opcode_name in {"PROTO", "FRAME"}:
            continue
        if opcode_name == "STOP":
            break
        if opcode_name == "MARK":
            stack.append(_ABSTRACT_MARK)
        elif opcode_name == "GLOBAL":
            module, name = _pickle_global_arg_parts(arg)
            stack.append(_AbstractGlobal(module, name) if module and name else _ABSTRACT_UNKNOWN)
        elif opcode_name == "STACK_GLOBAL":
            stack_name = pop_value()
            stack_module = pop_value()
            stack.append(
                _AbstractGlobal(stack_module, stack_name)
                if isinstance(stack_module, str) and isinstance(stack_name, str)
                else _ABSTRACT_UNKNOWN
            )
        elif opcode_name in {
            "BINUNICODE",
            "SHORT_BINUNICODE",
            "BINUNICODE8",
            "UNICODE",
            "STRING",
            "BINSTRING",
            "SHORT_BINSTRING",
        }:
            stack.append(str(arg))
        elif opcode_name in {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"}:
            stack.append(_AbstractBytes())
        elif opcode_name in {
            "BININT",
            "BININT1",
            "BININT2",
            "LONG",
            "LONG1",
            "LONG4",
            "INT",
            "FLOAT",
            "BINFLOAT",
        }:
            stack.append(arg)
        elif opcode_name == "NONE":
            stack.append(None)
        elif opcode_name == "NEWTRUE":
            stack.append(True)
        elif opcode_name == "NEWFALSE":
            stack.append(False)
        elif opcode_name == "EMPTY_TUPLE":
            stack.append(())
        elif opcode_name == "EMPTY_LIST":
            stack.append([])
        elif opcode_name == "EMPTY_DICT":
            stack.append({})
        elif opcode_name == "TUPLE":
            items = pop_marked_items()
            stack.append(tuple(items) if items is not None else _ABSTRACT_UNKNOWN)
        elif opcode_name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
            tuple_size = int(opcode_name[-1])
            if len(stack) < tuple_size:
                stack.append(_ABSTRACT_UNKNOWN)
                continue
            items = stack[-tuple_size:]
            del stack[-tuple_size:]
            stack.append(tuple(items))
        elif opcode_name == "LIST":
            items = pop_marked_items()
            stack.append(items if items is not None else _ABSTRACT_UNKNOWN)
        elif opcode_name == "APPEND":
            value = pop_value()
            if stack and isinstance(stack[-1], list):
                stack[-1].append(value)
            else:
                stack.append(_ABSTRACT_UNKNOWN)
        elif opcode_name == "APPENDS":
            items = pop_marked_items()
            if items is not None and stack and isinstance(stack[-1], list):
                stack[-1].extend(items)
            else:
                stack.append(_ABSTRACT_UNKNOWN)
        elif opcode_name == "DICT":
            items = pop_marked_items()
            stack.append(_abstract_dict_from_items(items) if items is not None else _ABSTRACT_UNKNOWN)
        elif opcode_name == "SETITEM":
            value = pop_value()
            key = pop_value()
            if stack and isinstance(stack[-1], dict):
                stack[-1][key] = value
            else:
                stack.append(_ABSTRACT_UNKNOWN)
        elif opcode_name == "SETITEMS":
            items = pop_marked_items()
            if items is not None and stack and isinstance(stack[-1], dict):
                stack[-1].update(_abstract_dict_from_items(items))
            else:
                stack.append(_ABSTRACT_UNKNOWN)
        elif opcode_name in {"BINPUT", "LONG_BINPUT", "PUT"}:
            key = memo_key(arg)
            if key is not None and stack:
                memo[key] = stack[-1]
        elif opcode_name == "MEMOIZE":
            if stack:
                memo[len(memo)] = stack[-1]
        elif opcode_name in {"BINGET", "LONG_BINGET", "GET"}:
            key = memo_key(arg)
            stack.append(memo.get(key, _ABSTRACT_UNKNOWN) if key is not None else _ABSTRACT_UNKNOWN)
        elif opcode_name == "REDUCE":
            args = pop_value()
            function = pop_value()
            if _abstract_global_is(function, _CODECS_ENCODE_REFERENCES):
                stack.append(
                    _AbstractBytes() if _codecs_encode_args_are_safe(args) else _AbstractCallResult(function, args)
                )
            elif _abstract_global_is(function, _NUMPY_DTYPE_REFERENCES):
                stack.append(
                    _AbstractNumpyDType()
                    if _numpy_dtype_reduce_args_are_safe(args)
                    else _AbstractCallResult(function, args)
                )
            elif _abstract_global_is(function, _NUMPY_RECONSTRUCT_REFERENCES):
                saw_numpy_reconstruct = True
                if _numpy_reconstruct_args_are_safe(args):
                    stack.append(_AbstractNumpyArraySeed())
                else:
                    unsafe_numpy_reconstruct = True
                    stack.append(_AbstractCallResult(function, args))
            else:
                stack.append(_AbstractCallResult(function, args))
        elif opcode_name == "BUILD":
            state = pop_value()
            obj = pop_value()
            if isinstance(obj, _AbstractNumpyArraySeed):
                if _numpy_ndarray_build_state_is_safe(state):
                    stack.append(_AbstractNumpyArray())
                else:
                    unsafe_numpy_reconstruct = True
                    stack.append(_ABSTRACT_UNKNOWN)
            elif isinstance(obj, _AbstractNumpyDType):
                stack.append(obj if _numpy_dtype_build_state_is_safe(state) else _ABSTRACT_UNKNOWN)
            else:
                stack.append(obj)
        elif opcode_name == "POP":
            if stack:
                stack.pop()
        elif opcode_name == "POP_MARK":
            pop_marked_items()
        elif opcode_name == "DUP":
            stack.append(stack[-1] if stack else _ABSTRACT_UNKNOWN)
        elif opcode_name in {"PERSID", "BINPERSID"}:
            stack.append(_ABSTRACT_UNKNOWN)
        else:
            stack.append(_ABSTRACT_UNKNOWN)

    return saw_numpy_reconstruct and not unsafe_numpy_reconstruct


def _pickle_global_arg_parts(arg: object) -> tuple[str, str]:
    if isinstance(arg, str):
        parts = arg.replace("\n", " ").split()
        if len(parts) == 2:
            return parts[0], parts[1]
    return "", ""


def _abstract_global_is(value: object, references: frozenset[tuple[str, str]]) -> bool:
    return isinstance(value, _AbstractGlobal) and (value.module, value.name) in references


def _abstract_dict_from_items(items: list[object]) -> dict[object, object]:
    return {items[index]: items[index + 1] for index in range(0, len(items) - 1, 2)}


def _codecs_encode_args_are_safe(args: object) -> bool:
    return isinstance(args, tuple) and len(args) == 2 and isinstance(args[0], str) and args[1] in {"latin1", "latin-1"}


def _numpy_dtype_reduce_args_are_safe(args: object) -> bool:
    return (
        isinstance(args, tuple)
        and len(args) == 3
        and isinstance(args[0], str)
        and isinstance(args[1], bool)
        and isinstance(args[2], bool)
    )


def _numpy_reconstruct_args_are_safe(args: object) -> bool:
    return (
        isinstance(args, tuple)
        and len(args) == 3
        and _abstract_global_is(args[0], _NUMPY_NDARRAY_REFERENCES)
        and _abstract_int_tuple_is_safe(args[1])
        and _abstract_bytes_value_is_safe(args[2])
    )


def _numpy_dtype_build_state_is_safe(state: object) -> bool:
    return _abstract_value_is_inert(state)


def _numpy_ndarray_build_state_is_safe(state: object) -> bool:
    return (
        isinstance(state, tuple)
        and len(state) == 5
        and isinstance(state[0], int)
        and not isinstance(state[0], bool)
        and _abstract_int_tuple_is_safe(state[1])
        and isinstance(state[2], _AbstractNumpyDType)
        and isinstance(state[3], bool)
        and _abstract_bytes_value_is_safe(state[4])
    )


def _abstract_int_tuple_is_safe(value: object) -> bool:
    return isinstance(value, tuple) and all(isinstance(item, int) and not isinstance(item, bool) for item in value)


def _abstract_bytes_value_is_safe(value: object) -> bool:
    return isinstance(value, (str, bytes, bytearray, _AbstractBytes))


def _abstract_value_is_inert(value: object) -> bool:
    if value is _ABSTRACT_UNKNOWN or value is _ABSTRACT_MARK:
        return False
    if isinstance(value, (_AbstractGlobal, _AbstractCallResult, _AbstractNumpyArraySeed)):
        return False
    if isinstance(value, (_AbstractBytes, _AbstractNumpyDType, _AbstractNumpyArray)):
        return True
    if value is None or isinstance(value, (str, bytes, bytearray, int, float, bool)):
        return True
    if isinstance(value, (tuple, list)):
        return all(_abstract_value_is_inert(item) for item in value)
    if isinstance(value, dict):
        return all(_abstract_value_is_inert(key) and _abstract_value_is_inert(item) for key, item in value.items())
    return False


def _with_call_graph_enrichment_errors(
    report: PickleReport,
    enrichment_errors: tuple[tuple[str, Exception], ...],
) -> PickleReport:
    errors = (
        *report.errors,
        *(
            ScanError(
                message=f"Python call-graph analysis could not complete: {error!s}",
                category="call_graph_analysis_error",
                location=report.source,
                exception_type=type(error).__name__,
                details={"analysis": analysis, "analysis_incomplete": True},
            )
            for analysis, error in enrichment_errors
        ),
    )
    metadata = {**report.to_dict()["metadata"], "analysis_incomplete": True}
    return PickleReport(
        source=report.source,
        status=ScanStatus.INCONCLUSIVE if report.status == ScanStatus.COMPLETE else report.status,
        verdict=(
            report.verdict
            if report.verdict in {SafetyVerdict.SUSPICIOUS, SafetyVerdict.MALICIOUS}
            else SafetyVerdict.UNKNOWN
        ),
        findings=report.findings,
        notices=report.notices,
        errors=errors,
        coverage=report.coverage,
        metadata=metadata,
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _with_call_graph_source_fingerprint_metadata(
    report: PickleReport,
    source_fingerprints: Mapping[str, Any] | None,
) -> PickleReport:
    if source_fingerprints is None:
        return report
    private_metadata = dict(report.private_metadata)
    private_metadata[_CALL_GRAPH_SOURCE_FINGERPRINTS_KEY] = dict(source_fingerprints)
    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=report.verdict,
        findings=report.findings,
        notices=report.notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=report.to_dict()["metadata"],
        private_metadata=private_metadata,
        duration_s=report.duration_s,
    )


def _with_unanalyzed_call_graph_notices(
    report: PickleReport,
    references: tuple[UnanalyzedCallGraphReference, ...],
) -> PickleReport:
    notices = (
        *report.notices,
        *(
            Notice(
                message="Python call-graph analysis could not inspect invoked callable source",
                severity=Severity.INFO,
                location=report.source,
                code="call_graph_source_unavailable",
                details={
                    "module": reference.module,
                    "name": reference.name,
                    "import_reference": reference.import_reference,
                    "reason": reference.reason,
                    "analysis_incomplete": True,
                },
            )
            for reference in references
        ),
    )
    metadata = {**report.to_dict()["metadata"], "analysis_incomplete": True}
    return PickleReport(
        source=report.source,
        status=ScanStatus.INCONCLUSIVE if report.status == ScanStatus.COMPLETE else report.status,
        verdict=(
            report.verdict
            if report.verdict in {SafetyVerdict.SUSPICIOUS, SafetyVerdict.MALICIOUS}
            else SafetyVerdict.UNKNOWN
        ),
        findings=report.findings,
        notices=notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=metadata,
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _call_graph_import_reference_limit_finding_to_report_finding(report: PickleReport) -> Finding:
    return Finding(
        message="Python call-graph analysis skipped import references beyond the unique-reference limit",
        severity=Severity.CRITICAL,
        location=report.source,
        rule_code="DANGEROUS_CALL_GRAPH_LIMIT",
        details={
            "analysis": "python_call_graph_limit",
            "max_unique_import_references": 32,
            "analysis_incomplete": True,
        },
        why=(
            "The pickle imports more unique globals than the bounded Python call-graph pass analyzes; "
            "unanalyzed globals can hide call-graph-only RCE primitives."
        ),
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
            **(
                {"invocation_import_reference": finding.invocation_import_reference}
                if finding.invocation_import_reference is not None
                else {}
            ),
            **({"opcode": finding.invocation_opcode} if finding.invocation_opcode is not None else {}),
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
            if not stream_truncated and _known_stream_has_uncovered_data(stream):
                stream_truncated = True

        spool.seek(0)
        return spool.read(), stream_truncated


def _known_stream_has_uncovered_data(stream: BinaryIO) -> bool:
    if not _stream_is_seekable(stream):
        return True
    try:
        position = stream.tell()
    except (AttributeError, OSError, ValueError):
        return True

    try:
        trailing_data = bool(stream.read(1))
    except Exception:
        with suppress(AttributeError, OSError, ValueError):
            stream.seek(position)
        return True
    if not trailing_data:
        return False
    with suppress(AttributeError, OSError, ValueError):
        stream.seek(position)
    return True


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
