"""Public scanner entrypoints for standalone pickle analysis."""

from __future__ import annotations

import ast
import io
import os
import pickletools
import tempfile
import time
import zipfile
from _collections import OrderedDict as _CANONICAL_COLLECTIONS_ORDERED_DICT
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from importlib import import_module
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, BinaryIO, cast

from .call_graph import (
    CallGraphFinding,
    StartupHookWriteFinding,
    UnanalyzedCallGraphReference,
    _begin_shared_source_report,
    _CallGraphAnalysisLimitError,
    _ensure_shared_source_snapshot_stable,
    _find_module_spec_without_imports,
    _is_skippable_pytorch_storage_persistent_id_reference,
    _module_spec_fields_without_hooks,
    _runtime_module_attribute_without_hooks,
    class_static_attribute_lookup_is_proven_source_backed,
    find_analyzed_callable_call_graph_global_positions,
    find_dangerous_call_graphs,
    find_startup_hook_write_call_graphs,
    find_unanalyzed_callable_call_graph_references,
    has_unanalyzed_call_graph_import_references,
    import_only_module_load_is_proven_safe_for_invocation,
    import_only_module_requires_origin_review,
    import_only_reference_is_proven_trusted,
    import_only_reference_is_proven_trusted_for_pickle_invocation,
    module_initialization_is_proven_inert,
    module_is_loaded_without_import_hooks,
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
_PICKLE_OPCODE_BYTES = frozenset(ord(opcode.code) for opcode in pickletools.opcodes)
_PICKLE_SECURITY_RELEVANT_OPCODES = frozenset(
    {"GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}
)
_PICKLE_DISCOVERY_SHORT_PROBE_BYTES = 16
_PICKLE_DISCOVERY_LONG_PROBE_BYTES = 64 * 1024
_TRUSTED_STORAGE_PICKLE_PROBE_BYTES = 4 * 1024
_PICKLE_FRAME_OPCODE = b"\x95"
_PROTO0_1_START_BYTES = b"()]}cilp0FGIJKLMNSTUVX"
_PROTO0_1_MAX_PROBE_OPCODES = _PICKLE_DISCOVERY_LONG_PROBE_BYTES
_PROTO0_1_IGNORABLE_TRAILING_BYTES = b" \t\r\n\x00"
_PROTO0_1_PREFIX_TRUNCATION_ERROR_PREFIXES = (
    "pickle exhausted before seeing STOP",
    "no newline found when trying to read ",
)
_PICKLE_FRAME_OPCODE_BYTES = 9
_PICKLE_INCOMPLETE_FRAME_MIN_PAYLOAD_OPCODES = 4
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
_MAX_PYTORCH_ZIP_STORAGE_REFERENCE_DATA_PICKLE_BYTES = 10 * 1024 * 1024
_MAX_PYTORCH_ZIP_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES = 64 * 1024 * 1024
_PYTORCH_STORAGE_TRUST_MAX_OPCODES = 100_000
_PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH = 1024
_PYTORCH_STORAGE_TRUST_MAX_MEMO_ENTRIES = 100_000
_PYTORCH_STORAGE_TRUST_MAX_TUPLE_WIDTH = 64
_PYTORCH_STORAGE_TRUST_MAX_REFERENCED_KEYS = 10_000
_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX = 2**63 - 1
_RUST_EXTENSION_MODULE = "modelaudit_picklescan._rust"
_MAX_INERT_INITIALIZATION_MODULES = 32
_SAFE_NUMPY_RECONSTRUCT_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024
_SAFE_NUMPY_RECONSTRUCT_MAX_OPCODES = 100_000
_TRUSTED_REFERENCE_RECONSTRUCTION_OPCODES = frozenset({"BUILD", "NEWOBJ", "NEWOBJ_EX"})
_PYTORCH_STORAGE_GLOBAL_NAMES = frozenset(
    {
        "BFloat16Storage",
        "BoolStorage",
        "ByteStorage",
        "CharStorage",
        "ComplexDoubleStorage",
        "ComplexFloatStorage",
        "DoubleStorage",
        "FloatStorage",
        "HalfStorage",
        "IntStorage",
        "LongStorage",
        "QInt32Storage",
        "QInt8Storage",
        "QUInt8Storage",
        "QUInt4x2Storage",
        "QUInt2x4Storage",
        "ShortStorage",
        "UntypedStorage",
    }
)
_PYTORCH_STORAGE_GLOBALS = frozenset(
    (module, name) for module in ("torch", "torch.storage") for name in _PYTORCH_STORAGE_GLOBAL_NAMES
)
_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT = str(_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX)
_PYTORCH_STORAGE_ITEM_SIZES = {
    "BFloat16Storage": 2,
    "BoolStorage": 1,
    "ByteStorage": 1,
    "CharStorage": 1,
    "ComplexDoubleStorage": 16,
    "ComplexFloatStorage": 8,
    "DoubleStorage": 8,
    "FloatStorage": 4,
    "HalfStorage": 2,
    "IntStorage": 4,
    "LongStorage": 8,
    "QInt32Storage": 4,
    "QInt8Storage": 1,
    "QUInt8Storage": 1,
    "ShortStorage": 2,
    "UntypedStorage": 1,
}
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
_SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES = frozenset(
    {
        ("accelerate.state", "PartialState"),
        ("accelerate.utils.dataclasses", "DeepSpeedPlugin"),
        ("accelerate.utils.dataclasses", "DistributedType"),
        ("joblib.numpy_pickle", "NumpyArrayWrapper"),
        ("numpy", "dtype"),
        ("numpy", "ndarray"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "scalar"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy.core.multiarray", "scalar"),
        ("torch", "BFloat16Storage"),
        ("torch", "BoolStorage"),
        ("torch", "ByteStorage"),
        ("torch", "CharStorage"),
        ("torch", "ComplexDoubleStorage"),
        ("torch", "ComplexFloatStorage"),
        ("torch", "DoubleStorage"),
        ("torch", "FloatStorage"),
        ("torch", "HalfStorage"),
        ("torch", "IntStorage"),
        ("torch", "LongStorage"),
        ("torch", "QInt32Storage"),
        ("torch", "QInt8Storage"),
        ("torch", "QUInt2x4Storage"),
        ("torch", "QUInt4x2Storage"),
        ("torch", "QUInt8Storage"),
        ("torch", "ShortStorage"),
        ("torch", "Size"),
        ("torch", "Storage"),
        ("torch", "UntypedStorage"),
        ("torch", "_rebuild_tensor"),
        ("torch", "_rebuild_tensor_v2"),
        ("torch", "bfloat16"),
        ("torch", "device"),
        ("torch._tensor", "_rebuild_from_type_v2"),
        ("torch._utils", "_rebuild_device_tensor_from_numpy"),
        ("torch._utils", "_rebuild_meta_tensor_no_storage"),
        ("torch._utils", "_rebuild_nested_tensor"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_parameter_with_state"),
        ("torch._utils", "_rebuild_qtensor"),
        ("torch._utils", "_rebuild_sparse_tensor"),
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_tensor_v3"),
        ("torch._utils", "_rebuild_wrapper_subclass"),
        ("torch.serialization", "_get_layout"),
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
_NUMPY_SAFE_OBJECT_RECONSTRUCTION_REFERENCES = (
    _NUMPY_RECONSTRUCT_REFERENCES | _NUMPY_NDARRAY_REFERENCES | _NUMPY_DTYPE_REFERENCES
)
_CODECS_ENCODE_REFERENCES = frozenset({("_codecs", "encode")})
_TRUSTED_STATIC_GETATTR_RECONSTRUCTIONS = frozenset(
    {
        ("ultralytics.nn.modules.head", "Detect", "forward"),
    }
)
_GETATTR_RESOLVED_SOURCE_PROOF_POSITION = -10_002
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_MIN_SIZE = 22
_ZIP_MAX_COMMENT_SIZE = 0xFFFF
_ZIP64_EOCD_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_EOCD_LOCATOR_SIZE = 20
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_EOCD_MIN_SIZE = 56
_ZIP64_SENTINEL_ENTRY_COUNT = 0xFFFF


def _source_backed_invocation_requires_loaded_identity(
    reference: tuple[str, str],
    *,
    suppress_safe_numpy_reconstruct: bool,
) -> bool:
    if suppress_safe_numpy_reconstruct and reference in _NUMPY_SAFE_OBJECT_RECONSTRUCTION_REFERENCES:
        return False
    return reference in _SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES


def _source_backed_import_requires_initialization_proof(
    reference: tuple[str, str],
    *,
    suppress_safe_numpy_reconstruct: bool = False,
) -> bool:
    if suppress_safe_numpy_reconstruct and reference in _NUMPY_SAFE_OBJECT_RECONSTRUCTION_REFERENCES:
        return False
    return reference in _SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES


class _StreamShortReadError(ValueError):
    def __init__(self, *, expected_size: int, bytes_read: int, partial_payload: bytes) -> None:
        super().__init__("Stream ended before the declared size was read")
        self.expected_size = expected_size
        self.bytes_read = bytes_read
        self.partial_payload = partial_payload


class _PickleDiscoveryProbeBudgetExceeded(ValueError):
    """Raised when another hidden ZIP-member probe would exceed the byte budget."""


class _PytorchZipDeadlineExceeded(TimeoutError):
    """Raised when Python-side PyTorch ZIP analysis exceeds ScanOptions.timeout_s."""


@dataclass(frozen=True)
class _PickleGlobalRef:
    module: str
    name: str
    position: int


@dataclass(frozen=True)
class _PytorchStorageRef:
    key: str
    module: str
    name: str
    location: str
    element_count: int
    item_size: int | None


@dataclass
class _PytorchOrderedDictState:
    mutated: bool = False
    used_as_hooks: bool = False


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


@dataclass(frozen=True)
class _PytorchStorageReferenceParse:
    referenced_keys: set[str]
    storage_refs_by_key: dict[str, _PytorchStorageRef]
    storage_global_positions: set[int]
    canonical_tensor_rebuild_invocations: set[tuple[int, int]]
    parse_complete: bool
    all_persistent_ids_are_pytorch_storage: bool


@dataclass(frozen=True)
class _PytorchZipDataPickleTrust:
    storage_keys: set[str]
    canonical_tensor_rebuild_invocations: frozenset[tuple[int, int]]


@dataclass(frozen=True)
class _PytorchZipStorageEntries:
    trusted_entry_ids: set[int]
    storage_probe_entry_ids: set[int]
    trusted_data_pkl_by_name: dict[str, _PytorchZipDataPickleTrust]


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
        _pytorch_zip_storage_member_sizes: Mapping[str, int] | None = None,
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
        if not stream_truncated and _pytorch_zip_storage_member_sizes is not None:
            trusted_data_pkl = _trusted_pytorch_data_pkl_from_storage_member_sizes(
                payload,
                _pytorch_zip_storage_member_sizes,
            )
            if trusted_data_pkl is not None:
                report = _without_trusted_pytorch_data_pkl_findings(
                    report,
                    trusted_data_pkl,
                    remove_persistent_ids=False,
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
        deadline = time.monotonic() + self.options.timeout_s
        try:
            preflight_entry_count = _read_zip_entry_count(path_or_stream, size)
            _check_pytorch_zip_deadline(deadline)
            if preflight_entry_count is not None and preflight_entry_count > _MAX_PYTORCH_ZIP_ENTRIES:
                return _pytorch_zip_entry_limit_report(
                    source=source,
                    size=size,
                    entry_count=preflight_entry_count,
                )

            with zipfile.ZipFile(path_or_stream, "r") as archive:
                entries = _bounded_zip_entries(archive, source=source, size=size)
                _check_pytorch_zip_deadline(deadline)
                if isinstance(entries, PickleReport):
                    return entries
                if not _has_pytorch_zip_metadata(entries):
                    return None

                pickle_entries, discovery_notices, trusted_data_pkl_by_name = _discover_pytorch_zip_pickle_entries(
                    archive,
                    entries,
                    source=source,
                    options=self.options,
                    deadline=deadline,
                )
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
                    _check_pytorch_zip_deadline(deadline)
                    member_name = entry.filename
                    member_source = f"{source}:{member_name}"
                    if entry.file_size > _MAX_PYTORCH_ZIP_PICKLE_MEMBER_BYTES:
                        skipped_notices.append(
                            Notice(
                                message=(
                                    "PyTorch ZIP pickle member skipped because it exceeds the standalone member "
                                    "scan limit"
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
                            member_report = self.scan_stream(
                                cast(BinaryIO, member_stream),
                                source=member_source,
                                size=entry.file_size,
                                enrich_call_graph=enrich_call_graph,
                            )
                        trusted_data_pkl = trusted_data_pkl_by_name.get(member_name)
                        if trusted_data_pkl is not None:
                            member_report = _without_trusted_pytorch_data_pkl_findings(
                                member_report,
                                trusted_data_pkl,
                            )
                        reports.append(member_report)
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
        except _PytorchZipDeadlineExceeded:
            return _pytorch_zip_notice_report(
                source=source,
                size=size,
                message="PyTorch ZIP analysis stopped at the configured timeout",
                code="pytorch_zip_scan_timeout",
                details={"timeout_s": self.options.timeout_s, "analysis_incomplete": True},
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


def _check_pytorch_zip_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _PytorchZipDeadlineExceeded


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
    options: ScanOptions,
    deadline: float,
) -> tuple[list[zipfile.ZipInfo], tuple[Notice, ...], dict[str, _PytorchZipDataPickleTrust]]:
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

    storage_entries, storage_notices = _validated_pytorch_storage_entry_ids(
        archive,
        entries,
        source=source,
        options=options,
        deadline=deadline,
    )
    notices.extend(storage_notices)

    for entry in entries:
        if entry.is_dir() or id(entry) in seen_entries:
            continue
        candidates.append(entry)

    probe_bytes_remaining = [_MAX_PYTORCH_ZIP_PICKLE_DISCOVERY_PROBE_BYTES]
    probed_member_count = 0
    for candidate_index, entry in enumerate(candidates):
        _check_pytorch_zip_deadline(deadline)
        try:
            entry_id = id(entry)
            storage_probe_bytes = None
            if entry_id in storage_entries.trusted_entry_ids:
                storage_probe_bytes = _TRUSTED_STORAGE_PICKLE_PROBE_BYTES
            elif entry_id in storage_entries.storage_probe_entry_ids:
                storage_probe_bytes = _PICKLE_DISCOVERY_LONG_PROBE_BYTES
            if storage_probe_bytes is not None:
                looks_like_pickle = _trusted_storage_zip_entry_looks_like_pickle(
                    archive,
                    entry,
                    probe_bytes_remaining,
                    deadline,
                    max_probe_bytes=storage_probe_bytes,
                )
            else:
                looks_like_pickle = _zip_entry_looks_like_pickle(archive, entry, probe_bytes_remaining, deadline)
            if looks_like_pickle:
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

    return pickle_entries, tuple(notices), storage_entries.trusted_data_pkl_by_name


def _validated_pytorch_storage_entry_ids(
    archive: zipfile.ZipFile,
    entries: list[zipfile.ZipInfo],
    *,
    source: str,
    options: ScanOptions,
    deadline: float,
) -> tuple[_PytorchZipStorageEntries, tuple[Notice, ...]]:
    members = [
        (entry.filename, entry)
        for entry in entries
        if not entry.is_dir() and _is_canonical_pytorch_zip_member_name(entry.filename)
    ]
    entries_by_name: dict[str, list[zipfile.ZipInfo]] = {}
    for name, entry in members:
        entries_by_name.setdefault(name, []).append(entry)

    trusted_entry_ids: set[int] = set()
    storage_probe_entry_ids: set[int] = set()
    trusted_data_pkl_by_name: dict[str, _PytorchZipDataPickleTrust] = {}
    notices: list[Notice] = []
    storage_reference_bytes_read = 0
    storage_reference_opcodes_remaining = [min(_PYTORCH_STORAGE_TRUST_MAX_OPCODES, options.max_opcodes)]
    for data_pkl_name, data_pkl_entries in entries_by_name.items():
        _check_pytorch_zip_deadline(deadline)
        if data_pkl_name.rsplit("/", 1)[-1] != "data.pkl":
            continue
        prefix = data_pkl_name[: -len("data.pkl")]
        if f"{prefix}version" not in entries_by_name or len(data_pkl_entries) != 1:
            continue

        storage_entries_by_key: dict[str, zipfile.ZipInfo] = {}
        data_prefix = f"{prefix}data/"
        for candidate_name, candidate_entries in entries_by_name.items():
            if not candidate_name.startswith(data_prefix) or len(candidate_entries) != 1:
                continue
            storage_key = candidate_name[len(data_prefix) :]
            if _is_ascii_decimal_digits(storage_key):
                storage_entries_by_key[storage_key] = candidate_entries[0]
        if not storage_entries_by_key:
            continue

        data_pkl_entry = data_pkl_entries[0]
        if data_pkl_entry.file_size > _MAX_PYTORCH_ZIP_STORAGE_REFERENCE_DATA_PICKLE_BYTES:
            notices.append(
                _pytorch_zip_storage_reference_validation_notice(
                    source=source,
                    data_pkl_member=data_pkl_name,
                    message=(
                        f"PyTorch ZIP storage reference validation skipped oversized data.pkl member {data_pkl_name}"
                    ),
                    code="pytorch_zip_storage_reference_validation_size_limit",
                    details={
                        "member_size": data_pkl_entry.file_size,
                        "max_member_size": _MAX_PYTORCH_ZIP_STORAGE_REFERENCE_DATA_PICKLE_BYTES,
                    },
                )
            )
            continue

        try:
            if (
                storage_reference_bytes_read + data_pkl_entry.file_size
                > _MAX_PYTORCH_ZIP_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES
            ):
                notices.append(
                    _pytorch_zip_storage_reference_validation_notice(
                        source=source,
                        data_pkl_member=data_pkl_name,
                        message=(
                            "PyTorch ZIP storage reference validation skipped data.pkl members after "
                            f"{_MAX_PYTORCH_ZIP_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES} bytes"
                        ),
                        code="pytorch_zip_storage_reference_validation_failed",
                        details={
                            "member_size": data_pkl_entry.file_size,
                            "bytes_read": storage_reference_bytes_read,
                            "max_total_bytes": _MAX_PYTORCH_ZIP_STORAGE_REFERENCE_TOTAL_DATA_PICKLE_BYTES,
                        },
                    )
                )
                continue
            with archive.open(data_pkl_entry, "r") as member:
                pickle_data = member.read(_MAX_PYTORCH_ZIP_STORAGE_REFERENCE_DATA_PICKLE_BYTES)
            storage_reference_bytes_read += len(pickle_data)
        except Exception as error:
            notices.append(
                _pytorch_zip_storage_reference_validation_notice(
                    source=source,
                    data_pkl_member=data_pkl_name,
                    message=f"Could not inspect PyTorch ZIP data.pkl storage references: {error!s}",
                    code="pytorch_zip_storage_reference_validation_failed",
                    details={"exception_type": type(error).__name__},
                )
            )
            continue

        reference_parse = _pytorch_storage_keys_from_pickle_bytes(
            pickle_data,
            opcode_budget_remaining=storage_reference_opcodes_remaining,
            deadline=deadline,
        )
        if not reference_parse.parse_complete:
            notices.append(
                _pytorch_zip_storage_reference_validation_notice(
                    source=source,
                    data_pkl_member=data_pkl_name,
                    message=f"Could not parse PyTorch ZIP data.pkl storage references in {data_pkl_name}",
                    code="pytorch_zip_storage_reference_validation_failed",
                    details={},
                )
            )
            continue

        referenced_storage_keys = reference_parse.referenced_keys
        existing_storage_keys = set(storage_entries_by_key)
        missing_storage_keys = referenced_storage_keys - existing_storage_keys
        storage_size_mismatch_keys = {
            key
            for key in referenced_storage_keys & existing_storage_keys
            if _pytorch_storage_size_mismatches(
                storage_entries_by_key[key].file_size,
                reference_parse.storage_refs_by_key.get(key),
            )
        }
        if missing_storage_keys:
            notices.append(
                _pytorch_zip_storage_reference_validation_notice(
                    source=source,
                    data_pkl_member=data_pkl_name,
                    message=f"PyTorch ZIP data.pkl references missing tensor storage members in {data_pkl_name}",
                    code="pytorch_zip_storage_reference_missing_members",
                    details={
                        "missing_storage_keys": sorted(missing_storage_keys)[:10],
                        "missing_storage_key_count": len(missing_storage_keys),
                    },
                )
            )

        trusted_storage_keys = referenced_storage_keys & existing_storage_keys
        if storage_size_mismatch_keys and reference_parse.canonical_tensor_rebuild_invocations:
            notices.append(
                _pytorch_zip_storage_reference_validation_notice(
                    source=source,
                    data_pkl_member=data_pkl_name,
                    message=(
                        "PyTorch ZIP data.pkl references tensor storage members with unexpected sizes "
                        f"in {data_pkl_name}"
                    ),
                    code="pytorch_zip_storage_reference_size_mismatch",
                    details={
                        "storage_size_mismatch_keys": sorted(storage_size_mismatch_keys)[:10],
                        "storage_size_mismatch_key_count": len(storage_size_mismatch_keys),
                    },
                )
            )
        validated_storage_keys = trusted_storage_keys - storage_size_mismatch_keys
        exact_trusted_storage_keys = (
            validated_storage_keys if reference_parse.all_persistent_ids_are_pytorch_storage else set()
        )
        storage_probe_keys = trusted_storage_keys - exact_trusted_storage_keys
        if exact_trusted_storage_keys and not missing_storage_keys:
            trusted_data_pkl_by_name[data_pkl_name] = _PytorchZipDataPickleTrust(
                storage_keys=exact_trusted_storage_keys,
                canonical_tensor_rebuild_invocations=frozenset(
                    reference_parse.canonical_tensor_rebuild_invocations if not storage_size_mismatch_keys else set()
                ),
            )
        for storage_key in exact_trusted_storage_keys:
            trusted_entry_ids.add(id(storage_entries_by_key[storage_key]))
        for storage_key in storage_probe_keys:
            storage_probe_entry_ids.add(id(storage_entries_by_key[storage_key]))

    return (
        _PytorchZipStorageEntries(
            trusted_entry_ids=trusted_entry_ids,
            storage_probe_entry_ids=storage_probe_entry_ids,
            trusted_data_pkl_by_name=trusted_data_pkl_by_name,
        ),
        tuple(notices),
    )


def _pytorch_storage_size_mismatches(
    storage_size_bytes: int,
    storage_ref: _PytorchStorageRef | None,
) -> bool:
    if storage_ref is None or storage_ref.item_size is None:
        return True
    return storage_size_bytes != storage_ref.element_count * storage_ref.item_size


def _trusted_pytorch_data_pkl_from_storage_member_sizes(
    pickle_data: bytes,
    storage_member_sizes: Mapping[str, int],
) -> _PytorchZipDataPickleTrust | None:
    reference_parse = _pytorch_storage_keys_from_pickle_bytes(pickle_data)
    if (
        not reference_parse.parse_complete
        or not reference_parse.referenced_keys
        or not reference_parse.all_persistent_ids_are_pytorch_storage
    ):
        return None
    if not reference_parse.referenced_keys <= storage_member_sizes.keys():
        return None
    if any(
        not isinstance(storage_member_sizes[key], int)
        or isinstance(storage_member_sizes[key], bool)
        or _pytorch_storage_size_mismatches(
            int(storage_member_sizes[key]),
            reference_parse.storage_refs_by_key.get(key),
        )
        for key in reference_parse.referenced_keys
    ):
        return None
    return _PytorchZipDataPickleTrust(
        storage_keys=set(reference_parse.referenced_keys),
        canonical_tensor_rebuild_invocations=frozenset(reference_parse.canonical_tensor_rebuild_invocations),
    )


def _read_zip_entry_probe(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    max_bytes: int,
    probe_bytes_remaining: list[int],
    deadline: float,
) -> bytes:
    _check_pytorch_zip_deadline(deadline)
    expected_bytes = min(max(entry.file_size, 0), max_bytes)
    if expected_bytes == 0:
        return b""
    if expected_bytes > probe_bytes_remaining[0]:
        raise _PickleDiscoveryProbeBudgetExceeded

    with archive.open(entry, "r") as member:
        sample = member.read(min(max_bytes, probe_bytes_remaining[0]))
    _check_pytorch_zip_deadline(deadline)
    probe_bytes_remaining[0] -= len(sample)
    return sample


def _zip_entry_looks_like_pickle(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    probe_bytes_remaining: list[int],
    deadline: float,
) -> bool:
    prefix = _read_zip_entry_probe(
        archive,
        entry,
        _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
        probe_bytes_remaining,
        deadline,
    )
    if not prefix:
        return False

    if prefix.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES):
        sample = _read_zip_entry_probe(
            archive,
            entry,
            _PICKLE_DISCOVERY_LONG_PROBE_BYTES,
            probe_bytes_remaining,
            deadline,
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
            deadline,
        )
    return _looks_like_proto0_or_1_pickle(sample, sample_is_prefix=entry.file_size > len(sample))


def _trusted_storage_zip_entry_looks_like_pickle(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    probe_bytes_remaining: list[int],
    deadline: float,
    *,
    max_probe_bytes: int = _TRUSTED_STORAGE_PICKLE_PROBE_BYTES,
) -> bool:
    prefix = _read_zip_entry_probe(
        archive,
        entry,
        _PICKLE_DISCOVERY_SHORT_PROBE_BYTES,
        probe_bytes_remaining,
        deadline,
    )
    if not prefix:
        return False
    is_binary_pickle_candidate = prefix.startswith(_PICKLE_BINARY_PROTOCOL_PREFIXES)
    is_frame_first_candidate = prefix.startswith(_PICKLE_FRAME_OPCODE)
    if not is_binary_pickle_candidate and not is_frame_first_candidate and prefix[0] not in _PROTO0_1_START_BYTES:
        return False

    sample = prefix
    if entry.file_size > len(prefix):
        sample = _read_zip_entry_probe(
            archive,
            entry,
            max_probe_bytes,
            probe_bytes_remaining,
            deadline,
        )
    if is_binary_pickle_candidate:
        return _binary_pickle_probe_should_scan(sample, sample_is_prefix=entry.file_size > len(sample))
    if is_frame_first_candidate:
        return _frame_first_trusted_storage_probe_should_scan(sample)
    return _proto0_or_1_trusted_storage_probe_should_scan(sample, sample_is_prefix=entry.file_size > len(sample))


def _binary_pickle_probe_should_scan(sample: bytes, *, sample_is_prefix: bool) -> bool:
    opcode_count = 0
    try:
        for opcode, _arg, _pos in pickletools.genops(sample):
            opcode_count += 1
            if opcode.name == "STOP":
                return opcode_count >= 2
    except Exception:
        return sample_is_prefix and (opcode_count >= 2 or _has_known_binary_pickle_second_opcode(sample))
    return sample_is_prefix and opcode_count >= 2


def _has_known_binary_pickle_second_opcode(sample: bytes) -> bool:
    return len(sample) >= 3 and sample[2] in _PICKLE_OPCODE_BYTES


def _proto0_or_1_trusted_storage_probe_should_scan(sample: bytes, *, sample_is_prefix: bool) -> bool:
    if _has_complete_pickle_stream_without_frame_stop_overrun(sample):
        return True
    if _has_security_relevant_opcode_in_incomplete_frame(sample):
        return True
    if not sample_is_prefix:
        return False
    if _contains_pickle_frame_opcode(sample):
        return False
    return _looks_like_proto0_or_1_pickle(sample, sample_is_prefix=True)


def _frame_first_trusted_storage_probe_should_scan(sample: bytes) -> bool:
    if not sample.startswith(_PICKLE_FRAME_OPCODE):
        return False
    return _has_complete_pickle_stream_without_frame_stop_overrun(
        sample
    ) or _has_structural_pickle_evidence_in_incomplete_frame(sample)


def _has_structural_pickle_evidence_in_incomplete_frame(sample: bytes) -> bool:
    frame_end: int | None = None
    payload_opcode_count = 0
    try:
        for opcode, arg, pos in pickletools.genops(sample):
            if pos is None:
                continue
            if opcode.name == "FRAME":
                if frame_end is not None or not isinstance(arg, int):
                    return False
                frame_end = pos + _PICKLE_FRAME_OPCODE_BYTES + arg
                if frame_end <= len(sample):
                    return False
                continue
            if frame_end is None or pos >= frame_end:
                return False
            payload_opcode_count += 1
    except Exception as exc:
        message = str(exc).lower()
        return (
            frame_end is not None
            and frame_end > len(sample)
            and payload_opcode_count >= _PICKLE_INCOMPLETE_FRAME_MIN_PAYLOAD_OPCODES
            and (
                "exhausted before seeing stop" in message
                or "no newline found when trying to read" in message
                or "not enough data" in message
                or "expected" in message
            )
        )
    return frame_end is not None and payload_opcode_count >= _PICKLE_INCOMPLETE_FRAME_MIN_PAYLOAD_OPCODES


def _has_security_relevant_opcode_in_incomplete_frame(sample: bytes) -> bool:
    incomplete_frame_seen = False
    security_relevant_opcode_seen = False
    try:
        for opcode, arg, pos in pickletools.genops(sample):
            if opcode.name == "FRAME" and isinstance(arg, int) and pos is not None:
                incomplete_frame_seen = pos + _PICKLE_FRAME_OPCODE_BYTES + arg > len(sample)
            elif opcode.name in _PICKLE_SECURITY_RELEVANT_OPCODES:
                security_relevant_opcode_seen = True
            if incomplete_frame_seen and security_relevant_opcode_seen:
                return True
    except Exception:
        return incomplete_frame_seen and security_relevant_opcode_seen
    return False


def _contains_pickle_frame_opcode(sample: bytes) -> bool:
    try:
        return any(opcode.name == "FRAME" for opcode, _arg, _pos in pickletools.genops(sample))
    except Exception:
        return False


def _has_complete_pickle_stream_without_frame_stop_overrun(sample: bytes) -> bool:
    active_frame_end = 0
    opcode_count = 0
    try:
        for opcode, arg, pos in pickletools.genops(sample):
            opcode_count += 1
            if pos is None:
                continue
            if opcode.name == "FRAME":
                if not isinstance(arg, int):
                    return False
                active_frame_end = max(active_frame_end, pos + _PICKLE_FRAME_OPCODE_BYTES + arg)
            elif opcode.name == "STOP":
                return opcode_count >= 2 and active_frame_end <= len(sample)
    except Exception:
        return False
    return False


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
    normalized = _normalize_zip_member_name(name).lower()
    return normalized == "data.pkl" or normalized.endswith("/data.pkl")


def _normalize_zip_member_name(name: str) -> str:
    return name.replace("\\", "/").lstrip("/")


def _is_canonical_pytorch_zip_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    parts = name.split("/")
    return all(part and part not in {".", ".."} for part in parts)


def _is_ascii_decimal_digits(value: str) -> bool:
    return value.isascii() and value.isdecimal()


def _coerce_pickle_string_arg(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def _split_protocol0_persid_fields(text: str) -> list[str] | None:
    if not text.startswith("(") or not text.endswith(")"):
        return None
    fields: list[str] = []
    start = 1
    in_quote: str | None = None
    escaped = False
    for index, char in enumerate(text[1:-1], start=1):
        if escaped:
            escaped = False
            continue
        if in_quote is not None:
            if char == "\\":
                escaped = True
            elif char == in_quote:
                in_quote = None
            continue
        if char in {"'", '"'}:
            in_quote = char
        elif char == ",":
            fields.append(text[start:index].strip())
            start = index + 1
    if in_quote is not None:
        return None
    fields.append(text[start:-1].strip())
    return fields


def _quoted_protocol0_field_value(field: str) -> str | None:
    if len(field) < 2 or field[0] not in {"'", '"'} or field[-1] != field[0]:
        return None
    value = field[1:-1]
    return None if "\\" in value else value


def _parse_pytorch_storage_element_count_text(storage_size: str) -> int | None:
    if not storage_size.isascii() or not storage_size.isdecimal():
        return None
    normalized = storage_size.lstrip("0") or "0"
    if len(normalized) > len(_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT):
        return None
    if (
        len(normalized) == len(_PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT)
        and normalized > _PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX_TEXT
    ):
        return None
    return int(normalized)


def _storage_ref_from_protocol0_persid_text(
    pid_text: Any,
    trusted_storage_keys: set[str] | None = None,
) -> _PytorchStorageRef | None:
    text = _coerce_pickle_string_arg(pid_text)
    if text is None:
        return None
    fields = _split_protocol0_persid_fields(text)
    if fields is None or len(fields) != 5:
        return None
    if _quoted_protocol0_field_value(fields[0]) != "storage":
        return None
    storage_type_field = fields[1]
    if not storage_type_field.startswith("<class '") or not storage_type_field.endswith("'>"):
        return None
    module, separator, name = storage_type_field[len("<class '") : -len("'>")].rpartition(".")
    if not separator or (module, name) not in _PYTORCH_STORAGE_GLOBALS:
        return None
    storage_key = _quoted_protocol0_field_value(fields[2])
    if storage_key is None or not _is_ascii_decimal_digits(storage_key):
        return None
    if trusted_storage_keys is not None and storage_key not in trusted_storage_keys:
        return None
    if _quoted_protocol0_field_value(fields[3]) is None:
        return None
    element_count = _parse_pytorch_storage_element_count_text(fields[4])
    if element_count is None:
        return None
    return _PytorchStorageRef(
        storage_key,
        module,
        name,
        _quoted_protocol0_field_value(fields[3]) or "",
        element_count,
        _PYTORCH_STORAGE_ITEM_SIZES.get(name),
    )


def _structural_storage_key_from_protocol0_persid_text(
    pid_text: Any,
    trusted_storage_keys: set[str] | None = None,
) -> str | None:
    text = _coerce_pickle_string_arg(pid_text)
    if text is None:
        return None
    fields = _split_protocol0_persid_fields(text)
    if fields is None or len(fields) < 4:
        return None
    if _quoted_protocol0_field_value(fields[0]) != "storage":
        return None
    storage_type_field = fields[1]
    if not storage_type_field.startswith("<class '") or not storage_type_field.endswith("'>"):
        return None
    module, separator, name = storage_type_field[len("<class '") : -len("'>")].rpartition(".")
    if not separator or (module, name) not in _PYTORCH_STORAGE_GLOBALS:
        return None
    storage_key = _quoted_protocol0_field_value(fields[2])
    if storage_key is None or not _is_ascii_decimal_digits(storage_key):
        return None
    if trusted_storage_keys is not None and storage_key not in trusted_storage_keys:
        return None
    if _quoted_protocol0_field_value(fields[3]) is None:
        return None
    return storage_key


def _storage_key_from_protocol0_persid_text(
    pid_text: Any,
    trusted_storage_keys: set[str] | None = None,
) -> str | None:
    storage_ref = _storage_ref_from_protocol0_persid_text(pid_text, trusted_storage_keys)
    return storage_ref.key if storage_ref is not None else None


def _protocol0_persid_text_from_preview(preview: Any) -> str | None:
    if not isinstance(preview, str) or not preview.startswith("str:") or len(preview) > 4096:
        return None
    try:
        value = ast.literal_eval(preview[len("str:") :])
    except (SyntaxError, TypeError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _is_trusted_pytorch_storage_persistent_id_finding(
    finding: Finding,
    trusted_storage_keys: set[str],
) -> bool:
    if finding.rule_code != "PERSISTENT_ID":
        return False
    details = finding.details
    storage_key = details.get("pytorch_storage_key")
    if (
        details.get("opcode") == "BINPERSID"
        and details.get("pytorch_storage_persistent_id") is True
        and isinstance(storage_key, str)
    ):
        return storage_key in trusted_storage_keys

    if details.get("opcode") != "PERSID":
        return False
    if details.get("pytorch_storage_persistent_id") is True and isinstance(storage_key, str):
        return storage_key in trusted_storage_keys

    persid_text = _protocol0_persid_text_from_preview(details.get("persistent_id_preview"))
    return _storage_key_from_protocol0_persid_text(persid_text, trusted_storage_keys) is not None


def _without_trusted_pytorch_data_pkl_findings(
    report: PickleReport,
    trusted_data_pkl: _PytorchZipDataPickleTrust,
    *,
    remove_persistent_ids: bool = True,
) -> PickleReport:
    findings = tuple(
        finding
        for finding in report.findings
        if not (
            remove_persistent_ids
            and _is_trusted_pytorch_storage_persistent_id_finding(finding, trusted_data_pkl.storage_keys)
        )
        and not _is_trusted_canonical_pytorch_tensor_rebuild_finding(report, finding, trusted_data_pkl)
    )
    if len(findings) == len(report.findings):
        return report
    verdict = report.verdict if findings else SafetyVerdict.CLEAN
    if not findings and report.status != ScanStatus.COMPLETE:
        verdict = SafetyVerdict.UNKNOWN
    return replace(report, findings=findings, verdict=verdict)


def _is_trusted_canonical_pytorch_tensor_rebuild_finding(
    report: PickleReport,
    finding: Finding,
    trusted_data_pkl: _PytorchZipDataPickleTrust,
) -> bool:
    if (
        report.status != ScanStatus.COMPLETE
        or not trusted_data_pkl.canonical_tensor_rebuild_invocations
        or finding.rule_code != "NON_ALLOWLISTED_GLOBAL"
        or str(finding.details.get("module", "")) != "torch._utils"
        or str(finding.details.get("name", "")) != "_rebuild_tensor_v2"
        or module_is_loaded_without_import_hooks("torch")
        or module_is_loaded_without_import_hooks("torch._utils")
        or not _collections_ordered_dict_binding_is_canonical()
        or not _torch_utils_origin_matches_installed_distribution()
    ):
        return False
    metadata = report.metadata
    if (
        bool(metadata.get("import_references_truncated"))
        or bool(metadata.get("callable_invocations_truncated"))
        or bool(metadata.get("non_allowlisted_global_imports_truncated"))
    ):
        return False
    position = _optional_int(finding.details.get("position"))
    if position is None:
        return False
    if not _canonical_pytorch_tensor_rebuild_import_reference_matches(metadata.get("import_references"), position):
        return False
    return _canonical_pytorch_tensor_rebuild_invocations_match(
        metadata.get("callable_invocations"),
        position,
        trusted_data_pkl.canonical_tensor_rebuild_invocations,
    )


def _collections_ordered_dict_binding_is_canonical() -> bool:
    return _runtime_module_attribute_without_hooks("collections", "OrderedDict") is _CANONICAL_COLLECTIONS_ORDERED_DICT


def _torch_utils_origin_matches_installed_distribution() -> bool:
    if import_only_module_requires_origin_review("torch._utils", "_rebuild_tensor_v2"):
        return False
    origins = _torch_and_utils_origins_without_imports()
    if origins is None:
        return False
    try:
        distribution = importlib_metadata.distribution("torch")
        distribution_files = distribution.files
        if distribution_files is None:
            return False
        owned_files = {str(file).replace("\\", "/") for file in distribution_files}
        if not {"torch/__init__.py", "torch/_utils.py"} <= owned_files:
            return False
        expected_torch_origin = Path(str(distribution.locate_file("torch/__init__.py"))).resolve()
        expected_torch_utils_origin = Path(str(distribution.locate_file("torch/_utils.py"))).resolve()
    except (importlib_metadata.PackageNotFoundError, OSError, RuntimeError, ValueError):
        return False
    if module_is_loaded_without_import_hooks("torch") or module_is_loaded_without_import_hooks("torch._utils"):
        return False
    current_origins = _torch_and_utils_origins_without_imports()
    if current_origins != origins:
        return False
    return (
        Path(origins[0]).resolve() == expected_torch_origin
        and Path(origins[1]).resolve() == expected_torch_utils_origin
    )


def _torch_and_utils_origins_without_imports() -> tuple[str, str] | None:
    torch_spec = _find_module_spec_without_imports("torch")
    torch_utils_spec = _find_module_spec_without_imports("torch._utils")
    if torch_spec is None or torch_utils_spec is None:
        return None
    torch_origin, _torch_loader = _module_spec_fields_without_hooks(torch_spec)
    torch_utils_origin, _torch_utils_loader = _module_spec_fields_without_hooks(torch_utils_spec)
    if type(torch_origin) is not str or type(torch_utils_origin) is not str:
        return None
    return torch_origin, torch_utils_origin


def _canonical_pytorch_tensor_rebuild_import_reference_matches(import_references: object, position: int) -> bool:
    references = [
        _mapping(raw_reference)
        for raw_reference in _sequence(import_references)
        if _optional_int(_mapping(raw_reference).get("position")) == position
    ]
    return bool(references) and all(
        str(reference.get("module", "")) == "torch._utils"
        and str(reference.get("name", "")) == "_rebuild_tensor_v2"
        and str(reference.get("opcode", "")) == "GLOBAL"
        for reference in references
    )


def _canonical_pytorch_tensor_rebuild_invocations_match(
    callable_invocations: object,
    position: int,
    canonical_invocations: frozenset[tuple[int, int]],
) -> bool:
    observed_invocations: set[tuple[int, int]] = set()
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        if _optional_int(invocation.get("global_position")) != position:
            continue
        opcode_position = _optional_int(invocation.get("opcode_position"))
        if (
            str(invocation.get("module", "")) != "torch._utils"
            or str(invocation.get("name", "")) != "_rebuild_tensor_v2"
            or str(invocation.get("opcode", "")) != "REDUCE"
            or invocation.get("positional_arg_count") != 6
            or opcode_position is None
        ):
            return False
        observed_invocations.add((position, opcode_position))
    return bool(observed_invocations) and observed_invocations <= canonical_invocations


def _complete_pickle_stream_payloads(payload: bytes) -> tuple[tuple[int, bytes], ...] | None:
    streams: list[tuple[int, bytes]] = []
    offset = 0
    opcode_count = 0
    stream = io.BytesIO(payload)
    try:
        while offset < len(payload):
            stream_end: int | None = None
            stream.seek(offset)
            for opcode, _arg, position in pickletools.genops(stream):
                opcode_count += 1
                if opcode_count > _PYTORCH_STORAGE_TRUST_MAX_OPCODES:
                    return None
                if opcode.name != "STOP":
                    continue
                if type(position) is not int:
                    return None
                stream_end = position + 1
                break
            if stream_end is None:
                return None
            streams.append((offset, payload[offset:stream_end]))
            offset = stream_end
    except Exception:
        return None
    return tuple(streams)


def _merge_pytorch_storage_reference_parses(
    parses: tuple[_PytorchStorageReferenceParse, ...],
) -> _PytorchStorageReferenceParse:
    referenced_keys: set[str] = set()
    storage_refs_by_key: dict[str, _PytorchStorageRef] = {}
    storage_global_positions: set[int] = set()
    for parsed in parses:
        if not parsed.parse_complete:
            return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
        for key, storage_ref in parsed.storage_refs_by_key.items():
            existing_storage_ref = storage_refs_by_key.get(key)
            if existing_storage_ref is not None and existing_storage_ref != storage_ref:
                return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
            storage_refs_by_key[key] = storage_ref
        referenced_keys.update(parsed.referenced_keys)
        storage_global_positions.update(parsed.storage_global_positions)
    return _PytorchStorageReferenceParse(
        referenced_keys=referenced_keys,
        storage_refs_by_key=storage_refs_by_key,
        storage_global_positions=storage_global_positions,
        # Rebuild context is stream-local; only storage PID structure composes safely.
        canonical_tensor_rebuild_invocations=set(),
        parse_complete=True,
        all_persistent_ids_are_pytorch_storage=all(parsed.all_persistent_ids_are_pytorch_storage for parsed in parses),
    )


def _pytorch_storage_keys_from_pickle_bytes(
    pickle_data: bytes,
    *,
    opcode_budget_remaining: list[int] | None = None,
    deadline: float | None = None,
    position_offset: int = 0,
) -> _PytorchStorageReferenceParse:
    pickle_streams = _complete_pickle_stream_payloads(pickle_data)
    if pickle_streams is None:
        return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
    if len(pickle_streams) > 1:
        return _merge_pytorch_storage_reference_parses(
            tuple(
                _pytorch_storage_keys_from_pickle_bytes(
                    stream_payload,
                    opcode_budget_remaining=opcode_budget_remaining,
                    deadline=deadline,
                    position_offset=position_offset + stream_offset,
                )
                for stream_offset, stream_payload in pickle_streams
            )
        )

    marker = object()
    canonical_tensor = object()
    canonical_batch_placeholder = object()
    canonical_batch_entries: list[tuple[str, object]] = []
    canonical_batch_target: object | None = None
    memo: dict[int, Any] = {}
    stack: list[Any] = []
    referenced_keys: set[str] = set()
    storage_refs_by_key: dict[str, _PytorchStorageRef] = {}
    storage_global_positions: set[int] = set()
    canonical_tensor_rebuild_invocations: set[tuple[int, int]] = set()
    tensor_rebuild_uses: set[tuple[int, int]] = set()
    tensor_rebuild_proof_valid = True
    all_persistent_ids_are_pytorch_storage = True

    def invalidate_tensor_rebuild_proof() -> None:
        nonlocal tensor_rebuild_proof_valid
        tensor_rebuild_proof_valid = False

    def clear_stack_after_malformed_provenance() -> None:
        invalidate_tensor_rebuild_proof()
        stack.clear()

    def poison_stack_top() -> None:
        invalidate_tensor_rebuild_proof()
        stack[-1] = None

    def mutate_tracked_ordered_dict(value: _PytorchOrderedDictState) -> None:
        if value.used_as_hooks:
            invalidate_tensor_rebuild_proof()
        value.mutated = True

    def ordered_dict_is_empty_hooks(value: object) -> bool:
        if not isinstance(value, _PytorchOrderedDictState) or value.mutated:
            return False
        value.used_as_hooks = True
        return True

    def value_contains_tracked_provenance(value: object, seen: set[int] | None = None) -> bool:
        if isinstance(value, _PytorchStorageRef | _PytorchOrderedDictState):
            return True
        if not isinstance(value, (tuple, list, dict)):
            return False
        if seen is None:
            seen = set()
        value_id = id(value)
        if value_id in seen:
            return False
        seen.add(value_id)
        if isinstance(value, dict):
            return any(value_contains_tracked_provenance(item, seen) for item in value.items())
        return any(value_contains_tracked_provenance(item, seen) for item in value)

    def apply_setitems_to_target(items: tuple[tuple[Any, Any], ...]) -> None:
        if isinstance(stack[-1], _PytorchStorageRef):
            poison_stack_top()
        elif isinstance(stack[-1], _PytorchOrderedDictState):
            mutate_tracked_ordered_dict(stack[-1])
        elif isinstance(stack[-1], dict):
            stack[-1].update(items)
        else:
            poison_stack_top()

    def pop_marked_tuple(*, max_width: int = _PYTORCH_STORAGE_TRUST_MAX_TUPLE_WIDTH) -> tuple[Any, ...] | None:
        items: list[Any] = []
        while stack:
            item = stack.pop()
            if item is marker:
                return tuple(reversed(items))
            items.append(item)
            if len(items) > max_width:
                raise ValueError("PyTorch storage trust parser marked collection exceeded its width limit")
        return None

    def compact_canonical_setitems_stack() -> bool:
        nonlocal canonical_batch_target

        if len(canonical_batch_entries) >= _PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH:
            return False
        for marker_index, item in enumerate(stack):
            if item is not marker or marker_index == 0:
                continue
            target = stack[marker_index - 1]
            if not isinstance(target, dict | _PytorchOrderedDictState):
                continue
            if isinstance(target, _PytorchOrderedDictState) and target.used_as_hooks:
                continue
            if canonical_batch_target is not None and target is not canonical_batch_target:
                continue
            pair_index = marker_index + 1
            if pair_index < len(stack) and stack[pair_index] is canonical_batch_placeholder:
                pair_index += 1
            if pair_index + 1 >= len(stack):
                continue
            key = stack[pair_index]
            value = stack[pair_index + 1]
            if not isinstance(key, str):
                continue
            if value is not canonical_tensor and not isinstance(value, (str, int, float, bytes, type(None))):
                continue
            if value is not canonical_tensor and not (
                any(item is canonical_tensor for item in stack[pair_index + 2 :])
                or any(entry_value is canonical_tensor for _entry_key, entry_value in canonical_batch_entries)
            ):
                continue
            if canonical_batch_target is None:
                canonical_batch_target = target
                stack.insert(marker_index + 1, canonical_batch_placeholder)
                pair_index += 1
            canonical_batch_entries.append((key, value))
            del stack[pair_index : pair_index + 2]
            return True
        return False

    def within_limits() -> bool:
        while len(stack) > _PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH:
            if not compact_canonical_setitems_stack():
                return False
        if canonical_batch_entries and not any(
            item is marker
            and marker_index > 0
            and stack[marker_index - 1] is canonical_batch_target
            and marker_index + 1 < len(stack)
            and stack[marker_index + 1] is canonical_batch_placeholder
            for marker_index, item in enumerate(stack)
        ):
            return False
        return (
            len(memo) <= _PYTORCH_STORAGE_TRUST_MAX_MEMO_ENTRIES
            and len(referenced_keys) <= _PYTORCH_STORAGE_TRUST_MAX_REFERENCED_KEYS
        )

    def memo_key(value: Any) -> int | None:
        try:
            key = int(value)
        except (TypeError, ValueError):
            return None
        return key if key >= 0 else None

    def storage_ref_from_pid(pid: Any) -> _PytorchStorageRef | None:
        if not isinstance(pid, tuple) or len(pid) != 5:
            return None
        if pid[0] != "storage":
            return None
        storage_type = pid[1]
        if not (
            isinstance(storage_type, _PickleGlobalRef)
            and (storage_type.module, storage_type.name) in _PYTORCH_STORAGE_GLOBALS
        ):
            return None
        storage_key = _coerce_pickle_string_arg(pid[2])
        if storage_key is None or storage_key == "":
            return None
        location = _coerce_pickle_string_arg(pid[3])
        if location is None:
            return None
        storage_size = pid[4]
        if (
            not isinstance(storage_size, int)
            or isinstance(storage_size, bool)
            or storage_size < 0
            or storage_size > _PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX
        ):
            return None
        storage_global_positions.add(storage_type.position)
        return _PytorchStorageRef(
            storage_key,
            storage_type.module,
            storage_type.name,
            location,
            storage_size,
            _PYTORCH_STORAGE_ITEM_SIZES.get(storage_type.name),
        )

    def structural_storage_key_from_pid(pid: Any) -> str | None:
        if not isinstance(pid, tuple) or len(pid) < 4:
            return None
        if pid[0] != "storage":
            return None
        storage_type = pid[1]
        if not (
            isinstance(storage_type, _PickleGlobalRef)
            and (storage_type.module, storage_type.name) in _PYTORCH_STORAGE_GLOBALS
        ):
            return None
        storage_key = _coerce_pickle_string_arg(pid[2])
        if storage_key is None or storage_key == "":
            return None
        return storage_key if _coerce_pickle_string_arg(pid[3]) is not None else None

    def rebuild_tensor_v2_args_are_canonical(args: Any) -> bool:
        return (
            isinstance(args, tuple)
            and len(args) == 6
            and isinstance(args[0], _PytorchStorageRef)
            and _pytorch_storage_ref_has_zip_size_proof(args[0])
            and isinstance(args[1], int)
            and not isinstance(args[1], bool)
            and args[1] >= 0
            and args[1] <= _PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX
            and _abstract_nonnegative_int_tuple(args[2])
            and _abstract_nonnegative_int_tuple(args[3])
            and len(args[2]) == len(args[3])
            and isinstance(args[4], bool)
            and ordered_dict_is_empty_hooks(args[5])
            and _pytorch_tensor_view_fits_storage(args[0], args[1], args[2], args[3])
        )

    def reduce_result(function: Any, args: Any, reduce_position: int) -> Any:
        if isinstance(function, _PickleGlobalRef) and (function.module, function.name) == (
            "collections",
            "OrderedDict",
        ):
            if args != () and value_contains_tracked_provenance(args):
                invalidate_tensor_rebuild_proof()
            return _PytorchOrderedDictState() if args == () else None
        if isinstance(function, _PickleGlobalRef) and (function.module, function.name) == (
            "torch._utils",
            "_rebuild_tensor_v2",
        ):
            tensor_rebuild_uses.add((function.position, reduce_position))
            if rebuild_tensor_v2_args_are_canonical(args):
                canonical_tensor_rebuild_invocations.add((function.position, reduce_position))
                return canonical_tensor
            else:
                invalidate_tensor_rebuild_proof()
            return None
        if value_contains_tracked_provenance(function) or value_contains_tracked_provenance(args):
            invalidate_tensor_rebuild_proof()
        return None

    try:
        for opcode_count, (opcode, arg, _pos) in enumerate(pickletools.genops(pickle_data), start=1):
            if deadline is not None and opcode_count % 1024 == 0:
                _check_pytorch_zip_deadline(deadline)
            if opcode_budget_remaining is not None:
                if opcode_budget_remaining[0] <= 0:
                    return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
                opcode_budget_remaining[0] -= 1
            if opcode_count > _PYTORCH_STORAGE_TRUST_MAX_OPCODES:
                return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
            position = position_offset + (_pos if type(_pos) is int else 0)
            opcode_name = opcode.name
            if opcode_name in {"PROTO", "FRAME"}:
                continue
            if opcode_name == "STOP":
                if not isinstance(_pos, int) or _pos + 1 != len(pickle_data):
                    invalidate_tensor_rebuild_proof()
                continue
            if opcode_name == "MARK":
                stack.append(marker)
            elif opcode_name in {
                "BINSTRING",
                "SHORT_BINSTRING",
                "BINUNICODE",
                "SHORT_BINUNICODE",
                "UNICODE",
                "BINBYTES",
                "SHORT_BINBYTES",
            }:
                stack.append(_coerce_pickle_string_arg(arg))
            elif opcode_name == "GLOBAL":
                global_name = _coerce_pickle_string_arg(arg)
                if global_name is None:
                    stack.append(None)
                else:
                    parts = global_name.split()
                    stack.append(_PickleGlobalRef(parts[0], parts[1], position) if len(parts) == 2 else None)
            elif opcode_name == "STACK_GLOBAL":
                if len(stack) < 2:
                    clear_stack_after_malformed_provenance()
                    continue
                name = _coerce_pickle_string_arg(stack.pop())
                module = _coerce_pickle_string_arg(stack.pop())
                stack.append(
                    _PickleGlobalRef(module, name, position) if module is not None and name is not None else None
                )
            elif opcode_name == "EMPTY_TUPLE":
                stack.append(())
            elif opcode_name == "EMPTY_LIST":
                stack.append([])
            elif opcode_name == "EMPTY_DICT":
                stack.append({})
            elif opcode_name == "TUPLE":
                tuple_value = pop_marked_tuple()
                if tuple_value is None:
                    clear_stack_after_malformed_provenance()
                else:
                    stack.append(tuple_value)
            elif opcode_name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
                tuple_size = int(opcode_name[-1])
                if len(stack) < tuple_size:
                    clear_stack_after_malformed_provenance()
                    continue
                tuple_items = stack[-tuple_size:]
                del stack[-tuple_size:]
                stack.append(tuple(tuple_items))
            elif opcode_name == "LIST":
                list_items = pop_marked_tuple()
                if list_items is None:
                    clear_stack_after_malformed_provenance()
                else:
                    stack.append(list(list_items))
            elif opcode_name == "DICT":
                dict_items = pop_marked_tuple()
                if dict_items is None or len(dict_items) % 2 != 0:
                    clear_stack_after_malformed_provenance()
                else:
                    stack.append({dict_items[index]: dict_items[index + 1] for index in range(0, len(dict_items), 2)})
            elif opcode_name in {"BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "INT", "FLOAT", "BINFLOAT"}:
                stack.append(arg)
            elif opcode_name == "NONE":
                stack.append(None)
            elif opcode_name == "NEWTRUE":
                stack.append(True)
            elif opcode_name == "NEWFALSE":
                stack.append(False)
            elif opcode_name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                key = memo_key(arg)
                if key is not None and stack and key not in memo:
                    memo[key] = stack[-1]
                else:
                    invalidate_tensor_rebuild_proof()
            elif opcode_name == "MEMOIZE":
                key = len(memo)
                if stack and key not in memo:
                    memo[key] = stack[-1]
                else:
                    invalidate_tensor_rebuild_proof()
            elif opcode_name in {"BINGET", "LONG_BINGET", "GET"}:
                key = memo_key(arg)
                if key is None or key not in memo:
                    invalidate_tensor_rebuild_proof()
                    stack.append(None)
                else:
                    stack.append(memo[key])
            elif opcode_name == "POP":
                if stack:
                    stack.pop()
                else:
                    invalidate_tensor_rebuild_proof()
            elif opcode_name == "POP_MARK":
                if pop_marked_tuple() is None:
                    invalidate_tensor_rebuild_proof()
            elif opcode_name == "DUP":
                if stack:
                    stack.append(stack[-1])
                else:
                    invalidate_tensor_rebuild_proof()
            elif opcode_name == "APPEND":
                if len(stack) < 2:
                    clear_stack_after_malformed_provenance()
                    continue
                value = stack.pop()
                if isinstance(stack[-1], list):
                    stack[-1].append(value)
                else:
                    poison_stack_top()
            elif opcode_name == "APPENDS":
                appended_items = pop_marked_tuple()
                if appended_items is None or not stack:
                    clear_stack_after_malformed_provenance()
                    continue
                if isinstance(stack[-1], list):
                    stack[-1].extend(appended_items)
                else:
                    poison_stack_top()
            elif opcode_name == "SETITEM":
                if len(stack) < 3:
                    clear_stack_after_malformed_provenance()
                    continue
                value = stack.pop()
                key = stack.pop()
                apply_setitems_to_target(((key, value),))
            elif opcode_name == "SETITEMS":
                setitem_items = pop_marked_tuple(max_width=_PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH)
                if setitem_items is None or len(setitem_items) % 2 != 0 or not stack:
                    if (
                        setitem_items is None
                        or not setitem_items
                        or setitem_items[0] is not canonical_batch_placeholder
                        or not stack
                        or stack[-1] is not canonical_batch_target
                        or (len(setitem_items) - 1) % 2 != 0
                    ):
                        clear_stack_after_malformed_provenance()
                        continue
                    remaining_items = setitem_items[1:]
                    if (
                        len(canonical_batch_entries) + len(remaining_items) // 2
                        > _PYTORCH_STORAGE_TRUST_MAX_STACK_DEPTH
                    ):
                        return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
                    setitem_pairs = tuple(canonical_batch_entries) + tuple(
                        (remaining_items[index], remaining_items[index + 1])
                        for index in range(0, len(remaining_items), 2)
                    )
                    canonical_batch_entries.clear()
                    canonical_batch_target = None
                else:
                    setitem_pairs = tuple(
                        (setitem_items[index], setitem_items[index + 1]) for index in range(0, len(setitem_items), 2)
                    )
                apply_setitems_to_target(setitem_pairs)
            elif opcode_name == "BINPERSID":
                pid = stack.pop() if stack else None
                storage_ref = storage_ref_from_pid(pid)
                if storage_ref is not None:
                    referenced_keys.add(storage_ref.key)
                    existing_ref = storage_refs_by_key.get(storage_ref.key)
                    if existing_ref is not None and existing_ref != storage_ref:
                        all_persistent_ids_are_pytorch_storage = False
                        invalidate_tensor_rebuild_proof()
                    storage_refs_by_key[storage_ref.key] = storage_ref
                    stack.append(storage_ref)
                else:
                    storage_key = structural_storage_key_from_pid(pid)
                    if storage_key is not None:
                        referenced_keys.add(storage_key)
                    all_persistent_ids_are_pytorch_storage = False
                    stack.append(None)
            elif opcode_name == "PERSID":
                storage_ref = _storage_ref_from_protocol0_persid_text(arg)
                if storage_ref is not None:
                    referenced_keys.add(storage_ref.key)
                    existing_ref = storage_refs_by_key.get(storage_ref.key)
                    if existing_ref is not None and existing_ref != storage_ref:
                        all_persistent_ids_are_pytorch_storage = False
                    storage_refs_by_key[storage_ref.key] = storage_ref
                else:
                    storage_key = _structural_storage_key_from_protocol0_persid_text(arg)
                    if storage_key is not None:
                        referenced_keys.add(storage_key)
                    all_persistent_ids_are_pytorch_storage = False
                invalidate_tensor_rebuild_proof()
                stack.append(None)
            elif opcode_name == "REDUCE":
                if len(stack) < 2:
                    clear_stack_after_malformed_provenance()
                    continue
                args = stack.pop()
                function = stack.pop()
                stack.append(reduce_result(function, args, position))
            elif opcode_name == "BUILD":
                if len(stack) < 2:
                    clear_stack_after_malformed_provenance()
                    continue
                state = stack.pop()
                obj = stack.pop()
                if isinstance(obj, _PytorchStorageRef):
                    invalidate_tensor_rebuild_proof()
                    stack.append(None)
                elif isinstance(obj, _PytorchOrderedDictState):
                    if state is not None:
                        mutate_tracked_ordered_dict(obj)
                    stack.append(obj)
                else:
                    if value_contains_tracked_provenance(obj) or value_contains_tracked_provenance(state):
                        invalidate_tensor_rebuild_proof()
                    stack.append(obj if state is None else None)
            else:
                clear_stack_after_malformed_provenance()
            if not within_limits():
                return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
    except Exception:
        return _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
    return _PytorchStorageReferenceParse(
        referenced_keys=referenced_keys,
        storage_refs_by_key=storage_refs_by_key,
        storage_global_positions=storage_global_positions,
        canonical_tensor_rebuild_invocations=(
            canonical_tensor_rebuild_invocations
            if tensor_rebuild_proof_valid and tensor_rebuild_uses == canonical_tensor_rebuild_invocations
            else set()
        ),
        parse_complete=True,
        all_persistent_ids_are_pytorch_storage=all_persistent_ids_are_pytorch_storage,
    )


def _pytorch_zip_storage_reference_validation_notice(
    *,
    source: str,
    data_pkl_member: str,
    message: str,
    code: str,
    details: dict[str, Any],
) -> Notice:
    return Notice(
        message=message,
        severity=Severity.INFO,
        location=f"{source}:{data_pkl_member}",
        code=code,
        details={
            "data_pkl_member": data_pkl_member,
            "analysis_incomplete": True,
            **details,
        },
    )


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
        combined.pop("critical_references_covered", None)
        combined["reusable"] = False
    return {_CALL_GRAPH_SOURCE_FINGERPRINTS_KEY: combined} if combined is not None else {}


_CALL_GRAPH_FINGERPRINT_MAPPING_KEYS = (
    "fingerprints",
    "read_fingerprints",
    "module_sources",
    "loaded_module_sources",
    "loaded_package_paths",
    "loaded_package_resolution_contexts",
    "namespace_package_resolution_contexts",
)


def _merge_call_graph_fingerprint_mapping(
    existing: Mapping[str, Any] | None,
    incoming: Mapping[str, Any],
    key: str,
) -> tuple[dict[str, Any], bool]:
    existing_value = existing.get(key) if existing is not None else None
    incoming_value = incoming.get(key)
    merged = dict(existing_value) if isinstance(existing_value, Mapping) else {}
    conflict = False
    if isinstance(incoming_value, Mapping):
        for item_key, value in incoming_value.items():
            if item_key in merged and merged[item_key] != value:
                conflict = True
            else:
                merged[item_key] = value
    return merged, conflict


def _merge_call_graph_source_fingerprint_metadata(
    existing: Mapping[str, Any] | None,
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    incoming_is_source_independent = _is_source_independent_call_graph_fingerprint_metadata(incoming)
    existing_is_source_independent = existing is not None and _is_source_independent_call_graph_fingerprint_metadata(
        existing
    )
    if incoming_is_source_independent and existing_is_source_independent:
        return _source_independent_call_graph_fingerprint_metadata(
            critical_references=(
                incoming.get("critical_references_covered") is True
                or (existing or {}).get("critical_references_covered") is True
            )
        )
    if incoming_is_source_independent:
        return dict(existing) if existing is not None else dict(incoming)
    if existing_is_source_independent:
        return dict(incoming)

    merged = dict(existing or {})
    mapping_conflict = False
    for key in _CALL_GRAPH_FINGERPRINT_MAPPING_KEYS:
        merged[key], conflict = _merge_call_graph_fingerprint_mapping(existing, incoming, key)
        mapping_conflict = mapping_conflict or conflict

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
        merged["reusable"] = incoming.get("reusable") is True and not mapping_conflict
        if existing is not None:
            merged["reusable"] = merged["reusable"] and existing.get("reusable") is True
    if mapping_conflict:
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
        report = _with_canonical_pytorch_storage_persistent_id_metadata(
            _report_from_native_dict(raw_report),
            payload,
            position_offset=native_position_offset,
        )
        if enrich_call_graph:
            if _call_graph_enrichment_is_redundant(report):
                return _with_call_graph_source_fingerprint_metadata(
                    report,
                    _source_independent_call_graph_fingerprint_metadata(
                        critical_references=not _call_graph_has_no_source_inputs(report)
                    ),
                )
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


def _with_canonical_pytorch_storage_persistent_id_metadata(
    report: PickleReport,
    payload: bytes,
    *,
    position_offset: int = 0,
) -> PickleReport:
    if not any(finding.rule_code == "PERSISTENT_ID" for finding in report.findings):
        return report
    try:
        storage_reference_parse = _pytorch_storage_keys_from_pickle_bytes(payload, position_offset=position_offset)
    except Exception:
        storage_reference_parse = _PytorchStorageReferenceParse(set(), {}, set(), set(), False, False)
    trusted_storage_keys = storage_reference_parse.referenced_keys
    proven_canonical_storage_ids = (
        storage_reference_parse.parse_complete
        and storage_reference_parse.all_persistent_ids_are_pytorch_storage
        and bool(trusted_storage_keys)
    )
    rust_canonical_storage_ids = _rust_pytorch_storage_persistent_id_flags_are_canonical(report)
    single_storage_key = next(iter(trusted_storage_keys)) if len(trusted_storage_keys) == 1 else None

    findings = tuple(
        _finding_with_details(
            finding,
            _canonical_pytorch_storage_persistent_id_details(
                finding.details,
                proven_canonical_storage_ids=proven_canonical_storage_ids,
                rust_canonical_storage_ids=rust_canonical_storage_ids,
                single_storage_key=single_storage_key,
            ),
        )
        for finding in report.findings
    )
    metadata = report.to_dict()["metadata"]
    import_references = metadata.get("import_references")
    if isinstance(import_references, list):
        metadata["import_references"] = [
            _canonical_pytorch_storage_import_reference(
                _mapping(reference),
                proven_canonical_storage_ids=proven_canonical_storage_ids,
                storage_global_positions=storage_reference_parse.storage_global_positions,
            )
            for reference in import_references
        ]
    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=report.verdict,
        findings=findings,
        notices=report.notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=metadata,
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _rust_pytorch_storage_persistent_id_flags_are_canonical(report: PickleReport) -> bool:
    flagged_reference_found = False
    for raw_reference in _sequence(report.metadata.get("import_references")):
        reference = _mapping(raw_reference)
        if reference.get("pytorch_storage_persistent_id") is not True:
            continue
        flagged_reference_found = True
        module = reference.get("module")
        name = reference.get("name")
        if type(module) is not str or type(name) is not str or (module, name) not in _PYTORCH_STORAGE_GLOBALS:
            return False
    return flagged_reference_found


def _canonical_pytorch_storage_import_reference(
    reference: Mapping[str, Any],
    *,
    proven_canonical_storage_ids: bool,
    storage_global_positions: set[int],
) -> dict[str, Any]:
    normalized = dict(reference)
    module = normalized.get("module")
    name = normalized.get("name")
    if type(module) is str and type(name) is str and (module, name) in _PYTORCH_STORAGE_GLOBALS:
        if proven_canonical_storage_ids and _optional_int(normalized.get("position")) in storage_global_positions:
            normalized["pytorch_storage_persistent_id"] = True
        else:
            normalized.pop("pytorch_storage_persistent_id", None)
        return normalized
    normalized.pop("pytorch_storage_persistent_id", None)
    return normalized


def _canonical_pytorch_storage_persistent_id_details(
    details: Mapping[str, Any],
    *,
    proven_canonical_storage_ids: bool,
    rust_canonical_storage_ids: bool,
    single_storage_key: str | None,
) -> dict[str, Any]:
    normalized = dict(details)
    if normalized.get("opcode") not in {"BINPERSID", "PERSID"}:
        return normalized
    if proven_canonical_storage_ids:
        normalized["pytorch_storage_persistent_id"] = True
        if single_storage_key is not None:
            normalized["pytorch_storage_key"] = single_storage_key
        return normalized
    if rust_canonical_storage_ids and normalized.get("pytorch_storage_persistent_id") is True:
        return normalized
    normalized.pop("pytorch_storage_persistent_id", None)
    normalized.pop("pytorch_storage_key", None)
    return normalized


def _finding_with_details(finding: Finding, details: Mapping[str, Any]) -> Finding:
    return Finding(
        message=finding.message,
        severity=finding.severity,
        location=finding.location,
        rule_code=finding.rule_code,
        details=details,
        why=finding.why,
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


def _source_independent_call_graph_fingerprint_metadata(*, critical_references: bool = False) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "reusable": True,
        "source_independent": True,
        "fingerprints": {},
        "read_fingerprints": {},
        "module_sources": {},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
    }
    if critical_references:
        metadata["critical_references_covered"] = True
    return metadata


def _is_source_independent_call_graph_fingerprint_metadata(metadata: Mapping[str, Any]) -> bool:
    normalized = dict(metadata)
    return normalized in (
        _source_independent_call_graph_fingerprint_metadata(),
        _source_independent_call_graph_fingerprint_metadata(critical_references=True),
    )


def _with_call_graph_findings(report: PickleReport, *, payload: bytes | None = None) -> PickleReport:
    import_references = report.metadata.get("import_references")
    callable_invocations = report.metadata.get("callable_invocations", ())
    suppress_safe_numpy_reconstruct = _pickle_payload_has_only_safe_numpy_ndarray_reconstruction(payload)
    enrichment_errors: list[tuple[str, Exception]] = []
    source_fingerprints: Mapping[str, Any] | None = None
    inert_initialization_modules: frozenset[str] = frozenset()
    trusted_import_references: frozenset[tuple[str, str]] = frozenset()
    trusted_invocation_global_positions: frozenset[int] = frozenset()
    analyzed_invocation_global_positions: frozenset[int] = frozenset()
    analyzed_invocation_references: frozenset[tuple[str, str]] = frozenset()
    invocation_load_safe_modules: frozenset[str] = frozenset()
    safe_getattr_reconstruction_keys: frozenset[tuple[int, int]] = frozenset()
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
        if not suppress_safe_numpy_reconstruct:
            numpy_reconstruct_positions = _numpy_reconstruct_global_positions(callable_invocations)
            invocation_classification = (
                invocation_classification[0],
                invocation_classification[1] - numpy_reconstruct_positions,
                invocation_classification[2] - _NUMPY_RECONSTRUCT_REFERENCES,
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
            trusted_invocation_global_positions = _proven_trusted_invocation_global_positions(callable_invocations)
        except Exception as error:
            enrichment_errors.append(("python_import_invocation_loaded_identity", error))
        try:
            invocation_load_safe_modules = _invocation_load_safe_modules(
                callable_invocations,
                invocation_classification[0] if invocation_classification is not None else frozenset(),
            )
        except Exception as error:
            enrichment_errors.append(("python_import_invocation_initialization", error))
        try:
            report = _with_untrusted_invoked_allowlisted_import_findings(
                report,
                import_references,
                invocation_classification[0] if invocation_classification is not None else frozenset(),
                analyzed_invocation_global_positions,
                invocation_load_safe_modules,
                invocation_classification[1] if invocation_classification is not None else frozenset(),
                trusted_invocation_global_positions,
                suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
            )
        except Exception as error:
            enrichment_errors.append(("python_import_allowlist_loaded_identity", error))
        try:
            if callable_invocations_complete:
                safe_getattr_reconstruction_keys = _proven_safe_getattr_reconstruction_keys(callable_invocations)
        except Exception as error:
            enrichment_errors.append(("python_getattr_reconstruction_analysis", error))
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

    if source_snapshot_stable and callable_invocations_complete and safe_getattr_reconstruction_keys:
        report = _without_proven_safe_getattr_reconstruction_findings(
            report,
            safe_getattr_reconstruction_keys,
        )

    if (
        source_snapshot_stable
        and callable_invocations_complete
        and non_allowlisted_global_imports_complete
        and invocation_classification is not None
        and (inert_initialization_modules or trusted_import_references or trusted_invocation_global_positions)
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
            invocation_load_safe_modules,
            trusted_reconstruction_global_positions,
            trusted_reconstruction_references,
            trusted_invocation_global_positions,
            suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
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


def _proven_safe_getattr_reconstruction_keys(callable_invocations: object) -> frozenset[tuple[int, int]]:
    keys: set[tuple[int, int]] = set()
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        if not _trusted_static_getattr_reconstruction(invocation):
            continue
        if not _getattr_reconstruction_has_source_backed_proof(invocation):
            continue
        if _getattr_reconstruction_reaches_dangerous_call_graph(invocation):
            continue
        global_position = _optional_int(invocation.get("global_position"))
        opcode_position = _optional_int(invocation.get("opcode_position"))
        if global_position is None or opcode_position is None:
            continue
        keys.add((global_position, opcode_position))
    return frozenset(keys)


def _trusted_static_getattr_reconstruction(invocation: Mapping[str, object]) -> bool:
    if str(invocation.get("opcode", "")) != "REDUCE":
        return False
    module = str(invocation.get("module", ""))
    name = str(invocation.get("name", ""))
    if module not in {"builtins", "__builtin__", "__builtins__"} or name != "getattr":
        return False
    if invocation.get("getattr_reconstruction") is not True:
        return False
    if invocation.get("getattr_attribute_is_safe_identifier") is not True:
        return False
    if invocation.get("getattr_callable_is_direct") is not True:
        return False
    if invocation.get("getattr_target_is_direct") is not True:
        return False
    target_module = str(invocation.get("getattr_target_module", ""))
    target_name = str(invocation.get("getattr_target_name", ""))
    attribute_name = str(invocation.get("getattr_attribute_name", ""))
    resolved_module = str(invocation.get("getattr_resolved_module", ""))
    resolved_name = str(invocation.get("getattr_resolved_name", ""))
    if (target_module, target_name, attribute_name) not in _TRUSTED_STATIC_GETATTR_RECONSTRUCTIONS:
        return False
    return resolved_module == target_module and resolved_name == f"{target_name}.{attribute_name}"


def _getattr_reconstruction_has_source_backed_proof(invocation: Mapping[str, object]) -> bool:
    target_module = str(invocation.get("getattr_target_module", ""))
    target_name = str(invocation.get("getattr_target_name", ""))
    attribute_name = str(invocation.get("getattr_attribute_name", ""))
    if not module_initialization_is_proven_inert(target_module):
        return False
    if not class_static_attribute_lookup_is_proven_source_backed(target_module, target_name, attribute_name):
        return False
    resolved_invocation = _getattr_reconstruction_resolved_source_proof_invocation(invocation)
    analyzed_positions = find_analyzed_callable_call_graph_global_positions((resolved_invocation,))
    return _GETATTR_RESOLVED_SOURCE_PROOF_POSITION in analyzed_positions


def _getattr_reconstruction_reaches_dangerous_call_graph(invocation: Mapping[str, object]) -> bool:
    resolved_invocation = _getattr_reconstruction_resolved_source_proof_invocation(invocation)
    return bool(find_dangerous_call_graphs((), (resolved_invocation,)))


def _getattr_reconstruction_resolved_source_proof_invocation(
    invocation: Mapping[str, object],
) -> dict[str, object]:
    resolved_module = str(invocation.get("getattr_resolved_module", ""))
    resolved_name = str(invocation.get("getattr_resolved_name", ""))
    return {
        "opcode": "REDUCE",
        "module": resolved_module,
        "name": resolved_name,
        "import_reference": f"{resolved_module}.{resolved_name}",
        "positional_arg_count": 0,
        "global_position": _GETATTR_RESOLVED_SOURCE_PROOF_POSITION,
        "opcode_position": invocation.get("opcode_position"),
    }


def _without_proven_safe_getattr_reconstruction_findings(
    report: PickleReport,
    safe_getattr_reconstruction_keys: frozenset[tuple[int, int]],
) -> PickleReport:
    fallback_global_positions = _safe_getattr_global_position_fallbacks(
        report.findings,
        safe_getattr_reconstruction_keys,
    )
    findings = tuple(
        finding
        for finding in report.findings
        if not _dangerous_getattr_call_is_proven_safe(
            finding,
            safe_getattr_reconstruction_keys,
            fallback_global_positions,
        )
    )
    if len(findings) == len(report.findings):
        return report
    return PickleReport(
        source=report.source,
        status=report.status,
        verdict=_verdict_for_findings(report.status, findings),
        findings=findings,
        notices=report.notices,
        errors=report.errors,
        coverage=report.coverage,
        metadata=report.to_dict()["metadata"],
        private_metadata=report.private_metadata,
        duration_s=report.duration_s,
    )


def _safe_getattr_global_position_fallbacks(
    findings: tuple[Finding, ...],
    safe_getattr_reconstruction_keys: frozenset[tuple[int, int]],
) -> frozenset[int]:
    safe_counts: dict[int, int] = {}
    missing_opcode_counts: dict[int, int] = {}
    for global_position, _opcode_position in safe_getattr_reconstruction_keys:
        safe_counts[global_position] = safe_counts.get(global_position, 0) + 1
    for finding in findings:
        if _optional_int(finding.details.get("opcode_position")) is not None:
            continue
        missing_opcode_global_position = _dangerous_getattr_call_global_position(finding)
        if missing_opcode_global_position is not None:
            missing_opcode_counts[missing_opcode_global_position] = (
                missing_opcode_counts.get(missing_opcode_global_position, 0) + 1
            )
    return frozenset(
        global_position
        for global_position, count in missing_opcode_counts.items()
        if count == 1 and safe_counts.get(global_position) == 1
    )


def _dangerous_getattr_call_is_proven_safe(
    finding: Finding,
    safe_getattr_reconstruction_keys: frozenset[tuple[int, int]],
    fallback_global_positions: frozenset[int],
) -> bool:
    key = _dangerous_getattr_call_key(finding)
    if key is not None:
        return key in safe_getattr_reconstruction_keys
    global_position = _dangerous_getattr_call_global_position(finding)
    return global_position is not None and global_position in fallback_global_positions


def _dangerous_getattr_call_global_position(finding: Finding) -> int | None:
    if finding.rule_code != "DANGEROUS_CALL" or str(finding.details.get("opcode", "")) != "REDUCE":
        return None
    module = str(finding.details.get("module", ""))
    name = str(finding.details.get("name", ""))
    if module not in {"builtins", "__builtin__", "__builtins__"} or name != "getattr":
        return None
    return _optional_int(finding.details.get("global_position"))


def _dangerous_getattr_call_key(finding: Finding) -> tuple[int, int] | None:
    global_position = _dangerous_getattr_call_global_position(finding)
    opcode_position = _optional_int(finding.details.get("opcode_position"))
    if global_position is None or opcode_position is None:
        return None
    return (global_position, opcode_position)


def _verdict_for_findings(status: ScanStatus, findings: tuple[Finding, ...]) -> SafetyVerdict:
    if any(finding.severity == Severity.CRITICAL for finding in findings):
        return SafetyVerdict.MALICIOUS
    if any(finding.severity == Severity.WARNING for finding in findings):
        return SafetyVerdict.SUSPICIOUS
    return SafetyVerdict.CLEAN if status == ScanStatus.COMPLETE else SafetyVerdict.UNKNOWN


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
        if _is_skippable_pytorch_storage_persistent_id_reference(reference):
            continue
        source_backed_import_initialization_untrusted = (
            _source_backed_import_requires_initialization_proof((module, name))
            and not module_is_loaded_without_import_hooks(module)
            and not module_initialization_is_proven_inert(module)
        )
        if (
            not module
            or not name
            or not import_reference
            or bool(reference.get("is_dangerous"))
            or not bool(reference.get("requires_origin_verification"))
            or key in existing_references
            or (
                not _allowlisted_import_requires_origin_finding(module, name)
                and not source_backed_import_initialization_untrusted
            )
        ):
            continue
        if source_backed_import_initialization_untrusted:
            message = (
                f"Found source-backed allowlisted global without inert import initialization proof: {import_reference}"
            )
            why = (
                "Source-backed framework metadata can execute module-level code when pickle resolves an unloaded "
                "GLOBAL; suppress it only when the module is already loaded or import-time initialization is "
                "proven inert."
            )
        else:
            message = f"Found allowlisted global reference from an untrusted module origin: {import_reference}"
            why = (
                "Allowlisted modules are safe only when they resolve from the standard library or installed "
                "site-packages; a project-local shadow module can execute arbitrary import-time code."
            )
        additional_findings.append(
            Finding(
                message=message,
                severity=Severity.WARNING,
                location=f"{report.source} (pos {position})" if position is not None else report.source,
                rule_code="NON_ALLOWLISTED_GLOBAL",
                details={
                    "opcode": str(reference.get("opcode", "")),
                    "module": module,
                    "name": name,
                    "import_reference": import_reference,
                    "position": position,
                    "source_backed_import_initialization_untrusted": source_backed_import_initialization_untrusted,
                },
                why=why,
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


def _with_untrusted_invoked_allowlisted_import_findings(
    report: PickleReport,
    import_references: object,
    invoked_global_positions: frozenset[int],
    analyzed_invocation_global_positions: frozenset[int],
    invocation_load_safe_modules: frozenset[str],
    trusted_reconstruction_global_positions: frozenset[int],
    trusted_invocation_global_positions: frozenset[int],
    *,
    suppress_safe_numpy_reconstruct: bool,
) -> PickleReport:
    if not invoked_global_positions:
        return report
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
        position = _optional_int(reference.get("position"))
        key = (import_reference, position)
        if (
            not module
            or not name
            or not import_reference
            or position is None
            or position not in invoked_global_positions
            or bool(reference.get("is_dangerous"))
            or not bool(reference.get("requires_origin_verification"))
            or (module, name) not in _SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES
            or key in existing_references
            or _invoked_allowlisted_import_reference_is_proven_safe(
                module,
                name,
                position,
                analyzed_invocation_global_positions,
                invocation_load_safe_modules,
                trusted_reconstruction_global_positions,
                trusted_invocation_global_positions,
                suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
            )
        ):
            continue
        additional_findings.append(
            Finding(
                message=f"Found invoked allowlisted global without trusted loaded implementation: {import_reference}",
                severity=Severity.WARNING,
                location=f"{report.source} (pos {position})",
                rule_code="NON_ALLOWLISTED_GLOBAL",
                details={
                    "opcode": str(reference.get("opcode", "")),
                    "module": module,
                    "name": name,
                    "import_reference": import_reference,
                    "position": position,
                    "invoked": True,
                },
                why=(
                    "Allowlisted callable globals are suppressible only when the loaded implementation can be "
                    "tied back to trusted inspected source or an approved extension owner."
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


def _invoked_allowlisted_import_reference_is_proven_safe(
    module: str,
    name: str,
    position: int,
    analyzed_invocation_global_positions: frozenset[int],
    invocation_load_safe_modules: frozenset[str],
    trusted_reconstruction_global_positions: frozenset[int],
    trusted_invocation_global_positions: frozenset[int],
    *,
    suppress_safe_numpy_reconstruct: bool,
) -> bool:
    reference = (module, name)
    if (
        not import_only_reference_is_proven_trusted(module, name)
        and position not in trusted_invocation_global_positions
    ):
        return False
    if (module, name) in _NUMPY_RECONSTRUCT_REFERENCES and not suppress_safe_numpy_reconstruct:
        return False
    if position in trusted_reconstruction_global_positions:
        return True
    if position in trusted_invocation_global_positions:
        return module in invocation_load_safe_modules
    if _source_backed_invocation_requires_loaded_identity(
        reference,
        suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
    ):
        return False
    return position in analyzed_invocation_global_positions and module in invocation_load_safe_modules


def _source_backed_framework_identity_requires_contextual_invocation(module: str, name: str) -> bool:
    reference = (module, name)
    return reference in _SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES and not (
        module == "numpy" or module.startswith("numpy.")
    )


def _proven_trusted_invocation_global_positions(callable_invocations: object) -> frozenset[int]:
    grouped: dict[int, list[Mapping[str, object]]] = {}
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        position = _optional_int(invocation.get("global_position"))
        module = str(invocation.get("module", ""))
        name = str(invocation.get("name", ""))
        if position is None or not module or not name:
            continue
        if module == "numpy" or module.startswith("numpy."):
            continue
        if (module, name) not in _SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES:
            continue
        grouped.setdefault(position, []).append(invocation)
    trusted_positions: list[int] = []
    for position, invocations in grouped.items():
        if all(
            module_is_loaded_without_import_hooks(str(invocation.get("module", "")))
            and import_only_reference_is_proven_trusted_for_pickle_invocation(
                str(invocation.get("module", "")),
                str(invocation.get("name", "")),
                invocation,
            )
            for invocation in invocations
        ):
            trusted_positions.append(position)
            if len(trusted_positions) >= _MAX_INERT_INITIALIZATION_MODULES:
                break
    return frozenset(trusted_positions)


def _allowlisted_import_requires_origin_finding(module: str, name: str) -> bool:
    return import_only_module_requires_origin_review(
        module,
        name,
    ) or _noncanonical_pytorch_storage_like_reference(module, name)


def _noncanonical_pytorch_storage_like_reference(module: str, name: str) -> bool:
    return (
        module in {"torch", "torch.storage"}
        and name.endswith("Storage")
        and (module, name) not in _PYTORCH_STORAGE_GLOBALS
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


def _without_proven_safe_import_findings(
    report: PickleReport,
    inert_initialization_modules: frozenset[str],
    trusted_import_references: frozenset[tuple[str, str]],
    invoked_global_positions: frozenset[int],
    analyzed_invocation_global_positions: frozenset[int],
    analyzed_invocation_references: frozenset[tuple[str, str]],
    invocation_load_safe_modules: frozenset[str],
    trusted_reconstruction_global_positions: frozenset[int],
    trusted_reconstruction_references: frozenset[tuple[str, str]],
    trusted_invocation_global_positions: frozenset[int],
    *,
    suppress_safe_numpy_reconstruct: bool,
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
            invocation_load_safe_modules,
            trusted_reconstruction_global_positions,
            trusted_reconstruction_references,
            trusted_invocation_global_positions,
            suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
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
    invocation_load_safe_modules: frozenset[str],
    trusted_reconstruction_global_positions: frozenset[int],
    trusted_reconstruction_references: frozenset[tuple[str, str]],
    trusted_invocation_global_positions: frozenset[int] = frozenset(),
    *,
    suppress_safe_numpy_reconstruct: bool = False,
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
    invocation_identity_is_trusted = (
        position in trusted_invocation_global_positions and module in invocation_load_safe_modules
        if position is not None
        else False
    )
    requires_loaded_identity = finding_is_invoked and _source_backed_invocation_requires_loaded_identity(
        reference,
        suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
    )
    requires_import_initialization_proof = (
        not finding_is_invoked
        and _source_backed_import_requires_initialization_proof(
            reference,
            suppress_safe_numpy_reconstruct=suppress_safe_numpy_reconstruct,
        )
    )
    import_initialization_is_proven_safe = (
        not requires_import_initialization_proof
        or module in inert_initialization_modules
        or module_is_loaded_without_import_hooks(module)
    )
    inert_reference_is_proven_safe = (
        position is not None and not finding_is_invoked and import_initialization_is_proven_safe
    )
    trusted_reference_is_proven_safe = position is not None and (
        (not finding_is_invoked and import_initialization_is_proven_safe)
        or invocation_is_trusted_reconstruction
        or invocation_identity_is_trusted
        or (
            not requires_loaded_identity
            and invocation_is_analyzed
            and (
                not _source_backed_framework_identity_requires_contextual_invocation(module, name)
                and (
                    reference not in _SOURCE_BACKED_FRAMEWORK_IDENTITY_REFERENCES
                    or module in invocation_load_safe_modules
                )
            )
        )
    )
    trusted_origin_is_proven = (
        invocation_identity_is_trusted
        if requires_loaded_identity
        else (module, name) in trusted_import_references or invocation_identity_is_trusted
    )
    return (trusted_reference_is_proven_safe and trusted_origin_is_proven) or (
        inert_reference_is_proven_safe and module in inert_initialization_modules
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


def _numpy_reconstruct_global_positions(callable_invocations: object) -> frozenset[int]:
    positions: set[int] = set()
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        position = _optional_int(invocation.get("global_position"))
        module = str(invocation.get("module", ""))
        name = str(invocation.get("name", ""))
        if position is not None and (module, name) in _NUMPY_RECONSTRUCT_REFERENCES:
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


def _invocation_load_safe_modules(
    callable_invocations: object,
    invoked_global_positions: frozenset[int],
) -> frozenset[str]:
    modules: set[str] = set()
    for raw_invocation in _sequence(callable_invocations):
        invocation = _mapping(raw_invocation)
        position = _optional_int(invocation.get("global_position"))
        module = str(invocation.get("module", ""))
        if (
            position is not None
            and position in invoked_global_positions
            and module
            and import_only_module_load_is_proven_safe_for_invocation(module)
        ):
            modules.add(module)
            if len(modules) >= _MAX_INERT_INITIALIZATION_MODULES:
                break
    return frozenset(modules)


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
        and import_only_reference_is_proven_trusted(finding.module, finding.name)
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
    if len(payload) > _SAFE_NUMPY_RECONSTRUCT_MAX_PAYLOAD_BYTES:
        return False

    saw_numpy_reconstruct = False
    unsafe_numpy_reconstruct = False
    stack: list[object] = []
    memo: dict[int, object] = {}

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
        offset = 0
        opcode_count = 0
        while offset < len(payload):
            stack = []
            stream_saw_stop = False
            for opcode, arg, pos in pickletools.genops(payload[offset:]):
                opcode_count += 1
                if opcode_count > _SAFE_NUMPY_RECONSTRUCT_MAX_OPCODES:
                    return False
                opcode_name = opcode.name
                if opcode_name in {"EXT1", "EXT2", "EXT4", "NEXT_BUFFER", "READONLY_BUFFER"}:
                    return False
                if opcode_name in {"PROTO", "FRAME"}:
                    continue
                if opcode_name == "STOP":
                    if pos is None:
                        return False
                    offset += pos + 1
                    stream_saw_stop = True
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
                            _AbstractBytes()
                            if _codecs_encode_args_are_safe(args)
                            else _AbstractCallResult(function, args)
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
            if not stream_saw_stop:
                return False
    except Exception:
        return False

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
        and (_abstract_bytes_value_is_safe(state[4]) or _abstract_value_is_inert(state[4]))
    )


def _abstract_int_tuple_is_safe(value: object) -> bool:
    return isinstance(value, tuple) and all(isinstance(item, int) and not isinstance(item, bool) for item in value)


def _abstract_nonnegative_int_tuple(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) <= _PYTORCH_STORAGE_TRUST_MAX_TUPLE_WIDTH
        and all(
            isinstance(item, int)
            and not isinstance(item, bool)
            and 0 <= item <= _PYTORCH_STORAGE_TRUST_MAX_TENSOR_INDEX
            for item in value
        )
    )


def _pytorch_storage_ref_has_zip_size_proof(storage: _PytorchStorageRef) -> bool:
    return _is_ascii_decimal_digits(storage.key) and storage.location == "cpu" and storage.item_size is not None


def _pytorch_tensor_view_fits_storage(
    storage: _PytorchStorageRef,
    offset: int,
    size: tuple[int, ...],
    stride: tuple[int, ...],
) -> bool:
    if any(dim == 0 for dim in size):
        return offset <= storage.element_count
    max_index = offset + sum((dim - 1) * item_stride for dim, item_stride in zip(size, stride, strict=True))
    return max_index < storage.element_count


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
