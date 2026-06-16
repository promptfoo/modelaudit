"""
Advanced file handling utilities for ModelAudit.

This module provides advanced utilities for scanning large model files (400B+ parameters)
with bounded windowed I/O, sharded model support, and distributed scanning capabilities.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
from contextlib import contextmanager, suppress
from contextvars import Context, ContextVar, copy_context
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from queue import Empty, Queue
from threading import BoundedSemaphore, RLock, Thread
from typing import TYPE_CHECKING, Any, ClassVar

from ..._safetensors_shards import (
    SAFETENSORS_SHARD_KIND,
    is_safetensors_family_pattern,
    parse_safetensors_shard_shape,
    safetensors_family_pattern,
)
from ..helpers.cache_decorator import (
    add_optional_dependency_availability_to_version_context,
    should_bypass_cache_for_safetensors_header_limit,
    should_bypass_cache_for_unavailable_hdf5_analysis,
    should_bypass_cache_for_zip_entry_preflight,
    should_defer_hash_for_file_backed_onnx,
)
from ..sources._huggingface_cache import _find_hf_cache_root, _path_has_part, _trusted_hf_blobs_root

if TYPE_CHECKING:
    from ...scanner_results import ScanResult

logger = logging.getLogger(__name__)

# Size thresholds for large models
EXTREME_MODEL_THRESHOLD = 50 * 1024 * 1024 * 1024  # 50GB - use memory mapping
LARGE_MODEL_THRESHOLD_200GB = 500 * 1024 * 1024 * 1024  # 500GB - distributed scanning
COLOSSAL_MODEL_THRESHOLD = 1024 * 1024 * 1024 * 1024  # 1TB - special handling

# Memory mapping parameters
MMAP_CHUNK_SIZE = 100 * 1024 * 1024  # 100MB chunks for memory mapping
MMAP_MAX_WINDOW = 500 * 1024 * 1024  # 500MB max window size

# Parallel scanning parameters
MAX_PARALLEL_WORKERS = 4
MAX_SCANNABLE_SHARDS = 256
SHARD_SCAN_TIMEOUT = 600  # 10 minutes per shard
_PARALLEL_SHARD_WORKER_SLOTS = BoundedSemaphore(MAX_PARALLEL_WORKERS)
MAX_RECORDED_MISSING_SHARD_INDICES = 1000
_SHARD_ALREADY_PINNED_CONFIG_KEY = "_trusted_shard_already_pinned"
_PREVALIDATED_SHARD_INFO_CONFIG_KEY = "_trusted_prevalidated_shard_info"
_DEFER_SAFETENSORS_INDEX_CONTENT_REVALIDATION_CONFIG_KEY = "_trusted_defer_safetensors_index_content_revalidation"
SAFETENSORS_INDEX_NAME = "model.safetensors.index.json"
SAFETENSORS_INDEX_SUFFIX = ".safetensors.index.json"
MAX_SAFETENSORS_SHARD_INDEX_BYTES = 10 * 1024 * 1024
MAX_SAFETENSORS_SHARD_INDEX_FILES = 256
MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SAFETENSORS_SHARD_INDEX_DIRECTORIES = 256
MAX_SAFETENSORS_SHARD_INDEX_DIRECTORY_ENTRIES = 4096
MAX_SAFETENSORS_SHARD_INDEX_TOTAL_DIRECTORY_ENTRIES = (
    2 * MAX_SAFETENSORS_SHARD_INDEX_DIRECTORIES * MAX_SAFETENSORS_SHARD_INDEX_DIRECTORY_ENTRIES
)
MAX_SAFETENSORS_SHARD_INDEX_OBSERVATIONS = 512
MAX_SAFETENSORS_SHARD_INDEX_TENSORS = 250_000
MAX_SAFETENSORS_SHARD_INDEX_JSON_TOKENS = (2 * MAX_SAFETENSORS_SHARD_INDEX_TENSORS) + 4096
MAX_SAFETENSORS_SHARD_ALIAS_IDENTITY_CHECKS = 1024
_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY = "_trusted_safetensors_index_inspection_context"

ValidatedShardTargets = dict[str, dict[str, int | str]]
ExpectedShardIndices = range | frozenset[int]


def _count_expected_shard_indices(expected_indices: ExpectedShardIndices) -> int:
    """Return range cardinality without relying on len(range(...)) for huge totals."""
    if isinstance(expected_indices, range):
        if expected_indices.step > 0:
            if expected_indices.start >= expected_indices.stop:
                return 0
            return ((expected_indices.stop - expected_indices.start - 1) // expected_indices.step) + 1
        if expected_indices.start <= expected_indices.stop:
            return 0
        return ((expected_indices.start - expected_indices.stop - 1) // abs(expected_indices.step)) + 1
    return len(expected_indices)


class _ShardPinUnavailableError(OSError):
    """Raised when a validated shard cannot be bound to a stable scan path."""


@dataclass
class _PinnedShardScan:
    """Descriptor-bound scan path plus post-scan inode stability state."""

    path: str
    changed_during_scan: bool = False


_PINNED_FILE_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
    "st_nlink",
)
CONTEXT_ONLY_COMPANION_TARGET_KEY = "_context_only_companion"


def _pinned_file_descriptor_changed(
    file_fd: int,
    expected_stat: os.stat_result,
    expected_hash: str | None = None,
    *,
    max_bytes: int | None = None,
    deadline: float | None = None,
) -> bool:
    """Return whether a pinned descriptor no longer matches observed metadata and bytes."""
    try:
        current_stat = os.fstat(file_fd)
    except OSError:
        return True
    if any(getattr(expected_stat, field) != getattr(current_stat, field) for field in _PINNED_FILE_IDENTITY_FIELDS):
        return True
    if expected_hash is not None:
        try:
            return (
                _hash_pinned_file_descriptor(
                    file_fd,
                    max_bytes=max_bytes,
                    deadline=deadline,
                )
                != expected_hash
            )
        except OSError:
            return True
    return False


@dataclass(frozen=True)
class _SafetensorsShardIndexInventory:
    """SafeTensors shard inventory or a captured index-validation error."""

    index_path: Path
    expected_source_paths: frozenset[str]
    expected_indices: ExpectedShardIndices
    index_base: str
    fingerprint: str | None = None
    generation: int | None = None
    error: str | None = None
    proven_unrelated: bool = False
    target_scope_complete: bool = False
    expected_source_identities: frozenset[tuple[int | str, ...]] = frozenset()
    target_identities_observed: bool = False
    target_identity_error: str | None = None
    normalized_shard_stem: str | None = None


@dataclass
class _SafetensorsIndexInspectionBudget:
    """Mutable aggregate caps and caches shared by related inspection scopes."""

    lock: RLock = field(default_factory=RLock)
    candidate_paths: set[str] = field(default_factory=set)
    directory_paths: set[str] = field(default_factory=set)
    charged_observations: set[tuple[Any, ...]] = field(default_factory=set)
    parsed_inventories: dict[tuple[Any, ...], _SafetensorsShardIndexInventory] = field(default_factory=dict)
    last_observations: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    generations: dict[str, int] = field(default_factory=dict)
    bytes_read: int = 0
    directory_entries_inspected: int = 0


@dataclass
class _SafetensorsIndexInspectionContext:
    """Bound and memoize local SafeTensors index inspection for one top-level scan."""

    _budget: _SafetensorsIndexInspectionBudget = field(default_factory=_SafetensorsIndexInspectionBudget)
    failure: str | None = None

    @property
    def lock(self) -> RLock:
        return self._budget.lock

    @property
    def candidate_paths(self) -> set[str]:
        return self._budget.candidate_paths

    @property
    def directory_paths(self) -> set[str]:
        return self._budget.directory_paths

    @property
    def charged_observations(self) -> set[tuple[Any, ...]]:
        return self._budget.charged_observations

    @property
    def parsed_inventories(self) -> dict[tuple[Any, ...], _SafetensorsShardIndexInventory]:
        return self._budget.parsed_inventories

    @property
    def last_observations(self) -> dict[str, tuple[Any, ...]]:
        return self._budget.last_observations

    @property
    def generations(self) -> dict[str, int]:
        return self._budget.generations

    @property
    def bytes_read(self) -> int:
        return self._budget.bytes_read

    @bytes_read.setter
    def bytes_read(self, value: int) -> None:
        self._budget.bytes_read = value

    @property
    def directory_entries_inspected(self) -> int:
        return self._budget.directory_entries_inspected

    @directory_entries_inspected.setter
    def directory_entries_inspected(self, value: int) -> None:
        self._budget.directory_entries_inspected = value

    def isolated_failure_context(self) -> "_SafetensorsIndexInspectionContext":
        """Share aggregate budgets while isolating one speculative probe's failure."""
        return _SafetensorsIndexInspectionContext(_budget=self._budget)

    def record_failure(self, message: str) -> str:
        """Retain the first aggregate inspection failure for the full scan."""
        with self.lock:
            if self.failure is None:
                self.failure = message
            return self.failure

    def register_directory(self, directory: Path) -> str | None:
        """Charge one lexical ancestor directory once."""
        normalized = _normalized_absolute_path(directory)
        with self.lock:
            if self.failure is not None:
                return self.failure
            self.directory_paths.add(normalized)
            if len(self.directory_paths) > MAX_SAFETENSORS_SHARD_INDEX_DIRECTORIES:
                self.failure = "safetensors index ancestor inspection limit exceeded"
            return self.failure

    def register_candidates(self, candidates: list[Path]) -> str | None:
        """Charge lexical index candidates once across the whole scan."""
        with self.lock:
            if self.failure is not None:
                return self.failure
            self.candidate_paths.update(_normalized_absolute_path(path) for path in candidates)
            if len(self.candidate_paths) > MAX_SAFETENSORS_SHARD_INDEX_FILES:
                self.failure = "safetensors index inspection limit exceeded"
            return self.failure

    def reserve_directory_entry(self) -> str | None:
        """Charge one physical directory entry across the full inspection context."""
        with self.lock:
            if self.failure is not None:
                return self.failure
            if self.directory_entries_inspected >= MAX_SAFETENSORS_SHARD_INDEX_TOTAL_DIRECTORY_ENTRIES:
                self.failure = "safetensors index aggregate directory entry limit exceeded"
                return self.failure
            self.directory_entries_inspected += 1
            return None

    def reserve_observation(
        self,
        observation: tuple[Any, ...],
        size: int,
    ) -> str | None:
        """Charge bounded bytes once for one stable content observation."""
        with self.lock:
            if self.failure is not None:
                return self.failure
            if observation in self.charged_observations:
                return None
            if len(self.charged_observations) >= MAX_SAFETENSORS_SHARD_INDEX_OBSERVATIONS:
                self.failure = "safetensors index observation limit exceeded"
                return self.failure
            if self.bytes_read + size > MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES:
                self.failure = "safetensors index aggregate byte limit exceeded"
                return self.failure
            self.charged_observations.add(observation)
            self.bytes_read += size
            return None

    def reserve_content_revalidation(self, size: int) -> str | None:
        """Charge every physical reread needed when stat identity is unreliable."""
        with self.lock:
            if self.failure is not None:
                return self.failure
            if self.bytes_read + size > MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES:
                self.failure = "safetensors index aggregate byte limit exceeded"
                return self.failure
            self.bytes_read += size
            return None

    def cached_inventory(self, cache_key: tuple[Any, ...]) -> _SafetensorsShardIndexInventory | None:
        """Return an unchanged parsed inventory, if any."""
        with self.lock:
            return self.parsed_inventories.get(cache_key)

    def record_inventory(
        self,
        cache_key: tuple[Any, ...],
        lexical_path: Path,
        observation: tuple[Any, ...],
        inventory: _SafetensorsShardIndexInventory,
    ) -> _SafetensorsShardIndexInventory:
        """Bind a parsed inventory to a monotonic observed path generation."""
        normalized_path = _normalized_absolute_path(lexical_path)
        with self.lock:
            if cache_key not in self.charged_observations:
                return inventory
            if self.last_observations.get(normalized_path) != observation:
                self.generations[normalized_path] = self.generations.get(normalized_path, 0) + 1
                self.last_observations[normalized_path] = observation
            generation = self.generations[normalized_path]
            result = replace(inventory, generation=generation)
            self.parsed_inventories[cache_key] = replace(inventory, generation=None)
            return result

    def observe_cached_inventory(
        self,
        cache_key: tuple[Any, ...],
        lexical_path: Path,
        observation: tuple[Any, ...],
    ) -> _SafetensorsShardIndexInventory | None:
        """Refresh generation state while reusing an unchanged parsed payload."""
        cached = self.cached_inventory(cache_key)
        if cached is None:
            return None
        return self.record_inventory(cache_key, lexical_path, observation, cached)


_CURRENT_SAFETENSORS_INDEX_CONTEXT: ContextVar[_SafetensorsIndexInspectionContext | None] = ContextVar(
    "modelaudit_safetensors_index_context",
    default=None,
)


def _safetensors_index_requires_content_revalidation() -> bool:
    """Return whether stat identity cannot safely prove unchanged index content."""
    return os.name == "nt"


def _safetensors_index_observation_prefix(
    index_path: Path,
    resolved_index: Path,
    index_stat: os.stat_result,
) -> tuple[Any, ...]:
    """Build the stable stat identity used by the parsed-index cache."""
    return (
        _normalized_absolute_path(index_path),
        _normalized_absolute_path(resolved_index),
        index_stat.st_dev,
        index_stat.st_ino,
        index_stat.st_mode,
        index_stat.st_size,
        index_stat.st_mtime_ns,
        index_stat.st_ctime_ns,
    )


def _safetensors_index_path_observation(index_path: Path) -> tuple[Any, ...] | None:
    """Snapshot one candidate's resolved target and nonfollowing stat identity."""
    try:
        resolved_index = index_path.resolve(strict=True)
        index_stat = os.stat(resolved_index, follow_symlinks=False)
    except (OSError, RuntimeError):
        return None
    return _safetensors_index_observation_prefix(index_path, resolved_index, index_stat)


class _DuplicateAwareSafetensorsIndexObject(dict[str, Any]):
    """Preserve overwritten JSON members so invalid indexes retain scope evidence."""

    def __init__(
        self,
        values: dict[str, Any],
        overwritten_items: list[tuple[str, Any]],
        *,
        has_duplicate_keys: bool,
    ) -> None:
        super().__init__(values)
        self.overwritten_items = overwritten_items
        self.has_duplicate_keys = has_duplicate_keys


def _load_safetensors_index_json(raw: bytes) -> Any:
    """Parse a bounded index document while retaining ambiguous duplicate members."""
    from ...scanners.safetensors_scanner import _validate_json_structural_token_limit

    _validate_json_structural_token_limit(
        raw,
        MAX_SAFETENSORS_SHARD_INDEX_JSON_TOKENS,
        "SafeTensors index",
    )
    saw_duplicate_key = False

    def preserve_duplicate_keys(pairs: list[tuple[str, Any]]) -> _DuplicateAwareSafetensorsIndexObject:
        nonlocal saw_duplicate_key
        parsed: dict[str, Any] = {}
        overwritten_items: list[tuple[str, Any]] = []
        has_duplicate_keys = False
        for key, value in pairs:
            if key in parsed:
                overwritten_items.append((key, parsed[key]))
                has_duplicate_keys = True
                saw_duplicate_key = True
            parsed[key] = value
            if isinstance(value, _DuplicateAwareSafetensorsIndexObject) and value.has_duplicate_keys:
                has_duplicate_keys = True
        return _DuplicateAwareSafetensorsIndexObject(
            parsed,
            overwritten_items,
            has_duplicate_keys=has_duplicate_keys,
        )

    parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=preserve_duplicate_keys)
    if isinstance(parsed, _DuplicateAwareSafetensorsIndexObject):
        parsed.has_duplicate_keys = saw_duplicate_key
    return parsed


def _activate_safetensors_index_inspection_context(
    context: _SafetensorsIndexInspectionContext | None = None,
) -> tuple[Any | None, _SafetensorsIndexInspectionContext]:
    """Activate one context, reusing an outer top-level scan when present."""
    active = _CURRENT_SAFETENSORS_INDEX_CONTEXT.get()
    selected = context or active or _SafetensorsIndexInspectionContext()
    if active is selected:
        return None, selected
    return _CURRENT_SAFETENSORS_INDEX_CONTEXT.set(selected), selected


def _deactivate_safetensors_index_inspection_context(token: Any | None) -> None:
    """Restore the previous scan context."""
    if token is not None:
        _CURRENT_SAFETENSORS_INDEX_CONTEXT.reset(token)


def _validated_stat_matches_target(opened_stat: os.stat_result, target: dict[str, int | str]) -> bool:
    """Return whether an opened shard still matches its validated target snapshot."""
    expected_values = (
        ("device", opened_stat.st_dev),
        ("inode", opened_stat.st_ino),
        ("size", opened_stat.st_size),
        ("mtime_ns", opened_stat.st_mtime_ns),
        ("ctime_ns", opened_stat.st_ctime_ns),
        ("nlink", opened_stat.st_nlink),
    )
    return stat.S_ISREG(opened_stat.st_mode) and all(
        not isinstance(target.get(key), int) or target[key] == current_value for key, current_value in expected_values
    )


def _fstat_or_close_owned_descriptor(file_fd: int) -> os.stat_result:
    """Read a newly owned descriptor's identity without leaking it on failure."""
    try:
        return os.fstat(file_fd)
    except BaseException:
        with suppress(OSError):
            os.close(file_fd)
        raise


def _descriptor_path_for_open_file(file_fd: int) -> str | None:
    """Return a stable path to an opened regular file descriptor."""
    opened_stat = os.fstat(file_fd)
    for descriptor_root in (
        Path("/proc") / str(os.getpid()) / "fd",
        Path("/proc/self/fd"),
        Path("/dev/fd"),
    ):
        candidate = descriptor_root / str(file_fd)
        try:
            if os.path.samestat(opened_stat, os.stat(candidate)):
                return str(candidate)
        except OSError:
            continue
    return None


def _rebase_pinned_shard_result(result: "ScanResult", pinned_path: str, report_path: str) -> None:
    """Replace transient descriptor paths in scanner-owned result fields."""

    def rebase(value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return value
        if isinstance(value, str):
            return value.replace(pinned_path, report_path)
        if isinstance(value, dict):
            return {key: rebase(item, depth + 1) for key, item in value.items()}
        if isinstance(value, list):
            return [rebase(item, depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(rebase(item, depth + 1) for item in value)
        return value

    for records in (result.issues, result.checks):
        for record in records:
            if isinstance(record.location, str):
                record.location = rebase(record.location)
            record.message = rebase(record.message)
            record.details = rebase(record.details)
    result.metadata = rebase(result.metadata)


def _open_windows_shard_guard_fd(path: str, *, open_reparse_point: bool = False) -> int:
    """Open a Windows shard for shared reads while denying writes and replacement."""
    import ctypes
    import ctypes.wintypes as wintypes
    import msvcrt

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    file_flags = 0x00000080
    if open_reparse_point:
        file_flags |= 0x00200000
    handle = create_file(
        path,
        0x80000000,
        0x00000001,
        None,
        3,
        file_flags,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle_value):
        raise ctypes_windows.WinError(ctypes_windows.get_last_error())

    handle_value = handle if isinstance(handle, int) else int(handle.value)
    try:
        msvcrt_module: Any = msvcrt
        return int(
            msvcrt_module.open_osfhandle(
                handle_value,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
            )
        )
    except Exception:
        kernel32.CloseHandle(handle_value)
        raise


@dataclass(frozen=True)
class _WindowsStagingDirectoryGuard:
    """Retained Windows directory handle plus its handle-bound pathname identity."""

    handle: int
    bound_path: Path
    expected_stat: os.stat_result


def _open_windows_staging_directory_guard(
    path: Path,
    expected_stat: os.stat_result,
) -> _WindowsStagingDirectoryGuard:
    """Open and bind one non-reparse Windows staging directory."""
    import ctypes
    import ctypes.wintypes as wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("file_attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    file_traverse = 0x0020
    file_read_attributes = 0x0080
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    handle = create_file(
        str(path),
        file_traverse | file_read_attributes,
        file_share_read | file_share_write,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    invalid_handle_value = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle_value):
        raise ctypes_windows.WinError(ctypes_windows.get_last_error())

    handle_value = handle if isinstance(handle, int) else int(handle.value)
    try:
        get_file_information = kernel32.GetFileInformationByHandleEx
        get_file_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        get_file_information.restype = wintypes.BOOL
        tag_info = FileAttributeTagInfo()
        if not get_file_information(
            handle,
            9,
            ctypes.byref(tag_info),
            ctypes.sizeof(tag_info),
        ):
            raise ctypes_windows.WinError(ctypes_windows.get_last_error())

        file_attribute_directory = 0x00000010
        file_attribute_reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        if not tag_info.file_attributes & file_attribute_directory or (
            tag_info.file_attributes & file_attribute_reparse_point
        ):
            raise _ShardPinUnavailableError("private staging directory changed while opening")

        get_final_path = kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = (
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        get_final_path.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        path_length = int(get_final_path(handle, buffer, len(buffer), 0))
        if path_length <= 0 or path_length >= len(buffer):
            raise _ShardPinUnavailableError("private staging directory path could not be bound")
        bound_path_text = buffer.value
        if bound_path_text.startswith("\\\\?\\UNC\\"):
            bound_path_text = f"\\\\{bound_path_text[8:]}"
        elif bound_path_text.startswith("\\\\?\\"):
            bound_path_text = bound_path_text[4:]
        bound_path = Path(bound_path_text)
        bound_stat = os.stat(bound_path, follow_symlinks=False)
        bound_attributes = getattr(bound_stat, "st_file_attributes", 0) or 0
        if (
            not stat.S_ISDIR(bound_stat.st_mode)
            or bool(bound_attributes & file_attribute_reparse_point)
            or not os.path.samestat(expected_stat, bound_stat)
        ):
            raise _ShardPinUnavailableError("private staging directory changed while opening")
        return _WindowsStagingDirectoryGuard(
            handle=handle_value,
            bound_path=bound_path,
            expected_stat=bound_stat,
        )
    except BaseException:
        kernel32.CloseHandle(handle_value)
        raise


def _close_windows_staging_directory_guard(guard: _WindowsStagingDirectoryGuard) -> None:
    """Release one retained Windows staging-directory handle."""
    import ctypes
    import ctypes.wintypes as wintypes

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    close_handle(guard.handle)


def _windows_staging_directory_identity_matches(path: Path, expected_stat: os.stat_result) -> bool:
    """Return whether one staging pathname still names an expected ordinary directory."""
    try:
        current_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    current_attributes = getattr(current_stat, "st_file_attributes", 0) or 0
    return (
        stat.S_ISDIR(current_stat.st_mode)
        and not bool(current_attributes & reparse_flag)
        and os.path.samestat(expected_stat, current_stat)
    )


def _windows_staging_directory_guard_matches(guard: _WindowsStagingDirectoryGuard) -> bool:
    """Return whether a retained staging directory still owns its bound path."""
    return _windows_staging_directory_identity_matches(guard.bound_path, guard.expected_stat)


@contextmanager
def _pinned_windows_shard_scan_path(
    resolved_path: str,
    target: dict[str, int | str],
) -> Iterator[_PinnedShardScan]:
    """Pin a Windows shard with open handles that prevent rename/delete replacement."""
    source_path = Path(resolved_path)
    source_fd: int | None = None
    pinned_scan: _PinnedShardScan | None = None
    source_stat: os.stat_result | None = None
    try:
        source_fd = _open_windows_shard_guard_fd(str(source_path))
        source_stat = os.fstat(source_fd)
        if not _validated_stat_matches_target(source_stat, target):
            raise _ShardPinUnavailableError("validated shard target changed before pinning")

        pinned_scan = _PinnedShardScan(path=str(source_path))
        yield pinned_scan
    except _ShardPinUnavailableError:
        raise
    except OSError as error:
        if pinned_scan is not None:
            raise
        raise _ShardPinUnavailableError(str(error)) from error
    finally:
        if pinned_scan is not None and source_stat is not None and source_fd is not None:
            pinned_scan.changed_during_scan = pinned_scan.changed_during_scan or _pinned_file_descriptor_changed(
                source_fd,
                source_stat,
            )
        if source_fd is not None:
            os.close(source_fd)


def _hash_pinned_file_descriptor(
    source_fd: int,
    *,
    max_bytes: int | None = None,
    deadline: float | None = None,
) -> str:
    """Hash one retained descriptor without transferring ownership of it."""
    copied_fd = os.dup(source_fd)
    try:
        os.lseek(copied_fd, 0, os.SEEK_SET)
        source = os.fdopen(copied_fd, "rb", closefd=True)
        copied_fd = -1
        digest = hashlib.sha256()
        hashed_bytes = 0
        with source:
            while chunk := source.read(1024 * 1024):
                hashed_bytes += len(chunk)
                if max_bytes is not None and max_bytes >= 0 and hashed_bytes > max_bytes:
                    raise _ShardPinUnavailableError("validated source exceeds the staging byte limit")
                if deadline is not None and time.time() > deadline:
                    raise _ShardPinUnavailableError("validated source staging exceeded the scan deadline")
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        if copied_fd >= 0:
            os.close(copied_fd)


def _open_posix_directory_chain(
    path: Path,
    directory_flags: int,
) -> tuple[Path, list[tuple[Path, int]]]:
    """Open every component of an absolute directory path without following later swaps."""
    resolved_path = Path(os.path.realpath(os.path.abspath(path)))
    if not resolved_path.is_absolute() or resolved_path.anchor != os.path.sep:
        raise _ShardPinUnavailableError("private staging parent is not an absolute POSIX path")

    opened: list[tuple[Path, int]] = []
    current_path = Path(resolved_path.anchor)
    try:
        current_fd = os.open(current_path, directory_flags)
        opened.append((current_path, current_fd))
        for part in resolved_path.parts[1:]:
            current_path /= part
            current_fd = os.open(part, directory_flags, dir_fd=current_fd)
            opened.append((current_path, current_fd))
    except BaseException:
        for _opened_path, opened_fd in reversed(opened):
            with suppress(OSError):
                os.close(opened_fd)
        raise
    return resolved_path, opened


def _create_private_staging_directory(parent_fd: int) -> str:
    """Create a private random child relative to a retained parent descriptor."""
    for _attempt in range(128):
        staging_name = f".modelaudit_scan_{secrets.token_hex(16)}"
        try:
            os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        return staging_name
    raise _ShardPinUnavailableError("could not allocate a private staging directory")


class _StagingMutationMonitor:
    """Watch private staging directories so pathname ABA cannot be erased by restoration."""

    def __init__(self, *, inotify_fd: int | None = None, kqueue: Any | None = None) -> None:
        self._inotify_fd = inotify_fd
        self._kqueue = kqueue

    @classmethod
    def arm(
        cls,
        directory_fds: Iterable[int],
        *,
        watch_contents: bool = True,
    ) -> "_StagingMutationMonitor":
        descriptors = tuple(directory_fds)
        if _is_linux_platform():
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            inotify_init1 = libc.inotify_init1
            inotify_init1.argtypes = (ctypes.c_int,)
            inotify_init1.restype = ctypes.c_int
            inotify_add_watch = libc.inotify_add_watch
            inotify_add_watch.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
            inotify_add_watch.restype = ctypes.c_int
            monitor_fd = inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
            if monitor_fd < 0:
                raise _ShardPinUnavailableError("private staging mutation monitoring is unavailable")
            mutation_mask = 0x00000400 | 0x00000800 | 0x00002000 | 0x00004000 | 0x00008000
            if watch_contents:
                mutation_mask |= (
                    0x00000002 | 0x00000004 | 0x00000008 | 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200
                )
            try:
                for descriptor in descriptors:
                    descriptor_path = _descriptor_path_for_open_file(descriptor)
                    if (
                        descriptor_path is None
                        or inotify_add_watch(
                            monitor_fd,
                            os.fsencode(descriptor_path),
                            mutation_mask,
                        )
                        < 0
                    ):
                        raise _ShardPinUnavailableError("private staging mutation monitoring is unavailable")
            except BaseException:
                os.close(monitor_fd)
                raise
            return cls(inotify_fd=monitor_fd)

        queue: Any | None = None
        try:
            import select

            def select_attribute(name: str) -> Any:
                return getattr(select, name)

            kqueue_factory = select_attribute("kqueue")
            kevent_factory = select_attribute("kevent")
            vnode_filter = select_attribute("KQ_FILTER_VNODE")
            add_flag = select_attribute("KQ_EV_ADD")
            clear_flag = select_attribute("KQ_EV_CLEAR")
            event_names = ["KQ_NOTE_DELETE", "KQ_NOTE_RENAME", "KQ_NOTE_ATTRIB", "KQ_NOTE_REVOKE"]
            if watch_contents:
                event_names.extend(("KQ_NOTE_WRITE", "KQ_NOTE_EXTEND", "KQ_NOTE_LINK"))
            fflags = sum(getattr(select, name, 0) for name in event_names)
            queue = kqueue_factory()
            changes = [
                kevent_factory(
                    descriptor,
                    filter=vnode_filter,
                    flags=add_flag | clear_flag,
                    fflags=fflags,
                )
                for descriptor in descriptors
            ]
            queue.control(changes, 0, 0)
        except (AttributeError, OSError, TypeError, ValueError) as error:
            if queue is not None:
                with suppress(Exception):
                    queue.close()
            raise _ShardPinUnavailableError("private staging mutation monitoring is unavailable") from error
        return cls(kqueue=queue)

    def changed(self, *, relevant_names: Collection[str] | None = None) -> bool:
        """Return whether a watched directory or relevant child observed a mutation."""
        if self._inotify_fd is not None:
            event_header = struct.Struct("iIII")
            normalized_names = None if relevant_names is None else {os.path.normcase(name) for name in relevant_names}
            for _chunk in range(256):
                try:
                    events = os.read(self._inotify_fd, 64 * 1024)
                except BlockingIOError:
                    return False
                except OSError:
                    return True
                if not events:
                    return False
                if normalized_names is None:
                    return True
                offset = 0
                while offset < len(events):
                    if len(events) - offset < event_header.size:
                        return True
                    _watch_descriptor, mask, _cookie, name_length = event_header.unpack_from(events, offset)
                    offset += event_header.size
                    if name_length > len(events) - offset:
                        return True
                    raw_name = events[offset : offset + name_length]
                    offset += name_length
                    name = os.fsdecode(raw_name.split(b"\0", 1)[0])
                    if not name or mask & (0x00000400 | 0x00000800 | 0x00002000 | 0x00004000 | 0x00008000):
                        return True
                    if os.path.normcase(name) in normalized_names:
                        return True
            return True
        if self._kqueue is not None:
            try:
                return bool(self._kqueue.control(None, 1024, 0))
            except OSError:
                return True
        return True

    def close(self) -> None:
        """Release the platform watcher."""
        if self._inotify_fd is not None:
            os.close(self._inotify_fd)
            self._inotify_fd = None
        if self._kqueue is not None:
            self._kqueue.close()
            self._kqueue = None


_LINUX_WRITE_LEASE_GUARD_CODE = r"""
import fcntl
import os
import signal
import sys

broken = False
reported = False


def report_break(_signal_number, _frame):
    global broken, reported
    broken = True
    if not reported:
        os.write(1, b"B")
        reported = True


try:
    signal.signal(signal.SIGIO, report_break)
    descriptors = [int(value) for value in sys.argv[1:]]
    for descriptor in descriptors:
        fcntl.fcntl(descriptor, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_RDLCK)
    os.write(1, b"R")
    while True:
        try:
            command = os.read(0, 1)
        except InterruptedError:
            continue
        if not command or command == b"X":
            break
    for descriptor in descriptors:
        try:
            fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        except OSError:
            broken = True
    os.write(1, b"B" if broken else b"C")
except BaseException:
    try:
        os.write(1, b"E")
    except Exception:
        pass
    raise SystemExit(1)
"""


class _LinuxWriteLeaseGuard:
    """Hold read leases in a helper process and report every attempted writer."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._changed: bool | None = None

    @classmethod
    def arm(cls, descriptors: Iterable[int], *, deadline: float | None = None) -> "_LinuxWriteLeaseGuard":
        import select

        unique_descriptors: list[int] = []
        identities: set[tuple[int, int]] = set()
        for descriptor in descriptors:
            descriptor_stat = os.fstat(descriptor)
            identity = descriptor_stat.st_dev, descriptor_stat.st_ino
            if identity in identities:
                continue
            identities.add(identity)
            unique_descriptors.append(descriptor)
        if not unique_descriptors:
            raise _ShardPinUnavailableError("private staging write protection is unavailable")

        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _LINUX_WRITE_LEASE_GUARD_CODE,
                *(str(fd) for fd in unique_descriptors),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(unique_descriptors),
        )
        assert process.stdout is not None
        handshake_timeout = 5.0
        if deadline is not None:
            handshake_timeout = min(handshake_timeout, max(deadline - time.time(), 0.0))
        try:
            readable, _, _ = select.select([process.stdout.fileno()], [], [], handshake_timeout)
            marker = os.read(process.stdout.fileno(), 1) if readable else b""
            if marker != b"R":
                raise _ShardPinUnavailableError("private staging write protection is unavailable")
            return cls(process)
        except BaseException:
            with suppress(OSError):
                process.kill()
            with suppress(OSError, subprocess.SubprocessError):
                process.communicate()
            raise

    def finish(self) -> bool:
        """Release leases and return whether any writer attempted to break them."""
        if self._changed is not None:
            return self._changed
        try:
            if self._process.poll() is None:
                stdout, _stderr = self._process.communicate(input=b"X", timeout=5)
            else:
                stdout, _stderr = self._process.communicate()
            self._changed = self._process.returncode != 0 or stdout != b"C"
        except (OSError, subprocess.SubprocessError):
            with suppress(OSError):
                self._process.kill()
            with suppress(OSError, subprocess.SubprocessError):
                self._process.communicate()
            self._changed = True
        return self._changed

    def close(self) -> None:
        self.finish()


def _is_linux_platform() -> bool:
    """Return the runtime platform check without type-checker constant folding."""
    return sys.platform.startswith("linux")


@contextmanager
def _open_exclusive_staging_target(
    destination: Path | str,
    destination_dir_fd: int | None,
) -> Iterator[Any]:
    """Open one new staging destination without following an existing entry."""
    if destination_dir_fd is None:
        with Path(destination).open("xb") as target:
            yield target
        return

    destination_fd = os.open(
        str(destination),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=destination_dir_fd,
    )
    with os.fdopen(destination_fd, "wb", closefd=True) as target:
        yield target


def _copy_pinned_file_descriptor(
    source_fd: int,
    destination: Path | str,
    *,
    destination_dir_fd: int | None = None,
    max_bytes: int | None = None,
    deadline: float | None = None,
) -> str:
    """Copy and hash an already-open regular file into private staging."""
    destination_created = False
    try:
        with _open_exclusive_staging_target(destination, destination_dir_fd) as target:
            destination_created = True
            copied_fd = os.dup(source_fd)
            try:
                source_size = os.fstat(copied_fd).st_size
                if max_bytes is not None and max_bytes >= 0 and source_size > max_bytes:
                    raise _ShardPinUnavailableError("validated source exceeds the staging byte limit")
                if deadline is not None and time.time() > deadline:
                    raise _ShardPinUnavailableError("validated source staging exceeded the scan deadline")
                os.lseek(copied_fd, 0, os.SEEK_SET)
                source = os.fdopen(copied_fd, "rb", closefd=True)
                copied_fd = -1
                digest = hashlib.sha256()
                with source:
                    copied_bytes = 0
                    while chunk := source.read(1024 * 1024):
                        copied_bytes += len(chunk)
                        if max_bytes is not None and max_bytes >= 0 and copied_bytes > max_bytes:
                            raise _ShardPinUnavailableError("validated source exceeds the staging byte limit")
                        if deadline is not None and time.time() > deadline:
                            raise _ShardPinUnavailableError("validated source staging exceeded the scan deadline")
                        digest.update(chunk)
                        target.write(chunk)
                target.flush()
                return digest.hexdigest()
            finally:
                if copied_fd >= 0:
                    os.close(copied_fd)
    except BaseException:
        if destination_created:
            with suppress(OSError):
                if destination_dir_fd is None:
                    Path(destination).unlink()
                else:
                    os.unlink(str(destination), dir_fd=destination_dir_fd)
        raise


@contextmanager
def _pinned_windows_logical_scan_path(
    resolved_path: str,
    target: dict[str, int | str],
    pinned_name: str,
    companion_targets: Mapping[str, tuple[str, dict[str, int | str]]] | None,
    *,
    borrowed_source_fd: int | None = None,
    copy_max_bytes: int | None = None,
    deadline: float | None = None,
) -> Iterator[_PinnedShardScan]:
    """Stage descriptor-read bytes under logical filenames while retaining Windows guards."""
    source_fd: int | None = borrowed_source_fd
    source_fd_owned = borrowed_source_fd is None
    source_stat: os.stat_result | None = None
    source_hash: str | None = None
    staged_source_fd: int | None = None
    staged_source_stat: os.stat_result | None = None
    companion_fds: list[tuple[int, os.stat_result, str | None]] = []
    staged_companion_fds: list[tuple[int, os.stat_result, str]] = []
    staging_path: Path | None = None
    staging_scan_root: Path | None = None
    initial_staging_stat: os.stat_result | None = None
    staged_file_stats: dict[Path, os.stat_result] = {}
    staging_directory_guards: dict[tuple[str, ...], _WindowsStagingDirectoryGuard] = {}
    created_staging_directories: dict[tuple[str, ...], tuple[Path, os.stat_result | None]] = {}
    pinned_scan: _PinnedShardScan | None = None
    remaining_copy_bytes = copy_max_bytes

    def bounded_copy_limit(expected_size: int) -> int:
        if remaining_copy_bytes is None:
            return expected_size
        return min(expected_size, max(remaining_copy_bytes, 0))

    def record_copied_bytes(copied_size: int) -> None:
        nonlocal remaining_copy_bytes
        if remaining_copy_bytes is not None:
            remaining_copy_bytes -= copied_size

    try:
        if source_fd is None:
            source_fd = _open_windows_shard_guard_fd(resolved_path)
        source_stat = os.fstat(source_fd)
        if not _validated_stat_matches_target(source_stat, target):
            raise _ShardPinUnavailableError("validated shard target changed before pinning")

        staging_path = Path(tempfile.mkdtemp(prefix=".modelaudit_scan_"))
        initial_staging_stat = os.stat(staging_path, follow_symlinks=False)
        opened_root_guard = _open_windows_staging_directory_guard(staging_path, initial_staging_stat)
        staging_directory_guards[()] = opened_root_guard
        staging_scan_root = opened_root_guard.bound_path
        staged_source = staging_scan_root / pinned_name
        source_hash = _copy_pinned_file_descriptor(
            source_fd,
            staged_source,
            max_bytes=bounded_copy_limit(source_stat.st_size),
            deadline=deadline,
        )
        staged_file_stat = os.stat(staged_source, follow_symlinks=False)
        record_copied_bytes(staged_file_stat.st_size)
        staged_file_stats[staged_source] = staged_file_stat
        if _pinned_file_descriptor_changed(
            source_fd,
            source_stat,
            source_hash,
            max_bytes=source_stat.st_size,
            deadline=deadline,
        ):
            raise _ShardPinUnavailableError("validated shard content changed while staging")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        staged_file_attributes = getattr(staged_file_stat, "st_file_attributes", 0) or 0
        if not stat.S_ISREG(staged_file_stat.st_mode) or bool(reparse_flag and staged_file_attributes & reparse_flag):
            raise _ShardPinUnavailableError("staged shard path changed while opening")
        staged_source_fd = _open_windows_shard_guard_fd(str(staged_source), open_reparse_point=True)
        staged_source_stat = os.fstat(staged_source_fd)
        staged_source_fd_attributes = getattr(staged_source_stat, "st_file_attributes", 0) or 0
        if (
            bool(reparse_flag and staged_source_fd_attributes & reparse_flag)
            or not os.path.samestat(staged_file_stat, staged_source_stat)
            or _pinned_file_descriptor_changed(
                staged_source_fd,
                staged_source_stat,
                source_hash,
                max_bytes=staged_source_stat.st_size,
                deadline=deadline,
            )
        ):
            raise _ShardPinUnavailableError("staged shard content changed while staging")
        staged_source_target: dict[str, int | str] = {
            "device": staged_file_stat.st_dev,
            "inode": staged_file_stat.st_ino,
            "size": staged_file_stat.st_size,
            "mtime_ns": staged_file_stat.st_mtime_ns,
            "ctime_ns": staged_file_stat.st_ctime_ns,
            "nlink": staged_file_stat.st_nlink,
        }

        for relative_name, (companion_path, companion_target) in (companion_targets or {}).items():
            relative_path = Path(relative_name)
            if (
                relative_path.is_absolute()
                or not relative_path.parts
                or any(part in {"", ".", ".."} for part in relative_path.parts)
            ):
                raise _ShardPinUnavailableError("validated companion path escaped its scan directory")
            companion_fd = _open_windows_shard_guard_fd(companion_path)
            companion_stat = _fstat_or_close_owned_descriptor(companion_fd)
            if not _validated_stat_matches_target(companion_stat, companion_target):
                os.close(companion_fd)
                raise _ShardPinUnavailableError("validated companion target changed before pinning")
            companion_fds.append((companion_fd, companion_stat, None))
            parent_parts: tuple[str, ...] = ()
            parent_guard = opened_root_guard
            for parent_part in relative_path.parts[:-1]:
                parent_parts = (*parent_parts, parent_part)
                existing_parent_guard = staging_directory_guards.get(parent_parts)
                if existing_parent_guard is not None:
                    parent_guard = existing_parent_guard
                    continue
                staged_directory = parent_guard.bound_path / parent_part
                try:
                    staged_directory.mkdir(mode=0o700)
                except FileExistsError as error:
                    raise _ShardPinUnavailableError("validated companion staging directory changed") from error
                created_staging_directories[parent_parts] = (staged_directory, None)
                staged_directory_stat = os.stat(staged_directory, follow_symlinks=False)
                created_staging_directories[parent_parts] = (staged_directory, staged_directory_stat)
                created_parent_guard = _open_windows_staging_directory_guard(
                    staged_directory,
                    staged_directory_stat,
                )
                staging_directory_guards[parent_parts] = created_parent_guard
                parent_guard = created_parent_guard
            staged_companion = parent_guard.bound_path / relative_path.name
            staged_companion_hash = _copy_pinned_file_descriptor(
                companion_fd,
                staged_companion,
                max_bytes=bounded_copy_limit(companion_stat.st_size),
                deadline=deadline,
            )
            companion_fds[-1] = (companion_fd, companion_stat, staged_companion_hash)
            staged_companion_path_stat = os.stat(staged_companion, follow_symlinks=False)
            record_copied_bytes(staged_companion_path_stat.st_size)
            staged_file_stats[staged_companion] = staged_companion_path_stat
            if _pinned_file_descriptor_changed(
                companion_fd,
                companion_stat,
                staged_companion_hash,
                max_bytes=companion_stat.st_size,
                deadline=deadline,
            ):
                raise _ShardPinUnavailableError("validated companion content changed while staging")
            staged_companion_attributes = getattr(staged_companion_path_stat, "st_file_attributes", 0) or 0
            if not stat.S_ISREG(staged_companion_path_stat.st_mode) or bool(
                reparse_flag and staged_companion_attributes & reparse_flag
            ):
                raise _ShardPinUnavailableError("staged companion path changed while opening")
            staged_companion_fd = _open_windows_shard_guard_fd(
                str(staged_companion),
                open_reparse_point=True,
            )
            staged_companion_stat = _fstat_or_close_owned_descriptor(staged_companion_fd)
            staged_companion_fd_attributes = getattr(staged_companion_stat, "st_file_attributes", 0) or 0
            if (
                not os.path.samestat(staged_companion_path_stat, staged_companion_stat)
                or bool(reparse_flag and staged_companion_fd_attributes & reparse_flag)
                or _pinned_file_descriptor_changed(
                    staged_companion_fd,
                    staged_companion_stat,
                    staged_companion_hash,
                    max_bytes=staged_companion_stat.st_size,
                    deadline=deadline,
                )
            ):
                os.close(staged_companion_fd)
                raise _ShardPinUnavailableError("staged companion content changed while staging")
            staged_companion_fds.append((staged_companion_fd, staged_companion_stat, staged_companion_hash))

        if any(
            not _windows_staging_directory_guard_matches(directory_guard)
            for directory_guard in staging_directory_guards.values()
        ):
            raise _ShardPinUnavailableError("private staging directory changed before scanner dispatch")
        if deadline is not None and time.time() > deadline:
            raise _ShardPinUnavailableError("validated source staging exceeded the scan deadline")
        with _pinned_windows_shard_scan_path(str(staged_source), staged_source_target) as pinned_scan:
            yield pinned_scan
            if (
                source_stat is None
                or source_fd is None
                or source_hash is None
                or _pinned_file_descriptor_changed(
                    source_fd,
                    source_stat,
                    source_hash,
                    max_bytes=source_stat.st_size,
                    deadline=deadline,
                )
            ):
                pinned_scan.changed_during_scan = True
            if (
                staged_source_fd is None
                or staged_source_stat is None
                or source_hash is None
                or _pinned_file_descriptor_changed(
                    staged_source_fd,
                    staged_source_stat,
                    source_hash,
                    max_bytes=staged_source_stat.st_size,
                    deadline=deadline,
                )
            ):
                pinned_scan.changed_during_scan = True
            for companion_fd, companion_stat, companion_hash in companion_fds:
                if companion_hash is None or _pinned_file_descriptor_changed(
                    companion_fd,
                    companion_stat,
                    companion_hash,
                    max_bytes=companion_stat.st_size,
                    deadline=deadline,
                ):
                    pinned_scan.changed_during_scan = True
                    break
            for companion_fd, companion_stat, companion_hash in staged_companion_fds:
                if _pinned_file_descriptor_changed(
                    companion_fd,
                    companion_stat,
                    companion_hash,
                    max_bytes=companion_stat.st_size,
                    deadline=deadline,
                ):
                    pinned_scan.changed_during_scan = True
                    break
    except _ShardPinUnavailableError:
        raise
    except OSError as error:
        if pinned_scan is not None:
            raise
        raise _ShardPinUnavailableError(str(error)) from error
    finally:
        for companion_fd, _staged_stat, _staged_hash in reversed(staged_companion_fds):
            os.close(companion_fd)
        if staged_source_fd is not None:
            os.close(staged_source_fd)
        for companion_fd, _source_stat, _source_hash in reversed(companion_fds):
            os.close(companion_fd)
        if source_fd_owned and source_fd is not None:
            os.close(source_fd)
        try:
            cleanup_root_guard: _WindowsStagingDirectoryGuard | None = staging_directory_guards.get(())
            root_is_stable = cleanup_root_guard is not None and _windows_staging_directory_guard_matches(
                cleanup_root_guard
            )
            if cleanup_root_guard is None and staging_path is not None and initial_staging_stat is not None:
                root_is_stable = _windows_staging_directory_identity_matches(
                    staging_path,
                    initial_staging_stat,
                )
            if root_is_stable:
                for staged_file, expected_stat in reversed(staged_file_stats.items()):
                    try:
                        current_file_stat = os.stat(staged_file, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISREG(current_file_stat.st_mode) and os.path.samestat(expected_stat, current_file_stat):
                        with suppress(OSError):
                            staged_file.unlink()
                for directory_parts in sorted(created_staging_directories, key=len, reverse=True):
                    created_path, created_stat = created_staging_directories[directory_parts]
                    directory_guard = staging_directory_guards.pop(directory_parts, None)
                    directory_stat: os.stat_result | None
                    if directory_guard is not None:
                        directory_path = directory_guard.bound_path
                        directory_stat = directory_guard.expected_stat
                        directory_is_stable = _windows_staging_directory_guard_matches(directory_guard)
                        _close_windows_staging_directory_guard(directory_guard)
                    else:
                        directory_path = created_path
                        directory_stat = created_stat
                        directory_is_stable = created_stat is not None and (
                            _windows_staging_directory_identity_matches(created_path, created_stat)
                        )
                    if (
                        directory_is_stable
                        and directory_stat is not None
                        and _windows_staging_directory_identity_matches(directory_path, directory_stat)
                    ):
                        with suppress(OSError):
                            directory_path.rmdir()

                cleanup_root_guard = staging_directory_guards.get(())
                root_path: Path | None
                root_stat: os.stat_result | None
                if cleanup_root_guard is not None:
                    del staging_directory_guards[()]
                    root_path = cleanup_root_guard.bound_path
                    root_stat = cleanup_root_guard.expected_stat
                    root_is_stable = _windows_staging_directory_guard_matches(cleanup_root_guard)
                    _close_windows_staging_directory_guard(cleanup_root_guard)
                else:
                    root_path = staging_path
                    root_stat = initial_staging_stat
                if (
                    root_is_stable
                    and root_path is not None
                    and root_stat is not None
                    and _windows_staging_directory_identity_matches(root_path, root_stat)
                ):
                    with suppress(OSError):
                        root_path.rmdir()
        finally:
            for _directory_parts, directory_guard in sorted(
                staging_directory_guards.items(),
                key=lambda item: len(item[0]),
                reverse=True,
            ):
                _close_windows_staging_directory_guard(directory_guard)
            staging_directory_guards.clear()


@contextmanager
def _pinned_shard_scan_path(
    resolved_path: str,
    target: dict[str, int | str],
    *,
    logical_path: str | None = None,
    companion_targets: Mapping[str, tuple[str, dict[str, int | str]]] | None = None,
    source_fd: int | None = None,
    companion_fds: Mapping[str, int] | None = None,
    require_regular_path: bool = False,
    copy_max_bytes: int | None = None,
    deadline: float | None = None,
) -> Iterator[_PinnedShardScan]:
    """Expose a validated shard through a directory descriptor immune to pathname ABA swaps."""
    if os.name == "nt":
        if companion_fds:
            raise _ShardPinUnavailableError("borrowed companion descriptors are unsupported on Windows")
        if logical_path is not None or companion_targets:
            pinned_name = Path(logical_path).name if logical_path is not None else Path(resolved_path).name
            if not pinned_name or pinned_name in {".", ".."}:
                raise _ShardPinUnavailableError("validated scan path omitted a safe filename")
            with _pinned_windows_logical_scan_path(
                resolved_path,
                target,
                pinned_name,
                companion_targets,
                borrowed_source_fd=source_fd,
                copy_max_bytes=copy_max_bytes,
                deadline=deadline,
            ) as windows_pinned_scan:
                yield windows_pinned_scan
        else:
            with _pinned_windows_shard_scan_path(resolved_path, target) as windows_pinned_scan:
                yield windows_pinned_scan
        return

    borrowed_source_fd = source_fd
    borrowed_companion_fds = dict(companion_fds or {})
    if borrowed_source_fd is not None and (
        not isinstance(borrowed_source_fd, int) or isinstance(borrowed_source_fd, bool) or borrowed_source_fd < 0
    ):
        raise _ShardPinUnavailableError("borrowed source descriptor is invalid")
    target_companion_names = set(companion_targets or {})
    if set(borrowed_companion_fds).difference(target_companion_names) or any(
        not isinstance(fd, int) or isinstance(fd, bool) or fd < 0 for fd in borrowed_companion_fds.values()
    ):
        raise _ShardPinUnavailableError("borrowed companion descriptor is invalid")

    source_path = Path(resolved_path)
    parent_fd: int | None = None
    source_fd = None
    staging_fd: int | None = None
    staging_parent_fd: int | None = None
    staging_parent_path: Path | None = None
    staging_path: Path | None = None
    initial_staging_stat: os.stat_result | None = None
    staging_descriptor_root: Path | None = None
    source_name = source_path.name
    pinned_name = Path(logical_path).name if logical_path is not None else source_name
    if not pinned_name or pinned_name in {".", ".."}:
        raise _ShardPinUnavailableError("validated scan path omitted a safe filename")
    pinned_created = False
    pinned_scan: _PinnedShardScan | None = None
    pinned_stat: os.stat_result | None = None
    pinned_source_copy_fd: int | None = None
    pinned_source_copy_stat: os.stat_result | None = None
    pinned_source_copy_hash: str | None = None
    pinned_companion_fds: list[tuple[int, os.stat_result, str | None]] = []
    pinned_companion_copy_fds: list[tuple[int, os.stat_result, str]] = []
    companion_parent_fds: list[int] = []
    created_staging_entries: list[tuple[int, str]] = []
    staged_entry_bindings: list[tuple[int, str, int]] = []
    staging_directory_fds: dict[tuple[str, ...], int] = {}
    staging_directory_stats: dict[int, os.stat_result] = {}
    staging_mutation_monitor: _StagingMutationMonitor | None = None
    staging_ancestor_bindings: list[tuple[Path, int]] = []
    staging_ancestor_monitor: _StagingMutationMonitor | None = None
    linux_write_lease_guard: _LinuxWriteLeaseGuard | None = None
    created_staging_directories: set[tuple[str, ...]] = set()
    remaining_copy_bytes = copy_max_bytes

    def bounded_copy_limit(expected_size: int) -> int:
        if remaining_copy_bytes is None:
            return expected_size
        return min(expected_size, max(remaining_copy_bytes, 0))

    def record_copied_bytes(copied_size: int) -> None:
        nonlocal remaining_copy_bytes
        if remaining_copy_bytes is not None:
            remaining_copy_bytes -= copied_size

    def staged_bindings_changed() -> bool:
        for entry_parent_fd, entry_name, expected_target_fd in staged_entry_bindings:
            try:
                current_entry_target = os.stat(entry_name, dir_fd=entry_parent_fd)
                expected_entry_target = os.fstat(expected_target_fd)
            except OSError:
                return True
            if not os.path.samestat(current_entry_target, expected_entry_target):
                return True
        return False

    def staging_path_binding_changed() -> bool:
        if staging_ancestor_monitor is None or staging_ancestor_monitor.changed():
            return True
        try:
            for ancestor_path, ancestor_fd in staging_ancestor_bindings:
                if not os.path.samestat(
                    os.stat(ancestor_path, follow_symlinks=False),
                    os.fstat(ancestor_fd),
                ):
                    return True
            if (
                staging_path is None
                or initial_staging_stat is None
                or not os.path.samestat(
                    os.stat(staging_path, follow_symlinks=False),
                    initial_staging_stat,
                )
            ):
                return True
        except OSError:
            return True
        return False

    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        nonblock = getattr(os, "O_NONBLOCK", 0)
        required_dir_fd_functions = [os.mkdir, os.open, os.stat, os.symlink, os.unlink]
        if (
            not nofollow
            or not directory
            or any(function not in os.supports_dir_fd for function in required_dir_fd_functions)
        ):
            raise _ShardPinUnavailableError("descriptor-bound shard scans are unsupported on this platform")

        directory_flags = os.O_RDONLY | directory | nofollow | cloexec
        if borrowed_source_fd is not None:
            source_fd = os.dup(borrowed_source_fd)
        else:
            parent_fd = os.open(source_path.parent, directory_flags)
            source_fd = os.open(
                source_name,
                os.O_RDONLY | nofollow | nonblock | cloexec,
                dir_fd=parent_fd,
            )
        source_stat = os.fstat(source_fd)
        if not _validated_stat_matches_target(source_stat, target):
            raise _ShardPinUnavailableError("validated shard target changed before pinning")

        source_descriptor_path = _descriptor_path_for_open_file(source_fd)
        if source_descriptor_path is None:
            raise _ShardPinUnavailableError("platform cannot expose the opened shard descriptor")

        staging_parent_path, staging_ancestor_bindings = _open_posix_directory_chain(
            Path(tempfile.gettempdir()),
            directory_flags,
        )
        staging_parent_fd = staging_ancestor_bindings[-1][1]
        staging_ancestor_monitor = _StagingMutationMonitor.arm(
            (descriptor for _path, descriptor in staging_ancestor_bindings),
            watch_contents=False,
        )
        staging_name = _create_private_staging_directory(staging_parent_fd)
        staging_path = staging_parent_path / staging_name
        initial_staging_stat = os.stat(staging_name, dir_fd=staging_parent_fd, follow_symlinks=False)
        staging_fd = os.open(staging_name, directory_flags, dir_fd=staging_parent_fd)
        staging_directory_fds[()] = staging_fd
        staging_stat = os.fstat(staging_fd)
        effective_uid = getattr(os, "geteuid", lambda: staging_stat.st_uid)()
        if (
            not stat.S_ISDIR(staging_stat.st_mode)
            or staging_stat.st_uid != effective_uid
            or stat.S_IMODE(staging_stat.st_mode) & 0o077
            or not os.path.samestat(staging_stat, initial_staging_stat)
            or staging_path_binding_changed()
        ):
            raise _ShardPinUnavailableError("private shard staging directory changed while opening")

        staging_descriptor_path = _descriptor_path_for_open_file(staging_fd)
        if staging_descriptor_path is None:
            raise _ShardPinUnavailableError("platform cannot expose the pinned shard directory")
        staging_descriptor_root = Path(staging_descriptor_path)

        portable_regular_fallback = staging_descriptor_root.parts[:3] == ("/", "dev", "fd")
        use_regular_copy = require_regular_path or portable_regular_fallback
        scan_root = staging_path if portable_regular_fallback else staging_descriptor_root

        if use_regular_copy:
            try:
                pinned_source_copy_hash = _copy_pinned_file_descriptor(
                    source_fd,
                    pinned_name,
                    destination_dir_fd=staging_fd,
                    max_bytes=bounded_copy_limit(source_stat.st_size),
                    deadline=deadline,
                )
            except OSError as error:
                raise _ShardPinUnavailableError("platform cannot retain a regular source scan path") from error
        else:
            os.symlink(source_descriptor_path, pinned_name, dir_fd=staging_fd)
        pinned_created = True
        pinned_stat = os.stat(pinned_name, dir_fd=staging_fd)
        if use_regular_copy:
            record_copied_bytes(pinned_stat.st_size)
        if (
            use_regular_copy and (not stat.S_ISREG(pinned_stat.st_mode) or pinned_stat.st_size != source_stat.st_size)
        ) or (not use_regular_copy and not os.path.samestat(source_stat, pinned_stat)):
            raise _ShardPinUnavailableError("validated shard target changed while pinning")
        if _pinned_file_descriptor_changed(
            source_fd,
            source_stat,
            pinned_source_copy_hash,
            max_bytes=source_stat.st_size,
            deadline=deadline,
        ):
            raise _ShardPinUnavailableError("validated shard target changed while staging")
        if use_regular_copy:
            pinned_source_copy_fd = os.open(
                pinned_name,
                os.O_RDONLY | nofollow | nonblock | cloexec,
                dir_fd=staging_fd,
            )
            pinned_source_copy_stat = os.fstat(pinned_source_copy_fd)
            staged_entry_bindings.append((staging_fd, pinned_name, pinned_source_copy_fd))
        else:
            staged_entry_bindings.append((staging_fd, pinned_name, source_fd))

        for relative_name, (companion_path, companion_target) in (companion_targets or {}).items():
            relative_path = Path(relative_name)
            context_only_companion = bool(companion_target.get(CONTEXT_ONLY_COMPANION_TARGET_KEY))
            companion_use_regular_copy = use_regular_copy or context_only_companion
            if (
                relative_path.is_absolute()
                or not relative_path.parts
                or any(part in {"", ".", ".."} for part in relative_path.parts)
            ):
                raise _ShardPinUnavailableError("validated companion path escaped its scan directory")
            companion_source = Path(companion_path)
            borrowed_companion_fd = borrowed_companion_fds.get(relative_name)
            if borrowed_companion_fd is not None:
                companion_fd = os.dup(borrowed_companion_fd)
            else:
                companion_parent_fd = os.open(companion_source.parent, directory_flags)
                companion_parent_fds.append(companion_parent_fd)
                companion_fd = os.open(
                    companion_source.name,
                    os.O_RDONLY | nofollow | nonblock | cloexec,
                    dir_fd=companion_parent_fd,
                )
            companion_stat = _fstat_or_close_owned_descriptor(companion_fd)
            if not _validated_stat_matches_target(companion_stat, companion_target):
                os.close(companion_fd)
                raise _ShardPinUnavailableError("validated companion target changed before pinning")
            pinned_companion_fds.append((companion_fd, companion_stat, None))
            companion_staging_parent_fd = staging_fd
            parent_parts: tuple[str, ...] = ()
            for parent_part in relative_path.parts[:-1]:
                parent_parts = (*parent_parts, parent_part)
                existing_parent_fd = staging_directory_fds.get(parent_parts)
                if existing_parent_fd is not None:
                    companion_staging_parent_fd = existing_parent_fd
                    continue
                try:
                    os.mkdir(parent_part, mode=0o700, dir_fd=companion_staging_parent_fd)
                except FileExistsError as error:
                    raise _ShardPinUnavailableError("validated companion staging directory changed") from error
                created_staging_directories.add(parent_parts)
                created_parent_fd = os.open(parent_part, directory_flags, dir_fd=companion_staging_parent_fd)
                created_parent_stat = _fstat_or_close_owned_descriptor(created_parent_fd)
                if (
                    not stat.S_ISDIR(created_parent_stat.st_mode)
                    or created_parent_stat.st_uid != effective_uid
                    or stat.S_IMODE(created_parent_stat.st_mode) & 0o077
                ):
                    os.close(created_parent_fd)
                    raise _ShardPinUnavailableError("validated companion staging directory changed")
                staging_directory_fds[parent_parts] = created_parent_fd
                staged_entry_bindings.append((companion_staging_parent_fd, parent_part, created_parent_fd))
                companion_staging_parent_fd = created_parent_fd
            companion_descriptor_path = _descriptor_path_for_open_file(companion_fd)
            if companion_descriptor_path is None:
                raise _ShardPinUnavailableError("platform cannot expose an opened companion descriptor")
            companion_copy_hash: str | None = None
            if companion_use_regular_copy:
                try:
                    companion_copy_hash = _copy_pinned_file_descriptor(
                        companion_fd,
                        relative_path.name,
                        destination_dir_fd=companion_staging_parent_fd,
                        max_bytes=bounded_copy_limit(companion_stat.st_size),
                        deadline=deadline,
                    )
                except OSError as error:
                    raise _ShardPinUnavailableError("platform cannot retain a regular companion scan path") from error
                created_staging_entries.append((companion_staging_parent_fd, relative_path.name))
                pinned_companion_fds[-1] = (companion_fd, companion_stat, companion_copy_hash)
                if _pinned_file_descriptor_changed(
                    companion_fd,
                    companion_stat,
                    companion_copy_hash,
                    max_bytes=companion_stat.st_size,
                    deadline=deadline,
                ):
                    raise _ShardPinUnavailableError("validated companion target changed while staging")
            else:
                os.symlink(companion_descriptor_path, relative_path.name, dir_fd=companion_staging_parent_fd)
                created_staging_entries.append((companion_staging_parent_fd, relative_path.name))
            pinned_companion_stat = os.stat(relative_path.name, dir_fd=companion_staging_parent_fd)
            if companion_use_regular_copy:
                record_copied_bytes(pinned_companion_stat.st_size)
            if (
                companion_use_regular_copy
                and (
                    not stat.S_ISREG(pinned_companion_stat.st_mode)
                    or pinned_companion_stat.st_size != companion_stat.st_size
                )
            ) or (not companion_use_regular_copy and not os.path.samestat(companion_stat, pinned_companion_stat)):
                raise _ShardPinUnavailableError("pinned companion scan path resolved to a different file")
            if companion_use_regular_copy:
                assert companion_copy_hash is not None
                pinned_companion_copy_fd = os.open(
                    relative_path.name,
                    os.O_RDONLY | nofollow | nonblock | cloexec,
                    dir_fd=companion_staging_parent_fd,
                )
                pinned_companion_copy_stat = _fstat_or_close_owned_descriptor(pinned_companion_copy_fd)
                pinned_companion_copy_fds.append(
                    (pinned_companion_copy_fd, pinned_companion_copy_stat, companion_copy_hash)
                )
                staged_entry_bindings.append(
                    (companion_staging_parent_fd, relative_path.name, pinned_companion_copy_fd)
                )
            else:
                staged_entry_bindings.append((companion_staging_parent_fd, relative_path.name, companion_fd))

        staging_directory_stats = {
            directory_fd: os.fstat(directory_fd) for directory_fd in staging_directory_fds.values()
        }
        write_lease_descriptors = [
            *([pinned_source_copy_fd] if pinned_source_copy_fd is not None else []),
            *(companion_fd for companion_fd, _stat, _hash in pinned_companion_copy_fds),
        ]
        if _is_linux_platform() and write_lease_descriptors:
            linux_write_lease_guard = _LinuxWriteLeaseGuard.arm(
                write_lease_descriptors,
                deadline=deadline,
            )
        staging_mutation_monitor = _StagingMutationMonitor.arm(
            [
                *staging_directory_fds.values(),
                source_fd,
                *(companion_fd for companion_fd, _stat, _hash in pinned_companion_fds),
                *([pinned_source_copy_fd] if pinned_source_copy_fd is not None else []),
                *(companion_fd for companion_fd, _stat, _hash in pinned_companion_copy_fds),
            ]
        )
        if (
            pinned_source_copy_fd is not None
            and pinned_source_copy_stat is not None
            and _pinned_file_descriptor_changed(
                pinned_source_copy_fd,
                pinned_source_copy_stat,
                pinned_source_copy_hash,
                max_bytes=pinned_source_copy_stat.st_size,
                deadline=deadline,
            )
        ):
            raise _ShardPinUnavailableError("pinned shard content changed before scanner dispatch")
        for companion_fd, companion_stat, copy_hash in pinned_companion_copy_fds:
            if _pinned_file_descriptor_changed(
                companion_fd,
                companion_stat,
                copy_hash,
                max_bytes=companion_stat.st_size,
                deadline=deadline,
            ):
                raise _ShardPinUnavailableError("pinned companion content changed before scanner dispatch")
        if staging_mutation_monitor.changed():
            raise _ShardPinUnavailableError("private staging content changed before scanner dispatch")
        if staging_path_binding_changed():
            raise _ShardPinUnavailableError("private staging path changed before scanner dispatch")
        if staged_bindings_changed():
            raise _ShardPinUnavailableError("private staging entry changed before scanner dispatch")
        if deadline is not None and time.time() > deadline:
            raise _ShardPinUnavailableError("validated source staging exceeded the scan deadline")

        scan_path = str(scan_root / pinned_name)
        opened_scan_stat = os.stat(scan_path)
        if (
            use_regular_copy
            and (
                pinned_source_copy_stat is None
                or not stat.S_ISREG(opened_scan_stat.st_mode)
                or not os.path.samestat(opened_scan_stat, pinned_source_copy_stat)
            )
        ) or (not use_regular_copy and not os.path.samestat(source_stat, opened_scan_stat)):
            raise _ShardPinUnavailableError("pinned shard scan path resolved to a different file")
        pinned_scan = _PinnedShardScan(path=scan_path)
        yield pinned_scan
    except _ShardPinUnavailableError:
        raise
    except OSError as error:
        if pinned_scan is not None:
            raise
        raise _ShardPinUnavailableError(str(error)) from error
    finally:
        if pinned_scan is not None and source_stat is not None and source_fd is not None:
            pinned_scan.changed_during_scan = pinned_scan.changed_during_scan or staging_path_binding_changed()
            if staging_mutation_monitor is None or staging_mutation_monitor.changed():
                pinned_scan.changed_during_scan = True
            pinned_scan.changed_during_scan = pinned_scan.changed_during_scan or _pinned_file_descriptor_changed(
                source_fd,
                source_stat,
                pinned_source_copy_hash,
                max_bytes=source_stat.st_size,
                deadline=deadline,
            )
            for companion_fd, companion_stat, companion_hash in pinned_companion_fds:
                if _pinned_file_descriptor_changed(
                    companion_fd,
                    companion_stat,
                    companion_hash,
                    max_bytes=companion_stat.st_size,
                    deadline=deadline,
                ):
                    pinned_scan.changed_during_scan = True
                    break
            if (
                pinned_source_copy_fd is not None
                and pinned_source_copy_stat is not None
                and _pinned_file_descriptor_changed(
                    pinned_source_copy_fd,
                    pinned_source_copy_stat,
                    pinned_source_copy_hash,
                    max_bytes=pinned_source_copy_stat.st_size,
                    deadline=deadline,
                )
            ):
                pinned_scan.changed_during_scan = True
            for companion_fd, companion_stat, companion_hash in pinned_companion_copy_fds:
                if _pinned_file_descriptor_changed(
                    companion_fd,
                    companion_stat,
                    companion_hash,
                    max_bytes=companion_stat.st_size,
                    deadline=deadline,
                ):
                    pinned_scan.changed_during_scan = True
                    break
            for directory_fd, expected_directory_stat in staging_directory_stats.items():
                if _pinned_file_descriptor_changed(directory_fd, expected_directory_stat):
                    pinned_scan.changed_during_scan = True
                    break
            pinned_scan.changed_during_scan = pinned_scan.changed_during_scan or staged_bindings_changed()
            if linux_write_lease_guard is not None and linux_write_lease_guard.finish():
                pinned_scan.changed_during_scan = True
        if linux_write_lease_guard is not None:
            linux_write_lease_guard.close()
        if pinned_source_copy_fd is not None:
            os.close(pinned_source_copy_fd)
        if staging_mutation_monitor is not None:
            staging_mutation_monitor.close()
        if staging_ancestor_monitor is not None:
            staging_ancestor_monitor.close()
        for companion_fd, _companion_stat, _companion_hash in reversed(pinned_companion_copy_fds):
            os.close(companion_fd)
        for entry_parent_fd, entry_name in reversed(created_staging_entries):
            with suppress(OSError):
                os.unlink(entry_name, dir_fd=entry_parent_fd)
        for directory_parts in sorted(created_staging_directories, key=len, reverse=True):
            parent_parts = directory_parts[:-1]
            parent_directory_fd = staging_directory_fds.get(parent_parts)
            if parent_directory_fd is None:
                continue
            with suppress(OSError):
                os.rmdir(directory_parts[-1], dir_fd=parent_directory_fd)
        if pinned_created and staging_fd is not None:
            with suppress(OSError):
                os.unlink(pinned_name, dir_fd=staging_fd)
        for directory_parts, directory_fd in sorted(
            staging_directory_fds.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            if directory_parts:
                os.close(directory_fd)
        if staging_fd is not None:
            os.close(staging_fd)
        if staging_path is not None and staging_parent_fd is not None and initial_staging_stat is not None:
            with suppress(OSError):
                final_staging_stat = os.stat(staging_path.name, dir_fd=staging_parent_fd, follow_symlinks=False)
                if os.path.samestat(initial_staging_stat, final_staging_stat):
                    os.rmdir(staging_path.name, dir_fd=staging_parent_fd)
        if source_fd is not None:
            os.close(source_fd)
        for companion_fd, _source_stat, _source_hash in reversed(pinned_companion_fds):
            os.close(companion_fd)
        for companion_parent_fd in reversed(companion_parent_fds):
            os.close(companion_parent_fd)
        for _ancestor_path, ancestor_fd in reversed(staging_ancestor_bindings):
            os.close(ancestor_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _supports_reliable_shard_cache_identity() -> bool:
    """Return whether sibling metadata changes reliably invalidate cached families."""
    # On supported Windows Python versions, st_ctime_ns is the file creation
    # time, so same-size in-place rewrites can preserve every cached identity field.
    return os.name != "nt"


def _is_resolved_path_within_directory(base_dir: Path, resolved_target: str) -> bool:
    """Return True when a resolved target remains inside the shard directory."""
    try:
        base_path = base_dir.resolve()
        target_path = Path(resolved_target).resolve()
    except (OSError, RuntimeError):
        return False
    if os.name == "nt":
        base_norm = os.path.normcase(os.path.normpath(str(base_path)))
        target_norm = os.path.normcase(os.path.normpath(str(target_path)))
        try:
            return os.path.commonpath([target_norm, base_norm]) == base_norm
        except ValueError:
            return False
    return target_path.is_relative_to(base_path)


def _build_advanced_shard_family_cache_fingerprint(
    shard_info: dict[str, Any] | None,
    hasher: Any,
) -> tuple[dict[str, Any] | None, bool]:
    """Return a content-bound shard-family fingerprint, or mark cache unsafe."""
    if shard_info is None:
        return None, True
    if not shard_info:
        return None, False

    pattern = shard_info.get("pattern")
    raw_shards = shard_info.get("shards")
    total_shards = shard_info.get("total_shards")
    expected_total_shards = shard_info.get("expected_total_shards")
    if (
        type(pattern) is not str
        or not pattern
        or not isinstance(raw_shards, list)
        or not raw_shards
        or any(type(shard_path) is not str or not shard_path for shard_path in raw_shards)
        or type(total_shards) is not int
        or total_shards != len(raw_shards)
        or (
            expected_total_shards is not None
            and (type(expected_total_shards) is not int or expected_total_shards != len(raw_shards))
        )
    ):
        return None, False

    for count_key in (
        "duplicate_shard_count",
        "missing_shard_count",
        "out_of_scope_shard_count",
        "unreadable_shard_count",
        "unvalidated_shard_count",
        "unexpected_shard_count",
    ):
        count = shard_info.get(count_key)
        if count is not None and (type(count) is not int or count != 0):
            return None, False

    for members_key in (
        "duplicate_shards",
        "missing_shard_indices",
        "out_of_scope_shards",
        "unreadable_shards",
        "unvalidated_shards",
        "unexpected_shards",
    ):
        suspect_members = shard_info.get(members_key)
        if suspect_members is not None and (not isinstance(suspect_members, list) or suspect_members):
            return None, False

    missing_indices_truncated = shard_info.get("missing_shard_indices_truncated")
    if missing_indices_truncated is not None and (
        type(missing_indices_truncated) is not bool or missing_indices_truncated
    ):
        return None, False

    members: list[dict[str, str]] = []
    resolved_member_identities: set[tuple[int | str, ...]] = set()
    for shard_path in sorted(raw_shards):
        try:
            resolved_path = str(Path(shard_path).resolve(strict=True))
            shard_stat = os.stat(resolved_path, follow_symlinks=False)
            if not stat.S_ISREG(shard_stat.st_mode):
                return None, False
            content_hash = hasher.hash_file(resolved_path)
        except Exception:
            return None, False
        normalized_resolved_path = os.path.normcase(os.path.normpath(resolved_path))
        resolved_identity: tuple[int | str, ...]
        if shard_stat.st_ino:
            resolved_identity = ("inode", shard_stat.st_dev, shard_stat.st_ino)
        else:
            resolved_identity = ("path", normalized_resolved_path)
        if resolved_identity in resolved_member_identities:
            return None, False
        resolved_member_identities.add(resolved_identity)
        if type(content_hash) is not str or not content_hash.startswith("secure:") or not content_hash[7:]:
            return None, False
        members.append({"path": resolved_path, "content_hash": content_hash})

    return (
        {
            "pattern": pattern,
            "expected_total_shards": expected_total_shards,
            "members": members,
        },
        True,
    )


def _build_advanced_shard_model_config_cache_fingerprint(
    file_path: str,
    hasher: Any,
) -> tuple[dict[str, str] | None, bool]:
    """Return the selected model config identity, or mark cache unsafe."""
    config_path = ShardedModelDetector.find_model_config(file_path)
    if config_path is None:
        return None, True

    try:
        resolved_path = str(Path(config_path).resolve(strict=True))
        config_stat = os.stat(config_path, follow_symlinks=False)
        if not stat.S_ISREG(config_stat.st_mode):
            return None, False
        content_hash = hasher.hash_file(resolved_path)
        post_resolved_path = str(Path(config_path).resolve(strict=True))
        post_hash_stat = os.stat(config_path, follow_symlinks=False)
    except Exception:
        return None, False

    if (
        resolved_path != post_resolved_path
        or not stat.S_ISREG(post_hash_stat.st_mode)
        or not os.path.samestat(config_stat, post_hash_stat)
        or any(
            current_value != previous_value
            for current_value, previous_value in (
                (post_hash_stat.st_size, config_stat.st_size),
                (post_hash_stat.st_mtime_ns, config_stat.st_mtime_ns),
                (post_hash_stat.st_ctime_ns, config_stat.st_ctime_ns),
            )
        )
        or type(content_hash) is not str
        or not content_hash.startswith("secure:")
        or not content_hash[7:]
    ):
        return None, False

    return {"path": resolved_path, "content_hash": content_hash}, True


def _mark_inconclusive_scan_outcome(result: "ScanResult", reason: str) -> None:
    """Mark a scan result as incomplete while preserving existing reasons."""
    from ...scanner_results import INCONCLUSIVE_SCAN_OUTCOME

    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    existing_reasons = result.metadata.get("scan_outcome_reasons")
    reasons = existing_reasons if isinstance(existing_reasons, list) else []
    if reason not in reasons:
        reasons.append(reason)
    result.metadata["scan_outcome_reasons"] = reasons


def _normalized_absolute_path(path: str | os.PathLike[str]) -> str:
    """Return the normalized absolute form used for shard-family membership."""
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def _summarize_missing_shard_indices(
    present_indices: set[int],
    expected_indices: ExpectedShardIndices,
) -> tuple[list[int], int, bool]:
    """Return a bounded sample, total count, and truncation flag for missing shards."""
    bounded_present_indices = {index for index in present_indices if index in expected_indices}
    missing_count = max(_count_expected_shard_indices(expected_indices) - len(bounded_present_indices), 0)
    if missing_count == 0:
        return [], 0, False

    missing_indices: list[int] = []
    for expected_index in expected_indices:
        if expected_index in bounded_present_indices:
            continue
        missing_indices.append(expected_index)
        if len(missing_indices) >= MAX_RECORDED_MISSING_SHARD_INDICES:
            break

    return missing_indices, missing_count, missing_count > len(missing_indices)


class ShardedModelDetector:
    """Detect and handle sharded model files."""

    # Common sharding patterns for large models
    SHARD_PATTERNS: ClassVar[list[str]] = [
        r"pytorch_model-(\d+)-of-(\d+)\.bin",  # HuggingFace PyTorch sharding
        r"model\.ckpt-(\d+)\.data-\d+-of-\d+",  # TensorFlow sharding
        r"model_weights_(\d+)\.h5",  # Keras sharding
        r"checkpoint_(\d+)\.pt",  # PyTorch checkpoint sharding
        r"params_shard_(\d+)\.bin",  # Custom parameter sharding
    ]

    @staticmethod
    def _expected_index_range(expected_total: int, *, zero_based: bool) -> range:
        if expected_total <= 0:
            return range(0)
        return range(0, expected_total) if zero_based else range(1, expected_total + 1)

    @classmethod
    def expected_indices_for_shard_family(
        cls,
        expected_total: int,
        authoritative_indices: ExpectedShardIndices | None = None,
    ) -> tuple[ExpectedShardIndices, str]:
        """Return the expected shard indices and the base policy used for a shard family."""
        if authoritative_indices is not None:
            zero_based = cls._expected_index_range(expected_total, zero_based=True)
            one_based = cls._expected_index_range(expected_total, zero_based=False)
            if authoritative_indices == zero_based or (
                not isinstance(authoritative_indices, range)
                and len(authoritative_indices) == _count_expected_shard_indices(zero_based)
                and all(index in zero_based for index in authoritative_indices)
            ):
                return zero_based, "zero"
            if authoritative_indices == one_based or (
                not isinstance(authoritative_indices, range)
                and len(authoritative_indices) == _count_expected_shard_indices(one_based)
                and all(index in one_based for index in authoritative_indices)
            ):
                return one_based, "one"
            return frozenset(authoritative_indices), "custom"

        one_based = cls._expected_index_range(expected_total, zero_based=False)
        # A shard named 00000 is not sufficient evidence that the family is
        # zero-based. Only a validated SafeTensors index may change the base.
        return one_based, "one"

    @staticmethod
    def _match_family_filename(
        file_name: str,
        pattern: str,
        *,
        expected_total: int | None,
        normalized_safetensors_stem: str | None,
    ) -> tuple[int | None, int | None] | None:
        """Match one filename without using regex case folding for SafeTensors stems."""
        if is_safetensors_family_pattern(pattern):
            parsed = parse_safetensors_shard_shape(file_name)
            if (
                parsed is None
                or normalized_safetensors_stem is None
                or parsed.normalized_stem != normalized_safetensors_stem
                or (expected_total is not None and parsed.total != expected_total)
            ):
                return None
            return parsed.index, parsed.total

        match = re.fullmatch(pattern, file_name)
        if match is None:
            return None
        current_index: int | None = None
        current_total: int | None = None
        if match.lastindex:
            with suppress(IndexError, ValueError):
                current_index = int(match.group(1))
        if (match.lastindex or 0) >= 2:
            with suppress(IndexError, ValueError):
                current_total = int(match.group(2))
        if expected_total is not None and current_total != expected_total:
            return None
        return current_index, current_total

    @classmethod
    def _add_bounded_family_candidate(
        cls,
        candidate: Path,
        candidate_paths: dict[str, Path],
        pattern: str,
        *,
        expected_total: int | None,
        normalized_safetensors_stem: str | None,
    ) -> bool:
        """Retain one unique family candidate, returning False at the family cap."""
        if (
            cls._match_family_filename(
                candidate.name,
                pattern,
                expected_total=expected_total,
                normalized_safetensors_stem=normalized_safetensors_stem,
            )
            is None
        ):
            return True
        normalized_candidate = os.path.normcase(os.path.normpath(os.path.abspath(candidate)))
        if normalized_candidate in candidate_paths:
            return True
        if len(candidate_paths) >= MAX_SCANNABLE_SHARDS:
            return False
        candidate_paths[normalized_candidate] = candidate
        return True

    @classmethod
    def match_shard_filename(cls, file_name: str) -> dict[str, int | str | None] | None:
        """Return shard metadata for a filename when it matches a known shard pattern."""
        safetensors_match = cls.match_safetensors_shard_filename(file_name)
        if safetensors_match is not None:
            return safetensors_match
        for pattern in cls.SHARD_PATTERNS:
            match = re.fullmatch(pattern, file_name)
            if not match:
                continue

            current_shard_index: int | None = None
            expected_total_shards: int | None = None
            if match.lastindex:
                with suppress(IndexError, ValueError):
                    current_shard_index = int(match.group(1))
            if (match.lastindex or 0) >= 2:
                with suppress(IndexError, ValueError):
                    expected_total_shards = int(match.group(2))

            return {
                "pattern": pattern,
                "current_shard_index": current_shard_index,
                "expected_total_shards": expected_total_shards,
            }

        return None

    @staticmethod
    def match_safetensors_shard_filename(file_name: str) -> dict[str, int | str | None] | None:
        """Return stem-safe metadata for an arbitrary-width SafeTensors shard basename."""
        parsed = parse_safetensors_shard_shape(file_name)
        if parsed is None:
            return None
        return {
            "pattern": safetensors_family_pattern(parsed.normalized_stem),
            "shard_kind": SAFETENSORS_SHARD_KIND,
            "shard_stem": parsed.stem,
            "normalized_shard_stem": parsed.normalized_stem,
            "current_shard_index": parsed.index,
            "expected_total_shards": parsed.total,
        }

    @staticmethod
    def _safe_index_target_path(index_dir: Path, raw_target: str) -> Path:
        """Return a local path for a SafeTensors index target or raise ValueError."""
        if not raw_target or "\\" in raw_target or ":" in raw_target:
            raise ValueError("unsafe safetensors index target path")
        target_path = PurePosixPath(raw_target)
        if target_path.is_absolute() or any(part in {"", ".", ".."} for part in target_path.parts):
            raise ValueError("unsafe safetensors index target path")
        return index_dir.joinpath(*target_path.parts)

    @staticmethod
    def _index_target_scope_path(index_dir: Path, raw_target: str) -> Path | None:
        """Normalize a target only for invalid-index scope comparison."""
        try:
            candidate = Path(raw_target)
            if not candidate.is_absolute():
                candidate = index_dir / candidate
            normalized_index_dir = _normalized_absolute_path(index_dir)
            normalized_candidate = _normalized_absolute_path(candidate)
            if os.path.commonpath([normalized_index_dir, normalized_candidate]) != normalized_index_dir:
                return None
        except (OSError, RuntimeError, ValueError):
            return None
        return Path(normalized_candidate)

    @staticmethod
    def _safetensors_stat_identity(
        path: str | os.PathLike[str],
        path_stat: os.stat_result,
    ) -> tuple[int | str, ...] | None:
        """Return a stable identity for alias comparison, if the platform exposes one."""
        if path_stat.st_ino:
            return ("inode", path_stat.st_dev, path_stat.st_ino)
        if path_stat.st_nlink > 1:
            return None
        try:
            resolved_path = Path(path).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return None
        return ("path", _normalized_absolute_path(resolved_path))

    @classmethod
    def _observe_safetensors_inventory_target_identities(
        cls,
        inventory: _SafetensorsShardIndexInventory,
    ) -> _SafetensorsShardIndexInventory:
        """Snapshot bounded target identities once for O(1) alias membership checks."""
        identities: set[tuple[int | str, ...]] = set()
        identity_error: str | None = None
        if len(inventory.expected_source_paths) > MAX_SAFETENSORS_SHARD_ALIAS_IDENTITY_CHECKS:
            identity_error = "safetensors index target identity is indeterminate"
        else:
            for source_path in sorted(inventory.expected_source_paths):
                try:
                    source_stat = os.stat(source_path)
                except FileNotFoundError:
                    try:
                        if os.path.lexists(source_path):
                            identity_error = "safetensors index target identity is indeterminate"
                            break
                    except (OSError, RuntimeError, ValueError):
                        identity_error = "safetensors index target identity is indeterminate"
                        break
                    continue
                except (OSError, RuntimeError, ValueError):
                    identity_error = "safetensors index target identity is indeterminate"
                    break
                identity = cls._safetensors_stat_identity(source_path, source_stat)
                if identity is None:
                    identity_error = "safetensors index target identity is indeterminate"
                    break
                identities.add(identity)
        return replace(
            inventory,
            expected_source_identities=frozenset(identities),
            target_identities_observed=True,
            target_identity_error=identity_error,
        )

    @classmethod
    def _read_safetensors_index_inventory(
        cls,
        index_dir: Path,
        index_path: Path,
        inspection_context: _SafetensorsIndexInspectionContext,
        *,
        force_content_revalidation: bool = False,
        content_revalidated_paths: set[str] | None = None,
    ) -> _SafetensorsShardIndexInventory:
        """Parse one SafeTensors index, returning its shard inventory or a validation error."""
        expected_paths: set[str] = set()
        target_scope_complete = False
        inventory_normalized_stem: str | None = None
        cache_key: tuple[Any, ...] | None = None
        observation_prefix: tuple[Any, ...] | None = None
        index_fingerprint: str | None = None
        try:
            resolved_index = index_path.resolve(strict=True)
            hf_cache_root = _find_hf_cache_root(index_path.absolute())
            trusted_hf_blobs_root = _trusted_hf_blobs_root(hf_cache_root) if hf_cache_root is not None else None
            index_target_allowed = _is_resolved_path_within_directory(index_dir, str(resolved_index)) or (
                trusted_hf_blobs_root is not None and resolved_index.is_relative_to(trusted_hf_blobs_root)
            )
            if not index_target_allowed:
                raise ValueError("safetensors index resolves outside the model directory")
            pre_read_stat = os.stat(resolved_index, follow_symlinks=False)
            if not stat.S_ISREG(pre_read_stat.st_mode):
                raise ValueError("safetensors index is not a regular file")
            if pre_read_stat.st_size > MAX_SAFETENSORS_SHARD_INDEX_BYTES:
                raise ValueError("safetensors index exceeds bounded parse limit")
            observation_prefix = _safetensors_index_observation_prefix(index_path, resolved_index, pre_read_stat)
            cache_key = (
                _normalized_absolute_path(index_dir),
                *observation_prefix,
            )
            cached = inspection_context.cached_inventory(cache_key)
            normalized_index_path = _normalized_absolute_path(index_path)
            revalidate_cached_content = (
                cached is not None
                and force_content_revalidation
                and _safetensors_index_requires_content_revalidation()
                and (content_revalidated_paths is None or normalized_index_path not in content_revalidated_paths)
            )
            if (
                force_content_revalidation
                and content_revalidated_paths is not None
                and (cached is None or revalidate_cached_content)
            ):
                content_revalidated_paths.add(normalized_index_path)
            if cached is not None and not revalidate_cached_content:
                cached_observation = (*observation_prefix, cached.fingerprint)
                observed_cached = inspection_context.observe_cached_inventory(
                    cache_key,
                    index_path,
                    cached_observation,
                )
                assert observed_cached is not None
                return observed_cached
            budget_error = (
                inspection_context.reserve_content_revalidation(pre_read_stat.st_size)
                if revalidate_cached_content
                else inspection_context.reserve_observation(cache_key, pre_read_stat.st_size)
            )
            if budget_error is not None:
                raise ValueError(budget_error)
            with resolved_index.open("rb") as index_file:
                opened_stat = os.fstat(index_file.fileno())
                if not os.path.samestat(pre_read_stat, opened_stat):
                    raise ValueError("safetensors index changed while opening")
                index_bytes = index_file.read(pre_read_stat.st_size)
            if len(index_bytes) > MAX_SAFETENSORS_SHARD_INDEX_BYTES:
                raise ValueError("safetensors index exceeds bounded parse limit")
            post_read_stat = os.stat(resolved_index, follow_symlinks=False)
            if (
                len(index_bytes) != pre_read_stat.st_size
                or not os.path.samestat(
                    pre_read_stat,
                    post_read_stat,
                )
                or any(
                    getattr(pre_read_stat, field) != getattr(post_read_stat, field)
                    for field in ("st_size", "st_mtime_ns", "st_ctime_ns")
                )
            ):
                raise ValueError("safetensors index changed while reading")
            index_fingerprint = hashlib.sha256(index_bytes).hexdigest()
            if cached is not None and cached.fingerprint == index_fingerprint:
                return inspection_context.record_inventory(
                    cache_key,
                    index_path,
                    (*observation_prefix, index_fingerprint),
                    cached,
                )
            index_doc = _load_safetensors_index_json(index_bytes)
            if not isinstance(index_doc, dict):
                raise ValueError("safetensors index root must be an object")
            weight_map_values = [index_doc.get("weight_map")]
            if isinstance(index_doc, _DuplicateAwareSafetensorsIndexObject):
                weight_map_values.extend(value for key, value in index_doc.overwritten_items if key == "weight_map")
            weight_maps = [value for value in weight_map_values if isinstance(value, dict) and value]
            if not weight_maps:
                raise ValueError("safetensors index weight_map must be a non-empty object")

            target_indices: set[int] = set()
            index_expected_total: int | None = None
            raw_targets: list[Any] = []
            for weight_map in weight_maps:
                raw_targets.extend(weight_map.values())
                if isinstance(weight_map, _DuplicateAwareSafetensorsIndexObject):
                    raw_targets.extend(value for _key, value in weight_map.overwritten_items)
            occurrence_limit_exceeded = len(raw_targets) > MAX_SAFETENSORS_SHARD_INDEX_TENSORS
            has_non_string_target = not all(isinstance(target, str) for target in raw_targets)
            string_targets = [target for target in raw_targets if isinstance(target, str)]
            target_candidates: Iterable[str] = sorted(set(string_targets))
            target_files: list[Path] = []
            target_path_error: ValueError | None = None
            all_target_paths_scoped = True
            for raw_target in target_candidates:
                try:
                    target_file = cls._safe_index_target_path(index_dir, raw_target)
                except ValueError as exc:
                    target_path_error = exc
                    all_target_paths_scoped = False
                    scope_path = cls._index_target_scope_path(index_dir, raw_target)
                    if scope_path is not None:
                        expected_paths.add(_normalized_absolute_path(scope_path))
                    continue
                target_files.append(target_file)
            expected_paths.update(_normalized_absolute_path(target_file) for target_file in target_files)
            target_scope_complete = all_target_paths_scoped
            if target_path_error is not None:
                raise target_path_error
            if occurrence_limit_exceeded:
                raise ValueError("safetensors index exceeds tensor occurrence limit")
            if has_non_string_target:
                raise ValueError("safetensors index weight_map targets must be strings")
            if isinstance(index_doc, _DuplicateAwareSafetensorsIndexObject) and index_doc.has_duplicate_keys:
                raise ValueError("safetensors index contains duplicate JSON object keys")
            target_matches = [cls.match_safetensors_shard_filename(target_file.name) for target_file in target_files]
            if target_matches and all(target_match is None for target_match in target_matches):
                inventory = _SafetensorsShardIndexInventory(
                    index_path=index_path,
                    expected_source_paths=frozenset(expected_paths),
                    expected_indices=cls._expected_index_range(1, zero_based=False),
                    index_base="invalid",
                    fingerprint=index_fingerprint,
                    error="safetensors index target does not match shard filename pattern",
                    proven_unrelated=True,
                    target_scope_complete=True,
                )
                inventory = cls._observe_safetensors_inventory_target_identities(inventory)
                assert cache_key is not None and observation_prefix is not None
                return inspection_context.record_inventory(
                    cache_key,
                    index_path,
                    (*observation_prefix, index_fingerprint),
                    inventory,
                )

            for target_match in target_matches:
                if target_match is None:
                    raise ValueError("safetensors index target does not match shard filename pattern")
                target_index = target_match["current_shard_index"]
                target_total = target_match["expected_total_shards"]
                target_stem = target_match.get("normalized_shard_stem")
                if (
                    not isinstance(target_index, int)
                    or not isinstance(target_total, int)
                    or not isinstance(target_stem, str)
                ):
                    raise ValueError("safetensors index target does not match shard filename pattern")
                if inventory_normalized_stem is None:
                    inventory_normalized_stem = target_stem
                elif target_stem != inventory_normalized_stem:
                    raise ValueError("safetensors index references multiple model shard families")
                if index_expected_total is None:
                    index_expected_total = target_total
                elif target_total != index_expected_total:
                    raise ValueError("safetensors index target total does not match selected shard total")
                target_indices.add(target_index)

            if index_expected_total is None:
                raise ValueError("safetensors index shard count does not match selected shard total")
            if len(expected_paths) != index_expected_total or len(target_indices) != index_expected_total:
                raise ValueError("safetensors index shard count does not match selected shard total")

            zero_based = cls._expected_index_range(index_expected_total, zero_based=True)
            one_based = cls._expected_index_range(index_expected_total, zero_based=False)
            if all(index in zero_based for index in target_indices):
                inventory = _SafetensorsShardIndexInventory(
                    index_path=index_path,
                    expected_source_paths=frozenset(expected_paths),
                    expected_indices=zero_based,
                    index_base="zero",
                    fingerprint=index_fingerprint,
                    target_scope_complete=True,
                    normalized_shard_stem=inventory_normalized_stem,
                )
                inventory = cls._observe_safetensors_inventory_target_identities(inventory)
                assert cache_key is not None and observation_prefix is not None
                return inspection_context.record_inventory(
                    cache_key,
                    index_path,
                    (*observation_prefix, index_fingerprint),
                    inventory,
                )
            if all(index in one_based for index in target_indices):
                inventory = _SafetensorsShardIndexInventory(
                    index_path=index_path,
                    expected_source_paths=frozenset(expected_paths),
                    expected_indices=one_based,
                    index_base="one",
                    fingerprint=index_fingerprint,
                    target_scope_complete=True,
                    normalized_shard_stem=inventory_normalized_stem,
                )
                inventory = cls._observe_safetensors_inventory_target_identities(inventory)
                assert cache_key is not None and observation_prefix is not None
                return inspection_context.record_inventory(
                    cache_key,
                    index_path,
                    (*observation_prefix, index_fingerprint),
                    inventory,
                )
            raise ValueError("safetensors index shard indices are ambiguous")
        except Exception as exc:
            inventory = _SafetensorsShardIndexInventory(
                index_path=index_path,
                expected_source_paths=frozenset(expected_paths),
                expected_indices=cls._expected_index_range(1, zero_based=False),
                index_base="invalid",
                fingerprint=index_fingerprint,
                error=str(exc),
                target_scope_complete=target_scope_complete,
                normalized_shard_stem=inventory_normalized_stem,
            )
            if target_scope_complete:
                inventory = cls._observe_safetensors_inventory_target_identities(inventory)
            if cache_key is not None and observation_prefix is not None:
                return inspection_context.record_inventory(
                    cache_key,
                    index_path,
                    (*observation_prefix, index_fingerprint),
                    inventory,
                )
            return inventory

    @staticmethod
    def _safetensors_inventory_file_relationship(
        inventory: _SafetensorsShardIndexInventory,
        current_file: Path,
    ) -> bool | None:
        """Return whether stable identity links a target, or None when indeterminate."""
        normalized_current = _normalized_absolute_path(current_file)
        if normalized_current in inventory.expected_source_paths:
            return True
        if not inventory.expected_source_paths:
            return False
        if not inventory.target_identities_observed or inventory.target_identity_error is not None:
            return None
        try:
            current_stat = os.stat(current_file)
        except (OSError, RuntimeError, ValueError):
            return None
        current_identity = ShardedModelDetector._safetensors_stat_identity(current_file, current_stat)
        if current_identity is None:
            return None
        return current_identity in inventory.expected_source_identities

    @classmethod
    def _safetensors_inventory_governs_file(
        cls,
        inventory: _SafetensorsShardIndexInventory,
        current_file: Path,
        pattern: str,
        expected_total: int,
    ) -> bool | None:
        """Return index authority, or None when target identity is indeterminate."""
        if not is_safetensors_family_pattern(pattern):
            return False
        normalized_current = _normalized_absolute_path(current_file)
        if normalized_current in inventory.expected_source_paths:
            return True
        current_match = parse_safetensors_shard_shape(current_file.name)
        if current_match is None:
            return False
        if inventory.normalized_shard_stem is None:
            return False
        if current_match.family != (inventory.normalized_shard_stem, expected_total):
            return False
        if _count_expected_shard_indices(inventory.expected_indices) != expected_total:
            return False
        file_relationship = cls._safetensors_inventory_file_relationship(inventory, current_file)
        if file_relationship is not False:
            return file_relationship
        current_parent = os.path.dirname(normalized_current)
        expected_parents = {os.path.dirname(source_path) for source_path in inventory.expected_source_paths}
        if current_parent not in expected_parents:
            return False
        current_details = cls.match_safetensors_shard_filename(current_file.name)
        current_stem = current_details.get("normalized_shard_stem") if current_details is not None else None
        expected_stems = {
            target_details.get("normalized_shard_stem")
            for source_path in inventory.expected_source_paths
            if (target_details := cls.match_safetensors_shard_filename(Path(source_path).name)) is not None
        }
        return isinstance(current_stem, str) and current_stem in expected_stems

    @staticmethod
    def _safetensors_inventory_is_proven_unrelated(
        inventory: _SafetensorsShardIndexInventory,
        current_file: Path,
    ) -> bool:
        """Return whether every non-shard target is a distinct stable local file."""
        if not inventory.proven_unrelated or not inventory.expected_source_paths:
            return False
        index_name = inventory.index_path.name
        if index_name.casefold() == SAFETENSORS_INDEX_NAME:
            return False
        current_match = parse_safetensors_shard_shape(current_file.name)
        if current_match is not None and index_name.casefold().endswith(SAFETENSORS_INDEX_SUFFIX):
            index_stem = index_name[: -len(SAFETENSORS_INDEX_SUFFIX)]
            if index_stem.casefold() == current_match.normalized_stem:
                return False
        normalized_current = _normalized_absolute_path(current_file)
        for source_path in inventory.expected_source_paths:
            if source_path == normalized_current:
                return False
            if not os.path.lexists(source_path):
                if os.path.islink(source_path):
                    return False
                continue
            try:
                if Path(source_path).samefile(current_file):
                    return False
            except OSError:
                return False
        return True

    @staticmethod
    def _safetensors_index_candidates(
        index_dir: Path,
        inspection_context: _SafetensorsIndexInspectionContext | None = None,
    ) -> tuple[list[Path], bool]:
        """Return bounded local index candidates, preferring the canonical name."""
        canonical_path = index_dir / SAFETENSORS_INDEX_NAME
        canonical_available = canonical_path.exists() or canonical_path.is_symlink()
        candidates: list[Path] = []
        try:
            for entry_count, candidate in enumerate(index_dir.iterdir(), start=1):
                if entry_count > MAX_SAFETENSORS_SHARD_INDEX_DIRECTORY_ENTRIES:
                    return candidates, True
                if inspection_context is not None and inspection_context.reserve_directory_entry() is not None:
                    return candidates, True
                basename = candidate.name
                if len(basename) <= len(SAFETENSORS_INDEX_SUFFIX) or not basename.lower().endswith(
                    SAFETENSORS_INDEX_SUFFIX
                ):
                    continue
                candidates.append(candidate)
                if len(candidates) > MAX_SAFETENSORS_SHARD_INDEX_FILES:
                    return candidates, True
        except OSError:
            return candidates, True
        if canonical_available:
            # Keep the actual directory entry when canonical_path is only a case-insensitive alias.
            for candidate in candidates:
                if candidate.name.casefold() != SAFETENSORS_INDEX_NAME:
                    continue
                if candidate == canonical_path:
                    break
                try:
                    if candidate.samefile(canonical_path):
                        break
                except OSError:
                    continue
            else:
                candidates.append(canonical_path)
                if len(candidates) > MAX_SAFETENSORS_SHARD_INDEX_FILES:
                    return candidates, True
        candidates.sort(
            key=lambda path: (path.name.casefold() != SAFETENSORS_INDEX_NAME, path.name.casefold(), path.name),
        )
        return candidates, False

    @classmethod
    def _load_safetensors_index_inventory(
        cls,
        dir_path: Path,
        pattern: str,
        expected_total: int | None,
        current_file: Path,
        index_search_root: Path,
        inspection_context: _SafetensorsIndexInspectionContext,
        *,
        force_content_revalidation: bool = False,
        content_revalidated_paths: set[str] | None = None,
        target_identity_refreshes: dict[str, _SafetensorsShardIndexInventory] | None = None,
    ) -> _SafetensorsShardIndexInventory | None:
        """Load a governing SafeTensors index inventory or captured validation error."""
        if not is_safetensors_family_pattern(pattern) or not isinstance(expected_total, int):
            return None

        try:
            absolute_dir = Path(os.path.abspath(dir_path)).resolve(strict=True)
            resolved_search_root = index_search_root.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        normalized_search_root = _normalized_absolute_path(resolved_search_root)
        try:
            if os.path.commonpath([_normalized_absolute_path(absolute_dir), normalized_search_root]) != (
                normalized_search_root
            ):
                return None
        except ValueError:
            return None

        index_dir = absolute_dir
        while True:
            directory_error = inspection_context.register_directory(index_dir)
            if directory_error is not None:
                return _SafetensorsShardIndexInventory(
                    index_path=index_dir / SAFETENSORS_INDEX_NAME,
                    expected_source_paths=frozenset(),
                    expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                    index_base="invalid",
                    error=directory_error,
                )
            index_candidates, candidate_limit_exceeded = cls._safetensors_index_candidates(
                index_dir,
                inspection_context,
            )
            if candidate_limit_exceeded:
                candidate_failure = inspection_context.record_failure(
                    "safetensors index inspection limit exceeded"
                    if len(index_candidates) > MAX_SAFETENSORS_SHARD_INDEX_FILES
                    else "safetensors index directory enumeration incomplete"
                )
                return _SafetensorsShardIndexInventory(
                    index_path=index_candidates[0] if index_candidates else index_dir / SAFETENSORS_INDEX_NAME,
                    expected_source_paths=frozenset(),
                    expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                    index_base="invalid",
                    error=candidate_failure,
                )
            candidate_error = inspection_context.register_candidates(index_candidates)
            if candidate_error is not None:
                return _SafetensorsShardIndexInventory(
                    index_path=index_candidates[0] if index_candidates else index_dir / SAFETENSORS_INDEX_NAME,
                    expected_source_paths=frozenset(),
                    expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                    index_base="invalid",
                    error=candidate_error,
                )

            candidate_observations = {
                candidate.name: _safetensors_index_path_observation(candidate) for candidate in index_candidates
            }

            def candidate_listing_failure(
                index_directory: Path = index_dir,
                expected_candidates: tuple[Path, ...] = tuple(index_candidates),
                expected_observations: dict[str, tuple[Any, ...] | None] = candidate_observations,
            ) -> _SafetensorsShardIndexInventory | None:
                for expected_candidate in expected_candidates:
                    if expected_observations.get(expected_candidate.name) != _safetensors_index_path_observation(
                        expected_candidate
                    ):
                        return _SafetensorsShardIndexInventory(
                            index_path=expected_candidate,
                            expected_source_paths=frozenset(),
                            expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                            index_base="invalid",
                            error="safetensors index changed during inspection",
                        )
                current_candidates, current_limit_exceeded = cls._safetensors_index_candidates(
                    index_directory,
                    inspection_context,
                )
                candidate_names = tuple(path.name for path in expected_candidates)
                current_candidate_names = tuple(path.name for path in current_candidates)
                if not current_limit_exceeded and current_candidate_names == candidate_names:
                    return None
                failure = inspection_context.record_failure(
                    "safetensors index inspection limit exceeded"
                    if len(current_candidates) > MAX_SAFETENSORS_SHARD_INDEX_FILES
                    else "safetensors index directory enumeration incomplete"
                )
                return _SafetensorsShardIndexInventory(
                    index_path=(
                        current_candidates[0]
                        if current_candidates
                        else expected_candidates[0]
                        if expected_candidates
                        else index_directory / SAFETENSORS_INDEX_NAME
                    ),
                    expected_source_paths=frozenset(),
                    expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                    index_base="invalid",
                    error=failure,
                )

            def stable_inventory(
                inventory: _SafetensorsShardIndexInventory,
            ) -> _SafetensorsShardIndexInventory:
                if inventory.error is not None:
                    return inventory
                return candidate_listing_failure() or inventory

            governing_inventory: _SafetensorsShardIndexInventory | None = None
            for index_path in index_candidates:
                inventory = cls._read_safetensors_index_inventory(
                    index_dir,
                    index_path,
                    inspection_context,
                    force_content_revalidation=force_content_revalidation,
                    content_revalidated_paths=content_revalidated_paths,
                )
                if force_content_revalidation and inventory.target_scope_complete:
                    normalized_index_path = _normalized_absolute_path(index_path)
                    refreshed_inventory = (
                        target_identity_refreshes.get(normalized_index_path)
                        if target_identity_refreshes is not None
                        else None
                    )
                    if (
                        refreshed_inventory is None
                        or refreshed_inventory.fingerprint != inventory.fingerprint
                        or refreshed_inventory.generation != inventory.generation
                        or refreshed_inventory.expected_source_paths != inventory.expected_source_paths
                    ):
                        refreshed_inventory = cls._observe_safetensors_inventory_target_identities(inventory)
                        if target_identity_refreshes is not None:
                            target_identity_refreshes[normalized_index_path] = refreshed_inventory
                    inventory = refreshed_inventory
                if inventory.error is not None:
                    if not inventory.target_scope_complete:
                        return stable_inventory(inventory)
                    same_directory_candidate = _normalized_absolute_path(index_dir) == _normalized_absolute_path(
                        absolute_dir
                    )
                    if cls._safetensors_inventory_file_relationship(inventory, current_file) is not False or (
                        same_directory_candidate
                        and not cls._safetensors_inventory_is_proven_unrelated(inventory, current_file)
                    ):
                        return stable_inventory(inventory)
                    continue
                governs_file = cls._safetensors_inventory_governs_file(
                    inventory,
                    current_file,
                    pattern,
                    expected_total,
                )
                if governs_file is None:
                    return stable_inventory(
                        _SafetensorsShardIndexInventory(
                            index_path=index_path,
                            expected_source_paths=inventory.expected_source_paths,
                            expected_indices=inventory.expected_indices,
                            index_base="invalid",
                            fingerprint=inventory.fingerprint,
                            error="safetensors index target identity is indeterminate",
                        )
                    )
                if not governs_file:
                    continue
                if governing_inventory is not None:
                    return stable_inventory(
                        _SafetensorsShardIndexInventory(
                            index_path=index_path,
                            expected_source_paths=(
                                governing_inventory.expected_source_paths | inventory.expected_source_paths
                            ),
                            expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                            index_base="invalid",
                            error="multiple safetensors indexes govern selected shard",
                        )
                    )
                governing_inventory = inventory
            if governing_inventory is not None:
                return stable_inventory(governing_inventory)
            if listing_failure := candidate_listing_failure():
                return listing_failure
            if _normalized_absolute_path(index_dir) == normalized_search_root:
                break
            index_dir = index_dir.parent
        return None

    @staticmethod
    def _safetensors_inventory_proof(
        inventory: _SafetensorsShardIndexInventory,
    ) -> tuple[str, str, str, int] | None:
        if (
            inventory.error is not None
            or inventory.index_base not in {"zero", "one"}
            or not isinstance(inventory.fingerprint, str)
            or not inventory.fingerprint
            or not isinstance(inventory.generation, int)
            or isinstance(inventory.generation, bool)
            or inventory.generation <= 0
        ):
            return None
        return (
            inventory.index_base,
            _normalized_absolute_path(inventory.index_path),
            inventory.fingerprint,
            inventory.generation,
        )

    @classmethod
    def refresh_safetensors_index_proof(
        cls,
        file_path: str,
        *,
        index_search_root: str | os.PathLike[str] | None = None,
        index_inspection_context: _SafetensorsIndexInspectionContext | None = None,
        force_content_revalidation: bool = False,
    ) -> tuple[tuple[str, str, str, int] | None, bool]:
        """Return current governing index proof and whether relevant authority is present."""
        shard_match = cls.match_safetensors_shard_filename(Path(file_path).name)
        if shard_match is None:
            return None, False
        expected_total = shard_match.get("expected_total_shards")
        family_pattern = shard_match.get("pattern")
        if (
            not isinstance(expected_total, int)
            or isinstance(expected_total, bool)
            or not isinstance(family_pattern, str)
        ):
            return None, False
        dir_path = Path(file_path).parent
        effective_search_root = Path(index_search_root) if index_search_root is not None else dir_path.absolute()
        inspection_context = (
            index_inspection_context or _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
        )
        inventory = cls._load_safetensors_index_inventory(
            dir_path,
            family_pattern,
            expected_total,
            Path(file_path),
            effective_search_root,
            inspection_context,
            force_content_revalidation=force_content_revalidation,
        )
        if inventory is None:
            return None, False
        proof = cls._safetensors_inventory_proof(inventory)
        if proof is None:
            return None, True
        return proof, True

    @classmethod
    def refresh_safetensors_index_proofs(
        cls,
        file_paths: Iterable[str],
        *,
        expected_total: int,
        index_search_root: str | os.PathLike[str],
        index_inspection_context: _SafetensorsIndexInspectionContext | None = None,
        force_content_revalidation: bool = False,
        require_declared_files: bool = False,
    ) -> tuple[tuple[str, str, str, int] | None, bool]:
        """Resolve one order-independent governing proof across selected shard parents."""
        inspection_context = (
            index_inspection_context or _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
        )
        search_root = Path(index_search_root)
        files_by_parent: dict[str, list[Path]] = {}
        family_pattern: str | None = None
        for file_path in file_paths:
            path = Path(file_path)
            shard_match = cls.match_safetensors_shard_filename(path.name)
            if shard_match is None or shard_match.get("expected_total_shards") != expected_total:
                return None, False
            path_pattern = shard_match.get("pattern")
            if not isinstance(path_pattern, str):
                return None, False
            if family_pattern is None:
                family_pattern = path_pattern
            elif path_pattern != family_pattern:
                return None, False
            files_by_parent.setdefault(_normalized_absolute_path(path.parent), []).append(path)
        if not files_by_parent or family_pattern is None:
            return None, False

        agreed_proof: tuple[str, str, str, int] | None = None
        authority_by_parent: list[bool] = []
        revalidated_indexes: set[str] = set()
        refreshed_target_identities: dict[str, _SafetensorsShardIndexInventory] = {}
        for parent_files in files_by_parent.values():
            current_file = parent_files[0]
            inventory = cls._load_safetensors_index_inventory(
                current_file.parent,
                family_pattern,
                expected_total,
                current_file,
                search_root,
                inspection_context,
                force_content_revalidation=force_content_revalidation,
                content_revalidated_paths=revalidated_indexes,
                target_identity_refreshes=refreshed_target_identities,
            )
            authority_present = inventory is not None
            authority_by_parent.append(authority_present)
            if inventory is None:
                continue
            proof = cls._safetensors_inventory_proof(inventory)
            if proof is None:
                return None, True
            if require_declared_files and any(
                cls._safetensors_inventory_file_relationship(inventory, file_path) is not True
                for file_path in parent_files
            ):
                return None, True
            if agreed_proof is None:
                agreed_proof = proof
            elif proof != agreed_proof:
                return None, True

        if agreed_proof is None:
            return None, any(authority_by_parent)
        if not all(authority_by_parent):
            return None, True
        return agreed_proof, True

    @classmethod
    def detect_shards(
        cls,
        file_path: str,
        *,
        allowed_paths: list[str] | None = None,
        allowed_targets: ValidatedShardTargets | None = None,
        index_search_root: str | os.PathLike[str] | None = None,
        index_inspection_context: _SafetensorsIndexInspectionContext | None = None,
        force_index_content_revalidation: bool = False,
    ) -> dict[str, Any] | None:
        """
        Detect if a file is part of a sharded model.

        Args:
            file_path: Path to check

        Returns:
            Dictionary with shard info if detected, None otherwise
        """
        file_name = Path(file_path).name
        dir_path = Path(file_path).parent
        effective_index_search_root = (
            Path(index_search_root) if index_search_root is not None else Path(os.path.abspath(dir_path))
        )
        inspection_context = (
            index_inspection_context or _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
        )
        requested_path = str(Path(file_path).absolute())
        allowed_path_set: set[str] | None = None
        if allowed_paths is not None:
            allowed_path_set = {os.path.normcase(os.path.normpath(os.path.abspath(path))) for path in allowed_paths}
        elif allowed_targets is None:
            allowed_path_set = cls._direct_hf_shard_allowed_paths(Path(file_path))

        safetensors_match = cls.match_safetensors_shard_filename(file_name)
        candidate_patterns = (
            [str(safetensors_match["pattern"])] if safetensors_match is not None else cls.SHARD_PATTERNS
        )
        for pattern in candidate_patterns:
            match = re.fullmatch(pattern, file_name) if safetensors_match is None else None
            if safetensors_match is not None or match is not None:
                # Found a sharded model
                shard_info: dict[str, Any] = {"pattern": pattern, "current_file": file_path, "shards": []}
                normalized_safetensors_stem: str | None = None
                if safetensors_match is not None:
                    raw_normalized_stem = safetensors_match["normalized_shard_stem"]
                    assert isinstance(raw_normalized_stem, str)
                    normalized_safetensors_stem = raw_normalized_stem
                    shard_info.update(
                        {
                            "shard_kind": SAFETENSORS_SHARD_KIND,
                            "shard_stem": safetensors_match["shard_stem"],
                            "normalized_shard_stem": normalized_safetensors_stem,
                        }
                    )
                expected_totals: set[int] = set()
                present_indices: set[int] = set()
                unreadable_shards: list[str] = []
                out_of_scope_shards: list[str] = []
                unvalidated_shards: list[str] = []
                duplicate_shards: list[str] = []
                shard_targets: dict[str, dict[str, int | str]] = {}
                seen_target_identities: set[tuple[int | str, ...]] = set()
                total_size = 0
                family_member_limit_exceeded = False
                requested_expected_total: int | None = None
                if safetensors_match is not None:
                    raw_expected_total = safetensors_match["expected_total_shards"]
                    if isinstance(raw_expected_total, int):
                        requested_expected_total = raw_expected_total
                        expected_totals.add(raw_expected_total)
                elif match is not None and (match.lastindex or 0) >= 2:
                    with suppress(IndexError, ValueError):
                        requested_expected_total = int(match.group(2))
                        expected_totals.add(requested_expected_total)
                normalized_allowed_targets: ValidatedShardTargets | None = None
                validated_peer_paths: list[Path] = []
                if allowed_targets is not None:
                    normalized_allowed_targets = {}
                    untyped_allowed_targets: Mapping[Any, Any] = allowed_targets
                    normalized_requested_path = os.path.normcase(os.path.normpath(os.path.abspath(file_path)))
                    # The requested shard is the dispatch authority. Reserve its
                    # slot before bounded peers so mapping order cannot evict it.
                    for source_path, target in untyped_allowed_targets.items():
                        if not isinstance(source_path, str) or not isinstance(target, dict):
                            continue
                        normalized_source = os.path.normcase(os.path.normpath(os.path.abspath(source_path)))
                        if normalized_source != normalized_requested_path:
                            continue
                        peer_path = Path(source_path)
                        if (
                            cls._match_family_filename(
                                peer_path.name,
                                pattern,
                                expected_total=requested_expected_total,
                                normalized_safetensors_stem=normalized_safetensors_stem,
                            )
                            is not None
                        ):
                            normalized_allowed_targets[normalized_source] = target
                            validated_peer_paths.append(peer_path)
                        break
                    for source_path, target in untyped_allowed_targets.items():
                        if not isinstance(source_path, str) or not isinstance(target, dict):
                            continue
                        peer_path = Path(source_path)
                        if (
                            cls._match_family_filename(
                                peer_path.name,
                                pattern,
                                expected_total=requested_expected_total,
                                normalized_safetensors_stem=normalized_safetensors_stem,
                            )
                            is None
                        ):
                            continue
                        normalized_source = os.path.normcase(os.path.normpath(os.path.abspath(source_path)))
                        if normalized_source in normalized_allowed_targets:
                            continue
                        if len(normalized_allowed_targets) >= MAX_SCANNABLE_SHARDS:
                            family_member_limit_exceeded = True
                            unvalidated_shards.append(source_path)
                            break
                        normalized_allowed_targets[normalized_source] = target
                        validated_peer_paths.append(peer_path)
                index_inventory = cls._load_safetensors_index_inventory(
                    dir_path,
                    pattern,
                    requested_expected_total,
                    Path(file_path),
                    effective_index_search_root,
                    inspection_context,
                    force_content_revalidation=force_index_content_revalidation,
                )
                if index_inventory is not None:
                    shard_info["safetensors_index_path"] = str(index_inventory.index_path)
                    shard_info["shard_index_base"] = index_inventory.index_base
                    if index_inventory.error is not None:
                        shard_info["safetensors_index_error"] = index_inventory.error
                        unvalidated_shards.append(str(index_inventory.index_path))
                    elif index_inventory.fingerprint is not None:
                        shard_info["safetensors_index_fingerprint"] = index_inventory.fingerprint
                        if index_inventory.generation is not None:
                            shard_info["safetensors_index_generation"] = index_inventory.generation
                        shard_info["safetensors_index_declares_current_file"] = (
                            cls._safetensors_inventory_file_relationship(index_inventory, Path(file_path)) is True
                        )

                # Collect bounded family candidates from local siblings and caller-snapshotted peers;
                # validated index targets are added below.
                candidate_paths: dict[str, Path] = {}
                current_path = Path(file_path)

                cls._add_bounded_family_candidate(
                    current_path,
                    candidate_paths,
                    pattern,
                    expected_total=requested_expected_total,
                    normalized_safetensors_stem=normalized_safetensors_stem,
                )
                try:
                    for entry_count, candidate in enumerate(dir_path.iterdir(), start=1):
                        if entry_count > MAX_SAFETENSORS_SHARD_INDEX_DIRECTORY_ENTRIES:
                            shard_info.setdefault(
                                "safetensors_index_error", "safetensors shard sibling inspection limit exceeded"
                            )
                            unvalidated_shards.append(str(dir_path))
                            break
                        if not cls._add_bounded_family_candidate(
                            candidate,
                            candidate_paths,
                            pattern,
                            expected_total=requested_expected_total,
                            normalized_safetensors_stem=normalized_safetensors_stem,
                        ):
                            family_member_limit_exceeded = True
                            if str(candidate) not in unvalidated_shards:
                                unvalidated_shards.append(str(candidate))
                            break
                except OSError:
                    shard_info.setdefault(
                        "safetensors_index_error",
                        "safetensors shard sibling inspection failed",
                    )
                    unvalidated_shards.append(str(dir_path))
                for candidate in validated_peer_paths:
                    if not cls._add_bounded_family_candidate(
                        candidate,
                        candidate_paths,
                        pattern,
                        expected_total=requested_expected_total,
                        normalized_safetensors_stem=normalized_safetensors_stem,
                    ):
                        family_member_limit_exceeded = True
                        if str(candidate) not in unvalidated_shards:
                            unvalidated_shards.append(str(candidate))
                        break
                if index_inventory is not None and index_inventory.error is None:
                    candidate_aliases_by_name: dict[str, list[Path]] = {}
                    for candidate in candidate_paths.values():
                        if (
                            cls._match_family_filename(
                                candidate.name,
                                pattern,
                                expected_total=requested_expected_total,
                                normalized_safetensors_stem=normalized_safetensors_stem,
                            )
                            is None
                        ):
                            continue
                        candidate_aliases_by_name.setdefault(os.path.normcase(candidate.name), []).append(candidate)
                    alias_comparisons = 0
                    for expected_source in index_inventory.expected_source_paths:
                        expected_path = Path(expected_source)
                        if expected_path.exists() or expected_path.is_symlink():
                            try:
                                resolved_expected = expected_path.resolve(strict=True)
                            except (OSError, RuntimeError):
                                resolved_expected = None
                            if resolved_expected is not None:
                                normalized_resolved_expected = os.path.normcase(
                                    os.path.normpath(str(resolved_expected))
                                )
                                matches_existing_alias = False
                                for candidate in candidate_aliases_by_name.get(
                                    os.path.normcase(expected_path.name),
                                    (),
                                ):
                                    if alias_comparisons >= MAX_SAFETENSORS_SHARD_ALIAS_IDENTITY_CHECKS:
                                        break
                                    alias_comparisons += 1
                                    try:
                                        resolved_candidate = candidate.resolve(strict=True)
                                    except (OSError, RuntimeError):
                                        continue
                                    if os.path.normcase(os.path.normpath(str(resolved_candidate))) == (
                                        normalized_resolved_expected
                                    ):
                                        matches_existing_alias = True
                                        break
                                if matches_existing_alias:
                                    continue
                            normalized_expected = os.path.normcase(os.path.normpath(os.path.abspath(expected_path)))
                            if normalized_expected not in candidate_paths and not cls._add_bounded_family_candidate(
                                expected_path,
                                candidate_paths,
                                pattern,
                                expected_total=requested_expected_total,
                                normalized_safetensors_stem=normalized_safetensors_stem,
                            ):
                                family_member_limit_exceeded = True
                                if str(expected_path) not in unvalidated_shards:
                                    unvalidated_shards.append(str(expected_path))
                                break

                shard_indices: dict[str, int] = {}
                for file in sorted(
                    candidate_paths.values(),
                    key=lambda candidate: (candidate != current_path, str(candidate)),
                ):
                    family_match = cls._match_family_filename(
                        file.name,
                        pattern,
                        expected_total=requested_expected_total,
                        normalized_safetensors_stem=normalized_safetensors_stem,
                    )
                    if family_match is not None:
                        candidate_shard_index, _candidate_expected_total = family_match
                        try:
                            resolved_file = str(file.resolve(strict=True))
                        except (OSError, RuntimeError):
                            unreadable_shards.append(str(file))
                            continue
                        normalized_resolved_file = os.path.normcase(os.path.normpath(resolved_file))
                        normalized_source_path = os.path.normcase(os.path.normpath(str(file.absolute())))
                        expected_target = (
                            normalized_allowed_targets.get(normalized_source_path)
                            if normalized_allowed_targets is not None
                            else None
                        )
                        inventory_root = (
                            index_inventory.index_path.parent
                            if index_inventory is not None and index_inventory.error is None
                            else dir_path
                        )
                        if normalized_allowed_targets is not None and expected_target is None:
                            if not _is_resolved_path_within_directory(inventory_root, resolved_file):
                                out_of_scope_shards.append(str(file))
                            else:
                                unvalidated_shards.append(str(file))
                            continue
                        if allowed_path_set is not None and normalized_resolved_file not in allowed_path_set:
                            if not _is_resolved_path_within_directory(inventory_root, resolved_file):
                                out_of_scope_shards.append(str(file))
                            else:
                                unvalidated_shards.append(str(file))
                            continue
                        if (
                            allowed_path_set is None
                            and normalized_allowed_targets is None
                            and not _is_resolved_path_within_directory(
                                inventory_root,
                                resolved_file,
                            )
                            and str(file.absolute()) != requested_path
                        ):
                            out_of_scope_shards.append(str(file))
                            continue
                        try:
                            shard_stat = os.stat(resolved_file, follow_symlinks=False)
                        except OSError:
                            unreadable_shards.append(str(file))
                            continue
                        if not stat.S_ISREG(shard_stat.st_mode):
                            unreadable_shards.append(str(file))
                            continue
                        if expected_target is not None:
                            expected_resolved_path = expected_target.get("resolved_path")
                            expected_device = expected_target.get("device")
                            expected_inode = expected_target.get("inode")
                            if not isinstance(
                                expected_resolved_path, str
                            ) or normalized_resolved_file != os.path.normcase(os.path.normpath(expected_resolved_path)):
                                unvalidated_shards.append(str(file))
                                continue
                            if any(
                                isinstance(expected_target.get(key), int) and expected_target[key] != current_value
                                for key, current_value in (
                                    ("size", shard_stat.st_size),
                                    ("mtime_ns", shard_stat.st_mtime_ns),
                                    ("ctime_ns", shard_stat.st_ctime_ns),
                                )
                            ):
                                unvalidated_shards.append(str(file))
                                continue
                            if (
                                isinstance(expected_device, int)
                                and isinstance(expected_inode, int)
                                and expected_inode
                                and (shard_stat.st_dev, shard_stat.st_ino) != (expected_device, expected_inode)
                            ):
                                unvalidated_shards.append(str(file))
                                continue
                        target_identity: tuple[int | str, ...]
                        if shard_stat.st_ino:
                            target_identity = ("inode", shard_stat.st_dev, shard_stat.st_ino)
                        else:
                            target_identity = ("path", normalized_resolved_file)
                        if target_identity in seen_target_identities:
                            duplicate_shards.append(str(file))
                            continue
                        seen_target_identities.add(target_identity)
                        shard_size = shard_stat.st_size
                        shard_info["shards"].append(str(file))
                        shard_targets[str(file)] = {
                            "resolved_path": resolved_file,
                            "device": shard_stat.st_dev,
                            "inode": shard_stat.st_ino,
                            "size": shard_size,
                            "mtime_ns": shard_stat.st_mtime_ns,
                            "ctime_ns": shard_stat.st_ctime_ns,
                            "nlink": shard_stat.st_nlink,
                        }
                        total_size += shard_size
                        if candidate_shard_index is not None:
                            present_indices.add(candidate_shard_index)
                            shard_indices[str(file)] = candidate_shard_index

                if family_member_limit_exceeded:
                    shard_info["shard_family_member_limit_exceeded"] = True
                    shard_info["maximum_scannable_shards"] = MAX_SCANNABLE_SHARDS
                    shard_info.setdefault("safetensors_index_error", "shard family member limit exceeded")

                if requested_expected_total is not None:
                    authoritative_indices = (
                        index_inventory.expected_indices
                        if index_inventory is not None and index_inventory.error is None
                        else None
                    )
                    expected_indices, index_base = cls.expected_indices_for_shard_family(
                        requested_expected_total,
                        authoritative_indices=authoritative_indices,
                    )
                    shard_info["shard_index_base"] = index_base
                    present_expected_indices: set[int] = set()
                    unexpected_shards: list[str] = []
                    validated_index_inventory = (
                        index_inventory if index_inventory is not None and index_inventory.error is None else None
                    )
                    for shard_path, shard_index in shard_indices.items():
                        if (
                            validated_index_inventory is not None
                            and cls._safetensors_inventory_file_relationship(
                                validated_index_inventory,
                                Path(shard_path),
                            )
                            is not True
                        ):
                            unexpected_shards.append(shard_path)
                            continue
                        if shard_index in expected_indices:
                            present_expected_indices.add(shard_index)
                        else:
                            unexpected_shards.append(shard_path)
                    if unexpected_shards:
                        shard_info["unexpected_shards"] = sorted(unexpected_shards)
                        shard_info["unexpected_shard_count"] = len(unexpected_shards)
                    missing_indices, missing_count, missing_indices_truncated = _summarize_missing_shard_indices(
                        present_expected_indices,
                        expected_indices,
                    )
                    if missing_count:
                        shard_info["missing_shard_count"] = missing_count
                        shard_info["missing_shard_indices"] = missing_indices
                        shard_info["missing_shard_indices_truncated"] = missing_indices_truncated

                shard_info["shards"].sort()
                shard_info["shard_targets"] = shard_targets
                shard_info["total_shards"] = len(shard_info["shards"])
                if unreadable_shards:
                    shard_info["unreadable_shards"] = sorted(unreadable_shards)
                    shard_info["unreadable_shard_count"] = len(unreadable_shards)
                if out_of_scope_shards:
                    shard_info["out_of_scope_shards"] = sorted(out_of_scope_shards)
                    shard_info["out_of_scope_shard_count"] = len(out_of_scope_shards)
                if unvalidated_shards:
                    shard_info["unvalidated_shards"] = sorted(unvalidated_shards)
                    shard_info["unvalidated_shard_count"] = len(unvalidated_shards)
                if duplicate_shards:
                    shard_info["duplicate_shards"] = sorted(duplicate_shards)
                    shard_info["duplicate_shard_count"] = len(duplicate_shards)
                if expected_totals:
                    expected_total = max(expected_totals)
                    shard_info["expected_total_shards"] = expected_total

                shard_info["total_size"] = total_size

                return shard_info

        return None

    @classmethod
    def _direct_hf_shard_allowed_paths(cls, file_path: Path) -> set[str] | None:
        """Allow complete direct scans of a real HF snapshot family backed by its blobs directory."""
        absolute_path = file_path.absolute()
        if not _path_has_part(absolute_path, "snapshots"):
            return None
        cache_root = _find_hf_cache_root(absolute_path)
        if cache_root is None:
            return None
        blobs_root = _trusted_hf_blobs_root(cache_root)
        if blobs_root is None:
            return None

        allowed_paths: set[str] = set()
        for candidate in absolute_path.parent.glob("*"):
            try:
                resolved_candidate = candidate.resolve(strict=True)
                candidate_stat = os.stat(resolved_candidate, follow_symlinks=False)
            except (OSError, RuntimeError):
                continue
            if not stat.S_ISREG(candidate_stat.st_mode):
                continue
            if _is_resolved_path_within_directory(
                absolute_path.parent,
                str(resolved_candidate),
            ) or resolved_candidate.is_relative_to(blobs_root):
                allowed_paths.add(os.path.normcase(os.path.normpath(str(resolved_candidate))))
        return allowed_paths or None

    @classmethod
    def find_model_config(cls, file_path: str) -> str | None:
        """Find the configuration file for a sharded model."""
        dir_path = Path(file_path).parent

        # Common config file names
        config_names = [
            "config.json",
            "model.safetensors.index.json",
            "pytorch_model.bin.index.json",
            "tf_model.h5.index.json",
            "model_index.json",
        ]

        for config_name in config_names:
            config_path = dir_path / config_name
            try:
                resolved_config = config_path.resolve(strict=True)
                config_stat = os.stat(resolved_config, follow_symlinks=False)
            except (OSError, RuntimeError):
                continue
            if not _is_resolved_path_within_directory(dir_path, str(resolved_config)):
                continue
            if stat.S_ISREG(config_stat.st_mode):
                return str(config_path)

        return None


def _safetensors_shard_info_authority_is_stable(
    shard_info: dict[str, Any] | None,
    *,
    index_search_root: str | os.PathLike[str] | None,
    index_inspection_context: _SafetensorsIndexInspectionContext,
    force_content_revalidation: bool,
) -> bool:
    """Require every SafeTensors shard parent to retain one agreed index proof."""
    if not isinstance(shard_info, dict) or shard_info.get("shard_kind") != SAFETENSORS_SHARD_KIND:
        return True
    expected_total = shard_info.get("expected_total_shards")
    raw_shards = shard_info.get("shards")
    if (
        not isinstance(expected_total, int)
        or isinstance(expected_total, bool)
        or expected_total <= 0
        or not isinstance(raw_shards, list)
        or not raw_shards
        or not all(isinstance(path, str) for path in raw_shards)
    ):
        return False

    index_base = shard_info.get("shard_index_base")
    index_path = shard_info.get("safetensors_index_path")
    index_fingerprint = shard_info.get("safetensors_index_fingerprint")
    index_generation = shard_info.get("safetensors_index_generation")
    authority_present = isinstance(index_path, str) and bool(index_path)
    expected_proof: tuple[str, str, str, int] | None = None
    if (
        isinstance(index_base, str)
        and index_base in {"zero", "one"}
        and isinstance(index_path, str)
        and bool(index_path)
        and isinstance(index_fingerprint, str)
        and bool(index_fingerprint)
        and isinstance(index_generation, int)
        and not isinstance(index_generation, bool)
        and index_generation > 0
    ):
        expected_proof = (index_base, _normalized_absolute_path(index_path), index_fingerprint, index_generation)

    shard_paths = [path for path in raw_shards if isinstance(path, str)]
    refreshed_proof, refreshed_authority_present = ShardedModelDetector.refresh_safetensors_index_proofs(
        shard_paths,
        expected_total=expected_total,
        index_search_root=index_search_root or Path(shard_paths[0]).absolute().parent,
        index_inspection_context=index_inspection_context,
        force_content_revalidation=force_content_revalidation,
    )
    return (refreshed_proof, refreshed_authority_present) == (expected_proof, authority_present)


def _grouped_shard_boundary_error(
    file_path: str,
    allowed_paths: list[str] | None,
    allowed_targets: ValidatedShardTargets | None = None,
) -> dict[str, str] | None:
    """Return details when a selected shard no longer matches its validated target set."""
    if (allowed_paths is None and allowed_targets is None) or ShardedModelDetector.match_shard_filename(
        Path(file_path).name
    ) is None:
        return None
    allowed_path_set = (
        {os.path.normcase(os.path.normpath(os.path.abspath(allowed_path))) for allowed_path in allowed_paths}
        if allowed_paths is not None
        else set()
    )
    try:
        resolved_path = Path(file_path).resolve(strict=True)
        resolved_stat = os.stat(resolved_path, follow_symlinks=False)
    except (OSError, RuntimeError) as e:
        return {"path": file_path, "error": str(e), "reason": "shard_target_unavailable"}
    normalized_resolved_path = os.path.normcase(os.path.normpath(str(resolved_path)))
    expected_target: dict[str, int | str] | None = None
    if allowed_targets is not None:
        normalized_source_path = os.path.normcase(os.path.normpath(os.path.abspath(file_path)))
        expected_target = next(
            (
                target
                for source_path, target in allowed_targets.items()
                if os.path.normcase(os.path.normpath(os.path.abspath(source_path))) == normalized_source_path
            ),
            None,
        )
        if expected_target is None:
            return {"path": file_path, "reason": "shard_path_outside_validated_family"}
        expected_path = expected_target.get("resolved_path")
        if not isinstance(expected_path, str) or normalized_resolved_path != os.path.normcase(
            os.path.normpath(expected_path)
        ):
            return {
                "path": file_path,
                "resolved_path": str(resolved_path),
                "reason": "shard_target_changed",
            }
    elif normalized_resolved_path not in allowed_path_set:
        return {
            "path": file_path,
            "resolved_path": str(resolved_path),
            "reason": "shard_target_outside_validated_family",
        }
    if not stat.S_ISREG(resolved_stat.st_mode):
        return {
            "path": file_path,
            "resolved_path": str(resolved_path),
            "reason": "shard_target_not_regular_file",
        }
    if expected_target is not None:
        expected_device = expected_target.get("device")
        expected_inode = expected_target.get("inode")
        if (
            isinstance(expected_device, int)
            and isinstance(expected_inode, int)
            and expected_inode
            and (resolved_stat.st_dev, resolved_stat.st_ino) != (expected_device, expected_inode)
        ):
            return {
                "path": file_path,
                "resolved_path": str(resolved_path),
                "reason": "shard_target_identity_changed",
            }
        if any(
            isinstance(expected_target.get(key), int) and expected_target[key] != current_value
            for key, current_value in (
                ("size", resolved_stat.st_size),
                ("mtime_ns", resolved_stat.st_mtime_ns),
                ("ctime_ns", resolved_stat.st_ctime_ns),
            )
        ):
            return {
                "path": file_path,
                "resolved_path": str(resolved_path),
                "reason": "shard_target_content_changed",
            }
    return None


def _shard_boundary_failure_result(scanner_name: str, file_path: str, details: dict[str, str]) -> "ScanResult":
    """Build a fail-closed result for a changed grouped shard representative."""
    from ...scanner_results import IssueSeverity, ScanResult

    result = ScanResult(scanner_name=scanner_name)
    result.add_check(
        name="Sharded Model Boundary Check",
        passed=False,
        message="Validated shard path changed before scanning; scan coverage is incomplete.",
        severity=IssueSeverity.INFO,
        location=file_path,
        details={
            **details,
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "shard_boundary_changed",
        },
    )
    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = "shard_boundary_changed"
    _mark_inconclusive_scan_outcome(result, "shard_boundary_changed")
    result.finish(success=False)
    return result


def _preserve_findings_with_shard_boundary_failure(
    result: "ScanResult",
    scanner_name: str,
    file_path: str,
    details: dict[str, str],
) -> "ScanResult":
    """Keep observed failures while marking changed shard coverage inconclusive."""
    from ...scanner_results import CheckStatus

    result.checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
    if not any(check.name == "Sharded Model Boundary Check" for check in result.checks):
        result.merge(_shard_boundary_failure_result(scanner_name, file_path, details))
    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = "shard_boundary_changed"
    _mark_inconclusive_scan_outcome(result, "shard_boundary_changed")
    result.finish(success=False)
    return result


class MemoryMappedHandler:
    """Scanner using bounded windowed I/O for large file sizes."""

    def __init__(self, file_path: str, scanner: Any):
        """
        Initialize memory-mapped scanner.

        Args:
            file_path: Path to the file
            scanner: Scanner instance to use
        """
        self.file_path = file_path
        self.scanner = scanner
        self.file_size = os.path.getsize(file_path)

    def scan_with_mmap(self, progress_callback: Callable[[str, float], None] | None = None) -> "ScanResult":
        """
        Scan file using memory mapping.

        Args:
            progress_callback: Optional progress callback

        Returns:
            ScanResult with findings
        """
        from ...scanner_results import (
            IssueSeverity,
            ScanResult,
            scan_result_has_inconclusive_outcome,
        )

        result = ScanResult(scanner_name=self.scanner.name)
        bytes_scanned = 0
        short_read = False

        try:
            with open(self.file_path, "rb", buffering=0) as f:
                opened_stat = os.fstat(f.fileno())
                scan_file_size = opened_stat.st_size
                self.file_size = scan_file_size
                if scan_file_size > 0:
                    # Whole-file mappings can terminate the process with SIGBUS if another
                    # process truncates the file. Bounded reads fail safely with a short read.
                    window_size = min(MMAP_MAX_WINDOW, scan_file_size)
                    position = 0

                    while position < scan_file_size:
                        end_pos = min(position + window_size, scan_file_size)
                        expected_bytes = end_pos - position
                        f.seek(position)
                        window_data = f.read(expected_bytes)
                        actual_end_pos = position + len(window_data)

                        if window_data:
                            window_result = self._analyze_window(window_data, position, detector_result=result)
                            result.merge(window_result)

                        # Overlapping windows should not inflate unique coverage or progress.
                        bytes_scanned = max(bytes_scanned, actual_end_pos)

                        if progress_callback:
                            percentage = (bytes_scanned / scan_file_size) * 100
                            progress_callback(
                                f"Memory-mapped scan: {bytes_scanned:,}/{scan_file_size:,} bytes",
                                percentage,
                            )

                        if len(window_data) != expected_bytes:
                            short_read = True
                            break
                        if end_pos >= scan_file_size:
                            break
                        position = end_pos - (1024 * 1024)  # 1MB overlap
                        if position <= 0:
                            position = end_pos  # Avoid going negative

                result.bytes_scanned = bytes_scanned
                final_stat = os.fstat(f.fileno())
                try:
                    path_stat = os.stat(self.file_path)
                except OSError:
                    path_stat = None
                opened_identity = (
                    opened_stat.st_dev,
                    opened_stat.st_ino,
                    opened_stat.st_size,
                    opened_stat.st_mtime_ns,
                    opened_stat.st_ctime_ns,
                )
                source_changed = (
                    short_read
                    or path_stat is None
                    or opened_identity
                    != (
                        final_stat.st_dev,
                        final_stat.st_ino,
                        final_stat.st_size,
                        final_stat.st_mtime_ns,
                        final_stat.st_ctime_ns,
                    )
                )
                if path_stat is not None:
                    source_changed = source_changed or opened_identity != (
                        path_stat.st_dev,
                        path_stat.st_ino,
                        path_stat.st_size,
                        path_stat.st_mtime_ns,
                        path_stat.st_ctime_ns,
                    )
                if source_changed:
                    reason = "memory_mapped_source_changed"
                    _mark_inconclusive_scan_outcome(result, reason)
                    result.add_check(
                        name="Memory-Mapped Source Stability",
                        passed=False,
                        message="File identity changed or a bounded read was incomplete; coverage is incomplete",
                        severity=IssueSeverity.INFO,
                        location=self.file_path,
                        details={
                            "scan_outcome_reason": reason,
                            "analysis_incomplete": True,
                            "opened_file_size": opened_stat.st_size,
                            "final_file_size": final_stat.st_size,
                            "short_read": short_read,
                        },
                    )

        except Exception as e:
            from ...scanners._evidence_redaction import redact_untrusted_error_message

            redacted_error = redact_untrusted_error_message(e)
            logger.error("Error during memory-mapped scanning: %s", redacted_error)
            result.add_check(
                name="Memory-Mapped Scan",
                passed=False,
                message=f"Memory-mapped scan error: {redacted_error}",
                severity=IssueSeverity.WARNING,
                details={
                    "error": redacted_error,
                    "exception_type": type(e).__name__,
                    "bytes_scanned": bytes_scanned,
                },
            )

        remove_failed_raw_detector_clean_checks = getattr(
            self.scanner,
            "_remove_failed_raw_detector_clean_checks",
            None,
        )
        if callable(remove_failed_raw_detector_clean_checks):
            remove_failed_raw_detector_clean_checks(result)

        result.finish(
            success=not scan_result_has_inconclusive_outcome(result)
            and not any(
                check.name == "Memory-Mapped Scan" and check.status.value == "failed" for check in result.checks
            ),
        )
        return result

    def _analyze_window(
        self,
        data: bytes,
        offset: int,
        detector_result: "ScanResult | None" = None,
    ) -> "ScanResult":
        """Analyze a window of data using the actual scanner's checks."""
        from ...scanner_results import IssueSeverity, ScanResult

        result = ScanResult(scanner_name=self.scanner.name)

        # First, run scanner-specific analysis if available
        if hasattr(self.scanner, "_analyze_chunk"):
            # Scanner has chunk analysis capability
            chunk_result = self.scanner._analyze_chunk(data, offset)
            result.merge(chunk_result)
        elif hasattr(self.scanner, "_analyze_bytes"):
            # Scanner can analyze raw bytes
            bytes_result = self.scanner._analyze_bytes(data, offset)
            result.merge(bytes_result)
        else:
            # Fall back to pattern matching for all scanners
            # This ensures we still catch obvious malicious patterns
            suspicious_patterns = [
                (b"exec", "exec() call detected"),
                (b"eval", "eval() call detected"),
                (b"__import__", "Dynamic import detected"),
                (b"os.system", "System command execution detected"),
                (b"subprocess", "Subprocess execution detected"),
                (b"pickle.loads", "Pickle deserialization detected"),
                (b"marshal.loads", "Marshal deserialization detected"),
                (b"compile(", "compile() call detected"),
                (b"__builtins__", "Builtins access detected"),
                (b"getattr", "Dynamic attribute access detected"),
            ]

            for pattern, message in suspicious_patterns:
                if pattern in data:
                    result.add_check(
                        name="Suspicious Pattern Detection",
                        passed=False,
                        message=message,
                        severity=IssueSeverity.CRITICAL,
                        location=f"offset {offset:,}",
                        details={"pattern": pattern.decode("utf-8", errors="ignore"), "offset": offset},
                    )

        # Run any additional scanner-specific checks
        if hasattr(self.scanner, "check_for_embedded_secrets"):
            # Check for embedded secrets in this window
            raw_detector_result = detector_result if detector_result is not None else result
            self.scanner.check_for_embedded_secrets(data, raw_detector_result, f"offset {offset:,}")

        if hasattr(self.scanner, "check_for_dangerous_imports"):
            # Check for dangerous imports
            self.scanner.check_for_dangerous_imports(data, result, f"offset {offset:,}")

        return result


class ParallelShardHandler:
    """Scan multiple model shards in parallel."""

    def __init__(
        self,
        shard_info: dict[str, Any],
        scanner_class: type,
        scanner_config: dict[str, Any] | None = None,
    ):
        """
        Initialize parallel shard scanner.

        Args:
            shard_info: Information about model shards
            scanner_class: Scanner class to use
            scanner_config: Configuration to preserve for each shard scanner
        """
        self.shard_info = shard_info
        self.scanner_class = scanner_class
        self.scanner_config = scanner_config

    def scan_shards(self, progress_callback: Callable[[str, float], None] | None = None) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """
        Scan all shards in parallel.

        Args:
            progress_callback: Optional progress callback

        Returns:
            Combined ScanResult from all shards
        """
        result = ScanResult(scanner_name="parallel_shard_scanner")
        shards = self.shard_info["shards"]
        total_shards = len(shards)
        completed_shards = 0
        success = True

        if total_shards > MAX_SCANNABLE_SHARDS:
            _mark_inconclusive_scan_outcome(result, "shard_count_limit_exceeded")
            result.add_check(
                name="Sharded Model Coverage Check",
                passed=False,
                message="Shard family exceeds the bounded parallel scan limit; scan coverage is incomplete.",
                severity=IssueSeverity.INFO,
                details={
                    "total_shards": total_shards,
                    "maximum_scannable_shards": MAX_SCANNABLE_SHARDS,
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_count_limit_exceeded",
                },
            )
            result.finish(success=False)
            return result

        # Add info about sharded model
        result.add_check(
            name="Sharded Model Detection",
            passed=True,
            message=f"Scanning sharded model with {total_shards} parts",
            severity=IssueSeverity.INFO,
            details={
                "total_shards": total_shards,
                "total_size": self.shard_info["total_size"],
                "shards": shards,
            },
        )

        expected_members: set[str] | None = None
        family_dir: Path | None = None
        if isinstance(self.shard_info.get("current_file"), str) and isinstance(self.shard_info.get("pattern"), str):
            expected_members = self._expected_family_members()
            family_dir = Path(self.shard_info["current_file"]).parent
            try:
                pre_scan_members = self._current_family_members()
            except (OSError, RuntimeError) as e:
                _mark_inconclusive_scan_outcome(result, "shard_family_changed")
                result.add_check(
                    name="Sharded Model Membership Check",
                    passed=False,
                    message="Unable to revalidate shard family membership before scanning.",
                    severity=IssueSeverity.INFO,
                    location=str(family_dir),
                    details={
                        "error": str(e),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "shard_family_changed",
                    },
                )
                result.finish(success=False)
                return result

            if pre_scan_members != expected_members:
                _mark_inconclusive_scan_outcome(result, "shard_family_changed")
                result.add_check(
                    name="Sharded Model Membership Check",
                    passed=False,
                    message="Shard family membership changed before scanning; scan coverage is incomplete.",
                    severity=IssueSeverity.INFO,
                    location=str(family_dir),
                    details={
                        "added_shards": sorted(pre_scan_members - expected_members),
                        "removed_shards": sorted(expected_members - pre_scan_members),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "shard_family_changed",
                    },
                )
                result.finish(success=False)
                return result

        from ...scanners._evidence_redaction import (
            redact_evidence_string,
            redact_untrusted_error_message,
        )

        max_workers = min(MAX_PARALLEL_WORKERS, total_shards)
        worker_slots = _PARALLEL_SHARD_WORKER_SLOTS
        worker_results: Queue[tuple[int, ScanResult | None, BaseException | None]] = Queue()
        active_workers: dict[int, tuple[str, float]] = {}
        next_shard_index = 0
        next_worker_id = 0

        def add_shard_error(shard: str, error: BaseException | str, exception_type: str) -> None:
            nonlocal success
            safe_shard = redact_evidence_string(shard, max_chars=500)
            safe_shard_name = redact_evidence_string(Path(shard).name, max_chars=500)
            safe_error = redact_untrusted_error_message(error)
            logger.error("Error scanning shard %s: %s", safe_shard, safe_error)
            success = False
            _mark_inconclusive_scan_outcome(result, "shard_scan_error")
            result.add_check(
                name="Shard Scan",
                passed=False,
                message=f"Error scanning shard: {safe_shard_name}",
                severity=IssueSeverity.INFO,
                location=safe_shard,
                details={
                    "error": safe_error,
                    "exception_type": exception_type,
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_scan_error",
                },
            )

        def run_shard(worker_id: int, shard: str, context: Context) -> None:
            shard_result: ScanResult | None = None
            error: BaseException | None = None
            try:
                shard_result = context.run(self._scan_single_shard, shard)
            except BaseException as exc:
                error = exc
            finally:
                worker_results.put((worker_id, shard_result, error))
                worker_slots.release()

        def start_worker_with_acquired_slot() -> None:
            nonlocal next_shard_index, next_worker_id
            shard = shards[next_shard_index]
            next_shard_index += 1
            worker_id = next_worker_id
            next_worker_id += 1
            worker = Thread(
                target=run_shard,
                args=(worker_id, shard, copy_context()),
                name="modelaudit-shard-scan",
                daemon=True,
            )
            try:
                worker.start()
            except BaseException:
                worker_slots.release()
                raise
            active_workers[worker_id] = (shard, time.monotonic() + SHARD_SCAN_TIMEOUT)

        def start_available_workers() -> None:
            while next_shard_index < total_shards and len(active_workers) < max_workers:
                if not worker_slots.acquire(blocking=False):
                    return
                start_worker_with_acquired_slot()

        start_available_workers()
        while active_workers or next_shard_index < total_shards:
            if not active_workers:
                acquired = worker_slots.acquire(timeout=SHARD_SCAN_TIMEOUT)
                if not acquired:
                    add_shard_error(
                        shards[next_shard_index],
                        f"Shard scan could not start within the {SHARD_SCAN_TIMEOUT}-second timeout.",
                        "TimeoutError",
                    )
                    break
                start_worker_with_acquired_slot()
                start_available_workers()
                continue

            next_deadline = min(deadline for _, deadline in active_workers.values())
            try:
                worker_id, shard_result, error = worker_results.get(timeout=max(0.0, next_deadline - time.monotonic()))
            except Empty:
                now = time.monotonic()
                overdue = [
                    (worker_id, shard) for worker_id, (shard, deadline) in active_workers.items() if deadline <= now
                ]
                if not overdue:
                    continue
                for _, shard in overdue:
                    add_shard_error(
                        shard,
                        f"Shard scan exceeded the {SHARD_SCAN_TIMEOUT}-second timeout.",
                        "TimeoutError",
                    )
                break

            shard, _ = active_workers.pop(worker_id)
            completed_shards += 1
            if error is not None:
                if not isinstance(error, Exception):
                    raise error
                add_shard_error(shard, error, type(error).__name__)
            else:
                assert shard_result is not None
                result.merge(shard_result)
                success = success and bool(shard_result.success)

                if progress_callback:
                    percentage = (completed_shards / total_shards) * 100
                    progress_callback(f"Scanned shard {completed_shards}/{total_shards}", percentage)

            start_available_workers()

        if expected_members is not None and family_dir is not None:
            membership_error: str | None
            try:
                post_scan_members = self._current_family_members()
            except (OSError, RuntimeError) as e:
                post_scan_members = set()
                membership_error = str(e)
            else:
                membership_error = None

            if post_scan_members != expected_members or membership_error is not None:
                success = False
                _mark_inconclusive_scan_outcome(result, "shard_family_changed")
                details: dict[str, Any] = {
                    "added_shards": sorted(post_scan_members - expected_members),
                    "removed_shards": sorted(expected_members - post_scan_members),
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_family_changed",
                }
                if membership_error is not None:
                    details["error"] = membership_error
                result.add_check(
                    name="Sharded Model Membership Check",
                    passed=False,
                    message="Shard family membership changed during scanning; scan coverage is incomplete.",
                    severity=IssueSeverity.INFO,
                    location=str(family_dir),
                    details=details,
                )

        result.finish(success=success and not result.has_errors and "scan_outcome" not in result.metadata)
        return result

    def _expected_family_members(self) -> set[str]:
        """Return every lexical family member categorized during detection."""
        members: set[str] = set()
        pattern = self.shard_info.get("pattern")
        expected_total = self.shard_info.get("expected_total_shards")
        normalized_safetensors_stem = self.shard_info.get("normalized_shard_stem")
        for key in (
            "shards",
            "unreadable_shards",
            "out_of_scope_shards",
            "unvalidated_shards",
            "duplicate_shards",
            "unexpected_shards",
        ):
            values = self.shard_info.get(key)
            if isinstance(values, list):
                for value in values:
                    if not isinstance(value, str) or not isinstance(pattern, str):
                        continue
                    if (
                        ShardedModelDetector._match_family_filename(
                            Path(value).name,
                            pattern,
                            expected_total=expected_total if isinstance(expected_total, int) else None,
                            normalized_safetensors_stem=(
                                normalized_safetensors_stem if isinstance(normalized_safetensors_stem, str) else None
                            ),
                        )
                        is None
                    ):
                        continue
                    members.add(str(Path(value).absolute()))
        return members

    def _current_family_members(self) -> set[str]:
        """Enumerate current lexical members of the detected shard family."""
        current_file = Path(self.shard_info["current_file"])
        pattern = self.shard_info["pattern"]
        expected_total = self.shard_info.get("expected_total_shards")
        normalized_safetensors_stem = self.shard_info.get("normalized_shard_stem")
        members: set[str] = set()
        family_directories = {current_file.parent}
        shard_targets = self.shard_info.get("shard_targets")
        if isinstance(shard_targets, dict):
            family_directories.update(
                Path(source_path).parent for source_path in shard_targets if isinstance(source_path, str)
            )
        total_entries_inspected = 0
        for family_directory in family_directories:
            for directory_entries_inspected, candidate in enumerate(family_directory.iterdir(), start=1):
                total_entries_inspected += 1
                if (
                    directory_entries_inspected > MAX_SAFETENSORS_SHARD_INDEX_DIRECTORY_ENTRIES
                    or total_entries_inspected > MAX_SAFETENSORS_SHARD_INDEX_TOTAL_DIRECTORY_ENTRIES
                ):
                    raise OSError("shard family membership inspection limit exceeded")
                if (
                    ShardedModelDetector._match_family_filename(
                        candidate.name,
                        pattern,
                        expected_total=expected_total if isinstance(expected_total, int) else None,
                        normalized_safetensors_stem=(
                            normalized_safetensors_stem if isinstance(normalized_safetensors_stem, str) else None
                        ),
                    )
                    is None
                ):
                    continue
                members.add(str(candidate.absolute()))
                if len(members) > MAX_SCANNABLE_SHARDS:
                    raise OSError("shard family member limit exceeded")
        return members

    def _scan_single_shard(self, shard_path: str) -> "ScanResult":
        from ...scanner_results import CheckStatus, IssueSeverity, ScanResult

        """Scan a single shard file."""
        scanner = (
            self.scanner_class(config=dict(self.scanner_config))
            if self.scanner_config is not None
            else self.scanner_class()
        )
        scan_path = shard_path
        target_validator: Callable[..., os.stat_result] | None = None
        validated_stat: os.stat_result | None = None
        validated_target: dict[str, int | str] | None = None
        shard_targets = self.shard_info.get("shard_targets")
        if isinstance(shard_targets, dict):
            target = shard_targets.get(shard_path)
            if isinstance(target, dict):
                validated_target = target
                resolved_path = target.get("resolved_path")
                expected_device = target.get("device")
                expected_inode = target.get("inode")
                expected_size = target.get("size")
                expected_mtime_ns = target.get("mtime_ns")
                expected_ctime_ns = target.get("ctime_ns")
                if not isinstance(resolved_path, str):
                    raise OSError(f"Missing validated target for shard {Path(shard_path).name}")

                def _validate_target(phase: str, *, ignore_ctime: bool = False) -> os.stat_result:
                    try:
                        current_resolved = str(Path(shard_path).resolve(strict=True))
                        current_stat = os.stat(resolved_path, follow_symlinks=False)
                    except (OSError, RuntimeError) as e:
                        raise OSError(
                            f"Validated shard target is no longer available {phase}: {Path(shard_path).name}"
                        ) from e
                    if current_resolved != resolved_path or not stat.S_ISREG(current_stat.st_mode):
                        raise OSError(f"Validated shard target changed {phase}: {Path(shard_path).name}")
                    if (
                        isinstance(expected_device, int)
                        and isinstance(expected_inode, int)
                        and expected_inode
                        and (current_stat.st_dev, current_stat.st_ino) != (expected_device, expected_inode)
                    ):
                        raise OSError(f"Validated shard identity changed {phase}: {Path(shard_path).name}")
                    if isinstance(expected_size, int) and current_stat.st_size != expected_size:
                        raise OSError(f"Validated shard size changed {phase}: {Path(shard_path).name}")
                    if (isinstance(expected_mtime_ns, int) and current_stat.st_mtime_ns != expected_mtime_ns) or (
                        not ignore_ctime
                        and isinstance(expected_ctime_ns, int)
                        and current_stat.st_ctime_ns != expected_ctime_ns
                    ):
                        raise OSError(f"Validated shard timestamp changed {phase}: {Path(shard_path).name}")
                    return current_stat

                target_validator = _validate_target
                validated_stat = target_validator("before scanning")
                scan_path = resolved_path

        pinned_scan: _PinnedShardScan | None = None
        try:
            already_pinned = bool(
                isinstance(self.scanner_config, dict)
                and self.scanner_config.get(_SHARD_ALREADY_PINNED_CONFIG_KEY) is True
            )
            if validated_target is None:
                result: ScanResult = scanner.scan(scan_path)
            elif already_pinned:
                result = scanner.scan(shard_path)
            else:
                validated_size = validated_target.get("size")
                copy_limit = validated_size if isinstance(validated_size, int) else None
                if isinstance(self.scanner_config, dict):
                    for limit_name in ("max_file_size", "max_total_size"):
                        configured_limit = self.scanner_config.get(limit_name)
                        if isinstance(configured_limit, int) and configured_limit > 0:
                            copy_limit = configured_limit if copy_limit is None else min(copy_limit, configured_limit)
                with _pinned_shard_scan_path(
                    scan_path,
                    validated_target,
                    copy_max_bytes=copy_limit,
                ) as pinned_scan:
                    result = scanner.scan(pinned_scan.path)
                    _rebase_pinned_shard_result(result, pinned_scan.path, shard_path)
        except _ShardPinUnavailableError as error:
            result = ScanResult(scanner_name=getattr(scanner, "name", "shard_scanner"))
            _mark_inconclusive_scan_outcome(result, "shard_pin_unavailable")
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "shard_pin_unavailable"
            result.add_check(
                name="Shard Scan Pinning",
                passed=False,
                message=f"Unable to bind shard to a stable scan path: {Path(shard_path).name}",
                severity=IssueSeverity.INFO,
                location=shard_path,
                details={
                    "error": "descriptor-bound shard pinning unavailable",
                    "exception_type": type(error).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_pin_unavailable",
                },
            )
            result.finish(success=False)
            return result
        if target_validator is not None and validated_stat is not None:
            try:
                if pinned_scan is not None and pinned_scan.changed_during_scan:
                    raise OSError(f"Validated shard content changed during scanning: {Path(shard_path).name}")
                post_scan_stat = target_validator("during scanning", ignore_ctime=pinned_scan is not None)
                identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(getattr(validated_stat, field) != getattr(post_scan_stat, field) for field in identity_fields):
                    raise OSError(f"Validated shard target changed during scanning: {Path(shard_path).name}")
            except OSError as error:
                # Keep security findings already observed, but discard passing
                # evidence that became untrustworthy when the target changed.
                result.checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
                _mark_inconclusive_scan_outcome(result, "shard_scan_error")
                result.add_check(
                    name="Shard Scan",
                    passed=False,
                    message=f"Error scanning shard: {Path(shard_path).name}",
                    severity=IssueSeverity.INFO,
                    location=shard_path,
                    details={
                        "error": str(error),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "shard_scan_error",
                    },
                )
                result.finish(success=False)
        return result


class AdvancedFileHandler:
    """Handler for large model files (400B+ parameters)."""

    def __init__(
        self,
        file_path: str,
        scanner: Any,
        progress_callback: Callable[[str, float], None] | None = None,
        timeout: int = 7200,  # 2 hours for large models
        allowed_shard_paths: list[str] | None = None,
        allowed_shard_targets: ValidatedShardTargets | None = None,
        index_search_root: str | os.PathLike[str] | None = None,
    ):
        """
        Initialize advanced file handler.

        Args:
            file_path: Path to the file
            scanner: Scanner instance
            progress_callback: Optional progress callback
            timeout: Maximum scan time
        """
        self.file_path = file_path
        self.scanner = scanner
        self.progress_callback = progress_callback
        self.timeout = timeout
        self.start_time = time.time()
        scanner_config = getattr(scanner, "config", {})
        configured_index_context = (
            scanner_config.get(_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY) if isinstance(scanner_config, dict) else None
        )
        self.index_inspection_context = (
            configured_index_context
            if isinstance(configured_index_context, _SafetensorsIndexInspectionContext)
            else _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
        )
        prevalidated_shard_info = (
            scanner_config.get(_PREVALIDATED_SHARD_INFO_CONFIG_KEY) if isinstance(scanner_config, dict) else None
        )
        self.uses_prevalidated_shard_info = isinstance(prevalidated_shard_info, dict)
        self.defers_safetensors_index_content_revalidation = bool(
            isinstance(scanner_config, dict)
            and scanner_config.get(_DEFER_SAFETENSORS_INDEX_CONTENT_REVALIDATION_CONFIG_KEY) is True
        )
        self.allowed_shard_paths = allowed_shard_paths
        self.allowed_shard_targets = allowed_shard_targets
        self.index_search_root = index_search_root
        self.shard_boundary_error = _grouped_shard_boundary_error(
            file_path,
            allowed_shard_paths,
            allowed_shard_targets,
        )

        # Check for sharded model
        self.detected_shard_info = (
            None
            if self.shard_boundary_error is not None
            else (
                dict(prevalidated_shard_info)
                if isinstance(prevalidated_shard_info, dict)
                else ShardedModelDetector.detect_shards(
                    file_path,
                    allowed_paths=allowed_shard_paths,
                    allowed_targets=allowed_shard_targets,
                    index_search_root=index_search_root,
                    index_inspection_context=self.index_inspection_context,
                )
            )
        )
        self.shard_info = self.detected_shard_info

        # Get file/model size
        if self.shard_boundary_error is not None:
            self.total_size = 0
            self.is_sharded = True
        elif self.shard_info:
            self.total_size = self.shard_info["total_size"]
            self.is_sharded = True
        else:
            self.total_size = os.path.getsize(file_path)
            self.is_sharded = False

    def scan(self) -> "ScanResult":
        """
        Scan the large model file.

        Returns:
            ScanResult with findings
        """
        logger.debug(f"Advanced scan initialized: {self.total_size:,} bytes, sharded={self.is_sharded}")

        # Determine scanning strategy
        if self.shard_boundary_error is not None:
            return _shard_boundary_failure_result(self.scanner.name, self.file_path, self.shard_boundary_error)
        if self.is_sharded:
            result = self._scan_sharded_model()
        elif self.total_size > LARGE_MODEL_THRESHOLD_200GB:
            result = self._scan_large_file_distributed()
        elif self.total_size > EXTREME_MODEL_THRESHOLD:
            result = self._scan_with_mmap()
        else:
            # Fall back to regular large file handler
            from .large_file_handler import LargeFileHandler

            handler = LargeFileHandler(self.file_path, self.scanner, self.progress_callback, self.timeout)
            result = handler.scan()

        if not self.uses_prevalidated_shard_info:
            authority_stable = _safetensors_shard_info_authority_is_stable(
                self.detected_shard_info,
                index_search_root=self.index_search_root,
                index_inspection_context=self.index_inspection_context,
                force_content_revalidation=not self.defers_safetensors_index_content_revalidation,
            )
            current_shard_info = ShardedModelDetector.detect_shards(
                self.file_path,
                allowed_paths=self.allowed_shard_paths,
                allowed_targets=self.allowed_shard_targets,
                index_search_root=self.index_search_root,
                index_inspection_context=self.index_inspection_context,
            )
            if not authority_stable or current_shard_info != self.detected_shard_info:
                return _preserve_findings_with_shard_boundary_failure(
                    result,
                    self.scanner.name,
                    self.file_path,
                    {"path": self.file_path, "reason": "shard_family_changed_during_scan"},
                )
        return result

    def _supports_bounded_large_file_analysis(self) -> bool:
        """Return True when the scanner exposes a bounded large-file strategy."""
        return any(hasattr(self.scanner, attr) for attr in ("_scan_with_mmap", "_analyze_chunk", "_analyze_bytes"))

    def _fail_closed_large_file_coverage(self, *, threshold_bytes: int) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """Abort with an operational-style result when large-file coverage would be partial."""
        result = ScanResult(scanner_name=self.scanner.name)
        result.add_check(
            name="Large File Detection",
            passed=True,
            message=f"Scanning file ({self.total_size:,} bytes) - processing may take additional time",
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": "unsupported",
                "note": "Bounded analysis unavailable for this scanner; aborting to avoid partial coverage.",
            },
        )
        result.add_check(
            name="Large File Coverage Check",
            passed=False,
            message=(
                "Error scanning file: "
                f"scanner {self.scanner.name} does not support bounded large-file analysis "
                "for this file size; aborting to avoid partial coverage."
            ),
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": "unsupported",
                "scanner": self.scanner.name,
                "threshold_bytes": threshold_bytes,
            },
        )
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = "unsupported_bounded_large_file_analysis"
        result.finish(success=False)
        return result

    def _scan_sharded_model(self) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """Scan a sharded model."""
        result = ScanResult(scanner_name=self.scanner.name)

        # Find and scan config file first
        config_path = ShardedModelDetector.find_model_config(self.file_path)
        if config_path:
            logger.debug(f"Model configuration detected: {config_path}")
            # Quick scan of config for metadata
            try:
                pre_open_stat = os.stat(config_path, follow_symlinks=False)
                if not stat.S_ISREG(pre_open_stat.st_mode):
                    raise OSError("Model configuration is not a regular file")
                flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                config_fd = os.open(config_path, flags)
                try:
                    opened_stat = os.fstat(config_fd)
                    post_open_stat = os.stat(config_path, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(opened_stat.st_mode)
                        or not stat.S_ISREG(post_open_stat.st_mode)
                        or not os.path.samestat(pre_open_stat, opened_stat)
                        or not os.path.samestat(opened_stat, post_open_stat)
                    ):
                        raise OSError("Model configuration changed while opening")
                    config_content = os.read(config_fd, 10240).decode("utf-8", errors="replace")
                finally:
                    os.close(config_fd)
                if "torch_dtype" in config_content:
                    result.add_check(
                        name="PyTorch Configuration Detection",
                        passed=True,
                        message="PyTorch model configuration detected",
                        severity=IssueSeverity.INFO,
                        location=config_path,
                        details={"config_file": config_path},
                    )
            except Exception as e:
                logger.warning(f"Failed to read config file: {e}")

        # Scan shards in parallel
        shard_scan_success = True
        if self.shard_info:
            scanner_config = getattr(self.scanner, "config", None)
            parallel_scanner = ParallelShardHandler(
                self.shard_info,
                self.scanner.__class__,
                scanner_config=dict(scanner_config) if isinstance(scanner_config, dict) else None,
            )
            shard_results = parallel_scanner.scan_shards(self.progress_callback)
            shard_scan_success = bool(shard_results.success)
            result.merge(shard_results)
            missing_count = self.shard_info.get("missing_shard_count")
            unreadable_count = self.shard_info.get("unreadable_shard_count")
            out_of_scope_count = self.shard_info.get("out_of_scope_shard_count")
            unvalidated_count = self.shard_info.get("unvalidated_shard_count")
            duplicate_count = self.shard_info.get("duplicate_shard_count")
            unexpected_count = self.shard_info.get("unexpected_shard_count")
            if isinstance(missing_count, int) and missing_count > 0:
                _mark_inconclusive_scan_outcome(result, "missing_model_shards")
            if isinstance(out_of_scope_count, int) and out_of_scope_count > 0:
                _mark_inconclusive_scan_outcome(result, "out_of_scope_model_shards")
            if isinstance(unreadable_count, int) and unreadable_count > 0:
                _mark_inconclusive_scan_outcome(result, "unreadable_model_shards")
            if isinstance(unvalidated_count, int) and unvalidated_count > 0:
                _mark_inconclusive_scan_outcome(result, "unvalidated_model_shards")
            if isinstance(duplicate_count, int) and duplicate_count > 0:
                _mark_inconclusive_scan_outcome(result, "duplicate_model_shard_targets")
            if isinstance(unexpected_count, int) and unexpected_count > 0:
                _mark_inconclusive_scan_outcome(result, "unexpected_model_shards")
            if isinstance(missing_count, int) and missing_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(f"Missing {missing_count} expected model shard(s); scan coverage is incomplete."),
                    severity=IssueSeverity.INFO,
                    location=self.file_path,
                    details={
                        "expected_total_shards": self.shard_info.get("expected_total_shards"),
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "missing_shard_count": missing_count,
                        "missing_shard_indices": self.shard_info.get("missing_shard_indices", []),
                        "missing_shard_indices_truncated": self.shard_info.get(
                            "missing_shard_indices_truncated", False
                        ),
                        "unreadable_shard_count": self.shard_info.get("unreadable_shard_count", 0),
                        "unreadable_shards": self.shard_info.get("unreadable_shards", []),
                        "out_of_scope_shard_count": self.shard_info.get("out_of_scope_shard_count", 0),
                        "out_of_scope_shards": self.shard_info.get("out_of_scope_shards", []),
                        "unvalidated_shard_count": self.shard_info.get("unvalidated_shard_count", 0),
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "duplicate_shard_count": self.shard_info.get("duplicate_shard_count", 0),
                        "duplicate_shards": self.shard_info.get("duplicate_shards", []),
                        "unexpected_shard_count": self.shard_info.get("unexpected_shard_count", 0),
                        "unexpected_shards": self.shard_info.get("unexpected_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "missing_model_shards",
                    },
                )
            elif isinstance(out_of_scope_count, int) and out_of_scope_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(
                        f"Skipped {out_of_scope_count} model shard(s) resolving outside the direct scan directory; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    location=self.file_path,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "out_of_scope_shard_count": out_of_scope_count,
                        "out_of_scope_shards": self.shard_info.get("out_of_scope_shards", []),
                        "unreadable_shard_count": self.shard_info.get("unreadable_shard_count", 0),
                        "unreadable_shards": self.shard_info.get("unreadable_shards", []),
                        "unvalidated_shard_count": self.shard_info.get("unvalidated_shard_count", 0),
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "duplicate_shard_count": self.shard_info.get("duplicate_shard_count", 0),
                        "duplicate_shards": self.shard_info.get("duplicate_shards", []),
                        "unexpected_shard_count": self.shard_info.get("unexpected_shard_count", 0),
                        "unexpected_shards": self.shard_info.get("unexpected_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "out_of_scope_model_shards",
                    },
                )
            elif isinstance(unreadable_count, int) and unreadable_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=f"Unable to read {unreadable_count} model shard(s); scan coverage is incomplete.",
                    severity=IssueSeverity.INFO,
                    location=self.file_path,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "unreadable_shard_count": unreadable_count,
                        "unreadable_shards": self.shard_info.get("unreadable_shards", []),
                        "unvalidated_shard_count": self.shard_info.get("unvalidated_shard_count", 0),
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "duplicate_shard_count": self.shard_info.get("duplicate_shard_count", 0),
                        "duplicate_shards": self.shard_info.get("duplicate_shards", []),
                        "unexpected_shard_count": self.shard_info.get("unexpected_shard_count", 0),
                        "unexpected_shards": self.shard_info.get("unexpected_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unreadable_model_shards",
                    },
                )
            elif isinstance(unvalidated_count, int) and unvalidated_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(
                        f"Skipped {unvalidated_count} model shard(s) outside the validated family; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    location=self.file_path,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "unvalidated_shard_count": unvalidated_count,
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "unexpected_shard_count": self.shard_info.get("unexpected_shard_count", 0),
                        "unexpected_shards": self.shard_info.get("unexpected_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unvalidated_model_shards",
                    },
                )
            elif isinstance(unexpected_count, int) and unexpected_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(
                        f"Found {unexpected_count} model shard(s) outside the expected family inventory; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    location=self.file_path,
                    details={
                        "expected_total_shards": self.shard_info.get("expected_total_shards"),
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "unexpected_shard_count": unexpected_count,
                        "unexpected_shards": self.shard_info.get("unexpected_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unexpected_model_shards",
                    },
                )
            if isinstance(duplicate_count, int) and duplicate_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(
                        f"Skipped {duplicate_count} model shard name(s) resolving to duplicate targets; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    location=self.file_path,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "duplicate_shard_count": duplicate_count,
                        "duplicate_shards": self.shard_info.get("duplicate_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "duplicate_model_shard_targets",
                    },
                )
        result.finish(success=shard_scan_success and not result.has_errors and "scan_outcome" not in result.metadata)
        return result

    def _scan_with_mmap(self) -> "ScanResult":
        """Scan using memory mapping."""
        if not self._supports_bounded_large_file_analysis():
            return self._fail_closed_large_file_coverage(threshold_bytes=EXTREME_MODEL_THRESHOLD)

        mmap_scanner = MemoryMappedHandler(self.file_path, self.scanner)
        return mmap_scanner.scan_with_mmap(self.progress_callback)

    def _scan_large_file_distributed(self) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """Scan very large files using only bounded, scanner-aware analysis."""
        logger.debug(f"Scanning file ({self.total_size:,} bytes) with bounded large-file analysis")

        if not self._supports_bounded_large_file_analysis():
            return self._fail_closed_large_file_coverage(threshold_bytes=LARGE_MODEL_THRESHOLD_200GB)

        result = ScanResult(scanner_name=self.scanner.name)
        strategy = (
            "scanner-defined memory-mapped analysis"
            if hasattr(self.scanner, "_scan_with_mmap")
            else "memory-mapped chunk analysis"
        )
        result.add_check(
            name="Large File Detection",
            passed=True,
            message=f"Scanning file ({self.total_size:,} bytes) - processing may take additional time",
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": strategy,
                "note": "Bounded analysis enabled for this scanner",
            },
        )

        mmap_scanner = MemoryMappedHandler(self.file_path, self.scanner)
        if hasattr(self.scanner, "_scan_with_mmap"):
            scan_result = self.scanner._scan_with_mmap(self.file_path, self.progress_callback)
        else:
            scan_result = mmap_scanner.scan_with_mmap(self.progress_callback)

        result.merge(scan_result)
        result.finish(success=bool(scan_result.success))
        return result


def should_use_advanced_handler(
    file_path: str,
    *,
    allowed_shard_paths: list[str] | None = None,
    allowed_shard_targets: ValidatedShardTargets | None = None,
    index_search_root: str | os.PathLike[str] | None = None,
) -> bool:
    """
    Check if file should use advanced file handler.

    Args:
        file_path: Path to check
        allowed_shard_paths: Validated shard targets permitted during grouped directory scans

    Returns:
        True if advanced handler should be used
    """
    if _grouped_shard_boundary_error(file_path, allowed_shard_paths, allowed_shard_targets) is not None:
        return True

    # Check for sharded model
    if ShardedModelDetector.detect_shards(
        file_path,
        allowed_paths=allowed_shard_paths,
        allowed_targets=allowed_shard_targets,
        index_search_root=index_search_root,
    ):
        return True

    # Check file size
    try:
        file_size = os.path.getsize(file_path)
        return file_size > EXTREME_MODEL_THRESHOLD
    except OSError:
        return False


def scan_advanced_large_file(
    file_path: str,
    scanner: Any,
    progress_callback: Callable[[str, float], None] | None = None,
    timeout: int = 7200,
    allowed_shard_paths: list[str] | None = None,
    allowed_shard_targets: ValidatedShardTargets | None = None,
    index_search_root: str | os.PathLike[str] | None = None,
) -> "ScanResult":
    """
    Scan a large file with advanced handler.

    Args:
        file_path: Path to scan
        scanner: Scanner instance
        progress_callback: Progress callback
        timeout: Maximum scan time

    Returns:
        ScanResult with findings
    """
    # Check if caching is enabled in scanner config
    config = getattr(scanner, "config", {})
    configured_index_context = config.get(_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY)
    index_inspection_context = (
        configured_index_context
        if isinstance(configured_index_context, _SafetensorsIndexInspectionContext)
        else _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
    )
    cache_enabled = config.get("cache_enabled", True)
    cache_dir = config.get("cache_dir")
    prevalidated_shard_info = config.get(_PREVALIDATED_SHARD_INFO_CONFIG_KEY)
    defer_index_content_revalidation = config.get(_DEFER_SAFETENSORS_INDEX_CONTENT_REVALIDATION_CONFIG_KEY) is True
    boundary_error = _grouped_shard_boundary_error(file_path, allowed_shard_paths, allowed_shard_targets)
    if boundary_error is not None:
        return _shard_boundary_failure_result(scanner.name, file_path, boundary_error)

    if should_bypass_cache_for_safetensors_header_limit(file_path, config):
        logger.debug(f"Bypassing advanced-file cache for bounded SafeTensors header failure: {file_path}")
        return scanner.scan(file_path)  # type: ignore[no-any-return]

    shard_info = (
        dict(prevalidated_shard_info)
        if isinstance(prevalidated_shard_info, dict)
        else ShardedModelDetector.detect_shards(
            file_path,
            allowed_paths=allowed_shard_paths,
            allowed_targets=allowed_shard_targets,
            index_search_root=index_search_root,
            index_inspection_context=index_inspection_context,
        )
    )
    if (
        shard_info is None
        and getattr(scanner, "name", None) == "onnx"
        and should_defer_hash_for_file_backed_onnx(file_path, config)
    ):
        logger.debug(f"Bypassing advanced-file cache for file-backed ONNX inspection: {file_path}")
        return scanner.scan(file_path)  # type: ignore[no-any-return]
    if shard_info is not None and not _supports_reliable_shard_cache_identity():
        logger.debug(f"Bypassing advanced-file cache for unreliable shard identities: {file_path}")
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
            allowed_shard_targets=allowed_shard_targets,
            index_search_root=index_search_root,
        )

    # If caching is disabled, proceed with direct scan
    if not cache_enabled:
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
            allowed_shard_targets=allowed_shard_targets,
            index_search_root=index_search_root,
        )
    if should_bypass_cache_for_zip_entry_preflight(file_path, config):
        logger.debug(f"Bypassing advanced-file cache for bounded ZIP entry preflight: {file_path}")
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
            allowed_shard_targets=allowed_shard_targets,
            index_search_root=index_search_root,
        )
    if should_bypass_cache_for_unavailable_hdf5_analysis(file_path):
        logger.debug(f"Bypassing advanced-file cache because HDF5 analysis is unavailable: {file_path}")
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
            allowed_shard_targets=allowed_shard_targets,
            index_search_root=index_search_root,
        )

    # Use cache manager for advanced large file scans
    try:
        from ...cache import get_cache_manager
        from ...cache.optimized_config import build_cache_version_context

        cache_manager = get_cache_manager(cache_dir, enabled=True)
        version_config = dict(config)
        cache_hasher = cache_manager.cache.hasher if cache_manager.cache is not None else None
        model_config_fingerprint: dict[str, str] | None = None
        if shard_info is not None:
            # A representative file key alone cannot describe sibling shard
            # membership, target identity, or incomplete-family state.
            version_config["advanced_shard_family"] = shard_info
            shard_family_fingerprint, shard_family_cacheable = _build_advanced_shard_family_cache_fingerprint(
                shard_info,
                cache_hasher,
            )
            if not shard_family_cacheable:
                logger.debug("Bypassing advanced-file cache for uncacheable shard family identity: %s", file_path)
                return _scan_advanced_large_file_internal(
                    file_path,
                    scanner,
                    progress_callback,
                    timeout,
                    allowed_shard_paths=allowed_shard_paths,
                    allowed_shard_targets=allowed_shard_targets,
                    index_search_root=index_search_root,
                )
            if shard_family_fingerprint is not None:
                version_config["advanced_shard_family_cache_fingerprint"] = shard_family_fingerprint
            model_config_fingerprint, model_config_cacheable = _build_advanced_shard_model_config_cache_fingerprint(
                file_path, cache_hasher
            )
            if not model_config_cacheable:
                logger.debug("Bypassing advanced-file cache for uncacheable shard model config: %s", file_path)
                return _scan_advanced_large_file_internal(
                    file_path,
                    scanner,
                    progress_callback,
                    timeout,
                    allowed_shard_paths=allowed_shard_paths,
                    allowed_shard_targets=allowed_shard_targets,
                    index_search_root=index_search_root,
                )
            version_config["advanced_shard_model_config_cache_fingerprint"] = model_config_fingerprint
        if allowed_shard_paths is not None:
            # The allowlist changes shard expansion, so direct advanced scans need distinct cache keys.
            version_config["advanced_allowed_shard_paths"] = sorted(
                {str(Path(path).resolve()) for path in allowed_shard_paths}
            )
        if index_search_root is not None:
            version_config["advanced_shard_index_search_root"] = _normalized_absolute_path(index_search_root)
        version_context = add_optional_dependency_availability_to_version_context(
            build_cache_version_context(version_config)
        )

        cache_miss_executed = False

        # Create wrapper function for cache manager
        def cached_advanced_scan_wrapper(fpath: str) -> dict:
            nonlocal cache_miss_executed
            cache_miss_executed = True
            result = _scan_advanced_large_file_internal(
                fpath,
                scanner,
                progress_callback,
                timeout,
                allowed_shard_paths=allowed_shard_paths,
                allowed_shard_targets=allowed_shard_targets,
                index_search_root=index_search_root,
            )
            current_shard_info = ShardedModelDetector.detect_shards(
                file_path,
                allowed_paths=allowed_shard_paths,
                allowed_targets=allowed_shard_targets,
                index_search_root=index_search_root,
                index_inspection_context=index_inspection_context,
            )
            if current_shard_info != shard_info:
                result = _preserve_findings_with_shard_boundary_failure(
                    result,
                    scanner.name,
                    file_path,
                    {"path": file_path, "reason": "shard_family_changed_during_scan"},
                )
            if shard_info is not None:
                current_model_config_fingerprint, current_model_config_cacheable = (
                    _build_advanced_shard_model_config_cache_fingerprint(file_path, cache_hasher)
                )
                if not current_model_config_cacheable or current_model_config_fingerprint != model_config_fingerprint:
                    result = _preserve_findings_with_shard_boundary_failure(
                        result,
                        scanner.name,
                        file_path,
                        {"path": file_path, "reason": "shard_model_config_changed_during_scan"},
                    )
            return result.to_dict(include_private_metadata=True)

        # Get cached result or perform scan
        result_dict = cache_manager.cached_scan(
            file_path,
            cached_advanced_scan_wrapper,
            version_context=version_context,
            include_private_metadata=True,
        )

        from ...utils.helpers.result_conversion import scan_result_from_dict

        result = scan_result_from_dict(result_dict)

        authority_stable = _safetensors_shard_info_authority_is_stable(
            shard_info,
            index_search_root=index_search_root,
            index_inspection_context=index_inspection_context,
            force_content_revalidation=not cache_miss_executed and not defer_index_content_revalidation,
        )
        post_scan_shard_info = ShardedModelDetector.detect_shards(
            file_path,
            allowed_paths=allowed_shard_paths,
            allowed_targets=allowed_shard_targets,
            index_search_root=index_search_root,
            index_inspection_context=index_inspection_context,
        )
        if not authority_stable or post_scan_shard_info != shard_info:
            return _preserve_findings_with_shard_boundary_failure(
                result,
                scanner.name,
                file_path,
                {"path": file_path, "reason": "shard_family_changed_during_scan"},
            )

        if shard_info is not None:
            post_scan_model_config_fingerprint, post_scan_model_config_cacheable = (
                _build_advanced_shard_model_config_cache_fingerprint(file_path, cache_hasher)
            )
            if not post_scan_model_config_cacheable or post_scan_model_config_fingerprint != model_config_fingerprint:
                return _preserve_findings_with_shard_boundary_failure(
                    result,
                    scanner.name,
                    file_path,
                    {"path": file_path, "reason": "shard_model_config_changed_during_scan"},
                )

        return result

    except Exception as e:
        # If cache system fails, fall back to direct scanning
        logger.warning(f"Advanced file cache error for {file_path}: {e}. Falling back to direct scan.")
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
            allowed_shard_targets=allowed_shard_targets,
            index_search_root=index_search_root,
        )


def _scan_advanced_large_file_internal(
    file_path: str,
    scanner: Any,
    progress_callback: Callable[[str, float], None] | None = None,
    timeout: int = 7200,
    allowed_shard_paths: list[str] | None = None,
    allowed_shard_targets: ValidatedShardTargets | None = None,
    index_search_root: str | os.PathLike[str] | None = None,
) -> "ScanResult":
    """
    Internal implementation of advanced large file scanning (cache-agnostic).

    Args:
        file_path: Path to scan
        scanner: Scanner instance
        progress_callback: Progress callback
        timeout: Maximum scan time

    Returns:
        ScanResult with findings
    """
    handler = AdvancedFileHandler(
        file_path,
        scanner,
        progress_callback,
        timeout,
        allowed_shard_paths=allowed_shard_paths,
        allowed_shard_targets=allowed_shard_targets,
        index_search_root=index_search_root,
    )
    return handler.scan()
