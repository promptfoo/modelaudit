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
import stat
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, suppress
from contextvars import ContextVar, copy_context
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import TYPE_CHECKING, Any, ClassVar

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
SHARD_SCAN_TIMEOUT = 600  # 10 minutes per shard
MAX_RECORDED_MISSING_SHARD_INDICES = 1000
_SHARD_ALREADY_PINNED_CONFIG_KEY = "_trusted_shard_already_pinned"
_PREVALIDATED_SHARD_INFO_CONFIG_KEY = "_trusted_prevalidated_shard_info"
_DEFER_SAFETENSORS_INDEX_CONTENT_REVALIDATION_CONFIG_KEY = "_trusted_defer_safetensors_index_content_revalidation"
SAFETENSORS_SHARD_PATTERN = r"model-(\d+)-of-(\d+)\.safetensors"
SAFETENSORS_INDEX_NAME = "model.safetensors.index.json"
SAFETENSORS_INDEX_SUFFIX = ".safetensors.index.json"
MAX_SAFETENSORS_SHARD_INDEX_BYTES = 10 * 1024 * 1024
MAX_SAFETENSORS_SHARD_INDEX_FILES = 256
MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SAFETENSORS_SHARD_INDEX_DIRECTORIES = 256
MAX_SAFETENSORS_SHARD_INDEX_OBSERVATIONS = 512
MAX_SAFETENSORS_SHARD_INDEX_TENSORS = 250_000
MAX_SAFETENSORS_SHARD_INDEX_JSON_TOKENS = (2 * MAX_SAFETENSORS_SHARD_INDEX_TENSORS) + 4096
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


@dataclass
class _SafetensorsIndexInspectionContext:
    """Bound and memoize local SafeTensors index inspection for one top-level scan."""

    lock: RLock = field(default_factory=RLock)
    candidate_paths: set[str] = field(default_factory=set)
    directory_paths: set[str] = field(default_factory=set)
    charged_observations: set[tuple[Any, ...]] = field(default_factory=set)
    parsed_inventories: dict[tuple[Any, ...], _SafetensorsShardIndexInventory] = field(default_factory=dict)
    last_observations: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    generations: dict[str, int] = field(default_factory=dict)
    bytes_read: int = 0
    failure: str | None = None

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


def _descriptor_relative_scan_path(directory_fd: int, filename: str) -> str | None:
    """Return a filename-preserving path rooted at an already-open directory."""
    for descriptor_root in (Path("/proc/self/fd"), Path("/dev/fd")):
        candidate = descriptor_root / str(directory_fd) / filename
        try:
            if stat.S_ISREG(os.stat(candidate).st_mode):
                return str(candidate)
        except OSError:
            continue
    return None


def _descriptor_path_for_open_file(file_fd: int) -> str | None:
    """Return a stable path to an opened regular file descriptor."""
    opened_stat = os.fstat(file_fd)
    for descriptor_root in (Path("/proc/self/fd"), Path("/dev/fd")):
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


def _open_windows_shard_guard_fd(path: str) -> int:
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
    handle = create_file(
        path,
        0x80000000,
        0x00000001,
        None,
        3,
        0x00000080,
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
            try:
                final_stat = os.fstat(source_fd)
            except OSError:
                pinned_scan.changed_during_scan = True
            else:
                identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                pinned_scan.changed_during_scan = any(
                    getattr(source_stat, field) != getattr(final_stat, field) for field in identity_fields
                )
        if source_fd is not None:
            os.close(source_fd)


@contextmanager
def _pinned_shard_scan_path(
    resolved_path: str,
    target: dict[str, int | str],
) -> Iterator[_PinnedShardScan]:
    """Expose a validated shard through a directory descriptor immune to pathname ABA swaps."""
    if os.name == "nt":
        with _pinned_windows_shard_scan_path(resolved_path, target) as windows_pinned_scan:
            yield windows_pinned_scan
        return

    source_path = Path(resolved_path)
    parent_fd: int | None = None
    source_fd: int | None = None
    staging_fd: int | None = None
    staging_path: Path | None = None
    pinned_name = source_path.name
    pinned_created = False
    pinned_scan: _PinnedShardScan | None = None
    pinned_stat: os.stat_result | None = None
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        nonblock = getattr(os, "O_NONBLOCK", 0)
        required_dir_fd_functions = (os.open, os.stat, os.symlink, os.unlink)
        if (
            not nofollow
            or not directory
            or any(function not in os.supports_dir_fd for function in required_dir_fd_functions)
        ):
            raise _ShardPinUnavailableError("descriptor-bound shard scans are unsupported on this platform")

        directory_flags = os.O_RDONLY | directory | nofollow | cloexec
        parent_fd = os.open(source_path.parent, directory_flags)
        source_fd = os.open(
            pinned_name,
            os.O_RDONLY | nofollow | nonblock | cloexec,
            dir_fd=parent_fd,
        )
        source_stat = os.fstat(source_fd)
        if not _validated_stat_matches_target(source_stat, target):
            raise _ShardPinUnavailableError("validated shard target changed before pinning")

        source_descriptor_path = _descriptor_path_for_open_file(source_fd)
        if source_descriptor_path is None:
            raise _ShardPinUnavailableError("platform cannot expose the opened shard descriptor")

        staging_path = Path(tempfile.mkdtemp(prefix=".modelaudit_scan_"))
        initial_staging_stat = os.stat(staging_path, follow_symlinks=False)
        staging_fd = os.open(staging_path, directory_flags)
        staging_stat = os.fstat(staging_fd)
        effective_uid = getattr(os, "geteuid", lambda: staging_stat.st_uid)()
        if (
            not stat.S_ISDIR(staging_stat.st_mode)
            or staging_stat.st_uid != effective_uid
            or stat.S_IMODE(staging_stat.st_mode) & 0o077
            or not os.path.samestat(staging_stat, initial_staging_stat)
        ):
            raise _ShardPinUnavailableError("private shard staging directory changed while opening")

        os.symlink(source_descriptor_path, pinned_name, dir_fd=staging_fd)
        pinned_created = True
        pinned_stat = os.stat(pinned_name, dir_fd=staging_fd)
        if not os.path.samestat(source_stat, pinned_stat):
            raise _ShardPinUnavailableError("validated shard target changed while pinning")

        scan_path = _descriptor_relative_scan_path(staging_fd, pinned_name)
        if scan_path is None:
            raise _ShardPinUnavailableError("platform cannot expose the pinned shard directory")
        opened_scan_stat = os.stat(scan_path)
        if not os.path.samestat(source_stat, opened_scan_stat):
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
        if pinned_scan is not None and pinned_stat is not None and source_fd is not None:
            try:
                final_stat = os.fstat(source_fd)
            except OSError:
                pinned_scan.changed_during_scan = True
            else:
                identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                pinned_scan.changed_during_scan = any(
                    getattr(pinned_stat, field) != getattr(final_stat, field) for field in identity_fields
                )
        if pinned_created and staging_fd is not None:
            with suppress(OSError):
                os.unlink(pinned_name, dir_fd=staging_fd)
        if staging_fd is not None:
            os.close(staging_fd)
        if staging_path is not None:
            with suppress(OSError):
                staging_path.rmdir()
        if source_fd is not None:
            os.close(source_fd)
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
        SAFETENSORS_SHARD_PATTERN,  # SafeTensors sharding
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

    @classmethod
    def match_shard_filename(cls, file_name: str) -> dict[str, int | str | None] | None:
        """Return shard metadata for a filename when it matches a known shard pattern."""
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
    def match_safetensors_shard_filename(file_name: str) -> dict[str, int | str] | None:
        """Return SafeTensors shard metadata for the exact SafeTensors shard pattern."""
        match = re.fullmatch(SAFETENSORS_SHARD_PATTERN, file_name)
        if match is None or (match.lastindex or 0) < 2:
            return None
        try:
            shard_index = int(match.group(1))
            expected_total = int(match.group(2))
        except (IndexError, ValueError):
            return None
        return {
            "pattern": SAFETENSORS_SHARD_PATTERN,
            "current_shard_index": shard_index,
            "expected_total_shards": expected_total,
        }

    @staticmethod
    def _safe_index_target_path(index_dir: Path, raw_target: str) -> Path:
        """Return a local path for a SafeTensors index target or raise ValueError."""
        if not raw_target or "\\" in raw_target:
            raise ValueError("unsafe safetensors index target path")
        target_path = PurePosixPath(raw_target)
        if target_path.is_absolute() or any(part in {"", ".", ".."} for part in target_path.parts):
            raise ValueError("unsafe safetensors index target path")
        return index_dir.joinpath(*target_path.parts)

    @classmethod
    def _read_safetensors_index_inventory(
        cls,
        index_dir: Path,
        index_path: Path,
        pattern: str,
        expected_total: int | None,
        inspection_context: _SafetensorsIndexInspectionContext,
        *,
        force_content_revalidation: bool = False,
        content_revalidated_paths: set[str] | None = None,
    ) -> _SafetensorsShardIndexInventory:
        """Parse one SafeTensors index, returning its shard inventory or a validation error."""
        expected_paths: set[str] = set()
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
                pattern,
                expected_total,
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
            index_expected_total: int | None = expected_total
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
            for raw_target in target_candidates:
                try:
                    target_file = cls._safe_index_target_path(index_dir, raw_target)
                except ValueError as exc:
                    target_path_error = exc
                    continue
                target_files.append(target_file)
            expected_paths.update(_normalized_absolute_path(target_file) for target_file in target_files)
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
                    expected_indices=cls._expected_index_range(expected_total or 1, zero_based=False),
                    index_base="invalid",
                    fingerprint=index_fingerprint,
                    error="safetensors index target does not match shard filename pattern",
                    proven_unrelated=True,
                )
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
                if not isinstance(target_index, int) or not isinstance(target_total, int):
                    raise ValueError("safetensors index target does not match shard filename pattern")
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
                )
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
                )
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
                expected_indices=cls._expected_index_range(expected_total or 1, zero_based=False),
                index_base="invalid",
                fingerprint=index_fingerprint,
                error=str(exc),
            )
            if cache_key is not None and observation_prefix is not None:
                return inspection_context.record_inventory(
                    cache_key,
                    index_path,
                    (*observation_prefix, index_fingerprint),
                    inventory,
                )
            return inventory

    @staticmethod
    def _safetensors_inventory_governs_file(
        inventory: _SafetensorsShardIndexInventory,
        current_file: Path,
        pattern: str,
        expected_total: int,
    ) -> bool:
        """Return whether an ancestor index is authoritative for this shard path."""
        normalized_current = _normalized_absolute_path(current_file)
        if normalized_current in inventory.expected_source_paths:
            return True
        current_match = re.fullmatch(pattern, current_file.name)
        if current_match is None or (current_match.lastindex or 0) < 2:
            return False
        try:
            current_total = int(current_match.group(2))
        except (IndexError, ValueError):
            return False
        if current_total != expected_total:
            return False
        if _count_expected_shard_indices(inventory.expected_indices) != expected_total:
            return False
        current_parent = os.path.dirname(normalized_current)
        expected_parents = {os.path.dirname(source_path) for source_path in inventory.expected_source_paths}
        return current_parent in expected_parents

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
    def _safetensors_index_candidates(index_dir: Path) -> tuple[list[Path], bool]:
        """Return bounded local index candidates, preferring the canonical name."""
        canonical_path = index_dir / SAFETENSORS_INDEX_NAME
        canonical_available = canonical_path.exists() or canonical_path.is_symlink()
        candidates: list[Path] = []
        try:
            for candidate in index_dir.iterdir():
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
    ) -> _SafetensorsShardIndexInventory | None:
        """Load a governing SafeTensors index inventory or captured validation error."""
        if pattern != SAFETENSORS_SHARD_PATTERN or not isinstance(expected_total, int):
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
            index_candidates, candidate_limit_exceeded = cls._safetensors_index_candidates(index_dir)
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
            governing_inventory: _SafetensorsShardIndexInventory | None = None
            for index_path in index_candidates:
                inventory = cls._read_safetensors_index_inventory(
                    index_dir,
                    index_path,
                    pattern,
                    None,
                    inspection_context,
                    force_content_revalidation=force_content_revalidation,
                    content_revalidated_paths=content_revalidated_paths,
                )
                if inventory.error is not None:
                    normalized_current = _normalized_absolute_path(current_file)
                    same_directory_candidate = _normalized_absolute_path(index_dir) == _normalized_absolute_path(
                        absolute_dir
                    )
                    if normalized_current in inventory.expected_source_paths or (
                        same_directory_candidate
                        and not cls._safetensors_inventory_is_proven_unrelated(inventory, current_file)
                    ):
                        return inventory
                    continue
                if not cls._safetensors_inventory_governs_file(inventory, current_file, pattern, expected_total):
                    continue
                if governing_inventory is not None:
                    return _SafetensorsShardIndexInventory(
                        index_path=index_path,
                        expected_source_paths=(
                            governing_inventory.expected_source_paths | inventory.expected_source_paths
                        ),
                        expected_indices=cls._expected_index_range(expected_total, zero_based=False),
                        index_base="invalid",
                        error="multiple safetensors indexes govern selected shard",
                    )
                governing_inventory = inventory
            if governing_inventory is not None:
                return governing_inventory
            if _normalized_absolute_path(index_dir) == normalized_search_root:
                break
            index_dir = index_dir.parent
        return None

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
        if not isinstance(expected_total, int) or isinstance(expected_total, bool):
            return None, False
        dir_path = Path(file_path).parent
        effective_search_root = Path(index_search_root) if index_search_root is not None else dir_path.absolute()
        inspection_context = (
            index_inspection_context or _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
        )
        inventory = cls._load_safetensors_index_inventory(
            dir_path,
            SAFETENSORS_SHARD_PATTERN,
            expected_total,
            Path(file_path),
            effective_search_root,
            inspection_context,
            force_content_revalidation=force_content_revalidation,
        )
        if inventory is None:
            return None, False
        if (
            inventory.error is not None
            or inventory.index_base not in {"zero", "one"}
            or not isinstance(inventory.fingerprint, str)
            or not inventory.fingerprint
            or not isinstance(inventory.generation, int)
            or isinstance(inventory.generation, bool)
            or inventory.generation <= 0
        ):
            return None, True
        return (
            (
                inventory.index_base,
                _normalized_absolute_path(inventory.index_path),
                inventory.fingerprint,
                inventory.generation,
            ),
            True,
        )

    @classmethod
    def refresh_safetensors_index_proofs(
        cls,
        file_paths: Iterable[str],
        *,
        expected_total: int,
        index_search_root: str | os.PathLike[str],
        index_inspection_context: _SafetensorsIndexInspectionContext | None = None,
        force_content_revalidation: bool = False,
    ) -> tuple[tuple[str, str, str, int] | None, bool]:
        """Resolve one order-independent governing proof across selected shard parents."""
        inspection_context = (
            index_inspection_context or _CURRENT_SAFETENSORS_INDEX_CONTEXT.get() or _SafetensorsIndexInspectionContext()
        )
        search_root = Path(index_search_root)
        representatives_by_parent: dict[str, Path] = {}
        for file_path in file_paths:
            path = Path(file_path)
            shard_match = cls.match_safetensors_shard_filename(path.name)
            if shard_match is None or shard_match.get("expected_total_shards") != expected_total:
                return None, False
            representatives_by_parent.setdefault(_normalized_absolute_path(path.parent), path)
        if not representatives_by_parent:
            return None, False

        agreed_proof: tuple[str, str, str, int] | None = None
        authority_by_parent: list[bool] = []
        revalidated_indexes: set[str] = set()
        for current_file in representatives_by_parent.values():
            inventory = cls._load_safetensors_index_inventory(
                current_file.parent,
                SAFETENSORS_SHARD_PATTERN,
                expected_total,
                current_file,
                search_root,
                inspection_context,
                force_content_revalidation=force_content_revalidation,
                content_revalidated_paths=revalidated_indexes,
            )
            authority_present = inventory is not None
            authority_by_parent.append(authority_present)
            if inventory is None:
                continue
            if (
                inventory.error is not None
                or inventory.index_base not in {"zero", "one"}
                or not isinstance(inventory.fingerprint, str)
                or not inventory.fingerprint
                or not isinstance(inventory.generation, int)
                or isinstance(inventory.generation, bool)
                or inventory.generation <= 0
            ):
                return None, True
            proof = (
                inventory.index_base,
                _normalized_absolute_path(inventory.index_path),
                inventory.fingerprint,
                inventory.generation,
            )
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
        normalized_allowed_targets = (
            {
                os.path.normcase(os.path.normpath(os.path.abspath(source_path))): target
                for source_path, target in allowed_targets.items()
                if isinstance(source_path, str) and isinstance(target, dict)
            }
            if allowed_targets is not None
            else None
        )
        validated_peer_paths = (
            [Path(source_path) for source_path in allowed_targets if isinstance(source_path, str)]
            if allowed_targets is not None
            else []
        )
        allowed_path_set: set[str] | None = None
        if allowed_paths is not None:
            allowed_path_set = {os.path.normcase(os.path.normpath(os.path.abspath(path))) for path in allowed_paths}
        elif normalized_allowed_targets is None:
            allowed_path_set = cls._direct_hf_shard_allowed_paths(Path(file_path))

        for pattern in cls.SHARD_PATTERNS:
            match = re.fullmatch(pattern, file_name)
            if match:
                # Found a sharded model
                shard_info: dict[str, Any] = {"pattern": pattern, "current_file": file_path, "shards": []}
                expected_totals: set[int] = set()
                present_indices: set[int] = set()
                unreadable_shards: list[str] = []
                out_of_scope_shards: list[str] = []
                unvalidated_shards: list[str] = []
                duplicate_shards: list[str] = []
                shard_targets: dict[str, dict[str, int | str]] = {}
                seen_target_identities: set[tuple[int | str, ...]] = set()
                total_size = 0
                requested_expected_total: int | None = None
                if (match.lastindex or 0) >= 2:
                    with suppress(IndexError, ValueError):
                        requested_expected_total = int(match.group(2))
                        expected_totals.add(requested_expected_total)
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
                            _normalized_absolute_path(file_path) in index_inventory.expected_source_paths
                        )

                # Collect local siblings and caller-snapshotted peers; validated index targets are added below.
                candidate_paths: dict[str, Path] = {}
                for candidate in (Path(file_path), *dir_path.glob("*"), *validated_peer_paths):
                    normalized_candidate = os.path.normcase(os.path.normpath(os.path.abspath(candidate)))
                    candidate_paths.setdefault(normalized_candidate, candidate)
                if index_inventory is not None and index_inventory.error is None:
                    for expected_source in index_inventory.expected_source_paths:
                        expected_path = Path(expected_source)
                        if expected_path.exists() or expected_path.is_symlink():
                            normalized_expected = os.path.normcase(os.path.normpath(os.path.abspath(expected_path)))
                            candidate_paths.setdefault(normalized_expected, expected_path)

                shard_indices: dict[str, int] = {}
                for file in sorted(candidate_paths.values(), key=str):
                    file_match = re.fullmatch(pattern, file.name)
                    if file_match:
                        candidate_expected_total: int | None = None
                        if (file_match.lastindex or 0) >= 2:
                            with suppress(IndexError, ValueError):
                                candidate_expected_total = int(file_match.group(2))
                        if (
                            requested_expected_total is not None
                            and candidate_expected_total != requested_expected_total
                        ):
                            continue
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
                        if file_match.lastindex:
                            with suppress(IndexError, ValueError):
                                shard_index = int(file_match.group(1))
                                present_indices.add(shard_index)
                                shard_indices[str(file)] = shard_index

                if not shard_info["shards"]:
                    return None

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
                    expected_source_paths = (
                        index_inventory.expected_source_paths
                        if index_inventory is not None and index_inventory.error is None
                        else None
                    )
                    for shard_path, shard_index in shard_indices.items():
                        normalized_source = os.path.normcase(os.path.normpath(os.path.abspath(shard_path)))
                        if expected_source_paths is not None and normalized_source not in expected_source_paths:
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
    if not isinstance(shard_info, dict) or shard_info.get("pattern") != SAFETENSORS_SHARD_PATTERN:
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

        with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_WORKERS, total_shards)) as executor:
            # Submit all shard scans
            future_to_shard = {
                executor.submit(copy_context().run, self._scan_single_shard, shard): shard for shard in shards
            }

            # Process results as they complete
            for future in as_completed(future_to_shard):
                shard = future_to_shard[future]
                completed_shards += 1

                try:
                    shard_result = future.result(timeout=SHARD_SCAN_TIMEOUT)
                    result.merge(shard_result)
                    success = success and bool(shard_result.success)

                    if progress_callback:
                        percentage = (completed_shards / total_shards) * 100
                        progress_callback(f"Scanned shard {completed_shards}/{total_shards}", percentage)

                except Exception as e:
                    from ...scanners._evidence_redaction import (
                        redact_evidence_string,
                        redact_untrusted_error_message,
                    )

                    safe_shard = redact_evidence_string(shard, max_chars=500)
                    safe_shard_name = redact_evidence_string(Path(shard).name, max_chars=500)
                    safe_error = redact_untrusted_error_message(e)
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
                            "exception_type": type(e).__name__,
                            "analysis_incomplete": True,
                            "scan_outcome": "inconclusive",
                            "scan_outcome_reason": "shard_scan_error",
                        },
                    )

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
                    match = re.fullmatch(pattern, Path(value).name)
                    if match is None:
                        continue
                    if isinstance(expected_total, int) and (match.lastindex or 0) >= 2:
                        with suppress(IndexError, ValueError):
                            if int(match.group(2)) != expected_total:
                                continue
                    members.add(str(Path(value).absolute()))
        return members

    def _current_family_members(self) -> set[str]:
        """Enumerate current lexical members of the detected shard family."""
        current_file = Path(self.shard_info["current_file"])
        pattern = self.shard_info["pattern"]
        expected_total = self.shard_info.get("expected_total_shards")
        members: set[str] = set()
        family_directories = {current_file.parent}
        shard_targets = self.shard_info.get("shard_targets")
        if isinstance(shard_targets, dict):
            family_directories.update(
                Path(source_path).parent for source_path in shard_targets if isinstance(source_path, str)
            )
        for family_directory in family_directories:
            for candidate in family_directory.glob("*"):
                match = re.fullmatch(pattern, candidate.name)
                if match is None:
                    continue
                if isinstance(expected_total, int) and (match.lastindex or 0) >= 2:
                    try:
                        if int(match.group(2)) != expected_total:
                            continue
                    except (IndexError, ValueError):
                        continue
                members.add(str(candidate.absolute()))
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
                with _pinned_shard_scan_path(scan_path, validated_target) as pinned_scan:
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
