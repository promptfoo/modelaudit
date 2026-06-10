"""
Advanced file handling utilities for ModelAudit.

This module provides advanced utilities for scanning large model files (400B+ parameters)
with bounded windowed I/O, sharded model support, and distributed scanning capabilities.
"""

import logging
import os
import re
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, suppress
from contextvars import copy_context
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from ..helpers.cache_decorator import (
    add_optional_dependency_availability_to_version_context,
    should_bypass_cache_for_safetensors_header_limit,
    should_bypass_cache_for_unavailable_hdf5_analysis,
    should_bypass_cache_for_zip_entry_preflight,
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

ValidatedShardTargets = dict[str, dict[str, int | str]]


class _ShardPinUnavailableError(OSError):
    """Raised when a validated shard cannot be bound to a stable scan path."""


@dataclass
class _PinnedShardScan:
    """Descriptor-bound scan path plus post-scan inode stability state."""

    path: str
    changed_during_scan: bool = False


def _validated_stat_matches_target(opened_stat: os.stat_result, target: dict[str, int | str]) -> bool:
    """Return whether an opened shard still matches its validated target snapshot."""
    expected_values = (
        ("device", opened_stat.st_dev),
        ("inode", opened_stat.st_ino),
        ("size", opened_stat.st_size),
        ("mtime_ns", opened_stat.st_mtime_ns),
        ("ctime_ns", opened_stat.st_ctime_ns),
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


@contextmanager
def _pinned_windows_shard_scan_path(
    resolved_path: str,
    target: dict[str, int | str],
) -> Iterator[_PinnedShardScan]:
    """Pin a Windows shard with open handles that prevent rename/delete replacement."""
    source_path = Path(resolved_path)
    source_fd: int | None = None
    pinned_fd: int | None = None
    staging_directory: tempfile.TemporaryDirectory[str] | None = None
    pinned_scan: _PinnedShardScan | None = None
    pinned_stat: os.stat_result | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        source_fd = os.open(source_path, flags)
        source_stat = os.fstat(source_fd)
        if not _validated_stat_matches_target(source_stat, target):
            raise _ShardPinUnavailableError("validated shard target changed before pinning")

        staging_directory = tempfile.TemporaryDirectory(
            prefix=".modelaudit_scan_",
            dir=str(source_path.parent),
        )
        pinned_path = Path(staging_directory.name) / source_path.name
        os.link(source_path, pinned_path, follow_symlinks=False)
        pinned_fd = os.open(pinned_path, flags)
        pinned_stat = os.fstat(pinned_fd)
        if not os.path.samestat(source_stat, pinned_stat):
            raise _ShardPinUnavailableError("validated shard target changed while pinning")

        pinned_scan = _PinnedShardScan(path=str(pinned_path))
        yield pinned_scan
    except _ShardPinUnavailableError:
        raise
    except OSError as error:
        if pinned_scan is not None:
            raise
        raise _ShardPinUnavailableError(str(error)) from error
    finally:
        if pinned_scan is not None and pinned_stat is not None and pinned_fd is not None:
            try:
                final_stat = os.fstat(pinned_fd)
            except OSError:
                pinned_scan.changed_during_scan = True
            else:
                identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                pinned_scan.changed_during_scan = any(
                    getattr(pinned_stat, field) != getattr(final_stat, field) for field in identity_fields
                )
        if pinned_fd is not None:
            os.close(pinned_fd)
        if staging_directory is not None:
            with suppress(OSError):
                staging_directory.cleanup()
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


def _summarize_missing_shard_indices(
    present_indices: set[int],
    expected_total: int,
) -> tuple[list[int], int, bool]:
    """Return a bounded sample, total count, and truncation flag for missing shards."""
    bounded_present_indices = {index for index in present_indices if 1 <= index <= expected_total}
    missing_count = max(expected_total - len(bounded_present_indices), 0)
    if missing_count == 0:
        return [], 0, False

    missing_indices: list[int] = []
    next_candidate = 1
    for present_index in sorted(bounded_present_indices):
        while next_candidate < present_index and len(missing_indices) < MAX_RECORDED_MISSING_SHARD_INDICES:
            missing_indices.append(next_candidate)
            next_candidate += 1
        if len(missing_indices) >= MAX_RECORDED_MISSING_SHARD_INDICES:
            break
        next_candidate = present_index + 1

    while next_candidate <= expected_total and len(missing_indices) < MAX_RECORDED_MISSING_SHARD_INDICES:
        missing_indices.append(next_candidate)
        next_candidate += 1

    return missing_indices, missing_count, missing_count > len(missing_indices)


class ShardedModelDetector:
    """Detect and handle sharded model files."""

    # Common sharding patterns for large models
    SHARD_PATTERNS: ClassVar[list[str]] = [
        r"pytorch_model-(\d+)-of-(\d+)\.bin",  # HuggingFace PyTorch sharding
        r"model-(\d+)-of-(\d+)\.safetensors",  # SafeTensors sharding
        r"model\.ckpt-(\d+)\.data-\d+-of-\d+",  # TensorFlow sharding
        r"model_weights_(\d+)\.h5",  # Keras sharding
        r"checkpoint_(\d+)\.pt",  # PyTorch checkpoint sharding
        r"params_shard_(\d+)\.bin",  # Custom parameter sharding
    ]

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

    @classmethod
    def detect_shards(
        cls,
        file_path: str,
        *,
        allowed_paths: list[str] | None = None,
        allowed_targets: ValidatedShardTargets | None = None,
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

                # Find local siblings plus any cross-directory peers that the
                # caller already resolved and snapshotted for this scan.
                candidate_paths: dict[str, Path] = {}
                for candidate in (*dir_path.glob("*"), *validated_peer_paths):
                    normalized_candidate = os.path.normcase(os.path.normpath(os.path.abspath(candidate)))
                    candidate_paths.setdefault(normalized_candidate, candidate)

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
                        if normalized_allowed_targets is not None and expected_target is None:
                            if not _is_resolved_path_within_directory(dir_path, resolved_file):
                                out_of_scope_shards.append(str(file))
                            else:
                                unvalidated_shards.append(str(file))
                            continue
                        if allowed_path_set is not None and normalized_resolved_file not in allowed_path_set:
                            if not _is_resolved_path_within_directory(dir_path, resolved_file):
                                out_of_scope_shards.append(str(file))
                            else:
                                unvalidated_shards.append(str(file))
                            continue
                        if (
                            allowed_path_set is None
                            and normalized_allowed_targets is None
                            and not _is_resolved_path_within_directory(
                                dir_path,
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
                            expected_path = expected_target.get("resolved_path")
                            expected_device = expected_target.get("device")
                            expected_inode = expected_target.get("inode")
                            if not isinstance(expected_path, str) or normalized_resolved_file != os.path.normcase(
                                os.path.normpath(expected_path)
                            ):
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
                        }
                        total_size += shard_size
                        if file_match.lastindex:
                            with suppress(IndexError, ValueError):
                                present_indices.add(int(file_match.group(1)))

                if not shard_info["shards"]:
                    return None

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
                    if present_indices:
                        missing_indices, missing_count, missing_indices_truncated = _summarize_missing_shard_indices(
                            present_indices,
                            expected_total,
                        )
                        if missing_count:
                            shard_info["missing_shard_count"] = missing_count
                            shard_info["missing_shard_indices"] = missing_indices
                            shard_info["missing_shard_indices_truncated"] = missing_indices_truncated

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
        for key in (
            "shards",
            "unreadable_shards",
            "out_of_scope_shards",
            "unvalidated_shards",
            "duplicate_shards",
        ):
            values = self.shard_info.get(key)
            if isinstance(values, list):
                members.update(str(Path(value).absolute()) for value in values if isinstance(value, str))
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
            if validated_target is None or already_pinned:
                result: ScanResult = scanner.scan(scan_path)
            else:
                with _pinned_shard_scan_path(scan_path, validated_target) as pinned_scan:
                    result = scanner.scan(pinned_scan.path)
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
        self.shard_boundary_error = _grouped_shard_boundary_error(
            file_path,
            allowed_shard_paths,
            allowed_shard_targets,
        )

        # Check for sharded model
        self.shard_info = (
            None
            if self.shard_boundary_error is not None
            else ShardedModelDetector.detect_shards(
                file_path,
                allowed_paths=allowed_shard_paths,
                allowed_targets=allowed_shard_targets,
            )
        )

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
            return self._scan_sharded_model()
        elif self.total_size > LARGE_MODEL_THRESHOLD_200GB:
            return self._scan_large_file_distributed()
        elif self.total_size > EXTREME_MODEL_THRESHOLD:
            return self._scan_with_mmap()
        else:
            # Fall back to regular large file handler
            from .large_file_handler import LargeFileHandler

            handler = LargeFileHandler(self.file_path, self.scanner, self.progress_callback, self.timeout)
            return handler.scan()

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
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unvalidated_model_shards",
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
    cache_enabled = config.get("cache_enabled", True)
    cache_dir = config.get("cache_dir")

    boundary_error = _grouped_shard_boundary_error(file_path, allowed_shard_paths, allowed_shard_targets)
    if boundary_error is not None:
        return _shard_boundary_failure_result(scanner.name, file_path, boundary_error)

    if should_bypass_cache_for_safetensors_header_limit(file_path, config):
        logger.debug(f"Bypassing advanced-file cache for bounded SafeTensors header failure: {file_path}")
        return scanner.scan(file_path)  # type: ignore[no-any-return]

    shard_info = ShardedModelDetector.detect_shards(
        file_path,
        allowed_paths=allowed_shard_paths,
        allowed_targets=allowed_shard_targets,
    )
    if shard_info is not None and not _supports_reliable_shard_cache_identity():
        logger.debug(f"Bypassing advanced-file cache for unreliable shard identities: {file_path}")
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
            allowed_shard_targets=allowed_shard_targets,
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
                )
            version_config["advanced_shard_model_config_cache_fingerprint"] = model_config_fingerprint
        if allowed_shard_paths is not None:
            # The allowlist changes shard expansion, so direct advanced scans need distinct cache keys.
            version_config["advanced_allowed_shard_paths"] = sorted(
                {str(Path(path).resolve()) for path in allowed_shard_paths}
            )
        version_context = add_optional_dependency_availability_to_version_context(
            build_cache_version_context(version_config)
        )

        # Create wrapper function for cache manager
        def cached_advanced_scan_wrapper(fpath: str) -> dict:
            result = _scan_advanced_large_file_internal(
                fpath,
                scanner,
                progress_callback,
                timeout,
                allowed_shard_paths=allowed_shard_paths,
                allowed_shard_targets=allowed_shard_targets,
            )
            current_shard_info = ShardedModelDetector.detect_shards(
                file_path,
                allowed_paths=allowed_shard_paths,
                allowed_targets=allowed_shard_targets,
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

        post_scan_shard_info = ShardedModelDetector.detect_shards(
            file_path,
            allowed_paths=allowed_shard_paths,
            allowed_targets=allowed_shard_targets,
        )
        if post_scan_shard_info != shard_info:
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
        )


def _scan_advanced_large_file_internal(
    file_path: str,
    scanner: Any,
    progress_callback: Callable[[str, float], None] | None = None,
    timeout: int = 7200,
    allowed_shard_paths: list[str] | None = None,
    allowed_shard_targets: ValidatedShardTargets | None = None,
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
    )
    return handler.scan()
