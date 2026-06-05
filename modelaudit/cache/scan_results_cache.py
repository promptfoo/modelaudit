"""File-based scan results cache implementation."""

import hashlib
import json
import logging
import os
import stat
import struct
import sys
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO

from ..utils.helpers.secure_hasher import SecureFileHasher
from .adaptive_cache_keys import AdaptiveCacheKeyGenerator
from .optimized_config import build_cache_version_context

logger = logging.getLogger(__name__)

AncestorEntry = tuple[str, int, int, int, int, int]


class _AncestorPathMonitor:
    """Track replacements of path components without treating sibling churn as a change."""

    _EVENT_STRUCT = struct.Struct("iIII")
    _IN_ATTRIB = 0x00000004
    _IN_MOVED_FROM = 0x00000040
    _IN_MOVED_TO = 0x00000080
    _IN_CREATE = 0x00000100
    _IN_DELETE = 0x00000200
    _IN_DELETE_SELF = 0x00000400
    _IN_MOVE_SELF = 0x00000800
    _IN_UNMOUNT = 0x00002000
    _IN_Q_OVERFLOW = 0x00004000
    _IN_IGNORED = 0x00008000
    _CHILD_EVENT_MASK = _IN_ATTRIB | _IN_MOVED_FROM | _IN_MOVED_TO | _IN_CREATE | _IN_DELETE
    _SELF_EVENT_MASK = _IN_DELETE_SELF | _IN_MOVE_SELF | _IN_UNMOUNT | _IN_IGNORED
    _WATCH_MASK = _CHILD_EVENT_MASK | _SELF_EVENT_MASK

    def __init__(self, file_path: str, ancestor_identity: tuple[AncestorEntry, ...]) -> None:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add_watch = libc.inotify_add_watch
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int

        self._fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")

        self._self_watches: set[int] = set()
        self._child_names: dict[int, set[str]] = {}
        watched_paths: dict[str, int] = {}

        def watch(path: str) -> int:
            existing = watched_paths.get(path)
            if existing is not None:
                return existing
            descriptor = int(add_watch(self._fd, os.fsencode(path), self._WATCH_MASK))
            if descriptor < 0:
                raise OSError(ctypes.get_errno(), f"inotify_add_watch failed for {path}")
            watched_paths[path] = descriptor
            return descriptor

        try:
            direct_parent = Path(ancestor_identity[0][0])
            self._child_names.setdefault(watch(str(direct_parent)), set()).add(Path(file_path).name)
            for entry in ancestor_identity:
                ancestor = Path(entry[0])
                self._self_watches.add(watch(str(ancestor)))
                self._child_names.setdefault(watch(str(ancestor.parent)), set()).add(ancestor.name)
        except Exception:
            self.close()
            raise

    def changed(self) -> bool:
        if self._fd < 0:
            return True
        while True:
            try:
                data = os.read(self._fd, 64 * 1024)
            except BlockingIOError:
                return False
            except OSError:
                return True
            if not data:
                return True

            offset = 0
            while offset + self._EVENT_STRUCT.size <= len(data):
                descriptor, mask, _cookie, name_length = self._EVENT_STRUCT.unpack_from(data, offset)
                offset += self._EVENT_STRUCT.size
                raw_name = data[offset : offset + name_length]
                offset += name_length
                name = os.fsdecode(raw_name.split(b"\0", 1)[0])
                if mask & self._IN_Q_OVERFLOW:
                    return True
                if descriptor in self._self_watches and mask & self._SELF_EVENT_MASK:
                    return True
                if mask & self._CHILD_EVENT_MASK and name in self._child_names.get(descriptor, set()):
                    return True

    def close(self) -> None:
        if getattr(self, "_fd", -1) >= 0:
            with suppress(OSError):
                os.close(self._fd)
            self._fd = -1

    def __del__(self) -> None:
        self.close()


class _WindowsPathLockMonitor:
    """Prevent file and ancestor replacement while a Windows scan is in flight."""

    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    def __init__(self, file_path: str, ancestor_identity: tuple[AncestorEntry, ...]) -> None:
        import ctypes

        kernel32 = vars(ctypes)["WinDLL"]("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int

        self._close_handle = close_handle
        self._handles: list[int] = []
        invalid_handle = ctypes.c_void_p(-1).value
        paths = [file_path, *(entry[0] for entry in ancestor_identity)]
        try:
            for path in dict.fromkeys(paths):
                handle = create_file(
                    os.path.abspath(path),
                    0,
                    self._FILE_SHARE_READ | self._FILE_SHARE_WRITE,
                    None,
                    self._OPEN_EXISTING,
                    self._FILE_FLAG_BACKUP_SEMANTICS,
                    None,
                )
                if handle in {None, invalid_handle}:
                    raise OSError(vars(ctypes)["get_last_error"](), f"CreateFileW failed for {path}")
                self._handles.append(int(handle))
        except Exception:
            self.close()
            raise

    def changed(self) -> bool:
        return False

    def close(self) -> None:
        for handle in getattr(self, "_handles", []):
            with suppress(OSError):
                self._close_handle(handle)
        self._handles = []

    def __del__(self) -> None:
        self.close()


class AncestorIdentity(tuple[AncestorEntry, ...]):
    monitor: _AncestorPathMonitor | _WindowsPathLockMonitor | None

    def __new__(
        cls,
        entries: tuple[AncestorEntry, ...] | list[AncestorEntry],
        monitor: _AncestorPathMonitor | _WindowsPathLockMonitor | None = None,
    ) -> "AncestorIdentity":
        identity = super().__new__(cls, entries)
        identity.monitor = monitor
        return identity


ScannedFileIdentity = tuple[os.stat_result, str, int, AncestorIdentity]

_MAX_CHANGE_CLOCK_ADVANCE_WAIT_SECONDS = 2.1
_MAX_IDENTITY_BARRIER_ATTEMPTS = 3


def _is_sampled_fingerprint(value: object) -> bool:
    """Return whether a stored hash represents sampled, incomplete file content."""
    return isinstance(value, str) and value.startswith("fingerprint:")


@dataclass
class CacheEntry:
    """Data class for cache entries."""

    cache_key: str
    file_info: dict[str, Any]
    version_info: dict[str, Any]
    scan_result: dict[str, Any]
    cache_metadata: dict[str, Any]


class ScanResultsCache:
    """
    File-based scan results cache using content hash + version for cache keys.

    Cache structure:
    ~/.modelaudit/cache/scan_results/
    ├── cache_metadata.json
    ├── ab/cd/abcd...ef.json  (hash-based file storage)
    └── xy/zw/xyzw...gh.json
    """

    def __init__(self, cache_dir: str | None = None):
        """
        Initialize the scan results cache.

        Args:
            cache_dir: Optional cache directory path. Defaults to ~/.modelaudit/cache/scan_results
        """
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "cache" / "scan_results")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.hasher = SecureFileHasher()
        self.key_generator = AdaptiveCacheKeyGenerator()
        self._change_clock_probes: dict[int, tuple[BinaryIO, Path]] = {}
        self._change_clock_probe_lock = threading.Lock()

        self._ensure_metadata_exists()

    def get_cached_result(
        self,
        file_path: str,
        version_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Get cached scan result if available and valid with optimized file system calls.

        Args:
            file_path: Path to file to check cache for

        Returns:
            Cached scan result dictionary if found and valid, None otherwise
        """
        cached_result, file_identity = self.get_cached_result_with_identity(
            file_path,
            version_context=version_context,
        )
        if file_identity is not None:
            self.release_ancestor_identity(file_identity[-1])
        return cached_result

    def get_cached_result_with_stat(
        self,
        file_path: str,
        file_stat: os.stat_result,
        version_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Get a cached scan result while reusing an existing stat result.

        Args:
            file_path: Path to file to check cache for
            file_stat: Pre-computed os.stat_result to reuse
            version_context: Optional cache version context for config-sensitive invalidation

        Returns:
            Cached scan result dictionary if found and valid, None otherwise
        """
        cached_result, file_identity = self.get_cached_result_with_identity(
            file_path,
            version_context=version_context,
        )
        if file_identity is not None:
            self.release_ancestor_identity(file_identity[-1])
        return cached_result

    def get_cached_result_with_identity(
        self,
        file_path: str,
        version_context: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, ScannedFileIdentity | None]:
        """Return a cache lookup plus the monitored identity reusable by a miss scan."""
        file_identity: ScannedFileIdentity | None = None
        try:
            if self._path_has_symlink_component(file_path):
                logger.debug("Bypassing scan-result cache lookup for symlinked path %s", file_path)
                return None, None

            file_identity = self.capture_file_identity(file_path)
            file_stat, file_hash, _change_token, _ancestor_identity = file_identity
            cache_key, _content_hash = self._generate_cache_key_material(
                file_path,
                file_stat=file_stat,
                version_context=version_context,
                content_hash=file_hash,
            )
            if not cache_key:
                return None, file_identity

            cache_file_path = self._get_cache_file_path(cache_key)
            if not cache_file_path.exists():
                self._record_cache_miss("not_found")
                return None, file_identity

            with open(cache_file_path, encoding="utf-8") as f:
                cache_entry = json.load(f)

            if not self._is_cache_entry_valid_with_stat(
                cache_entry,
                file_path,
                file_stat,
                verified_content_hash=file_hash,
            ):
                cache_file_path.unlink()
                self._record_cache_miss("invalid")
                return None, file_identity

            cache_entry["cache_metadata"]["access_count"] += 1
            cache_entry["cache_metadata"]["last_access"] = time.time()

            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)

            if not self._file_identity_matches(file_path, file_identity):
                self._record_cache_miss("changed")
                return None, file_identity

            self._record_cache_hit()
            logger.debug(f"Cache hit for {os.path.basename(file_path)}")
            return cache_entry["scan_result"], file_identity

        except Exception as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            self._record_cache_miss("error")
            return None, file_identity

    def get_cached_result_by_key(
        self,
        cache_key: str,
        *,
        file_path: str | None = None,
        file_stat: os.stat_result | None = None,
    ) -> dict[str, Any] | None:
        """
        Get cached scan result by pre-generated cache key (for performance optimization).

        Args:
            cache_key: Pre-generated cache key

        Returns:
            Cached scan result dictionary if found, None otherwise
        """
        file_identity: ScannedFileIdentity | None = None
        try:
            if file_path is not None:
                if self._path_has_symlink_component(file_path):
                    logger.debug("Bypassing scan-result cache lookup for symlinked path %s", file_path)
                    return None
                if not self._get_cache_file_path(cache_key).exists():
                    self._record_cache_miss("not_found")
                    return None
                file_identity = self.capture_file_identity(file_path)
                file_stat = file_identity[0]
            return self._get_cached_result_by_key(
                cache_key,
                file_path=file_path,
                file_stat=file_stat,
                verified_content_hash=file_identity[1] if file_identity is not None else None,
                expected_file_identity=file_identity,
            )
        except Exception as e:
            logger.debug(f"Cache lookup failed for key {cache_key[:8]}...: {e}")
            self._record_cache_miss("error")
            return None
        finally:
            if file_identity is not None:
                self.release_ancestor_identity(file_identity[-1])

    def _get_cached_result_by_key(
        self,
        cache_key: str,
        file_path: str | None = None,
        file_stat: os.stat_result | None = None,
        verified_content_hash: str | None = None,
        expected_file_identity: ScannedFileIdentity | None = None,
    ) -> dict[str, Any] | None:
        """Get a cached result using a precomputed key, optionally validating with caller-provided stat data."""
        try:
            if file_path is not None and self._path_has_symlink_component(file_path):
                logger.debug("Bypassing scan-result cache lookup for symlinked path %s", file_path)
                return None

            cache_file_path = self._get_cache_file_path(cache_key)

            if not cache_file_path.exists():
                self._record_cache_miss("not_found")
                return None

            # Load cache entry
            with open(cache_file_path, encoding="utf-8") as f:
                cache_entry = json.load(f)

            if _is_sampled_fingerprint(cache_entry.get("file_info", {}).get("hash")):
                cache_file_path.unlink()
                self._record_cache_miss("invalid")
                return None

            if (
                file_path is not None
                and file_stat is not None
                and not self._is_cache_entry_valid_with_stat(
                    cache_entry,
                    file_path,
                    file_stat,
                    verified_content_hash=verified_content_hash,
                )
            ):
                cache_file_path.unlink()
                self._record_cache_miss("invalid")
                return None

            # Update access statistics
            cache_entry["cache_metadata"]["access_count"] += 1
            cache_entry["cache_metadata"]["last_access"] = time.time()

            # Write back updated entry (async write would be better but adds complexity)
            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)

            if (
                file_path is not None
                and expected_file_identity is not None
                and not self._file_identity_matches(file_path, expected_file_identity)
            ):
                self._record_cache_miss("changed")
                return None

            self._record_cache_hit()
            logger.debug(f"Cache hit for key {cache_key[:8]}...")
            return cache_entry["scan_result"]  # type: ignore[no-any-return]

        except Exception as e:
            logger.debug(f"Cache lookup failed for key {cache_key[:8]}...: {e}")
            self._record_cache_miss("error")
            return None

    def store_result(
        self,
        file_path: str,
        scan_result: dict[str, Any],
        scan_duration_ms: int | None = None,
        version_context: dict[str, Any] | None = None,
        expected_file_stat: os.stat_result | None = None,
        expected_file_hash: str | None = None,
        expected_change_token: int | None = None,
        expected_ancestor_identity: AncestorIdentity | None = None,
    ) -> bool:
        """
        Store scan result in cache with optimized file system calls.

        Args:
            file_path: Path to file that was scanned
            scan_result: Scan result dictionary to cache
            scan_duration_ms: Optional scan duration in milliseconds
            version_context: Optional cache version context for config-sensitive invalidation
            expected_file_stat: File metadata captured before the scan
            expected_file_hash: Secure content hash captured before the scan
            expected_change_token: Platform-specific modification token captured before the scan
            expected_ancestor_identity: Ancestor directory identities captured before the scan
        Returns:
            True when a cache entry was persisted, False when storage was skipped or failed.
        """
        temporary_cache_path: Path | None = None
        try:
            if self._path_has_symlink_component(file_path):
                logger.debug("Skipping cache store for symlinked path %s", file_path)
                return False
            if (
                expected_file_stat is None
                or expected_file_hash is None
                or expected_change_token is None
                or expected_ancestor_identity is None
            ):
                logger.debug("Skipping cache store for %s: missing expected file identity", file_path)
                return False

            # Get file stats ONCE and reuse
            file_stat = os.stat(file_path)
            verified_current_hash: str | None = None
            if not self._stat_matches(file_stat, expected_file_stat):
                logger.debug("Skipping cache store for %s: file metadata changed during scan", file_path)
                return False
            if self._get_file_change_token(file_path, file_stat) != expected_change_token:
                logger.debug("Skipping cache store for %s: file change token changed during scan", file_path)
                return False
            if self._ancestor_monitor_changed(
                expected_ancestor_identity
            ) or not self._ancestor_identity_matches_for_store(
                expected_ancestor_identity,
                self._capture_ancestor_identity(file_path),
            ):
                logger.debug("Skipping cache store for %s: ancestor path changed during scan", file_path)
                return False

            verified_current_hash = self.hasher.hash_file_with_stat(file_path, file_stat)
            if verified_current_hash != expected_file_hash:
                logger.debug("Skipping cache store for %s: file hash changed during scan", file_path)
                return False
            post_hash_stat = os.stat(file_path)
            if not self._stat_matches(post_hash_stat, expected_file_stat):
                logger.debug("Skipping cache store for %s: file metadata changed during verification", file_path)
                return False
            if self._get_file_change_token(file_path, post_hash_stat) != expected_change_token:
                logger.debug("Skipping cache store for %s: file changed during verification", file_path)
                return False
            if self._ancestor_monitor_changed(
                expected_ancestor_identity
            ) or not self._ancestor_identity_matches_for_store(
                expected_ancestor_identity,
                self._capture_ancestor_identity(file_path),
            ):
                logger.debug("Skipping cache store for %s: ancestor path changed during verification", file_path)
                return False
            file_stat = post_hash_stat

            version_info = self._get_version_info(version_context)
            if version_info is None:
                return False

            # Pass file_stat to avoid redundant calls
            cache_key, content_hash = self._generate_cache_key_material(
                file_path,
                file_stat=file_stat,
                version_context=version_context,
                version_info=version_info,
                content_hash=verified_current_hash,
            )
            if not cache_key:
                return False

            # Large-file cache keys already require this exact secure content hash.
            file_hash = content_hash or verified_current_hash or self.hasher.hash_file_with_stat(file_path, file_stat)
            mtime_ns = getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1_000_000_000))

            cache_entry = CacheEntry(
                cache_key=cache_key,
                file_info={
                    "hash": file_hash,
                    "size": file_stat.st_size,
                    "original_name": os.path.basename(file_path),
                    "mtime": file_stat.st_mtime,
                    "mtime_ns": mtime_ns,
                },
                version_info=version_info,
                scan_result=scan_result,
                cache_metadata={
                    "scanned_at": time.time(),
                    "last_access": time.time(),
                    "access_count": 1,
                    "scan_duration_ms": scan_duration_ms,
                    "file_format": self._detect_file_format(file_path),
                },
            )

            # Serialize privately so readers cannot observe an entry before the
            # final source-identity verification succeeds.
            cache_file_path = self._get_cache_file_path(cache_key)
            cache_file_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=cache_file_path.parent,
                prefix=f".{cache_file_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as f:
                temporary_cache_path = Path(f.name)
                json.dump(asdict(cache_entry), f, indent=2)

            final_stat = os.stat(file_path)
            if (
                not self._stat_matches(final_stat, expected_file_stat)
                or self._get_file_change_token(file_path, final_stat) != expected_change_token
                or self._ancestor_monitor_changed(expected_ancestor_identity)
                or not self._ancestor_identity_matches_for_store(
                    expected_ancestor_identity,
                    self._capture_ancestor_identity(file_path),
                )
            ):
                logger.debug("Discarding cache store for %s: path changed during persistence", file_path)
                return False

            assert temporary_cache_path is not None
            os.replace(temporary_cache_path, cache_file_path)
            temporary_cache_path = None

            logger.debug(f"Cached scan result for {os.path.basename(file_path)}")
            return True

        except Exception as e:
            logger.debug(f"Failed to cache result for {file_path}: {e}")
            return False
        finally:
            if temporary_cache_path is not None:
                temporary_cache_path.unlink(missing_ok=True)
            self.release_ancestor_identity(expected_ancestor_identity)

    def capture_file_identity(self, file_path: str) -> ScannedFileIdentity:
        """Capture a stable stat, content hash, and platform change token before scanning."""
        if self._path_has_symlink_component(file_path):
            raise ValueError(f"Symlinked paths are not cacheable: {file_path}")

        preliminary_stat = os.stat(file_path)
        probe = self._get_change_clock_probe(file_path, preliminary_stat.st_dev)
        preliminary_change_token = self._get_file_change_token(file_path, preliminary_stat)
        preliminary_ancestor_identity = self._capture_ancestor_identity(file_path)

        for _attempt in range(_MAX_IDENTITY_BARRIER_ATTEMPTS):
            barrier_token = self._advance_change_clock(
                file_path,
                probe,
                preliminary_change_token,
                preliminary_ancestor_identity,
            )
            if self._path_has_symlink_component(file_path):
                raise ValueError(f"Symlinked paths are not cacheable: {file_path}")
            initial_stat = os.stat(file_path)
            initial_change_token = self._get_file_change_token(file_path, initial_stat)
            initial_ancestor_identity = self._capture_ancestor_identity(file_path)
            newest_initial_token = self._newest_identity_change_token(
                initial_change_token,
                initial_ancestor_identity,
            )
            if newest_initial_token < barrier_token:
                break
            preliminary_change_token = initial_change_token
            preliminary_ancestor_identity = initial_ancestor_identity
        else:
            raise ValueError(f"File kept changing while capturing cache identity: {file_path}")

        monitored_ancestor_identity = self._monitor_ancestor_identity(file_path, initial_ancestor_identity)
        try:
            monitored_stat = os.stat(file_path)
            if (
                not self._stat_matches(initial_stat, monitored_stat)
                or initial_change_token != self._get_file_change_token(file_path, monitored_stat)
                or not self._ancestor_identity_matches(
                    initial_ancestor_identity,
                    self._capture_ancestor_identity(file_path),
                )
            ):
                raise ValueError(f"File changed while starting cache identity monitor: {file_path}")

            content_hash = self.hasher.hash_file_with_stat(file_path, initial_stat)
            verified_stat = os.stat(file_path)
            verified_change_token = self._get_file_change_token(file_path, verified_stat)
            verified_ancestor_identity = self._capture_ancestor_identity(file_path)

            if (
                not self._stat_matches(initial_stat, verified_stat)
                or initial_change_token != verified_change_token
                or self._ancestor_monitor_changed(monitored_ancestor_identity)
                or not self._ancestor_identity_matches_for_store(
                    monitored_ancestor_identity,
                    verified_ancestor_identity,
                )
            ):
                raise ValueError(f"File changed while capturing cache identity: {file_path}")

            return verified_stat, content_hash, verified_change_token, monitored_ancestor_identity
        except Exception:
            self.release_ancestor_identity(monitored_ancestor_identity)
            raise

    def _get_change_clock_probe(self, file_path: str, file_device: int) -> BinaryIO:
        """Return a reusable probe whose inode lives on the scanned file's filesystem."""
        with self._change_clock_probe_lock:
            existing = self._change_clock_probes.get(file_device)
            if existing is not None:
                return existing[0]

            if os.name == "nt":
                candidates = [Path(tempfile.gettempdir())]
            else:
                candidates = [self.cache_dir, Path(tempfile.gettempdir())]
            ancestor = Path(os.path.abspath(file_path)).parent
            while True:
                candidates.append(ancestor)
                if ancestor.parent == ancestor:
                    break
                ancestor = ancestor.parent
            if os.name == "nt":
                candidates.append(self.cache_dir)

            checked: set[Path] = set()
            for candidate in candidates:
                if candidate in checked:
                    continue
                checked.add(candidate)
                if not self._directory_is_on_device(candidate, file_device):
                    continue

                probe: BinaryIO | None = None
                try:
                    # Keep the probe open so nested captures do not mutate ancestor directories.
                    probe = tempfile.TemporaryFile(  # noqa: SIM115
                        mode="w+b",
                        prefix=".modelaudit-cache-clock-",
                        dir=candidate,
                    )
                    if os.fstat(probe.fileno()).st_dev != file_device:
                        probe.close()
                        continue
                    self._change_clock_probes[file_device] = (probe, candidate)
                    return probe
                except OSError:
                    if probe is not None:
                        with suppress(OSError):
                            probe.close()

        raise ValueError(f"No writable cache identity probe directory for: {file_path}")

    @staticmethod
    def _directory_is_on_device(directory: Path, device: int) -> bool:
        try:
            return directory.is_dir() and directory.stat().st_dev == device
        except OSError:
            return False

    def _advance_change_clock(
        self,
        file_path: str,
        probe: BinaryIO,
        file_change_token: int,
        ancestor_identity: AncestorIdentity,
    ) -> int:
        """Advance the filesystem change clock past the captured identity or decline caching."""
        file_stat = os.stat(file_path)
        if os.fstat(probe.fileno()).st_dev != file_stat.st_dev:
            raise ValueError(f"Cache identity probe is on a different filesystem: {file_path}")

        newest_captured_token = self._newest_identity_change_token(
            file_change_token,
            ancestor_identity,
        )

        deadline = time.monotonic() + _MAX_CHANGE_CLOCK_ADVANCE_WAIT_SECONDS
        while time.monotonic() < deadline:
            probe_token = self._touch_change_clock_probe(probe)
            if probe_token > newest_captured_token:
                return probe_token
            time.sleep(0.001)

        raise ValueError(f"Filesystem change clock did not advance for cache identity: {file_path}")

    @staticmethod
    def _newest_identity_change_token(
        file_change_token: int,
        ancestor_identity: AncestorIdentity,
    ) -> int:
        captured_tokens = [file_change_token]
        if os.name != "nt":
            captured_tokens.extend(entry[-1] for entry in ancestor_identity)
        return max(captured_tokens)

    def _touch_change_clock_probe(self, probe: BinaryIO) -> int:
        if os.name != "nt":
            os.utime(probe.fileno(), None)
            probe_stat = os.fstat(probe.fileno())
            return self._get_file_change_token("", probe_stat)

        import msvcrt

        probe.seek(0)
        probe.truncate(0)
        probe.write(b"\0")
        probe.flush()
        os.fsync(probe.fileno())
        msvcrt_windows: Any = msvcrt
        return self._get_windows_handle_change_token(msvcrt_windows.get_osfhandle(probe.fileno()))

    def _capture_ancestor_identity(self, file_path: str) -> AncestorIdentity:
        """Capture lexical ancestors, including a change token for the direct parent."""
        file_device = os.stat(file_path).st_dev
        ancestor = Path(os.path.abspath(file_path)).parent
        identity: list[AncestorEntry] = []
        direct_parent = True
        while True:
            ancestor_path = str(ancestor)
            if ancestor.is_symlink():
                raise ValueError(f"Symlink ancestors are not cacheable: {ancestor_path}")
            ancestor_stat = os.stat(ancestor_path)
            if ancestor_stat.st_dev != file_device:
                break
            parent_on_same_device = ancestor.parent != ancestor and os.stat(ancestor.parent).st_dev == file_device
            if not direct_parent and not parent_on_same_device:
                break
            identity.append(
                (
                    ancestor_path,
                    ancestor_stat.st_dev,
                    ancestor_stat.st_ino,
                    ancestor_stat.st_mode,
                    getattr(
                        ancestor_stat,
                        "st_mtime_ns",
                        int(ancestor_stat.st_mtime * 1_000_000_000),
                    ),
                    self._get_file_change_token(ancestor_path, ancestor_stat),
                )
            )
            if not parent_on_same_device:
                break
            direct_parent = False
            ancestor = ancestor.parent
        return AncestorIdentity(identity)

    @staticmethod
    def _ancestor_identity_matches(expected: AncestorIdentity, current: AncestorIdentity) -> bool:
        return len(expected) == len(current) and all(
            expected_entry == current_entry for expected_entry, current_entry in zip(expected, current, strict=True)
        )

    @staticmethod
    def _ancestor_identity_matches_for_store(expected: AncestorIdentity, current: AncestorIdentity) -> bool:
        if expected.monitor is None:
            return ScanResultsCache._ancestor_identity_matches(expected, current)
        return len(expected) == len(current) and all(
            expected_entry[:4] == current_entry[:4]
            for expected_entry, current_entry in zip(expected, current, strict=True)
        )

    @staticmethod
    def _ancestor_monitor_changed(identity: AncestorIdentity) -> bool:
        return identity.monitor is not None and identity.monitor.changed()

    def _file_identity_matches(self, file_path: str, expected: ScannedFileIdentity) -> bool:
        expected_stat, _expected_hash, expected_change_token, expected_ancestor_identity = expected
        try:
            current_stat = os.stat(file_path)
            return (
                self._stat_matches(current_stat, expected_stat)
                and self._get_file_change_token(file_path, current_stat) == expected_change_token
                and not self._ancestor_monitor_changed(expected_ancestor_identity)
                and self._ancestor_identity_matches_for_store(
                    expected_ancestor_identity,
                    self._capture_ancestor_identity(file_path),
                )
            )
        except (OSError, ValueError):
            return False

    @staticmethod
    def release_ancestor_identity(identity: AncestorIdentity | None) -> None:
        if identity is not None and identity.monitor is not None:
            identity.monitor.close()

    @staticmethod
    def _monitor_ancestor_identity(file_path: str, identity: AncestorIdentity) -> AncestorIdentity:
        if not identity:
            return identity
        try:
            monitor: _AncestorPathMonitor | _WindowsPathLockMonitor | None = None
            platform_name = getattr(sys, "platform", "")
            if platform_name.startswith("linux"):
                monitor = _AncestorPathMonitor(
                    file_path,
                    tuple(identity),
                )
            elif platform_name == "win32":
                monitor = _WindowsPathLockMonitor(file_path, tuple(identity))
            if monitor is None:
                return identity
            return AncestorIdentity(tuple(identity), monitor)
        except (AttributeError, OSError):
            return identity

    @staticmethod
    def _path_has_symlink_component(file_path: str) -> bool:
        path = Path(file_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        current = Path(path.anchor)
        for component in path.parts[1:]:
            if component in {"", "."}:
                continue
            if component == "..":
                current = current.parent
                continue
            current /= component
            component_stat = os.lstat(current)
            if stat.S_ISLNK(component_stat.st_mode) or getattr(component_stat, "st_file_attributes", 0) & 0x400:
                return True
        return False

    @staticmethod
    def _get_file_change_token(file_path: str, file_stat: os.stat_result) -> int:
        """Return a modification generation that changes even when mtime is restored."""
        if os.name != "nt":
            return getattr(file_stat, "st_ctime_ns", int(file_stat.st_ctime * 1_000_000_000))

        import ctypes
        from ctypes import wintypes

        win_dll = ctypes.WinDLL  # type: ignore[attr-defined]
        get_last_error = ctypes.get_last_error  # type: ignore[attr-defined]
        win_error = ctypes.WinError  # type: ignore[attr-defined]
        kernel32 = win_dll("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateFileW(
            file_path,
            0x0080,
            0x0001 | 0x0002 | 0x0004,
            None,
            3,
            0x02000000,
            None,
        )
        if handle == wintypes.HANDLE(-1).value:
            raise win_error(get_last_error())

        try:
            return ScanResultsCache._get_windows_handle_change_token(handle)
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _get_windows_handle_change_token(handle: int) -> int:
        import ctypes
        from ctypes import wintypes

        class FileBasicInfo(ctypes.Structure):
            _fields_ = [
                ("creation_time", ctypes.c_longlong),
                ("last_access_time", ctypes.c_longlong),
                ("last_write_time", ctypes.c_longlong),
                ("change_time", ctypes.c_longlong),
                ("file_attributes", wintypes.DWORD),
            ]

        win_dll = ctypes.WinDLL  # type: ignore[attr-defined]
        get_last_error = ctypes.get_last_error  # type: ignore[attr-defined]
        win_error = ctypes.WinError  # type: ignore[attr-defined]
        kernel32 = win_dll("kernel32", use_last_error=True)
        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL

        basic_info = FileBasicInfo()
        if not kernel32.GetFileInformationByHandleEx(
            handle,
            0,
            ctypes.byref(basic_info),
            ctypes.sizeof(basic_info),
        ):
            raise win_error(get_last_error())
        return int(basic_info.change_time)

    @staticmethod
    def _stat_matches(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_mode == right.st_mode
            and left.st_size == right.st_size
            and getattr(left, "st_mtime_ns", int(left.st_mtime * 1_000_000_000))
            == getattr(right, "st_mtime_ns", int(right.st_mtime * 1_000_000_000))
            and getattr(left, "st_ctime_ns", int(left.st_ctime * 1_000_000_000))
            == getattr(right, "st_ctime_ns", int(right.st_ctime * 1_000_000_000))
        )

    def generate_cache_key(
        self,
        file_path: str,
        file_stat: os.stat_result | None = None,
        version_context: dict[str, Any] | None = None,
        version_info: dict[str, Any] | None = None,
    ) -> str | None:
        """Public wrapper for cache key generation used by higher-level cache callers."""
        return self._generate_cache_key(
            file_path,
            file_stat=file_stat,
            version_context=version_context,
            version_info=version_info,
        )

    def _generate_cache_key(
        self,
        file_path: str,
        file_stat: os.stat_result | None = None,
        version_context: dict[str, Any] | None = None,
        version_info: dict[str, Any] | None = None,
    ) -> str | None:
        """
        Generate cache key from file hash and version info.

        Args:
            file_path: Path to file
            file_stat: Optional pre-computed os.stat_result to avoid redundant calls

        Returns:
            Cache key string or None if generation failed
        """
        cache_key, _content_hash = self._generate_cache_key_material(
            file_path,
            file_stat=file_stat,
            version_context=version_context,
            version_info=version_info,
        )
        return cache_key

    def _generate_cache_key_material(
        self,
        file_path: str,
        file_stat: os.stat_result | None = None,
        version_context: dict[str, Any] | None = None,
        version_info: dict[str, Any] | None = None,
        content_hash: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Generate a cache key and surface any secure content hash already computed for it."""
        try:
            if self._path_has_symlink_component(file_path):
                logger.debug("Skipping scan-result cache key for symlinked path %s", file_path)
                return None, None

            if file_stat is None:
                file_stat = os.stat(file_path)

            file_key, content_hash = self.key_generator.generate_key_material_with_stat_reuse(
                file_path,
                file_stat,
                content_hash=content_hash,
            )
            if _is_sampled_fingerprint(content_hash):
                logger.debug(
                    "Skipping scan-result cache key for %s: sampled large-file fingerprints are not cacheable",
                    file_path,
                )
                return None, None

            resolved_version_info = (
                version_info if version_info is not None else self._get_version_info(version_context)
            )
            if resolved_version_info is None:
                return None, None

            # Create version fingerprint
            version_str = json.dumps(resolved_version_info, sort_keys=True)
            version_hash = hashlib.blake2b(version_str.encode(), digest_size=16).hexdigest()

            # Combine file hash with version hash
            # Remove any prefix from file hash for key generation
            clean_file_key = file_key.split(":")[-1]
            cache_key = f"{clean_file_key}_{version_hash}"

            return cache_key, content_hash

        except Exception as e:
            logger.debug(f"Failed to generate cache key for {file_path}: {e}")
            return None, None

    def _get_cache_file_path(self, cache_key: str) -> Path:
        """
        Get file system path for cache key using hash-based directory structure.

        Args:
            cache_key: Cache key string

        Returns:
            Path to cache file
        """
        # Create nested directory structure: ab/cd/cache_key.json
        # This prevents too many files in a single directory
        return self.cache_dir / cache_key[:2] / cache_key[2:4] / f"{cache_key}.json"

    def _get_version_info(self, version_context: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Get current version information for cache invalidation.

        Returns None when a material component cannot be resolved, signalling
        that caching must be skipped to avoid key collisions.
        """
        try:
            from modelaudit import __version__ as modelaudit_version
        except ImportError:
            modelaudit_version = "dev"
        except Exception as e:
            logger.debug(f"Failed to resolve modelaudit version: {e}")
            modelaudit_version = "unknown"

        try:
            config_hash = self._get_config_hash(version_context)
        except Exception as e:
            logger.debug(f"Failed to compute cache config hash, disabling cache for this key: {e}")
            return None

        try:
            scanner_versions = self._get_scanner_versions()
        except Exception as e:
            logger.debug(f"Failed to resolve scanner versions, disabling cache for this key: {e}")
            return None

        return {
            "modelaudit_version": modelaudit_version,
            "scanner_versions": scanner_versions,
            "config_hash": config_hash,
        }

    def _get_scanner_versions(self) -> dict[str, str]:
        """Get version fingerprint for all scanners."""
        from modelaudit.scanners import _registry

        versions = {}
        for scanner_id in sorted(_registry.get_available_scanners()):
            info = _registry.get_scanner_info(scanner_id) or {}
            versions[scanner_id] = str(info.get("version", "1.0"))

        return versions

    def _get_config_hash(self, version_context: dict[str, Any] | None = None) -> str:
        """Hash of current scanning configuration that affects results."""
        config_data = version_context or build_cache_version_context()

        config_str = json.dumps(config_data, sort_keys=True)
        return hashlib.blake2b(config_str.encode(), digest_size=8).hexdigest()

    def _is_cache_entry_valid(self, cache_entry: dict[str, Any], file_path: str) -> bool:
        """
        Validate that cache entry is still valid.

        Args:
            cache_entry: Cache entry dictionary
            file_path: Current file path

        Returns:
            True if entry is valid, False otherwise
        """
        current_stat = os.stat(file_path)
        return self._is_cache_entry_valid_with_stat(cache_entry, file_path, current_stat)

    def _is_cache_entry_valid_with_stat(
        self,
        cache_entry: dict[str, Any],
        file_path: str,
        file_stat: os.stat_result,
        verified_content_hash: str | None = None,
    ) -> bool:
        """
        Validate that cache entry is still valid with stat reuse.

        Args:
            cache_entry: Cache entry dictionary
            file_path: Current file path
            file_stat: Pre-computed os.stat_result

        Returns:
            True if entry is valid, False otherwise
        """
        try:
            # Check file hasn't changed
            cached_mtime_ns = cache_entry["file_info"].get("mtime_ns")
            cached_size = cache_entry["file_info"]["size"]
            current_mtime_ns = getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1_000_000_000))

            if cached_mtime_ns is None:
                cached_mtime_ns = int(float(cache_entry["file_info"]["mtime"]) * 1_000_000_000)

            if int(cached_mtime_ns) != current_mtime_ns:
                return False

            # Check file size
            if file_stat.st_size != cached_size:
                return False

            cached_hash = cache_entry["file_info"].get("hash")
            if verified_content_hash is not None:
                if cached_hash != verified_content_hash:
                    return False
            # Metadata-only cache keys must still validate file contents, or an
            # in-place rewrite that restores size/mtime can hit stale entries.
            elif not self.key_generator._should_use_content_hash(file_stat.st_size) and cached_hash is not None:
                current_hash = self.hasher.hash_file_with_stat(file_path, file_stat)
                if current_hash != cached_hash:
                    return False

            # Check entry isn't too old (30 days default)
            scanned_at = cache_entry["cache_metadata"]["scanned_at"]
            age_days = (time.time() - scanned_at) / (24 * 60 * 60)

            return not age_days > 30

        except Exception:
            return False

    def _detect_file_format(self, file_path: str) -> str:
        """Detect file format for analytics."""
        extension = Path(file_path).suffix.lower()

        format_map = {
            ".pkl": "pickle",
            ".pickle": "pickle",
            ".pt": "pytorch",
            ".pth": "pytorch",
            ".bin": "pytorch",
            ".h5": "keras",
            ".keras": "keras",
            ".pb": "tensorflow",
            ".onnx": "onnx",
            ".safetensors": "safetensors",
        }

        return format_map.get(extension, "unknown")

    def cleanup_old_entries(self, max_age_days: int = 30) -> int:
        """
        Clean up old cache entries.

        Args:
            max_age_days: Maximum age in days for cache entries

        Returns:
            Number of entries removed
        """
        removed_count = 0
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)

        logger.debug(f"Cleaning cache entries older than {max_age_days} days")

        # Walk through all cache files
        for cache_file in self.cache_dir.rglob("*.json"):
            if cache_file.name == "cache_metadata.json":
                continue

            try:
                with open(cache_file, encoding="utf-8") as f:
                    cache_entry = json.load(f)

                last_access = cache_entry["cache_metadata"]["last_access"]

                if last_access < cutoff_time:
                    cache_file.unlink()
                    removed_count += 1

            except Exception as e:
                logger.debug(f"Error processing cache file {cache_file}: {e}")
                # Remove corrupted cache files
                cache_file.unlink()
                removed_count += 1

        # Clean up empty directories
        self._cleanup_empty_directories()

        logger.debug(f"Removed {removed_count} old cache entries")
        return removed_count

    def _cleanup_empty_directories(self):
        """Remove empty cache subdirectories."""
        for root, dirs, _files in os.walk(self.cache_dir, topdown=False):
            for dirname in dirs:
                dir_path = Path(root) / dirname
                try:
                    if not any(dir_path.iterdir()):
                        dir_path.rmdir()
                except OSError:
                    pass  # Directory not empty or other error

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        try:
            metadata = self._load_cache_metadata()

            # Count current entries
            total_files = len(list(self.cache_dir.rglob("*.json"))) - 1  # Exclude metadata file

            # Calculate disk usage
            total_size = sum(f.stat().st_size for f in self.cache_dir.rglob("*") if f.is_file())

            stats = metadata.get("statistics", {})
            cache_hits = stats.get("cache_hits", 0)
            cache_misses = stats.get("cache_misses", 0)

            hit_rate = cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0.0

            return {
                "total_entries": total_files,
                "total_size_mb": total_size / (1024 * 1024),
                "cache_hits": cache_hits,
                "cache_misses": cache_misses,
                "hit_rate": hit_rate,
                "avg_scan_time_ms": stats.get("avg_scan_time_ms", 0.0),
            }
        except Exception as e:
            logger.warning(f"Failed to get cache stats: {e}")
            return {
                "total_entries": 0,
                "total_size_mb": 0.0,
                "cache_hits": 0,
                "cache_misses": 0,
                "hit_rate": 0.0,
                "avg_scan_time_ms": 0.0,
            }

    def clear_cache(self) -> None:
        """Clear entire cache."""
        import shutil

        logger.debug("Clearing entire scan results cache")

        # Remove all cache files except metadata
        for item in self.cache_dir.iterdir():
            if item.name != "cache_metadata.json":
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        # Reset metadata
        self._create_initial_metadata()
        logger.debug("Cache cleared successfully")

    def _ensure_metadata_exists(self):
        """Ensure cache metadata file exists."""
        if not self.metadata_file.exists():
            self._create_initial_metadata()

    def _create_initial_metadata(self):
        """Create initial cache metadata."""
        metadata = {
            "version": "1.0",
            "created_at": time.time(),
            "last_cleanup": time.time(),
            "statistics": {"total_entries": 0, "cache_hits": 0, "cache_misses": 0, "avg_scan_time_ms": 0.0},
            "settings": {"max_entries": 100000, "max_age_days": 30, "cleanup_threshold": 0.9},
        }

        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

    def _load_cache_metadata(self) -> dict[str, Any]:
        """Load cache metadata from file."""
        try:
            with open(self.metadata_file, encoding="utf-8") as f:
                return json.load(f)  # type: ignore[no-any-return]
        except Exception:
            # Return default metadata if file can't be loaded
            return {"statistics": {"cache_hits": 0, "cache_misses": 0, "avg_scan_time_ms": 0.0}}

    def _record_cache_hit(self):
        """Record a cache hit in statistics."""
        try:
            metadata = self._load_cache_metadata()
            metadata["statistics"]["cache_hits"] += 1

            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to record cache hit: {e}")

    def _record_cache_miss(self, reason: str = "unknown") -> None:
        """Record a cache miss in statistics."""
        try:
            metadata = self._load_cache_metadata()
            metadata["statistics"]["cache_misses"] += 1

            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to record cache miss: {e}")
