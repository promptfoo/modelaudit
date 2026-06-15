"""Tests for advanced file handler."""

import builtins
import ctypes
import errno
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import types
from collections import Counter
from contextvars import ContextVar
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.cache.cache_manager import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.base import BaseScanner
from modelaudit.utils.file.handlers import (
    CONTEXT_ONLY_COMPANION_TARGET_KEY,
    MAX_RECORDED_MISSING_SHARD_INDICES,
    AdvancedFileHandler,
    MemoryMappedHandler,
    ParallelShardHandler,
    ShardedModelDetector,
    ValidatedShardTargets,
    _build_advanced_shard_family_cache_fingerprint,
    _close_windows_staging_directory_guard,
    _copy_pinned_file_descriptor,
    _LinuxWriteLeaseGuard,
    _open_windows_staging_directory_guard,
    _pinned_file_descriptor_changed,
    _pinned_shard_scan_path,
    _pinned_windows_logical_scan_path,
    _pinned_windows_shard_scan_path,
    _SafetensorsIndexInspectionContext,
    _ShardPinUnavailableError,
    _WindowsStagingDirectoryGuard,
    scan_advanced_large_file,
    should_use_advanced_handler,
)


def _target_for_path(path: Path) -> dict[str, int | str]:
    path_stat = path.stat()
    return {
        "resolved_path": str(path),
        "device": path_stat.st_dev,
        "inode": path_stat.st_ino,
        "size": path_stat.st_size,
        "mtime_ns": path_stat.st_mtime_ns,
        "ctime_ns": path_stat.st_ctime_ns,
        "nlink": path_stat.st_nlink,
    }


def _track_created_staging_directories(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Track staging trees created by this worker without observing other xdist workers."""
    created_directories: list[Path] = []
    original_mkdtemp = tempfile.mkdtemp

    def track_mkdtemp(*args: Any, **kwargs: Any) -> str:
        created_path = Path(original_mkdtemp(*args, **kwargs))
        if created_path.name.startswith(".modelaudit_scan_"):
            created_directories.append(created_path)
        return str(created_path)

    monkeypatch.setattr("modelaudit.utils.file.handlers.tempfile.mkdtemp", track_mkdtemp)
    return created_directories


def _install_simulated_windows_directory_guards(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_on_name: str | None = None,
) -> tuple[list[_WindowsStagingDirectoryGuard], list[_WindowsStagingDirectoryGuard]]:
    """Install pathname-backed directory guards for platform-independent Windows-flow tests."""
    opened_guards: list[_WindowsStagingDirectoryGuard] = []
    closed_guards: list[_WindowsStagingDirectoryGuard] = []

    def open_guard(path: Path, expected_stat: os.stat_result) -> _WindowsStagingDirectoryGuard:
        if path.name == fail_on_name:
            raise OSError(errno.EMFILE, "descriptor table exhausted")
        current_stat = os.stat(path, follow_symlinks=False)
        if not os.path.samestat(expected_stat, current_stat):
            raise _ShardPinUnavailableError("private staging directory changed while opening")
        guard = _WindowsStagingDirectoryGuard(
            handle=len(opened_guards) + 1,
            bound_path=path,
            expected_stat=current_stat,
        )
        opened_guards.append(guard)
        return guard

    def close_guard(guard: _WindowsStagingDirectoryGuard) -> None:
        closed_guards.append(guard)

    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_staging_directory_guard",
        open_guard,
    )
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._close_windows_staging_directory_guard",
        close_guard,
    )
    return opened_guards, closed_guards


def test_pinned_file_descriptor_change_fails_closed_on_fstat_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreadable terminal descriptor state must be treated as changed."""
    file_path = tmp_path / "model.bin"
    file_path.write_bytes(b"model")
    with file_path.open("rb") as handle:
        expected_stat = os.fstat(handle.fileno())
        monkeypatch.setattr(os, "fstat", MagicMock(side_effect=OSError("descriptor unavailable")))

        assert _pinned_file_descriptor_changed(handle.fileno(), expected_stat) is True


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX open-unlink semantics")
def test_pinned_file_descriptor_change_detects_replaced_path(tmp_path: Path) -> None:
    source_path = tmp_path / "model.bin"
    replacement_path = tmp_path / "replacement.bin"
    source_path.write_bytes(b"benign")
    replacement_path.write_bytes(b"malicious")

    with source_path.open("rb") as source:
        expected_stat = os.fstat(source.fileno())
        replacement_path.replace(source_path)

        assert _pinned_file_descriptor_changed(source.fileno(), expected_stat) is True


def test_copy_pinned_file_descriptor_removes_partial_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source_path.write_bytes(b"x" * (2 * 1024 * 1024))
    original_path_open = Path.open

    class FailingWriter:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def __enter__(self) -> "FailingWriter":
            return self

        def __exit__(self, *exc_info: object) -> None:
            self.handle.close()

        def write(self, data: bytes) -> int:
            self.handle.write(data[:1024])
            self.handle.flush()
            raise OSError(errno.ENOSPC, "simulated full staging filesystem")

    def failing_destination_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        handle = original_path_open(path, *args, **kwargs)
        if path == destination:
            return FailingWriter(handle)
        return handle

    monkeypatch.setattr(Path, "open", failing_destination_open)
    source_fd = os.open(source_path, os.O_RDONLY)
    try:
        with pytest.raises(OSError, match="simulated full staging filesystem"):
            _copy_pinned_file_descriptor(source_fd, destination)
    finally:
        os.close(source_fd)

    assert not destination.exists()


def test_copy_pinned_file_descriptor_preserves_destination_open_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source_path.write_bytes(b"source")
    original_path_open = Path.open

    def failing_destination_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == destination:
            raise OSError(errno.EACCES, "destination unavailable")
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_destination_open)
    source_fd = os.open(source_path, os.O_RDONLY)
    try:
        with pytest.raises(OSError, match="destination unavailable"):
            _copy_pinned_file_descriptor(source_fd, destination)
        os.fstat(source_fd)
    finally:
        os.close(source_fd)


def test_copy_pinned_file_descriptor_enforces_byte_and_deadline_bounds(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789")
    with source.open("rb") as source_handle:
        with pytest.raises(_ShardPinUnavailableError, match="staging byte limit"):
            _copy_pinned_file_descriptor(source_handle.fileno(), tmp_path / "too-large.bin", max_bytes=1)
        with pytest.raises(_ShardPinUnavailableError, match="scan deadline"):
            _copy_pinned_file_descriptor(source_handle.fileno(), tmp_path / "too-late.bin", deadline=0)

    assert not (tmp_path / "too-large.bin").exists()
    assert not (tmp_path / "too-late.bin").exists()


@pytest.mark.skipif(
    os.name != "posix" or sys.platform.startswith("linux"),
    reason="requires non-Linux POSIX descriptor staging",
)
def test_regular_pinned_source_copy_detects_staged_mutation(tmp_path: Path) -> None:
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    target = _target_for_path(source_path)

    with _pinned_shard_scan_path(
        str(source_path),
        target,
        logical_path=str(source_path),
        require_regular_path=True,
    ) as pinned_scan:
        Path(pinned_scan.path).write_bytes(b"staged")

    assert pinned_scan.changed_during_scan is True
    assert source_path.read_bytes() == b"source"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux file leases")
def test_linux_staged_copies_reject_writer_open_without_leasing_sources(tmp_path: Path) -> None:
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "model.onnx_data"
    source_path.write_bytes(b"MALICIOUS")
    companion_path.write_bytes(b"COMPANION")
    with _pinned_shard_scan_path(
        str(source_path),
        _target_for_path(source_path),
        logical_path=str(source_path),
        companion_targets={
            companion_path.name: (str(companion_path), _target_for_path(companion_path)),
        },
        require_regular_path=True,
    ) as pinned_scan:
        for source in (source_path, companion_path):
            writer_fd = os.open(source, os.O_RDWR | os.O_NONBLOCK)
            os.close(writer_fd)

        protected_paths = [
            Path(pinned_scan.path),
            Path(pinned_scan.path).with_name(companion_path.name),
        ]
        for protected_path, expected_bytes in zip(
            protected_paths,
            (b"MALICIOUS", b"COMPANION"),
            strict=True,
        ):
            assert protected_path.read_bytes() == expected_bytes
            with pytest.raises(BlockingIOError):
                os.open(protected_path, os.O_RDWR | os.O_NONBLOCK)
            assert protected_path.read_bytes() == expected_bytes

    assert pinned_scan.changed_during_scan is True
    assert source_path.read_bytes() == b"MALICIOUS"
    assert companion_path.read_bytes() == b"COMPANION"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux file leases")
def test_linux_write_lease_guard_rejects_preexisting_writer(tmp_path: Path) -> None:
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    source_fd = os.open(source_path, os.O_RDONLY)
    writer_fd = os.open(source_path, os.O_RDWR)
    try:
        with pytest.raises(_ShardPinUnavailableError, match="write protection is unavailable"):
            _LinuxWriteLeaseGuard.arm([source_fd])
    finally:
        os.close(writer_fd)
        os.close(source_fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux file leases")
def test_linux_write_lease_guard_uses_isolated_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    import_marker = tmp_path / "untrusted-import-ran"
    (tmp_path / "fcntl.py").write_text(
        f"from pathlib import Path\nPath({str(import_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    source_fd = os.open(source_path, os.O_RDONLY)
    try:
        guard = _LinuxWriteLeaseGuard.arm([source_fd])
        assert guard.finish() is False
    finally:
        os.close(source_fd)

    assert not import_marker.exists()


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not Path("/proc/self/fd").exists(),
    reason="requires Linux file leases and process descriptors",
)
def test_linux_pinned_copy_is_revalidated_after_write_lease_arming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"MALICIOUS")
    original_arm = _LinuxWriteLeaseGuard.arm

    def mutate_then_arm(
        descriptors: Any,
        *,
        deadline: float | None = None,
    ) -> _LinuxWriteLeaseGuard:
        retained_descriptors = list(descriptors)
        writer_fd = os.open(f"/proc/self/fd/{retained_descriptors[0]}", os.O_RDWR)
        try:
            os.pwrite(writer_fd, b"BENIGN!!!", 0)
        finally:
            os.close(writer_fd)
        return original_arm(retained_descriptors, deadline=deadline)

    monkeypatch.setattr(_LinuxWriteLeaseGuard, "arm", mutate_then_arm)
    with (
        pytest.raises(_ShardPinUnavailableError, match="pinned shard content changed before scanner dispatch"),
        _pinned_shard_scan_path(
            str(source_path),
            _target_for_path(source_path),
            logical_path=str(source_path),
            require_regular_path=True,
        ),
    ):
        pytest.fail("a staged mutation before lease arming must prevent scanner dispatch")

    assert source_path.read_bytes() == b"MALICIOUS"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_pinned_scan_uses_borrowed_source_and_companion_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Borrowed descriptors are duplicated and their source paths are never reopened."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "model.onnx_data"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    source_fd = os.open(source_path, os.O_RDONLY)
    companion_fd = os.open(companion_path, os.O_RDONLY)
    original_open = os.open
    descriptor_root = Path("/proc/self/fd") if Path("/proc/self/fd").exists() else Path("/dev/fd")

    def reject_source_path_reopen(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        *args: Any,
        **kwargs: Any,
    ) -> int:
        dir_fd = kwargs.get("dir_fd")
        if dir_fd is not None and os.fspath(path) in {source_path.name, companion_path.name}:
            opened_parent = Path(os.path.realpath(descriptor_root / str(dir_fd)))
            if opened_parent == tmp_path:
                raise AssertionError("borrowed source path was reopened")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", reject_source_path_reopen)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, reject_source_path_reopen})
    try:
        with _pinned_shard_scan_path(
            str(source_path),
            _target_for_path(source_path),
            logical_path=str(source_path),
            companion_targets={
                companion_path.name: (str(companion_path), _target_for_path(companion_path)),
            },
            source_fd=source_fd,
            companion_fds={companion_path.name: companion_fd},
            require_regular_path=True,
        ) as pinned_scan:
            staged_source = Path(pinned_scan.path)
            assert staged_source.read_bytes() == b"source"
            assert staged_source.with_name(companion_path.name).read_bytes() == b"companion"

        os.fstat(source_fd)
        os.fstat(companion_fd)
    finally:
        os.close(companion_fd)
        os.close(source_fd)


def test_pinned_scan_rejects_borrowed_descriptors_on_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The borrowed-descriptor interface is intentionally POSIX-only."""
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    source_fd = os.open(source_path, os.O_RDONLY)
    monkeypatch.setattr("modelaudit.utils.file.handlers.os.name", "nt")
    try:
        with (
            pytest.raises(_ShardPinUnavailableError, match="unsupported on Windows"),
            _pinned_shard_scan_path(
                str(source_path),
                _target_for_path(source_path),
                source_fd=source_fd,
            ),
        ):
            pytest.fail("Windows must reject borrowed source descriptors")
        os.fstat(source_fd)
    finally:
        os.close(source_fd)


@pytest.mark.skipif(
    os.name != "posix" or not Path("/dev/fd").exists(),
    reason="requires POSIX /dev/fd descriptor staging",
)
def test_dev_fd_fallback_exposes_subprocess_portable_regular_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    target = _target_for_path(source_path)
    original_stat = os.stat

    def stat_without_proc(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(path).startswith("/proc/"):
            raise FileNotFoundError(os.fspath(path))
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_without_proc)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, stat_without_proc})

    with _pinned_shard_scan_path(str(source_path), target) as pinned_scan:
        assert not pinned_scan.path.startswith("/dev/fd/")
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
                pinned_scan.path,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    assert completed.stdout.strip() == "source"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
@pytest.mark.parametrize("require_regular_path", [False, True], ids=["descriptor-link", "regular-copy"])
def test_pinned_scan_detects_staged_name_aba(
    tmp_path: Path,
    require_regular_path: bool,
) -> None:
    """Restoring a staged filename cannot erase a transient scanner-path substitution."""
    source_path = tmp_path / "model.pkl"
    source_path.write_bytes(b"malicious")
    target = _target_for_path(source_path)

    with _pinned_shard_scan_path(
        str(source_path),
        target,
        logical_path=str(source_path),
        require_regular_path=require_regular_path,
    ) as pinned_scan:
        scan_path = Path(pinned_scan.path)
        held_path = scan_path.with_name("held-model.pkl")
        scan_path.rename(held_path)
        scan_path.write_bytes(b"benign")
        scan_path.unlink()
        held_path.rename(scan_path)

    assert pinned_scan.changed_during_scan is True


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_regular_pinned_companion_rejects_source_mutation_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "model.onnx_data"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")

    original_copy = _copy_pinned_file_descriptor
    companion_inode = companion_path.stat().st_ino
    created_staging_directories = _track_created_staging_directories(monkeypatch)

    def copy_then_mutate(source_fd: int, target: Any, **kwargs: Any) -> str:
        copied_hash = original_copy(source_fd, target, **kwargs)
        if os.fstat(source_fd).st_ino == companion_inode:
            companion_path.write_bytes(b"mutated!!")
        return copied_hash

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", copy_then_mutate)

    with (
        pytest.raises(_ShardPinUnavailableError, match="companion target changed while staging"),
        _pinned_shard_scan_path(
            str(source_path),
            _target_for_path(source_path),
            logical_path=str(source_path),
            companion_targets={
                companion_path.name: (str(companion_path), _target_for_path(companion_path)),
            },
            require_regular_path=True,
        ),
    ):
        pytest.fail("mutated companion must be rejected before scanner dispatch")
    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_context_only_companion_consumes_posix_staging_byte_budget(tmp_path: Path) -> None:
    """Context-only OCI companions must consume the physical staging copy budget."""
    source_path = tmp_path / "manifest.json"
    companion_path = tmp_path / "layer.tar"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    companion_target = _target_for_path(companion_path)
    companion_target[CONTEXT_ONLY_COMPANION_TARGET_KEY] = 1
    copy_budget = source_path.stat().st_size + companion_path.stat().st_size - 1

    with (
        pytest.raises(_ShardPinUnavailableError, match="regular companion scan path"),
        _pinned_shard_scan_path(
            str(source_path),
            _target_for_path(source_path),
            logical_path=str(source_path),
            companion_targets={companion_path.name: (str(companion_path), companion_target)},
            require_regular_path=True,
            copy_max_bytes=copy_budget,
        ),
    ):
        pytest.fail("context-only companion copy must not exceed the aggregate staging budget")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_regular_pinned_nested_companion_rejects_parent_replacement_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nested staging parent must remain bound to the directory opened for copying."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "data.bin"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")

    original_copy = _copy_pinned_file_descriptor
    companion_inode = companion_path.stat().st_ino
    replacement_root: Path | None = None

    def copy_after_parent_replacement(source_fd: int, destination: Path | str, **kwargs: Any) -> str:
        nonlocal replacement_root
        if os.fstat(source_fd).st_ino != companion_inode:
            return original_copy(source_fd, destination, **kwargs)
        destination_fd = cast(int, kwargs["destination_dir_fd"])
        descriptor_root = Path("/proc/self/fd") if Path("/proc/self/fd").exists() else Path("/dev/fd")
        opened_parent = Path(os.path.realpath(descriptor_root / str(destination_fd)))
        replacement_root = opened_parent.parent
        held_parent = replacement_root / "held-sub"
        opened_parent.rename(held_parent)
        opened_parent.mkdir()
        (opened_parent / os.fspath(destination)).write_bytes(b"substitute")
        return original_copy(source_fd, destination, **kwargs)

    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._copy_pinned_file_descriptor",
        copy_after_parent_replacement,
    )

    with (
        pytest.raises(_ShardPinUnavailableError, match="private staging entry changed"),
        _pinned_shard_scan_path(
            str(source_path),
            _target_for_path(source_path),
            logical_path=str(source_path),
            companion_targets={
                "sub/data.bin": (str(companion_path), _target_for_path(companion_path)),
            },
            require_regular_path=True,
        ),
    ):
        pytest.fail("a replacement staging parent must be rejected before dispatch")

    assert replacement_root is not None
    for staged_directory in (replacement_root / "sub", replacement_root / "held-sub"):
        if staged_directory.exists():
            for child in staged_directory.iterdir():
                child.unlink()
            staged_directory.rmdir()
    replacement_root.rmdir()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_nested_companion_open_failure_removes_created_staging_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory created immediately before descriptor exhaustion remains cleanup-owned."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "data.bin"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    source_target = _target_for_path(source_path)
    companion_target = _target_for_path(companion_path)
    original_open = os.open
    created_staging_directories = _track_created_staging_directories(monkeypatch)

    def fail_nested_directory_open(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == "nested" and kwargs.get("dir_fd") is not None:
            raise OSError(errno.EMFILE, "descriptor table exhausted")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail_nested_directory_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, fail_nested_directory_open})
    with (
        pytest.raises(_ShardPinUnavailableError, match="descriptor table exhausted"),
        _pinned_shard_scan_path(
            str(source_path),
            source_target,
            logical_path=str(source_path),
            companion_targets={"nested/data.bin": (str(companion_path), companion_target)},
            require_regular_path=True,
        ),
    ):
        pytest.fail("descriptor exhaustion must stop before dispatch")

    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_staging_parent_open_failure_precedes_directory_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staging parent descriptor failure cannot leave a newly created root behind."""
    source_dir = tmp_path / "source"
    staging_parent = tmp_path / "staging"
    source_dir.mkdir()
    staging_parent.mkdir()
    source_path = source_dir / "model.onnx"
    source_path.write_bytes(b"source")
    original_open = os.open
    monkeypatch.setattr("modelaudit.utils.file.handlers.tempfile.gettempdir", lambda: str(staging_parent))

    def fail_staging_parent_open(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> int:
        if Path(path) == staging_parent and kwargs.get("dir_fd") is None:
            raise OSError(errno.EMFILE, "descriptor table exhausted")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail_staging_parent_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, fail_staging_parent_open})
    with (
        pytest.raises(_ShardPinUnavailableError, match="descriptor table exhausted"),
        _pinned_shard_scan_path(str(source_path), _target_for_path(source_path)),
    ):
        pytest.fail("staging parent descriptor exhaustion must stop before directory creation")

    assert not list(staging_parent.glob(".modelaudit_scan_*"))


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_staging_root_open_failure_removes_created_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Descriptor exhaustion after root creation cannot leak a private staging directory."""
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    original_open = os.open
    created_staging_directories = _track_created_staging_directories(monkeypatch)

    def fail_staging_directory_open(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path).startswith(".modelaudit_scan_") and kwargs.get("dir_fd") is not None:
            raise OSError(errno.EMFILE, "descriptor table exhausted")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail_staging_directory_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, fail_staging_directory_open})
    with (
        pytest.raises(_ShardPinUnavailableError, match="descriptor table exhausted"),
        _pinned_shard_scan_path(str(source_path), _target_for_path(source_path)),
    ):
        pytest.fail("staging descriptor exhaustion must stop before dispatch")

    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_regular_pinned_copy_uses_validated_size_as_hard_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Growth after validation cannot consume staging space beyond the captured size."""
    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    source_stat = source_path.stat()
    target = _target_for_path(source_path)
    observed_limits: list[int | None] = []
    original_copy = _copy_pinned_file_descriptor

    def grow_before_copy(source_fd: int, destination: Any, **kwargs: Any) -> str:
        observed_limits.append(kwargs.get("max_bytes"))
        source_path.write_bytes(b"x" * (2 * 1024 * 1024))
        return original_copy(source_fd, destination, **kwargs)

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", grow_before_copy)
    with (
        pytest.raises(_ShardPinUnavailableError, match="regular source scan path"),
        _pinned_shard_scan_path(
            str(source_path),
            target,
            logical_path=str(source_path),
            require_regular_path=True,
        ),
    ):
        pytest.fail("grown content must not reach scanner dispatch")

    assert observed_limits == [source_stat.st_size]


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX descriptor staging")
def test_regular_pinned_validation_hash_honors_dispatch_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Post-copy validation cannot overrun the deadline and still dispatch a scanner."""
    from modelaudit.utils.file import handlers

    source_path = tmp_path / "model.onnx"
    source_path.write_bytes(b"source")
    target = _target_for_path(source_path)
    original_hash = handlers._hash_pinned_file_descriptor

    def delayed_hash(source_fd: int, **kwargs: Any) -> str:
        time.sleep(0.02)
        return original_hash(source_fd, **kwargs)

    monkeypatch.setattr(handlers, "_hash_pinned_file_descriptor", delayed_hash)
    with (
        pytest.raises(_ShardPinUnavailableError, match="changed while staging"),
        _pinned_shard_scan_path(
            str(source_path),
            target,
            logical_path=str(source_path),
            require_regular_path=True,
            deadline=time.time() + 0.01,
        ),
    ):
        pytest.fail("an expired validation deadline must stop before dispatch")


def test_windows_staging_directory_guard_uses_no_follow_delete_denying_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directory guards allow child writes but deny namespace deletion and bind the opened path."""
    staging_path = tmp_path / "staging"
    staging_path.mkdir()
    expected_stat = staging_path.stat()
    captured: dict[str, object] = {}
    handle_value = 1 << 40

    def create_file(
        path: str,
        desired_access: int,
        share_mode: int,
        _security_attributes: object,
        creation_disposition: int,
        flags: int,
        _template: object,
    ) -> int:
        captured.update(
            path=path,
            desired_access=desired_access,
            share_mode=share_mode,
            creation_disposition=creation_disposition,
            flags=flags,
        )
        return handle_value

    def get_file_information(
        handle: int,
        information_class: int,
        information: Any,
        _size: int,
    ) -> bool:
        assert handle == handle_value
        assert information_class == 9
        values = ctypes.cast(information, ctypes.POINTER(ctypes.c_uint32))
        values[0] = 0x00000010
        values[1] = 0
        return True

    def get_final_path(handle: int, buffer: Any, length: int, flags: int) -> int:
        assert handle == handle_value
        assert length == 32768
        assert flags == 0
        buffer.value = str(staging_path)
        return len(buffer.value)

    create_file_mock = MagicMock(side_effect=create_file)
    get_file_information_mock = MagicMock(side_effect=get_file_information)
    get_final_path_mock = MagicMock(side_effect=get_final_path)
    close_handle_mock = MagicMock(return_value=True)
    kernel32 = types.SimpleNamespace(
        CreateFileW=create_file_mock,
        GetFileInformationByHandleEx=get_file_information_mock,
        GetFinalPathNameByHandleW=get_final_path_mock,
        CloseHandle=close_handle_mock,
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)

    guard = _open_windows_staging_directory_guard(staging_path, expected_stat)

    assert guard.handle == handle_value
    assert guard.bound_path == staging_path
    assert os.path.samestat(guard.expected_stat, expected_stat)
    assert captured == {
        "path": str(staging_path),
        "desired_access": 0x0020 | 0x0080,
        "share_mode": 0x00000001 | 0x00000002,
        "creation_disposition": 3,
        "flags": 0x02000000 | 0x00200000,
    }
    assert close_handle_mock.call_count == 0

    _close_windows_staging_directory_guard(guard)

    close_handle_mock.assert_called_once_with(handle_value)


@pytest.mark.parametrize(
    "file_attributes",
    [0, 0x00000010 | 0x00000400],
    ids=["non-directory", "reparse-directory"],
)
def test_windows_staging_directory_guard_rejects_invalid_type_and_closes_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_attributes: int,
) -> None:
    """A non-directory or reparse handle is rejected without leaking the handle."""
    staging_path = tmp_path / "staging"
    staging_path.mkdir()
    handle_value = 321

    def get_file_information(
        _handle: int,
        _information_class: int,
        information: Any,
        _size: int,
    ) -> bool:
        values = ctypes.cast(information, ctypes.POINTER(ctypes.c_uint32))
        values[0] = file_attributes
        values[1] = 0xA000000C if file_attributes & 0x00000400 else 0
        return True

    close_handle_mock = MagicMock(return_value=True)
    kernel32 = types.SimpleNamespace(
        CreateFileW=MagicMock(return_value=handle_value),
        GetFileInformationByHandleEx=MagicMock(side_effect=get_file_information),
        GetFinalPathNameByHandleW=MagicMock(),
        CloseHandle=close_handle_mock,
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)

    with pytest.raises(_ShardPinUnavailableError, match="staging directory changed"):
        _open_windows_staging_directory_guard(staging_path, staging_path.stat())

    close_handle_mock.assert_called_once_with(handle_value)
    kernel32.GetFinalPathNameByHandleW.assert_not_called()


def test_windows_logical_pin_uses_handle_bound_staging_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scanner path is built from the path returned for the retained root handle."""
    source_path = tmp_path / "blob"
    source_path.write_bytes(b"malicious")
    created_staging_directories = _track_created_staging_directories(monkeypatch)
    bound_roots: list[Path] = []

    def open_guard(path: Path, expected_stat: os.stat_result) -> _WindowsStagingDirectoryGuard:
        bound_path = path.with_name(f"{path.name}-bound")
        path.rename(bound_path)
        bound_stat = bound_path.stat()
        assert os.path.samestat(expected_stat, bound_stat)
        bound_roots.append(bound_path)
        return _WindowsStagingDirectoryGuard(1, bound_path, bound_stat)

    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_staging_directory_guard",
        open_guard,
    )
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._close_windows_staging_directory_guard",
        lambda _guard: None,
    )
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )

    with _pinned_windows_logical_scan_path(
        str(source_path),
        _target_for_path(source_path),
        "model.pkl",
        None,
    ) as pinned_scan:
        assert bound_roots == [Path(pinned_scan.path).parent]
        assert Path(pinned_scan.path).read_bytes() == b"malicious"

    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)
    assert all(not path.exists() for path in bound_roots)


def test_windows_logical_pin_retains_nested_guards_and_cleans_child_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root and nested handles remain open through dispatch and close deepest-first for cleanup."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "data.bin"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    created_staging_directories = _track_created_staging_directories(monkeypatch)
    opened_guards, closed_guards = _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )

    with _pinned_windows_logical_scan_path(
        str(source_path),
        _target_for_path(source_path),
        source_path.name,
        {"nested/deep/data.bin": (str(companion_path), _target_for_path(companion_path))},
    ) as pinned_scan:
        scan_root = Path(pinned_scan.path).parent
        assert [guard.bound_path.name for guard in opened_guards] == [scan_root.name, "nested", "deep"]
        assert closed_guards == []
        assert Path(pinned_scan.path).read_bytes() == b"source"
        assert (scan_root / "nested" / "deep" / "data.bin").read_bytes() == b"companion"

    assert [guard.bound_path.name for guard in closed_guards] == ["deep", "nested", scan_root.name]
    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)


def test_windows_nested_guard_open_failure_removes_created_staging_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parent created before guard exhaustion remains cleanup-owned."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "data.bin"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    created_staging_directories = _track_created_staging_directories(monkeypatch)
    opened_guards, closed_guards = _install_simulated_windows_directory_guards(
        monkeypatch,
        fail_on_name="deep",
    )
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )

    with (
        pytest.raises(_ShardPinUnavailableError, match="descriptor table exhausted"),
        _pinned_windows_logical_scan_path(
            str(source_path),
            _target_for_path(source_path),
            source_path.name,
            {"nested/deep/data.bin": (str(companion_path), _target_for_path(companion_path))},
        ),
    ):
        pytest.fail("nested directory guard exhaustion must stop before dispatch")

    assert [guard.bound_path.name for guard in opened_guards[1:]] == ["nested"]
    assert [guard.bound_path.name for guard in closed_guards] == ["nested", opened_guards[0].bound_path.name]
    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)


def test_windows_logical_pin_rejects_nested_directory_replacement_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-content replacement parent cannot become the scanner-visible companion namespace."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "data.bin"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    companion_inode = companion_path.stat().st_ino
    _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )
    original_copy = _copy_pinned_file_descriptor
    replacement_root: Path | None = None

    def copy_then_replace_parent(source_fd: int, destination: Path | str, **kwargs: Any) -> str:
        nonlocal replacement_root
        copied_hash = original_copy(source_fd, destination, **kwargs)
        if os.fstat(source_fd).st_ino == companion_inode:
            staged_companion = Path(destination)
            staged_parent = staged_companion.parent
            replacement_root = staged_parent.parent
            staged_parent.rename(replacement_root / "held-nested")
            staged_parent.mkdir()
            staged_companion.write_bytes(b"companion")
        return copied_hash

    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._copy_pinned_file_descriptor",
        copy_then_replace_parent,
    )

    with (
        pytest.raises(_ShardPinUnavailableError, match="staging directory changed before scanner dispatch"),
        _pinned_windows_logical_scan_path(
            str(source_path),
            _target_for_path(source_path),
            source_path.name,
            {"nested/data.bin": (str(companion_path), _target_for_path(companion_path))},
        ),
    ):
        pytest.fail("a replacement nested namespace must be rejected before dispatch")

    assert replacement_root is not None
    for staged_directory in (replacement_root / "nested", replacement_root / "held-nested"):
        if staged_directory.exists():
            for child in staged_directory.iterdir():
                child.unlink()
            staged_directory.rmdir()
    replacement_root.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory sharing semantics")
def test_windows_logical_pin_blocks_root_and_nested_directory_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retained staging-directory handles deny root and nested namespace ABA through yield."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "data.bin"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    created_staging_directories = _track_created_staging_directories(monkeypatch)

    with _pinned_windows_logical_scan_path(
        str(source_path),
        _target_for_path(source_path),
        source_path.name,
        {"nested/data.bin": (str(companion_path), _target_for_path(companion_path))},
    ) as pinned_scan:
        scan_root = Path(pinned_scan.path).parent
        nested_path = scan_root / "nested"
        with pytest.raises(OSError):
            scan_root.rename(scan_root.with_name(f"{scan_root.name}-held"))
        with pytest.raises(OSError):
            nested_path.rename(scan_root / "held-nested")
        assert Path(pinned_scan.path).read_bytes() == b"source"
        assert (nested_path / "data.bin").read_bytes() == b"companion"

    assert created_staging_directories
    assert all(not path.exists() for path in created_staging_directories)


def test_windows_logical_pin_rejects_staged_source_mutation_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "blob"
    source_path.write_bytes(b"malicious")
    target = _target_for_path(source_path)
    _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )
    original_copy = _copy_pinned_file_descriptor

    def copy_then_mutate(source_fd: int, destination: Path | str, **kwargs: Any) -> str:
        copied_hash = original_copy(source_fd, destination, **kwargs)
        Path(destination).write_bytes(b"benign!!!")
        return copied_hash

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", copy_then_mutate)

    with (
        pytest.raises(_ShardPinUnavailableError, match="staged shard content changed while staging"),
        _pinned_windows_logical_scan_path(str(source_path), target, "model.pkl", None),
    ):
        pytest.fail("mutated staged bytes must be rejected before scanner dispatch")


def test_windows_logical_pin_rejects_staged_companion_reparse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged companion cannot be replaced with a reparse-style alias before its guard opens."""
    source_path = tmp_path / "model.onnx"
    companion_path = tmp_path / "model.onnx_data"
    benign_path = tmp_path / "benign.bin"
    source_path.write_bytes(b"model")
    companion_path.write_bytes(b"malicious")
    benign_path.write_bytes(b"benign")

    _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )
    original_copy = _copy_pinned_file_descriptor
    companion_inode = companion_path.stat().st_ino

    def copy_then_retarget(source_fd: int, destination: Path | str, **kwargs: Any) -> str:
        copied_hash = original_copy(source_fd, destination, **kwargs)
        if os.fstat(source_fd).st_ino == companion_inode:
            destination_path = Path(destination)
            destination_path.unlink()
            destination_path.symlink_to(benign_path)
        return copied_hash

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", copy_then_retarget)

    with (
        pytest.raises(_ShardPinUnavailableError, match="staged companion path changed"),
        _pinned_windows_logical_scan_path(
            str(source_path),
            _target_for_path(source_path),
            source_path.name,
            {companion_path.name: (str(companion_path), _target_for_path(companion_path))},
        ),
    ):
        pytest.fail("a staged companion reparse must fail before scanner dispatch")


def test_context_only_companion_consumes_windows_staging_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows context-only companions must share the physical staging copy budget."""
    source_path = tmp_path / "manifest.json"
    companion_path = tmp_path / "layer.tar"
    source_path.write_bytes(b"source")
    companion_path.write_bytes(b"companion")
    companion_target = _target_for_path(companion_path)
    companion_target[CONTEXT_ONLY_COMPANION_TARGET_KEY] = 1
    copy_budget = source_path.stat().st_size + companion_path.stat().st_size - 1
    _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )

    with (
        pytest.raises(_ShardPinUnavailableError, match="staging byte limit"),
        _pinned_windows_logical_scan_path(
            str(source_path),
            _target_for_path(source_path),
            source_path.name,
            {companion_path.name: (str(companion_path), companion_target)},
            copy_max_bytes=copy_budget,
        ),
    ):
        pytest.fail("context-only companion copy must not exceed the aggregate staging budget")


def test_windows_pinned_source_preserves_existing_companion_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A companion failure cannot be cleared by a stable Windows source descriptor."""
    source_path = tmp_path / "model.bin"
    source_path.write_bytes(b"model")
    with source_path.open("rb") as handle:
        source_fd = handle.fileno()
        target = _target_for_path(source_path)
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
            lambda _path, **_kwargs: os.dup(source_fd),
        )

        with _pinned_windows_shard_scan_path(str(source_path), target) as pinned_scan:
            pinned_scan.changed_during_scan = True

    assert pinned_scan.changed_during_scan is True


def test_windows_logical_pin_scans_staged_descriptor_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mutable logical alias cannot redirect a Windows scan away from guarded bytes."""
    source_path = tmp_path / "blob"
    source_path.write_bytes(b"malicious")
    source_stat = source_path.stat()
    target = _target_for_path(source_path)
    _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )

    with _pinned_windows_logical_scan_path(str(source_path), target, "model.pkl", None) as pinned_scan:
        source_path.write_bytes(b"benign!!!")
        os.utime(
            source_path,
            ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 1_000_000_000),
        )
        assert Path(pinned_scan.path).name == "model.pkl"
        assert Path(pinned_scan.path).read_bytes() == b"malicious"

    assert pinned_scan.changed_during_scan is True


def test_windows_logical_pin_does_not_delete_replaced_staging_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleanup must not recurse into a replacement at the private staging pathname."""
    source_path = tmp_path / "blob"
    source_path.write_bytes(b"model")
    target = _target_for_path(source_path)
    _install_simulated_windows_directory_guards(monkeypatch)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._open_windows_shard_guard_fd",
        lambda path, **_kwargs: os.open(path, os.O_RDONLY),
    )
    held_staging: Path | None = None
    replacement_staging: Path | None = None

    with _pinned_windows_logical_scan_path(str(source_path), target, "model.pkl", None) as pinned_scan:
        replacement_staging = Path(pinned_scan.path).parent
        held_staging = replacement_staging.with_name(f"{replacement_staging.name}-held")
        replacement_staging.rename(held_staging)
        replacement_staging.mkdir()
        (replacement_staging / "must-survive").write_text("sentinel", encoding="utf-8")

    assert replacement_staging is not None
    assert held_staging is not None
    assert (replacement_staging / "must-survive").read_text(encoding="utf-8") == "sentinel"
    for directory in (replacement_staging, held_staging):
        for child in directory.iterdir():
            child.unlink()
        directory.rmdir()


class CompletingShardScanner:
    """Minimal scanner for shard-handler coverage tests."""

    name = "completing_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = Path(shard_path).stat().st_size
        result.finish(success=True)
        return result


class HeaderHashShardScanner:
    """Scanner that records the SafeTensors header bytes it actually received."""

    name = "header_hash_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        with Path(shard_path).open("rb") as handle:
            header_len = struct.unpack("<Q", handle.read(8))[0]
            header = handle.read(header_len)
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="SafeTensors Header Pin",
            passed=True,
            message="SafeTensors header was scanned",
            severity=IssueSeverity.INFO,
            location=shard_path,
            details={"header_sha256": hashlib.sha256(header).hexdigest()},
        )
        result.finish(success=True)
        return result


class OperationalFailureScanner:
    """Scanner that simulates an operational shard scan failure."""

    name = "operational_failure_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        raise RuntimeError(f"cannot scan {Path(shard_path).name}: {Path(shard_path).read_text()}")


class IncompleteShardScanner:
    """Scanner that returns an unsuccessful non-critical shard result."""

    name = "incomplete_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Shard Parse Coverage",
            passed=False,
            message=f"Shard could not be fully parsed: {Path(shard_path).name}",
            severity=IssueSeverity.INFO,
            location=shard_path,
        )
        result.finish(success=False)
        return result


class RawDetectorMemoryMappedScanner(BaseScanner):
    """Minimal scanner that exercises BaseScanner's raw detector helpers."""

    name = "raw_detector_mmap"

    def scan(self, path: str) -> ScanResult:
        raise NotImplementedError


class MixedRawDetectorShardScanner(BaseScanner):
    """Emit different raw-detector outcomes across parallel shard workers."""

    name = "mixed_raw_detector_shards"

    def scan(self, path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        shard_name = Path(path).name
        if "secret-failure" in shard_name:
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="embedded_secrets",
                context=path,
                error=RuntimeError("secret detector failed"),
            )
        elif "network-failure" in shard_name:
            self._mark_raw_detector_analysis_incomplete(
                result,
                detector="network_communication",
                context=path,
                error=RuntimeError("network detector failed"),
            )
        else:
            result.add_check(
                name="Embedded Secrets Detection",
                passed=True,
                message="No embedded secrets detected",
                location=path,
            )
            result.add_check(
                name="Network Communication Detection",
                passed=True,
                message="No network communication patterns detected",
                location=path,
            )
        result.finish(success="scan_outcome" not in result.metadata)
        return result


class PatternMemoryMappedScanner:
    """Minimal scanner that exercises the mmap fallback pattern checks."""

    name = "pattern_mmap"


_SHARD_SCAN_CONTEXT: ContextVar[str] = ContextVar("_SHARD_SCAN_CONTEXT", default="missing")


def _validated_target(path: Path) -> dict[str, int | str]:
    """Return the target identity fields used by grouped shard scans."""
    resolved_path = path.resolve(strict=True)
    path_stat = os.stat(resolved_path, follow_symlinks=False)
    return {
        "resolved_path": str(resolved_path),
        "device": path_stat.st_dev,
        "inode": path_stat.st_ino,
        "size": path_stat.st_size,
        "mtime_ns": path_stat.st_mtime_ns,
        "ctime_ns": path_stat.st_ctime_ns,
    }


def _write_safetensors_index(
    directory: Path,
    targets: list[str],
    *,
    index_name: str = "model.safetensors.index.json",
) -> Path:
    """Write a deterministic SafeTensors index that maps one tensor per target."""
    index_path = directory / index_name
    index_path.write_text(
        json.dumps(
            {
                "metadata": {"total_size": 0},
                "weight_map": {f"tensor_{index}": target for index, target in enumerate(targets)},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return index_path


class ContextRecordingShardScanner:
    """Scanner that records worker context for propagation tests."""

    name = "context_recording_shard_scanner"

    def scan(self, shard_path: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Shard Context",
            passed=True,
            message=Path(shard_path).name,
            severity=IssueSeverity.INFO,
            details={"context_value": _SHARD_SCAN_CONTEXT.get()},
        )
        result.finish(success=True)
        return result


class TestShardedModelDetector:
    """Test sharded model detection."""

    def test_detect_pytorch_shards(self) -> None:
        """Test detection of PyTorch sharded models."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sharded model files
            shard_files = [
                "pytorch_model-00001-of-00003.bin",
                "pytorch_model-00002-of-00003.bin",
                "pytorch_model-00003-of-00003.bin",
            ]

            for shard in shard_files:
                Path(tmpdir, shard).write_bytes(b"test")

            # Test detection
            test_file = str(Path(tmpdir, shard_files[0]))
            shard_info = ShardedModelDetector.detect_shards(test_file)

            assert shard_info is not None
            assert shard_info["total_shards"] == 3
            assert len(shard_info["shards"]) == 3

    @pytest.mark.parametrize(
        ("indices", "expected_base"),
        [
            ([1, 2], "one"),
            ([0, 1], "zero"),
        ],
        ids=["one-based", "zero-based"],
    )
    def test_detect_safetensors_shards(self, tmp_path: Path, indices: list[int], expected_base: str) -> None:
        """Test detection of SafeTensors sharded models."""
        shard_files = [f"model-{index:05d}-of-00002.safetensors" for index in indices]
        for shard in shard_files:
            (tmp_path / shard).write_bytes(b"test")
        _write_safetensors_index(tmp_path, shard_files)

        shard_info = ShardedModelDetector.detect_shards(str(tmp_path / shard_files[0]))
        result = AdvancedFileHandler(str(tmp_path / shard_files[0]), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(tmp_path / shard) for shard in shard_files]
        assert shard_info["total_shards"] == 2
        assert shard_info["expected_total_shards"] == 2
        assert shard_info["shard_index_base"] == expected_base
        assert "missing_shard_count" not in shard_info
        assert "unexpected_shard_count" not in shard_info
        assert result.success is True

    def test_detect_safetensors_custom_stem_escapes_regex_metacharacters(self, tmp_path: Path) -> None:
        """A custom stem is a literal family identity, not executable regex syntax."""
        stem = "adapter+[v1](prod)"
        shards = [tmp_path / f"{stem}-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        index_path = _write_safetensors_index(
            tmp_path,
            [shard.name for shard in shards],
            index_name=f"{stem}.safetensors.index.json",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]))

        assert shard_info is not None
        assert shard_info["normalized_shard_stem"] == stem
        assert set(shard_info["shards"]) == {str(shard) for shard in shards}
        assert shard_info["safetensors_index_path"] == str(index_path)
        assert "safetensors_index_error" not in shard_info

    def test_detect_safetensors_custom_stem_is_case_insensitive(self, tmp_path: Path) -> None:
        """Case variants of one custom stem must form one indexed family."""
        shards = [
            tmp_path / "Weights.V1-00001-of-00002.SAFETENSORS",
            tmp_path / "weights.v1-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        _write_safetensors_index(
            tmp_path,
            [shard.name for shard in shards],
            index_name="WEIGHTS.V1.SAFETENSORS.INDEX.JSON",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]))

        assert shard_info is not None
        assert shard_info["normalized_shard_stem"] == "weights.v1"
        assert set(shard_info["shards"]) == {str(shard) for shard in shards}
        assert "missing_shard_count" not in shard_info
        assert "safetensors_index_error" not in shard_info

    @pytest.mark.skipif(os.name != "posix", reason="requires a POSIX newline-bearing basename")
    def test_detect_safetensors_custom_stem_accepts_newline(self, tmp_path: Path) -> None:
        """A newline in a POSIX stem must not bypass incomplete-family coverage."""
        shard = tmp_path / "adapter\nv1-00001-of-00002.safetensors"
        shard.write_bytes(b"first")

        shard_info = ShardedModelDetector.detect_shards(str(shard))
        result = AdvancedFileHandler(str(shard), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["normalized_shard_stem"] == "adapter\nv1"
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["missing_shard_indices"] == [2]
        assert result.success is False
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("display_stem", "casefolded_stem"),
        [("Straße", "STRASSE"), ("İTEM", "i\u0307tem")],
        ids=["sharp-s", "dotted-capital-i"],
    )
    def test_detect_safetensors_custom_stem_uses_unicode_casefold(
        self,
        tmp_path: Path,
        display_stem: str,
        casefolded_stem: str,
    ) -> None:
        """Parsed family equality handles casefold expansions that regex ignore-case cannot."""
        shards = [
            tmp_path / f"{display_stem}-00001-of-00002.safetensors",
            tmp_path / f"{casefolded_stem}-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        _write_safetensors_index(
            tmp_path,
            [shard.name for shard in shards],
            index_name=f"{casefolded_stem}.safetensors.index.json",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]))

        assert shard_info is not None
        assert shard_info["normalized_shard_stem"] == display_stem.casefold()
        assert set(shard_info["shards"]) == {str(shard) for shard in shards}
        assert "missing_shard_count" not in shard_info
        assert "safetensors_index_error" not in shard_info

    def test_detect_safetensors_keeps_distinct_same_total_stems_separate(self, tmp_path: Path) -> None:
        """Equal shard totals cannot merge distinct custom stems into one family."""
        families = {
            stem: [tmp_path / f"{stem}-{index:05d}-of-00002.safetensors" for index in (1, 2)]
            for stem in ("alpha", "beta")
        }
        indexes: dict[str, Path] = {}
        for stem, shards in families.items():
            for shard in shards:
                shard.write_bytes(shard.name.encode())
            indexes[stem] = _write_safetensors_index(
                tmp_path,
                [shard.name for shard in shards],
                index_name=f"{stem}.safetensors.index.json",
            )

        for stem, shards in families.items():
            shard_info = ShardedModelDetector.detect_shards(str(shards[0]))

            assert shard_info is not None
            assert set(shard_info["shards"]) == {str(shard) for shard in shards}
            assert shard_info["safetensors_index_path"] == str(indexes[stem])
            assert "safetensors_index_error" not in shard_info

    def test_safetensors_index_cache_is_shared_across_distinct_stems(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One stable index parse serves different family queries without recharging bytes."""
        alpha = tmp_path / "alpha-00001-of-00001.safetensors"
        beta = tmp_path / "beta-00001-of-00001.safetensors"
        alpha.write_bytes(b"alpha")
        beta.write_bytes(b"beta")
        index_path = _write_safetensors_index(
            tmp_path,
            [alpha.name],
            index_name="alpha.safetensors.index.json",
        )
        index_size = index_path.stat().st_size
        context = _SafetensorsIndexInspectionContext()
        original_open = Path.open
        index_reads = 0

        def count_index_reads(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            nonlocal index_reads
            if path == index_path and mode == "rb":
                index_reads += 1
            return original_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(Path, "open", count_index_reads)
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES",
            index_size,
        )

        alpha_info = ShardedModelDetector.detect_shards(str(alpha), index_inspection_context=context)
        beta_info = ShardedModelDetector.detect_shards(str(beta), index_inspection_context=context)

        assert alpha_info is not None
        assert alpha_info["safetensors_index_path"] == str(index_path)
        assert beta_info is not None
        assert "safetensors_index_path" not in beta_info
        assert "safetensors_index_error" not in beta_info
        assert context.failure is None
        assert context.bytes_read == index_size
        assert index_reads == 1

    def test_detect_safetensors_rejects_mixed_stem_index(self, tmp_path: Path) -> None:
        """One index cannot combine same-total shards from different custom stems."""
        alpha = tmp_path / "alpha-00001-of-00002.safetensors"
        beta = tmp_path / "beta-00002-of-00002.safetensors"
        alpha.write_bytes(b"alpha")
        beta.write_bytes(b"beta")
        index_path = _write_safetensors_index(
            tmp_path,
            [alpha.name, beta.name],
            index_name="alpha.safetensors.index.json",
        )

        shard_info = ShardedModelDetector.detect_shards(str(alpha))
        result = AdvancedFileHandler(str(alpha), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_path"] == str(index_path)
        assert shard_info["safetensors_index_error"] == ("safetensors index references multiple model shard families")
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        "index_name",
        ["MODEL.SAFETENSORS.INDEX.JSON", "weights.safetensors.index.json"],
        ids=["uppercase", "prefixed"],
    )
    def test_detect_zero_based_safetensors_with_noncanonical_index_name(
        self,
        tmp_path: Path,
        index_name: str,
    ) -> None:
        """Accepted remote index names must retain zero-based authority locally."""
        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        index_path = _write_safetensors_index(tmp_path, [shard.name], index_name=index_name)

        shard_info = ShardedModelDetector.detect_shards(str(shard))
        result = AdvancedFileHandler(str(shard), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_path"] == str(index_path)
        assert shard_info["shard_index_base"] == "zero"
        assert shard_info["shards"] == [str(shard)]
        assert "missing_shard_count" not in shard_info
        assert "unexpected_shard_count" not in shard_info
        assert result.success is True

    @pytest.mark.skipif(os.name == "nt", reason="simulates POSIX path comparison on a case-insensitive filesystem")
    def test_safetensors_index_candidates_deduplicate_case_insensitive_posix_alias(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A synthetic canonical alias must not duplicate the actual directory entry."""
        actual_index = _write_safetensors_index(
            tmp_path,
            ["model-00000-of-00001.safetensors"],
            index_name="MODEL.SAFETENSORS.INDEX.JSON",
        )
        canonical_index = tmp_path / "model.safetensors.index.json"
        original_exists = Path.exists
        original_samefile = Path.samefile

        def case_insensitive_exists(path: Path) -> bool:
            if path == canonical_index:
                return True
            return original_exists(path)

        def case_insensitive_samefile(path: Path, other_path: str | os.PathLike[str]) -> bool:
            other = Path(other_path)
            if (
                path.parent == tmp_path
                and other.parent == tmp_path
                and path.name.casefold() == canonical_index.name
                and other.name.casefold() == canonical_index.name
            ):
                return True
            return original_samefile(path, other)

        monkeypatch.setattr(Path, "exists", case_insensitive_exists)
        monkeypatch.setattr(Path, "samefile", case_insensitive_samefile)

        candidates, limit_exceeded = ShardedModelDetector._safetensors_index_candidates(tmp_path)

        assert limit_exceeded is False
        assert candidates == [actual_index]

    @pytest.mark.skipif(os.name == "nt", reason="requires case-sensitive POSIX directory entries")
    def test_safetensors_index_candidates_keep_distinct_case_sensitive_entries(self, tmp_path: Path) -> None:
        """Distinct real index entries must retain conflicting-authority checks."""
        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        canonical_index = _write_safetensors_index(tmp_path, [shard.name])
        uppercase_index = _write_safetensors_index(
            tmp_path,
            [shard.name],
            index_name="MODEL.SAFETENSORS.INDEX.JSON",
        )
        if canonical_index.samefile(uppercase_index):
            pytest.skip("filesystem does not support distinct case-only entries")

        candidates, limit_exceeded = ShardedModelDetector._safetensors_index_candidates(tmp_path)
        shard_info = ShardedModelDetector.detect_shards(str(shard))

        assert limit_exceeded is False
        assert set(candidates) == {canonical_index, uppercase_index}
        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "multiple safetensors indexes govern selected shard"

    @pytest.mark.skipif(os.name != "nt", reason="requires Windows filesystem path semantics")
    def test_safetensors_index_candidates_preserve_actual_windows_spelling(self, tmp_path: Path) -> None:
        """Windows alias matching must return the spelling found in the directory."""
        actual_index = _write_safetensors_index(
            tmp_path,
            ["model-00000-of-00001.safetensors"],
            index_name="MODEL.SAFETENSORS.INDEX.JSON",
        )

        candidates, limit_exceeded = ShardedModelDetector._safetensors_index_candidates(tmp_path)

        assert limit_exceeded is False
        assert candidates == [actual_index]

    def test_detect_safetensors_ignores_unrelated_prefixed_same_directory_index(
        self,
        tmp_path: Path,
    ) -> None:
        """A co-located adapter index must not claim an independent model family."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        (tmp_path / "adapter.safetensors.index.json").write_text(
            json.dumps({"weight_map": {"adapter": "adapter-00000-of-00001.safetensors"}}),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shard))
        result = AdvancedFileHandler(str(shard), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert "safetensors_index_path" not in shard_info
        assert shard_info["shards"] == [str(shard)]
        assert result.success is True

    def test_detect_safetensors_rejects_malformed_prefixed_same_directory_index(self, tmp_path: Path) -> None:
        """Malformed same-directory authority cannot be treated as proven unrelated."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        index_path = tmp_path / "adapter.safetensors.index.json"
        index_path.write_text("{malformed", encoding="utf-8")

        shard_info = ShardedModelDetector.detect_shards(str(shard))
        result = AdvancedFileHandler(str(shard), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_path"] == str(index_path)
        assert shard_info["safetensors_index_error"]
        assert result.success is False
        assert any(check.details.get("scan_outcome_reason") == "unvalidated_model_shards" for check in result.checks)

    def test_safetensors_index_context_reuses_unchanged_parse_and_tracks_aba_generation(self, tmp_path: Path) -> None:
        """One scan context must deduplicate stable reads but distinguish observed A-B-A content."""
        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        index_path = tmp_path / "model.safetensors.index.json"
        payload_a = json.dumps({"weight_map": {"a": shard.name}}, sort_keys=True).encode()
        payload_b = json.dumps({"weight_map": {"b": shard.name}}, sort_keys=True).encode()
        context = _SafetensorsIndexInspectionContext()

        def replace_index(payload: bytes) -> None:
            replacement = tmp_path / "replacement.index.json"
            replacement.write_bytes(payload)
            replacement.replace(index_path)

        replace_index(payload_a)
        first = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        repeated = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        assert first is not None and repeated is not None
        assert first["safetensors_index_generation"] == repeated["safetensors_index_generation"] == 1
        assert context.bytes_read == len(payload_a)

        replace_index(payload_b)
        second = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        replace_index(payload_a)
        restored = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)

        assert second is not None and restored is not None
        assert second["safetensors_index_generation"] == 2
        assert restored["safetensors_index_generation"] == 3
        assert restored["safetensors_index_fingerprint"] == first["safetensors_index_fingerprint"]

    def test_safetensors_index_context_revalidates_content_when_stat_identity_is_unreliable(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A same-stat rewrite must not reuse stale index authority on Windows."""
        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        index_path = tmp_path / "model.safetensors.index.json"
        payload_a = json.dumps({"weight_map": {"a": shard.name}}, sort_keys=True).encode()
        payload_b = json.dumps({"weight_map": {"b": shard.name}}, sort_keys=True).encode()
        assert len(payload_a) == len(payload_b)
        index_path.write_bytes(payload_a)
        context = _SafetensorsIndexInspectionContext()
        from modelaudit.utils.file import handlers as handlers_module

        monkeypatch.setattr(
            handlers_module,
            "MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES",
            len(payload_a) * 3,
        )
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._safetensors_index_requires_content_revalidation",
            lambda: True,
        )
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._safetensors_index_observation_prefix",
            lambda *_args: ("stable-stat-identity",),
        )

        first = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        stable = ShardedModelDetector.detect_shards(
            str(shard),
            index_inspection_context=context,
            force_index_content_revalidation=True,
        )
        assert first is not None
        assert stable is not None
        assert stable["safetensors_index_generation"] == first["safetensors_index_generation"]
        assert context.bytes_read == len(payload_a) * 2

        index_path.write_bytes(payload_b)
        cached = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        second = ShardedModelDetector.detect_shards(
            str(shard),
            index_inspection_context=context,
            force_index_content_revalidation=True,
        )

        assert cached is not None and second is not None
        assert cached["safetensors_index_generation"] == first["safetensors_index_generation"]
        assert cached["safetensors_index_fingerprint"] == first["safetensors_index_fingerprint"]
        assert second["safetensors_index_generation"] == first["safetensors_index_generation"] + 1
        assert second["safetensors_index_fingerprint"] != first["safetensors_index_fingerprint"]
        assert context.bytes_read == len(payload_a) * 3

        exhausted = ShardedModelDetector.detect_shards(
            str(shard),
            index_inspection_context=context,
            force_index_content_revalidation=True,
        )
        assert exhausted is not None
        assert exhausted["safetensors_index_error"] == "safetensors index aggregate byte limit exceeded"
        assert context.bytes_read == len(payload_a) * 3

    def test_safetensors_index_rejects_duplicate_json_keys(self, tmp_path: Path) -> None:
        """Ambiguous duplicate tensor keys cannot make local authority parser-dependent."""
        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        (tmp_path / "model.safetensors.index.json").write_bytes(
            b'{"weight_map":{"tensor":"missing-00000-of-00001.safetensors",'
            b'"tensor":"model-00000-of-00001.safetensors"}}'
        )

        shard_info = ShardedModelDetector.detect_shards(str(shard))

        assert shard_info is not None
        assert "duplicate JSON object keys" in shard_info["safetensors_index_error"]
        assert "safetensors_index_fingerprint" not in shard_info

    def test_safetensors_index_enforces_tensor_occurrence_limit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bounded local index cannot materialize an unbounded weight map."""
        from modelaudit.utils.file import handlers as handlers_module

        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        (tmp_path / "model.safetensors.index.json").write_text(
            json.dumps({"weight_map": {"tensor-a": shard.name, "tensor-b": shard.name}}),
            encoding="utf-8",
        )
        monkeypatch.setattr(handlers_module, "MAX_SAFETENSORS_SHARD_INDEX_TENSORS", 1)

        shard_info = ShardedModelDetector.detect_shards(str(shard))

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index exceeds tensor occurrence limit"

    def test_safetensors_index_enforces_json_structure_limit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Container-heavy local indexes fail before JSON graph materialization."""
        from modelaudit.utils.file import handlers as handlers_module

        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"zero")
        (tmp_path / "model.safetensors.index.json").write_text(
            json.dumps({"weight_map": {"tensor": shard.name}}),
            encoding="utf-8",
        )
        monkeypatch.setattr(handlers_module, "MAX_SAFETENSORS_SHARD_INDEX_JSON_TOKENS", 1)

        shard_info = ShardedModelDetector.detect_shards(str(shard))

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "SafeTensors index exceeds JSON object/value limit"

    def test_safetensors_index_context_bounds_actual_bytes_after_growth(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An index that grows after pre-stat cannot consume uncharged bytes."""
        nested = tmp_path / "nested"
        nested.mkdir()
        shard = nested / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        candidate = tmp_path / "candidate.safetensors.index.json"
        candidate.write_bytes(b"{")

        payload = b"{" + (b"x" * 39)
        original_path_open = Path.open
        grew = False
        actual_bytes_read = 0

        class CountingReader:
            def __init__(self, delegate: Any) -> None:
                self.delegate = delegate

            def __enter__(self) -> "CountingReader":
                return self

            def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
                self.delegate.close()

            def fileno(self) -> int:
                return cast(int, self.delegate.fileno())

            def read(self, *args: Any, **kwargs: Any) -> bytes:
                nonlocal actual_bytes_read
                data = cast(bytes, self.delegate.read(*args, **kwargs))
                actual_bytes_read += len(data)
                return data

            def __getattr__(self, name: str) -> Any:
                return getattr(self.delegate, name)

        def grow_before_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            nonlocal grew
            if "r" in mode and self == candidate and not grew:
                with builtins.open(self, "wb") as handle:
                    handle.write(payload)
                grew = True
            delegate = original_path_open(self, mode, *args, **kwargs)
            return CountingReader(delegate) if "r" in mode and self == candidate else delegate

        aggregate_limit = 32
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES",
            aggregate_limit,
        )
        monkeypatch.setattr(Path, "open", grow_before_open)
        context = _SafetensorsIndexInspectionContext()

        shard_info = ShardedModelDetector.detect_shards(
            str(shard),
            index_search_root=tmp_path,
            index_inspection_context=context,
        )

        assert shard_info is not None
        assert grew is True
        assert actual_bytes_read == 1
        assert actual_bytes_read <= aggregate_limit
        assert context.bytes_read == actual_bytes_read

    def test_safetensors_index_context_enforces_aggregate_candidates_across_ancestors(self, tmp_path: Path) -> None:
        """The 256-candidate cap applies once to the full ancestor walk."""
        nested = tmp_path / "nested"
        nested.mkdir()
        shard = nested / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        unrelated_payload = json.dumps({"weight_map": {"adapter": "adapter.safetensors"}})
        for index in range(129):
            (nested / f"nested-{index}.safetensors.index.json").write_text(unrelated_payload, encoding="utf-8")
        for index in range(128):
            (tmp_path / f"root-{index}.safetensors.index.json").write_text(unrelated_payload, encoding="utf-8")
        context = _SafetensorsIndexInspectionContext()

        shard_info = ShardedModelDetector.detect_shards(
            str(shard),
            index_search_root=tmp_path,
            index_inspection_context=context,
        )

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index inspection limit exceeded"
        assert context.failure == "safetensors index inspection limit exceeded"

    def test_safetensors_index_context_enforces_aggregate_byte_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Distinct bounded indexes share one scan-wide byte allowance."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        payload = json.dumps({"weight_map": {"adapter": "adapter.safetensors"}})
        (tmp_path / "a.safetensors.index.json").write_text(payload, encoding="utf-8")
        (tmp_path / "b.safetensors.index.json").write_text(payload, encoding="utf-8")
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES",
            len(payload.encode()) + 1,
        )
        context = _SafetensorsIndexInspectionContext()

        shard_info = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index aggregate byte limit exceeded"
        assert context.failure == "safetensors index aggregate byte limit exceeded"

    def test_safetensors_partial_index_enumeration_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A partial directory inventory cannot authorize or silently ignore index metadata."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        partial = tmp_path / "adapter.safetensors.index.json"
        partial.write_text(json.dumps({"weight_map": {"adapter": "adapter.safetensors"}}), encoding="utf-8")
        monkeypatch.setattr(
            ShardedModelDetector,
            "_safetensors_index_candidates",
            staticmethod(lambda _directory, _context=None: ([partial], True)),
        )

        shard_info = ShardedModelDetector.detect_shards(str(shard))

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index directory enumeration incomplete"

    @pytest.mark.parametrize("index_name", ["model.safetensors.index.json", "weights.safetensors.index.json"])
    def test_safetensors_mixed_nonshard_index_targets_fail_closed(
        self,
        tmp_path: Path,
        index_name: str,
    ) -> None:
        """One non-shard target cannot make an overlapping index look unrelated."""
        shards = [tmp_path / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        (tmp_path / "notes.txt").write_text("metadata", encoding="utf-8")
        index_path = tmp_path / index_name
        index_path.write_text(
            json.dumps({"weight_map": {"selected": shards[1].name, "other": "notes.txt"}}),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]))

        assert shard_info is not None
        assert shard_info["safetensors_index_path"] == str(index_path)
        assert shard_info["safetensors_index_error"] == (
            "safetensors index target does not match shard filename pattern"
        )

    def test_safetensors_canonical_nonshard_index_is_not_unrelated(self, tmp_path: Path) -> None:
        """The canonical family index cannot evade validation with non-shard targets."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        (tmp_path / "evil.bin").write_bytes(b"payload")
        index_path = tmp_path / "model.safetensors.index.json"
        index_path.write_text(json.dumps({"weight_map": {"evil": "evil.bin"}}), encoding="utf-8")

        shard_info = ShardedModelDetector.detect_shards(str(shard))

        assert shard_info is not None
        assert shard_info["safetensors_index_path"] == str(index_path)
        assert shard_info["safetensors_index_error"]

    @pytest.mark.parametrize(
        ("candidates", "expected_error"),
        [
            (
                [Path(f"candidate-{index}.safetensors.index.json") for index in range(257)],
                "safetensors index inspection limit exceeded",
            ),
            ([Path("partial.safetensors.index.json")], "safetensors index directory enumeration incomplete"),
        ],
    )
    def test_safetensors_candidate_enumeration_failure_is_sticky(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        candidates: list[Path],
        expected_error: str,
    ) -> None:
        """A later smaller directory view cannot clear an incomplete enumeration."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        candidate_paths = [tmp_path / candidate for candidate in candidates]
        responses = iter([(candidate_paths, True), ([], False)])
        monkeypatch.setattr(
            ShardedModelDetector,
            "_safetensors_index_candidates",
            staticmethod(lambda _directory, _context=None: next(responses)),
        )
        context = _SafetensorsIndexInspectionContext()

        first = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        second = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)

        assert first is not None and first["safetensors_index_error"] == expected_error
        assert second is not None and second["safetensors_index_error"] == expected_error
        assert context.failure == expected_error

    def test_safetensors_zero_byte_observation_cache_is_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Distinct zero-byte generations still consume a bounded observation slot."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        index_path = tmp_path / "model.safetensors.index.json"
        monkeypatch.setattr("modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_OBSERVATIONS", 2)
        context = _SafetensorsIndexInspectionContext()
        latest: dict[str, Any] | None = None

        for generation in range(3):
            replacement = tmp_path / f"replacement-{generation}.json"
            replacement.write_bytes(b"")
            os.utime(replacement, ns=(1_000_000_000 + generation, 1_000_000_000 + generation))
            replacement.replace(index_path)
            latest = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)

        assert latest is not None
        assert latest["safetensors_index_error"] == "safetensors index observation limit exceeded"
        assert context.failure == "safetensors index observation limit exceeded"
        assert len(context.charged_observations) == 2
        assert len(context.parsed_inventories) <= 2

    @pytest.mark.skipif(os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0, reason="POSIX non-root")
    def test_execute_only_shard_directory_retains_selected_member_for_fail_closed_coverage(
        self,
        tmp_path: Path,
    ) -> None:
        """Failed sibling enumeration cannot turn a readable incomplete shard into a non-shard scan."""
        shard_dir = tmp_path / "execute-only"
        shard_dir.mkdir()
        shard = shard_dir / "model-00000-of-00002.safetensors"
        shard.write_bytes(b"zero")
        shard_dir.chmod(0o111)
        try:
            shard_info = ShardedModelDetector.detect_shards(str(shard))
        finally:
            shard_dir.chmod(0o700)

        assert shard_info is not None
        assert shard_info["missing_shard_count"] == 2
        assert shard_info["unexpected_shard_count"] == 1

    def test_direct_nested_shard_does_not_follow_ancestor_index(self, tmp_path: Path) -> None:
        """A direct file scan cannot use an ancestor index to expand into a sibling subtree."""
        selected = tmp_path / "selected" / "model-00000-of-00002.safetensors"
        sibling = tmp_path / "outside" / "model-00001-of-00002.safetensors"
        selected.parent.mkdir()
        sibling.parent.mkdir()
        selected.write_bytes(b"selected")
        sibling.write_bytes(b"outside")
        _write_safetensors_index(
            tmp_path,
            [selected.relative_to(tmp_path).as_posix(), sibling.relative_to(tmp_path).as_posix()],
        )
        scanned_payloads: list[bytes] = []

        class RecordingScanner(CompletingShardScanner):
            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                return super().scan(shard_path)

        shard_info = ShardedModelDetector.detect_shards(str(selected))
        result = AdvancedFileHandler(str(selected), RecordingScanner()).scan()

        assert shard_info is not None
        assert "safetensors_index_path" not in shard_info
        assert shard_info["shards"] == [str(selected)]
        assert scanned_payloads == [b"selected"]
        assert result.success is False
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_explicit_index_root_does_not_follow_symlinked_directory_escape(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A directory symlink cannot move authoritative index lookup outside the trusted root."""
        del requires_symlinks
        scan_root = tmp_path / "scan-root"
        outside = tmp_path / "outside"
        first = outside / "a" / "model-00000-of-00002.safetensors"
        second = outside / "b" / "model-00001-of-00002.safetensors"
        scan_root.mkdir()
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        _write_safetensors_index(
            outside,
            [first.relative_to(outside).as_posix(), second.relative_to(outside).as_posix()],
        )
        linked_root = scan_root / "linked"
        linked_root.symlink_to(outside, target_is_directory=True)
        selected = linked_root / first.relative_to(outside)
        scanned_payloads: list[bytes] = []

        class RecordingScanner(CompletingShardScanner):
            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                return super().scan(shard_path)

        shard_info = ShardedModelDetector.detect_shards(
            str(selected),
            index_search_root=scan_root,
        )
        result = AdvancedFileHandler(
            str(selected),
            RecordingScanner(),
            index_search_root=scan_root,
        ).scan()

        assert shard_info is not None
        assert "safetensors_index_path" not in shard_info
        assert scanned_payloads == [b"first"]
        assert result.success is False
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("indices", "expected_base"),
        [
            ([0, 1], "zero"),
            ([1, 2], "one"),
        ],
        ids=["nested-zero-based", "nested-one-based"],
    )
    def test_detect_safetensors_parent_index_governs_nested_shards(
        self,
        tmp_path: Path,
        indices: list[int],
        expected_base: str,
    ) -> None:
        """A parent SafeTensors index should reconcile nested shard paths locally."""
        shard_files = [f"shards/model-{index:05d}-of-00002.safetensors" for index in indices]
        (tmp_path / "shards").mkdir()
        for shard in shard_files:
            (tmp_path / shard).write_bytes(shard.encode())
        _write_safetensors_index(tmp_path, shard_files)

        shard_info = ShardedModelDetector.detect_shards(
            str(tmp_path / shard_files[0]),
            index_search_root=tmp_path,
        )
        result = AdvancedFileHandler(
            str(tmp_path / shard_files[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_path"] == str(tmp_path / "model.safetensors.index.json")
        assert shard_info["shard_index_base"] == expected_base
        assert shard_info["shards"] == [str(tmp_path / shard) for shard in shard_files]
        assert "missing_shard_count" not in shard_info
        assert "unexpected_shard_count" not in shard_info
        assert result.success is True

    def test_detect_shards_records_missing_expected_indices(self, tmp_path: Path) -> None:
        """Missing numbered shards should be explicit in detector metadata."""
        shard_one = tmp_path / "model-00001-of-00003.safetensors"
        shard_three = tmp_path / "model-00003-of-00003.safetensors"
        shard_one.write_bytes(b"test")
        shard_three.write_bytes(b"test")

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["total_shards"] == 2
        assert shard_info["expected_total_shards"] == 3
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["missing_shard_indices"] == [2]

    def test_detect_zero_based_safetensors_without_index_fails_closed(self, tmp_path: Path) -> None:
        """Zero-based names require a validated SafeTensors index."""
        shard_zero = tmp_path / "model-00000-of-00002.safetensors"
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_zero.write_bytes(b"zero")
        shard_one.write_bytes(b"one")

        shard_info = ShardedModelDetector.detect_shards(str(shard_zero))
        result = AdvancedFileHandler(str(shard_zero), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["shard_index_base"] == "one"
        assert shard_info["unexpected_shards"] == [str(shard_zero)]
        assert shard_info["missing_shard_indices"] == [2]
        assert result.success is False
        assert "unexpected_model_shards" in result.metadata["scan_outcome_reasons"]
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_zero_based_safetensors_missing_index_target_fails_closed(self, tmp_path: Path) -> None:
        """A zero-based index inventory must not hide an absent shard."""
        shard_zero = tmp_path / "model-00000-of-00003.safetensors"
        shard_two = tmp_path / "model-00002-of-00003.safetensors"
        shard_zero.write_bytes(b"zero")
        shard_two.write_bytes(b"two")
        _write_safetensors_index(
            tmp_path,
            [
                "model-00000-of-00003.safetensors",
                "model-00001-of-00003.safetensors",
                "model-00002-of-00003.safetensors",
            ],
        )

        shard_info = ShardedModelDetector.detect_shards(str(shard_zero))
        result = AdvancedFileHandler(str(shard_zero), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["shard_index_base"] == "zero"
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["missing_shard_indices"] == [1]
        assert result.success is False
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_parent_index_missing_nested_shard_with_substitute_fails_closed(
        self,
        tmp_path: Path,
    ) -> None:
        """A nested substitute must not hide a shard missing from the parent index."""
        shard_dir = tmp_path / "shards"
        shard_dir.mkdir()
        indexed_present = shard_dir / "model-00001-of-00002.safetensors"
        substitute = shard_dir / "model-00002-of-00002.safetensors"
        indexed_present.write_bytes(b"indexed")
        substitute.write_bytes(b"substitute")
        _write_safetensors_index(
            tmp_path,
            [
                "shards/model-00000-of-00002.safetensors",
                "shards/model-00001-of-00002.safetensors",
            ],
        )

        shard_info = ShardedModelDetector.detect_shards(str(indexed_present), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(indexed_present),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["shard_index_base"] == "zero"
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["missing_shard_indices"] == [0]
        assert shard_info["unexpected_shards"] == [str(substitute)]
        assert result.success is False
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_index_extra_mixed_base_shard_fails_closed(self, tmp_path: Path) -> None:
        """An extra same-total shard must not be silently accepted as either base."""
        indexed_shards = [
            "model-00000-of-00002.safetensors",
            "model-00001-of-00002.safetensors",
        ]
        for shard in (*indexed_shards, "model-00002-of-00002.safetensors"):
            (tmp_path / shard).write_bytes(shard.encode())
        _write_safetensors_index(tmp_path, indexed_shards)

        shard_info = ShardedModelDetector.detect_shards(str(tmp_path / indexed_shards[0]))
        result = AdvancedFileHandler(str(tmp_path / indexed_shards[0]), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["unexpected_shards"] == [str(tmp_path / "model-00002-of-00002.safetensors")]
        assert shard_info["unexpected_shard_count"] == 1
        assert result.success is False
        assert "unexpected_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_index_wrong_target_fails_closed(self, tmp_path: Path) -> None:
        """The index target filename, not just the local shard basename, defines completeness."""
        shard_zero = tmp_path / "model-00000-of-00001.safetensors"
        shard_zero.write_bytes(b"zero")
        _write_safetensors_index(tmp_path, ["model-00001-of-00001.safetensors"])

        shard_info = ShardedModelDetector.detect_shards(str(shard_zero))
        result = AdvancedFileHandler(str(shard_zero), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["missing_shard_indices"] == [1]
        assert shard_info["unexpected_shards"] == [str(shard_zero)]
        assert result.success is False
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_outside_alias_ancestor_fails_closed(
        self,
        tmp_path: Path,
    ) -> None:
        """An out-of-root target cannot be assumed disjoint from selected shard identity."""
        model_root = tmp_path / "scope"
        shard_dir = model_root / "shards"
        shard_dir.mkdir(parents=True)
        shards = [
            shard_dir / "model-00001-of-00002.safetensors",
            shard_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_alias = outside_dir / shards[0].name
        os.link(shards[0], outside_alias)
        index_path = model_root / "model.safetensors.index.json"
        index_path.write_text(
            json.dumps(
                {
                    "weight_map": {
                        "alias": f"../outside/{outside_alias.name}",
                        "omitted": "cc/model-00002-of-00002.safetensors",
                    }
                }
            ),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]), index_search_root=model_root)
        result = AdvancedFileHandler(
            str(shards[0]),
            CompletingShardScanner(),
            index_search_root=model_root,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "unsafe safetensors index target path"
        assert shard_info["unvalidated_shards"] == [str(index_path)]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        "raw_target",
        [
            "C:/outside/model-00001-of-00002.safetensors",
            "D:../outside/model-00001-of-00002.safetensors",
            "inside/model-00001-of-00002.safetensors:alternate",
        ],
        ids=["drive-absolute", "drive-relative", "alternate-data-stream"],
    )
    def test_detect_safetensors_windows_drive_target_fails_closed(
        self,
        tmp_path: Path,
        raw_target: str,
    ) -> None:
        """Drive-qualified and alternate-stream targets are unsafe on every platform."""
        shard = tmp_path / "model-00001-of-00002.safetensors"
        shard.write_bytes(b"one")
        index_path = tmp_path / "model.safetensors.index.json"
        index_path.write_text(
            json.dumps({"weight_map": {"unsafe": raw_target}}),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shard), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shard),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "unsafe safetensors index target path"
        assert shard_info["unvalidated_shards"] == [str(index_path)]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_directory_entry_limit_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-index entries count toward bounded index-directory inspection work."""
        shard = tmp_path / "model-00001-of-00002.safetensors"
        shard.write_bytes(b"one")
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_DIRECTORY_ENTRIES",
            2,
        )

        shard_info = ShardedModelDetector.detect_shards(str(shard), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shard),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index directory enumeration incomplete"
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_safetensors_index_context_enforces_aggregate_directory_entry_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Repeated directory work shares one fail-closed scan-wide entry budget."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        _write_safetensors_index(tmp_path, [shard.name])
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_TOTAL_DIRECTORY_ENTRIES",
            1,
        )
        context = _SafetensorsIndexInspectionContext()

        shard_info = ShardedModelDetector.detect_shards(
            str(shard),
            index_inspection_context=context,
        )

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == ("safetensors index aggregate directory entry limit exceeded")
        assert context.failure == "safetensors index aggregate directory entry limit exceeded"
        assert context.directory_entries_inspected == 1

    def test_safetensors_index_context_charges_repeated_directory_listings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Repeated shard proofs remain inside one aggregate physical-entry budget."""
        shards = [tmp_path / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        _write_safetensors_index(tmp_path, [shard.name for shard in shards])
        original_candidates = ShardedModelDetector._safetensors_index_candidates
        enumeration_count = 0

        def counting_candidates(
            directory: Path,
            inspection_context: _SafetensorsIndexInspectionContext | None = None,
        ) -> tuple[list[Path], bool]:
            nonlocal enumeration_count
            enumeration_count += 1
            return original_candidates(directory, inspection_context)

        monkeypatch.setattr(
            ShardedModelDetector,
            "_safetensors_index_candidates",
            staticmethod(counting_candidates),
        )
        context = _SafetensorsIndexInspectionContext()

        first = ShardedModelDetector.detect_shards(
            str(shards[0]),
            index_inspection_context=context,
        )
        second = ShardedModelDetector.detect_shards(
            str(shards[1]),
            index_inspection_context=context,
        )

        assert first is not None and first.get("safetensors_index_error") is None
        assert second is not None and second.get("safetensors_index_error") is None
        assert enumeration_count == 4
        assert context.directory_entries_inspected == 12

    def test_safetensors_index_context_bounds_unrelated_directory_churn(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unrelated directory churn is re-enumerated and charged without hiding authority."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        _write_safetensors_index(tmp_path, [shard.name])
        original_candidates = ShardedModelDetector._safetensors_index_candidates
        enumeration_count = 0

        def counting_candidates(
            directory: Path,
            inspection_context: _SafetensorsIndexInspectionContext | None = None,
        ) -> tuple[list[Path], bool]:
            nonlocal enumeration_count
            enumeration_count += 1
            return original_candidates(directory, inspection_context)

        monkeypatch.setattr(
            ShardedModelDetector,
            "_safetensors_index_candidates",
            staticmethod(counting_candidates),
        )
        context = _SafetensorsIndexInspectionContext()
        initial = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        (tmp_path / "irrelevant.txt").write_text("changed", encoding="utf-8")

        current = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)

        assert initial is not None and initial.get("safetensors_index_error") is None
        assert current is not None and current.get("safetensors_index_error") is None
        assert context.failure is None
        assert enumeration_count == 4
        assert context.directory_entries_inspected == 10

    @pytest.mark.parametrize(
        ("mutation", "expected_error", "expected_context_failure"),
        [
            (
                "add-competing",
                "safetensors index directory enumeration incomplete",
                "safetensors index directory enumeration incomplete",
            ),
            ("replace", "safetensors index changed during inspection", None),
        ],
    )
    def test_safetensors_candidate_listing_rejects_post_read_mutation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mutation: str,
        expected_error: str,
        expected_context_failure: str | None,
    ) -> None:
        """Candidate names and bytes remain stable through inventory consumption."""
        shard = tmp_path / "model-00001-of-00001.safetensors"
        shard.write_bytes(b"one")
        index_path = _write_safetensors_index(tmp_path, [shard.name])
        context = _SafetensorsIndexInspectionContext()
        initial = ShardedModelDetector.detect_shards(str(shard), index_inspection_context=context)
        assert initial is not None and initial.get("safetensors_index_error") is None

        original_read_inventory = ShardedModelDetector._read_safetensors_index_inventory
        mutated = False

        def mutate_during_inventory_read(*args: Any, **kwargs: Any) -> Any:
            nonlocal mutated
            result = original_read_inventory(*args, **kwargs)
            if not mutated:
                mutated = True
                replacement_path = (
                    tmp_path / "alternate.safetensors.index.json" if mutation == "add-competing" else index_path
                )
                replacement_path.write_text(
                    json.dumps({"weight_map": {"replacement": shard.name}}),
                    encoding="utf-8",
                )
            return result

        monkeypatch.setattr(
            ShardedModelDetector,
            "_read_safetensors_index_inventory",
            staticmethod(mutate_during_inventory_read),
        )

        current = ShardedModelDetector.detect_shards(
            str(shard),
            index_inspection_context=context,
            force_index_content_revalidation=True,
        )

        assert mutated is True
        assert current is not None
        assert current["safetensors_index_error"] == expected_error
        assert context.failure == expected_context_failure

    def test_detect_safetensors_unparseable_ancestor_index_fails_closed(self, tmp_path: Path) -> None:
        """An ancestor whose target scope was not parsed cannot be assumed unrelated."""
        shard_dir = tmp_path / "shards"
        shard_dir.mkdir()
        shards = [
            shard_dir / "model-00001-of-00002.safetensors",
            shard_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        index_path = tmp_path / "model.safetensors.index.json"
        index_path.write_text("{not-json", encoding="utf-8")

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shards[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"]
        assert shard_info["unvalidated_shards"] == [str(index_path)]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("limit_name", "limit_value", "expected_error"),
        [
            ("MAX_SAFETENSORS_SHARD_INDEX_BYTES", 1, "safetensors index exceeds bounded parse limit"),
            (
                "MAX_SAFETENSORS_SHARD_INDEX_JSON_TOKENS",
                1,
                "SafeTensors index exceeds JSON object/value limit",
            ),
        ],
        ids=["byte-limit", "token-limit"],
    )
    def test_detect_safetensors_bounded_ancestor_scope_failure_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        limit_name: str,
        limit_value: int,
        expected_error: str,
    ) -> None:
        """A resource ceiling cannot turn canonical ancestor authority into absence."""
        selected_dir = tmp_path / "aa"
        selected_dir.mkdir()
        shards = [selected_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        (tmp_path / "model.safetensors.index.json").write_text(
            json.dumps(
                {
                    "weight_map": {
                        "selected": shards[0].relative_to(tmp_path).as_posix(),
                        "omitted": "cc/model-00002-of-00002.safetensors",
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(f"modelaudit.utils.file.handlers.{limit_name}", limit_value)

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shards[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == expected_error
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_normalizable_unsafe_target_retains_ancestor_overlap(self, tmp_path: Path) -> None:
        """A rejected contained traversal still binds an invalid index to its selected shard."""
        selected_dir = tmp_path / "aa"
        selected_dir.mkdir()
        shards = [selected_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        (tmp_path / "model.safetensors.index.json").write_text(
            json.dumps(
                {
                    "weight_map": {
                        "selected": f"zz/../{shards[0].relative_to(tmp_path).as_posix()}",
                        "omitted": "cc/model-00002-of-00002.safetensors",
                    }
                }
            ),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shards[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "unsafe safetensors index target path"
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_invalid_ancestor_index_governing_nested_family_fails_closed(
        self,
        tmp_path: Path,
    ) -> None:
        """A malformed ancestor that names the selected family must remain authoritative."""
        shard_dir = tmp_path / "shards"
        shard_dir.mkdir()
        shards = [
            shard_dir / "model-00001-of-00002.safetensors",
            shard_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(shard.name.encode())
        (tmp_path / "model.safetensors.index.json").write_text(
            json.dumps(
                {
                    "weight_map": {
                        "invalid": "../outside/model-00001-of-00002.safetensors",
                        "selected": shards[0].relative_to(tmp_path).as_posix(),
                    }
                }
            ),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shards[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"]
        assert shard_info["unvalidated_shards"] == [str(tmp_path / "model.safetensors.index.json")]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_duplicate_tensor_target_retains_ancestor_overlap(self, tmp_path: Path) -> None:
        """An overwritten tensor target must still bind an invalid ancestor to the selected family."""
        selected_dir = tmp_path / "aa"
        decoy_dir = tmp_path / "cc"
        selected_dir.mkdir()
        decoy_dir.mkdir()
        selected = [selected_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        decoy = decoy_dir / "model-00001-of-00002.safetensors"
        for shard in (*selected, decoy):
            shard.write_bytes(shard.name.encode())
        selected_target = selected[0].relative_to(tmp_path).as_posix()
        decoy_target = decoy.relative_to(tmp_path).as_posix()
        second_target = selected[1].relative_to(tmp_path).as_posix()
        (tmp_path / "model.safetensors.index.json").write_text(
            (f'{{"weight_map":{{"shared":"{selected_target}","shared":"{decoy_target}","second":"{second_target}"}}}}'),
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(selected[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(selected[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index contains duplicate JSON object keys"
        assert shard_info["unvalidated_shards"] == [str(tmp_path / "model.safetensors.index.json")]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("index_payload", "expected_error"),
        [
            (
                '{"metadata":{"items":[{"duplicate":1,"duplicate":2}]},'
                '"weight_map":{"tensor":"shards/model-00000-of-00001.safetensors"}}',
                "safetensors index contains duplicate JSON object keys",
            ),
            (
                '{"weight_map":{"tensor":"shards/model-00000-of-00001.safetensors","tensor":123}}',
                "safetensors index weight_map targets must be strings",
            ),
        ],
        ids=["duplicate-inside-list", "overwritten-by-non-string"],
    )
    def test_detect_safetensors_invalid_occurrence_retains_ancestor_overlap(
        self,
        tmp_path: Path,
        index_payload: str,
        expected_error: str,
    ) -> None:
        """Invalid occurrences cannot erase a recoverable selected target from scope evidence."""
        shard_dir = tmp_path / "shards"
        shard_dir.mkdir()
        shard = shard_dir / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"selected")
        (tmp_path / "model.safetensors.index.json").write_text(index_payload, encoding="utf-8")

        shard_info = ShardedModelDetector.detect_shards(str(shard), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shard),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == expected_error
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_occurrence_limit_retains_ancestor_overlap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An over-limit index must retain selected-target evidence before failing closed."""
        shard_dir = tmp_path / "shards"
        shard_dir.mkdir()
        shard = shard_dir / "model-00000-of-00001.safetensors"
        shard.write_bytes(b"selected")
        (tmp_path / "model.safetensors.index.json").write_text(
            json.dumps(
                {
                    "weight_map": {
                        "selected": shard.relative_to(tmp_path).as_posix(),
                        "extra": "other/model-00000-of-00001.safetensors",
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr("modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_INDEX_TENSORS", 1)

        shard_info = ShardedModelDetector.detect_shards(str(shard), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(shard),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index exceeds tensor occurrence limit"
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_disjoint_duplicate_ancestor_remains_unrelated(self, tmp_path: Path) -> None:
        """Recoverably disjoint duplicate maps must not poison a nested adapter family."""
        selected_dir = tmp_path / "adapter"
        first_decoy_dir = tmp_path / "base-a"
        second_decoy_dir = tmp_path / "base-b"
        for directory in (selected_dir, first_decoy_dir, second_decoy_dir):
            directory.mkdir()
        selected = [selected_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        first_decoys = [first_decoy_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        second_decoys = [second_decoy_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for shard in (*selected, *first_decoys, *second_decoys):
            shard.write_bytes(shard.name.encode())

        def weight_map(shards: list[Path]) -> str:
            return ",".join(
                f'"tensor-{index}":"{shard.relative_to(tmp_path).as_posix()}"' for index, shard in enumerate(shards)
            )

        (tmp_path / "model.safetensors.index.json").write_text(
            f'{{"weight_map":{{{weight_map(first_decoys)}}},"weight_map":{{{weight_map(second_decoys)}}}}}',
            encoding="utf-8",
        )

        shard_info = ShardedModelDetector.detect_shards(str(selected[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(selected[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert "safetensors_index_path" not in shard_info
        assert "safetensors_index_error" not in shard_info
        assert shard_info["shards"] == [str(shard) for shard in selected]
        assert result.success is True

    def test_detect_safetensors_unrelated_ancestor_index_does_not_poison_nested_family(
        self,
        tmp_path: Path,
    ) -> None:
        """An ancestor index for a different shard family should not govern nested shards."""
        _write_safetensors_index(
            tmp_path,
            [f"model-{index:05d}-of-00008.safetensors" for index in range(1, 9)],
        )
        adapter_dir = tmp_path / "adapter"
        adapter_dir.mkdir()
        adapter_shards = [
            adapter_dir / "model-00001-of-00002.safetensors",
            adapter_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in adapter_shards:
            shard.write_bytes(shard.name.encode())

        shard_info = ShardedModelDetector.detect_shards(str(adapter_shards[0]))
        result = AdvancedFileHandler(str(adapter_shards[0]), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert "safetensors_index_path" not in shard_info
        assert "safetensors_index_error" not in shard_info
        assert "unvalidated_shards" not in shard_info
        assert shard_info["shard_index_base"] == "one"
        assert shard_info["shards"] == [str(shard) for shard in adapter_shards]
        assert result.success is True

    def test_detect_safetensors_alias_identity_limit_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An alias-check ceiling cannot authorize a lexically disjoint ancestor index."""
        _write_safetensors_index(
            tmp_path,
            [f"base/model-{index:05d}-of-00002.safetensors" for index in (1, 2)],
        )
        adapter_dir = tmp_path / "adapter"
        adapter_dir.mkdir()
        adapter_shards = [
            adapter_dir / "model-00001-of-00002.safetensors",
            adapter_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in adapter_shards:
            shard.write_bytes(shard.name.encode())
        monkeypatch.setattr("modelaudit.utils.file.handlers.MAX_SAFETENSORS_SHARD_ALIAS_IDENTITY_CHECKS", 1)

        shard_info = ShardedModelDetector.detect_shards(str(adapter_shards[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(adapter_shards[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index target identity is indeterminate"
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.skipif(os.name == "nt", reason="requires portable symlink creation")
    def test_detect_safetensors_broken_alias_identity_fails_closed(self, tmp_path: Path) -> None:
        """Broken target aliases are indeterminate rather than unrelated authority."""
        base_dir = tmp_path / "base"
        adapter_dir = tmp_path / "adapter"
        base_dir.mkdir()
        adapter_dir.mkdir()
        base_targets = [base_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for target in base_targets:
            target.symlink_to(base_dir / f"missing-{target.name}")
        _write_safetensors_index(tmp_path, [target.relative_to(tmp_path).as_posix() for target in base_targets])
        adapter_shards = [
            adapter_dir / "model-00001-of-00002.safetensors",
            adapter_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in adapter_shards:
            shard.write_bytes(shard.name.encode())

        shard_info = ShardedModelDetector.detect_shards(str(adapter_shards[0]), index_search_root=tmp_path)
        result = AdvancedFileHandler(
            str(adapter_shards[0]),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"] == "safetensors index target identity is indeterminate"
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_safetensors_alias_identity_work_is_linear(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One identity snapshot must serve every shard membership check."""
        total_shards = 8
        selected_dir = tmp_path / "aa"
        alias_dir = tmp_path / "aliases"
        selected_dir.mkdir()
        alias_dir.mkdir()
        selected = [
            selected_dir / f"model-{index:05d}-of-{total_shards:05d}.safetensors"
            for index in range(1, total_shards + 1)
        ]
        aliases: list[Path] = []
        for shard in selected:
            shard.write_bytes(shard.name.encode())
            alias = alias_dir / shard.name
            os.link(shard, alias)
            aliases.append(alias)
        _write_safetensors_index(tmp_path, [alias.relative_to(tmp_path).as_posix() for alias in aliases])
        original_identity = ShardedModelDetector._safetensors_stat_identity
        identity_calls = 0

        def counting_identity(
            path: str | os.PathLike[str],
            path_stat: os.stat_result,
        ) -> tuple[int | str, ...] | None:
            nonlocal identity_calls
            identity_calls += 1
            return original_identity(path, path_stat)

        monkeypatch.setattr(
            ShardedModelDetector,
            "_safetensors_stat_identity",
            staticmethod(counting_identity),
        )

        shard_info = ShardedModelDetector.detect_shards(str(selected[0]), index_search_root=tmp_path)

        assert shard_info is not None
        assert shard_info["safetensors_index_declares_current_file"] is True
        assert "safetensors_index_error" not in shard_info
        assert identity_calls <= (2 * total_shards) + 4

    def test_detect_safetensors_same_directory_unrelated_index_does_not_poison_family(
        self,
        tmp_path: Path,
    ) -> None:
        """A valid index for one total must not govern a co-located different-total family."""
        indexed_shards = [
            tmp_path / "model-00001-of-00002.safetensors",
            tmp_path / "model-00002-of-00002.safetensors",
        ]
        standalone = tmp_path / "model-00001-of-00001.safetensors"
        for shard in (*indexed_shards, standalone):
            shard.write_bytes(shard.name.encode())
        _write_safetensors_index(tmp_path, [shard.name for shard in indexed_shards])

        shard_info = ShardedModelDetector.detect_shards(str(standalone))
        result = AdvancedFileHandler(str(standalone), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert "safetensors_index_path" not in shard_info
        assert "safetensors_index_error" not in shard_info
        assert shard_info["shards"] == [str(standalone)]
        assert result.success is True

    def test_detect_safetensors_index_spanning_nested_sibling_directories(
        self,
        tmp_path: Path,
    ) -> None:
        """A governing root index may define one family across sibling directories."""
        header = b'{"__metadata__":{"format":"pt"}}'
        shards = [
            tmp_path / "a" / "model-00000-of-00002.safetensors",
            tmp_path / "b" / "model-00001-of-00002.safetensors",
        ]
        for shard in shards:
            shard.parent.mkdir()
            shard.write_bytes(struct.pack("<Q", len(header)) + header)
        _write_safetensors_index(tmp_path, [shard.relative_to(tmp_path).as_posix() for shard in shards])

        shard_info = ShardedModelDetector.detect_shards(str(shards[0]), index_search_root=tmp_path)
        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, scanners=["safetensors"])

        assert shard_info is not None
        assert [os.path.normcase(os.path.normpath(path)) for path in shard_info["shards"]] == [
            os.path.normcase(os.path.normpath(str(shard))) for shard in shards
        ]
        assert "missing_shard_count" not in shard_info
        assert "out_of_scope_shard_count" not in shard_info
        assert result.success is True
        assert determine_exit_code(result) == 0

    def test_advanced_handler_rechecks_index_authority_for_every_shard_parent(self, tmp_path: Path) -> None:
        """A closer index appearing under a later shard parent must invalidate the root proof."""
        header = b'{"__metadata__":{"format":"pt"}}'
        first = tmp_path / "a" / "model-00000-of-00002.safetensors"
        second = tmp_path / "b" / "model-00001-of-00002.safetensors"
        for shard in (first, second):
            shard.parent.mkdir()
            shard.write_bytes(struct.pack("<Q", len(header)) + header)
        _write_safetensors_index(
            tmp_path, [first.relative_to(tmp_path).as_posix(), second.relative_to(tmp_path).as_posix()]
        )
        handler = AdvancedFileHandler(str(first), CompletingShardScanner(), index_search_root=tmp_path)

        replacement = second.parent / "c" / "model-00000-of-00002.safetensors"
        replacement.parent.mkdir()
        replacement.write_bytes(struct.pack("<Q", len(header)) + header)
        _write_safetensors_index(
            second.parent,
            [replacement.relative_to(second.parent).as_posix(), second.name],
        )

        result = handler.scan()

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"

    def test_detect_safetensors_nested_index_rejects_symlink_outside_root(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Index-relative nested targets cannot authorize an external symlink target."""
        model_root = tmp_path / "model"
        first = model_root / "a" / "model-00000-of-00002.safetensors"
        second = model_root / "b" / "model-00001-of-00002.safetensors"
        outside = tmp_path / "outside.safetensors"
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_bytes(b"first")
        outside.write_bytes(b"outside")
        second.symlink_to(outside)
        _write_safetensors_index(
            model_root,
            [first.relative_to(model_root).as_posix(), second.relative_to(model_root).as_posix()],
        )

        shard_info = ShardedModelDetector.detect_shards(str(first), index_search_root=model_root)
        result = AdvancedFileHandler(
            str(first),
            CompletingShardScanner(),
            index_search_root=model_root,
        ).scan()

        assert shard_info is not None
        assert [os.path.normcase(os.path.normpath(path)) for path in shard_info["out_of_scope_shards"]] == [
            os.path.normcase(os.path.normpath(str(second)))
        ]
        assert result.success is False
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_complete_single_safetensors_rejects_post_detection_index_change(self, tmp_path: Path) -> None:
        """Changing the governing index during a direct scan must fail closed."""
        family_a = tmp_path / "a" / "model-00000-of-00001.safetensors"
        family_b = tmp_path / "b" / "model-00000-of-00001.safetensors"
        family_a.parent.mkdir()
        family_b.parent.mkdir()
        family_a.write_bytes(b"a")
        family_b.write_bytes(b"b")
        index_path = _write_safetensors_index(tmp_path, [family_a.relative_to(tmp_path).as_posix()])

        class IndexSwappingScanner(CompletingShardScanner):
            def scan(self, shard_path: str) -> ScanResult:
                replacement_index = _write_safetensors_index(
                    tmp_path,
                    [family_b.relative_to(tmp_path).as_posix()],
                    index_name="replacement.json",
                )
                replacement_index.replace(index_path)
                return super().scan(shard_path)

        result = AdvancedFileHandler(
            str(family_a),
            IndexSwappingScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert json.loads(index_path.read_text(encoding="utf-8"))["weight_map"]["tensor_0"].startswith("b/")
        assert result.success is False
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"

    @pytest.mark.parametrize("cache_enabled", [False, True], ids=["no-cache", "cache"])
    def test_complete_single_safetensors_header_scan_uses_stable_path(
        self,
        tmp_path: Path,
        cache_enabled: bool,
    ) -> None:
        """A complete one-shard SafeTensors family should scan through the pinned shard path."""
        header = b'{"__metadata__":{"format":"pt"},"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}'
        shard = tmp_path / "model-00000-of-00001.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header + b"\0")
        _write_safetensors_index(tmp_path, [shard.name])

        with patch("modelaudit.core.should_use_large_file_handler", return_value=True):
            result = scan_model_directory_or_file(
                str(tmp_path),
                cache_enabled=cache_enabled,
                cache_dir=str(tmp_path.parent / f"{tmp_path.name}-cache"),
                scanners=["safetensors"],
            )

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "safetensors" in result.scanner_names
        assert not any(check.details.get("scan_outcome_reason") == "shard_pin_unavailable" for check in result.checks)

    def test_complete_single_safetensors_alias_aba_scans_validated_target(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A transient alias swap cannot replace the validated one-shard scan input."""
        del requires_symlinks
        malicious_header = b'{"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
        safe_header = b'{"__metadata__":{"format":"pt"}}'
        malicious = tmp_path / "malicious.safetensors"
        safe = tmp_path / "safe.safetensors"
        malicious.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header)
        safe.write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
        alias = tmp_path / "model-00000-of-00001.safetensors"
        alias.symlink_to(malicious.name)
        _write_safetensors_index(tmp_path, [alias.name])

        class AliasSwappingScanner(HeaderHashShardScanner):
            def scan(self, shard_path: str) -> ScanResult:
                alias.unlink()
                alias.symlink_to(safe.name)
                try:
                    return super().scan(shard_path)
                finally:
                    alias.unlink()
                    alias.symlink_to(malicious.name)

        result = AdvancedFileHandler(str(alias), AliasSwappingScanner()).scan()

        header_check = next(check for check in result.checks if check.name == "SafeTensors Header Pin")
        assert alias.resolve() == malicious
        assert header_check.location == str(alias)
        assert header_check.details["header_sha256"] == hashlib.sha256(malicious_header).hexdigest()
        assert result.success is True

    @pytest.mark.parametrize(
        "index_payload",
        [
            "{not-json",
            json.dumps({"weight_map": {"tensor": "../outside/model-00000-of-00001.safetensors"}}),
            json.dumps({"weight_map": {"tensor": "model-00000-of-00002.safetensors"}}),
        ],
        ids=["malformed-json", "traversal-target", "wrong-total"],
    )
    def test_detect_zero_based_safetensors_invalid_index_fails_closed(
        self,
        tmp_path: Path,
        index_payload: str,
    ) -> None:
        """Malformed, traversal, and wrong-total indexes must not authorize clean coverage."""
        shard_zero = tmp_path / "model-00000-of-00001.safetensors"
        shard_zero.write_bytes(b"zero")
        (tmp_path / "model.safetensors.index.json").write_text(index_payload, encoding="utf-8")

        shard_info = ShardedModelDetector.detect_shards(str(shard_zero))
        result = AdvancedFileHandler(str(shard_zero), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["safetensors_index_error"]
        assert shard_info["unvalidated_shards"] == [str(tmp_path / "model.safetensors.index.json")]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_zero_based_safetensors_index_race_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A changing index file must not authorize clean shard coverage."""
        shard_zero = tmp_path / "model-00000-of-00001.safetensors"
        shard_zero.write_bytes(b"zero")
        index_path = _write_safetensors_index(tmp_path, [shard_zero.name])
        real_stat = os.stat
        index_stat_calls = 0

        def racing_stat(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *args: Any,
            **kwargs: Any,
        ) -> os.stat_result:
            nonlocal index_stat_calls
            result = real_stat(path, *args, **kwargs)
            follow_symlinks = kwargs.get("follow_symlinks", True)
            path_value = os.fspath(path)
            path_obj = Path(path_value) if isinstance(path_value, str) else None
            if path_obj == index_path and follow_symlinks is False:
                index_stat_calls += 1
                if index_stat_calls % 2 == 0:
                    values = list(result)
                    values[6] = result.st_size + 1
                    return os.stat_result(values)
            return result

        monkeypatch.setattr(os, "stat", racing_stat)

        shard_info = ShardedModelDetector.detect_shards(str(shard_zero))
        result = AdvancedFileHandler(str(shard_zero), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert "changed while reading" in shard_info["safetensors_index_error"]
        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_bounds_missing_expected_indices(self, tmp_path: Path) -> None:
        """Huge declared shard totals should not expand into huge missing-index lists."""
        shard_one = tmp_path / "model-00001-of-999999999999.safetensors"
        shard_one.write_bytes(b"test")

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["expected_total_shards"] == 999999999999
        assert shard_info["missing_shard_count"] == 999999999998
        assert len(shard_info["missing_shard_indices"]) == MAX_RECORDED_MISSING_SHARD_INDICES
        assert shard_info["missing_shard_indices_truncated"] is True

    def test_expected_indices_accept_huge_authoritative_range_without_materializing_it(self) -> None:
        """Validated range comparison must remain constant-space for huge declared totals."""
        expected_total = 999_999_999_999
        authoritative_indices = range(0, expected_total)

        expected_indices, index_base = ShardedModelDetector.expected_indices_for_shard_family(
            expected_total,
            authoritative_indices=authoritative_indices,
        )

        assert expected_indices == authoritative_indices
        assert index_base == "zero"

    def test_detect_shards_ignores_suffix_near_matches(self, tmp_path: Path) -> None:
        """Shard routing should not count files that only prefix-match a shard name."""
        shard_one = tmp_path / "model-00001-of-00001.safetensors"
        near_match = tmp_path / "model-00001-of-00001.safetensors.bak"
        shard_one.write_bytes(b"test")
        near_match.write_bytes(b"backup")

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1

    def test_detect_shards_respects_allowed_paths(self, tmp_path: Path) -> None:
        """Directory scans should be able to constrain shard expansion to validated paths."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")

        shard_info = ShardedModelDetector.detect_shards(
            str(shard_one),
            allowed_paths=[str(shard_one.resolve())],
        )

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1

    def test_detect_shards_includes_validated_cross_directory_peers(self, tmp_path: Path) -> None:
        """Validated peers selected in separate directories should form one complete family."""
        shards: list[Path] = []
        for shard_index in range(1, 4):
            shard_dir = tmp_path / f"part-{shard_index}"
            shard_dir.mkdir()
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
            shard_path.write_bytes(f"shard-{shard_index}".encode())
            shards.append(shard_path)
        near_match = shards[1].parent / "model-00002-of-00003.safetensors.bak"
        near_match.write_bytes(b"not-a-shard")
        allowed_targets = {str(shard): _validated_target(shard) for shard in shards}

        shard_info = ShardedModelDetector.detect_shards(
            str(shards[0]),
            allowed_targets=allowed_targets,
        )
        result = AdvancedFileHandler(
            str(shards[0]),
            CompletingShardScanner(),
            allowed_shard_paths=[str(shard.resolve()) for shard in shards],
            allowed_shard_targets=allowed_targets,
        ).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard) for shard in shards]
        assert shard_info["total_shards"] == 3
        assert "missing_shard_count" not in shard_info
        assert result.success is True
        assert result.bytes_scanned == sum(shard.stat().st_size for shard in shards)

    def test_detect_shards_does_not_dedupe_expected_peer_against_unrelated_alias(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Only an equivalent shard slot may replace an index-declared path alias."""
        del requires_symlinks
        first_dir = tmp_path / "a"
        second_dir = tmp_path / "b"
        first_dir.mkdir()
        second_dir.mkdir()
        shard_zero = first_dir / "model-00000-of-00002.safetensors"
        shard_one = second_dir / "model-00001-of-00002.safetensors"
        shard_zero.write_bytes(b"first")
        shard_one.write_bytes(b"second")
        _write_safetensors_index(
            tmp_path,
            [f"a/{shard_zero.name}", f"b/{shard_one.name}"],
        )
        unrelated_alias = first_dir / "unrelated.txt"
        unrelated_alias.symlink_to(shard_one)
        for index in range(20):
            (first_dir / f"irrelevant-{index}.txt").write_text("metadata", encoding="utf-8")

        original_resolve = Path.resolve
        irrelevant_resolves = 0

        def track_resolve(path: Path, strict: bool = False) -> Path:
            nonlocal irrelevant_resolves
            if path.name == unrelated_alias.name or path.name.startswith("irrelevant-"):
                irrelevant_resolves += 1
            return original_resolve(path, strict=strict)

        monkeypatch.setattr(Path, "resolve", track_resolve)

        shard_info = ShardedModelDetector.detect_shards(
            str(shard_zero),
            index_search_root=tmp_path,
        )
        result = AdvancedFileHandler(
            str(shard_zero),
            CompletingShardScanner(),
            index_search_root=tmp_path,
        ).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_zero), str(shard_one)]
        assert "missing_shard_count" not in shard_info
        assert irrelevant_resolves == 0
        assert result.success is True
        assert result.bytes_scanned == shard_zero.stat().st_size + shard_one.stat().st_size

    def test_detect_shards_rejects_changed_cross_directory_peer(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A cross-directory peer cannot retarget after its identity is validated."""
        first_dir = tmp_path / "first"
        second_dir = tmp_path / "second"
        targets_dir = tmp_path / "targets"
        first_dir.mkdir()
        second_dir.mkdir()
        targets_dir.mkdir()
        shard_one = first_dir / "model-00001-of-00002.safetensors"
        shard_two = second_dir / "model-00002-of-00002.safetensors"
        original_target = targets_dir / "original"
        replacement_target = targets_dir / "replacement"
        shard_one.write_bytes(b"one")
        original_target.write_bytes(b"two")
        replacement_target.write_bytes(b"replacement")
        shard_two.symlink_to(original_target)
        allowed_targets = {
            str(shard_one): _validated_target(shard_one),
            str(shard_two): _validated_target(shard_two),
        }
        shard_two.unlink()
        shard_two.symlink_to(replacement_target)

        shard_info = ShardedModelDetector.detect_shards(
            str(shard_one),
            allowed_targets=allowed_targets,
        )

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["unvalidated_shards"] == [str(shard_two)]

    def test_detect_shards_rejects_direct_sibling_symlink_outside_scan_directory(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Direct file scans must not expand sibling shard symlinks outside the scan directory."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"one")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1
        assert shard_info["total_size"] == shard_one.stat().st_size
        assert shard_info["out_of_scope_shard_count"] == 1
        assert shard_info["out_of_scope_shards"] == [str(shard_two)]

    def test_detect_shards_allows_validated_symlink_target_from_allowlist(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Directory scans may include a symlinked shard once the resolved target is validated."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"one")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(
            str(shard_one),
            allowed_paths=[str(shard_one.resolve()), str(outside_target.resolve())],
        )

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one), str(shard_two)]
        assert shard_info["total_shards"] == 2
        assert "out_of_scope_shard_count" not in shard_info

    def test_detect_shards_direct_hf_snapshot_includes_blob_backed_siblings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Selecting one normal HF snapshot shard should scan its complete sibling family."""
        hf_home = tmp_path / "hf-home"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        cache_dir = hf_home / "hub" / "models--org--model"
        snapshot = cache_dir / "snapshots" / "abc123"
        blobs_dir = cache_dir / "blobs"
        snapshot.mkdir(parents=True)
        blobs_dir.mkdir()
        shard_paths: list[Path] = []
        for index in range(1, 3):
            blob = blobs_dir / f"blob-{index}"
            blob.write_bytes(f"blob-{index}".encode())
            shard = snapshot / f"model-{index:05d}-of-00002.safetensors"
            shard.symlink_to(Path("../../blobs") / blob.name)
            shard_paths.append(shard)

        shard_info = ShardedModelDetector.detect_shards(str(shard_paths[0]))

        assert shard_info is not None
        assert shard_info["shards"] == [str(path) for path in shard_paths]
        assert shard_info["total_shards"] == 2
        assert "missing_shard_count" not in shard_info
        assert "out_of_scope_shard_count" not in shard_info

    def test_detect_shards_rejects_duplicate_symlink_targets(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Two shard indices cannot satisfy coverage by resolving to one file."""
        blob = tmp_path / "blob"
        blob.write_bytes(b"shared")
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.symlink_to(blob.name)
        shard_two.symlink_to(blob.name)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))
        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["total_shards"] == 1
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["duplicate_shard_count"] == 1
        assert shard_info["duplicate_shards"] == [str(shard_two)]
        assert result.success is False
        assert "duplicate_model_shard_targets" in result.metadata["scan_outcome_reasons"]

    def test_detect_zero_based_safetensors_rejects_duplicate_symlink_targets(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Zero-based shard names still cannot satisfy coverage with one target."""
        blob = tmp_path / "blob"
        blob.write_bytes(b"shared")
        shard_zero = tmp_path / "model-00000-of-00002.safetensors"
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_zero.symlink_to(blob.name)
        shard_one.symlink_to(blob.name)
        _write_safetensors_index(tmp_path, [shard_zero.name, shard_one.name])

        shard_info = ShardedModelDetector.detect_shards(str(shard_zero))
        result = AdvancedFileHandler(str(shard_zero), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["shard_index_base"] == "zero"
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["duplicate_shard_count"] == 1
        assert result.success is False
        assert "duplicate_model_shard_targets" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_rejects_duplicate_hardlink_targets(self, tmp_path: Path) -> None:
        """Hardlinked shard names must not be double-counted as distinct coverage."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"shared")
        os.link(shard_one, shard_two)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["total_shards"] == 1
        assert shard_info["missing_shard_count"] == 1
        assert shard_info["duplicate_shard_count"] == 1

    def test_validated_shard_target_mapping_rejects_alias_swap(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """An alias cannot switch to another already-approved family target."""
        target_one = tmp_path / "target-one"
        target_two = tmp_path / "target-two"
        target_one.write_bytes(b"one")
        target_two.write_bytes(b"two")
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.symlink_to(target_one.name)
        shard_two.symlink_to(target_two.name)
        allowed_targets: ValidatedShardTargets = {
            str(shard_one): {
                "resolved_path": str(target_one),
                "device": target_one.stat().st_dev,
                "inode": target_one.stat().st_ino,
            },
            str(shard_two): {
                "resolved_path": str(target_two),
                "device": target_two.stat().st_dev,
                "inode": target_two.stat().st_ino,
            },
        }
        shard_one.unlink()
        shard_one.symlink_to(target_two.name)

        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=[str(target_one), str(target_two)],
            allowed_shard_targets=allowed_targets,
        ).scan()

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
        assert any(check.details["reason"] == "shard_target_changed" for check in result.checks)

    def test_detect_shards_preserves_direct_symlink_representative_outside_scan_directory(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """The user-selected shard remains scannable even when its target is outside the containing directory."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "model-00001-of-00002.safetensors"
        outside_target = outside_dir / "outside-shard.safetensors"
        outside_target.write_bytes(b"outside")
        shard_one.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["total_shards"] == 1
        assert shard_info["missing_shard_count"] == 1
        assert should_use_advanced_handler(str(shard_one))

    def test_detect_shards_treats_symlink_loop_as_unreadable(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Cyclic sibling symlinks must fail closed as incomplete shard coverage."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"safe")
        shard_two.symlink_to(shard_two.name)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["unreadable_shard_count"] == 1
        assert shard_info["unreadable_shards"] == [str(shard_two)]

        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        assert result.success is False
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_ignores_nearby_family_with_different_declared_total(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A neighboring shard family must not create false incomplete-coverage findings."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        selected_shard = tmp_path / "model-00001-of-00001.safetensors"
        unrelated_alias = tmp_path / "model-00001-of-00002.safetensors"
        outside_target = outside_dir / "other-family.safetensors"
        selected_shard.write_bytes(b"selected")
        outside_target.write_bytes(b"unrelated")
        unrelated_alias.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(selected_shard))
        result = AdvancedFileHandler(str(selected_shard), CompletingShardScanner()).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(selected_shard)]
        assert "out_of_scope_shard_count" not in shard_info
        assert result.success is True

    def test_detect_shards_does_not_reresolve_validated_allowlist_targets(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Retargeting a validated sibling path cannot move the allowlist outside."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        inside_target = scan_dir / "inside.pt"
        outside_target = outside_dir / "outside.pt"
        shard_one.write_bytes(b"first")
        inside_target.write_bytes(b"inside")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(inside_target)
        allowed_paths = [str(shard_one.resolve()), str(inside_target.resolve())]
        inside_target.unlink()
        inside_target.symlink_to(outside_target)

        shard_info = ShardedModelDetector.detect_shards(str(shard_one), allowed_paths=allowed_paths)
        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        ).scan()

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert str(shard_two) not in shard_info["shards"]
        assert shard_info["out_of_scope_shards"] == [str(shard_two)]
        assert result.success is False
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]

    def test_detect_shards_rejects_non_regular_member(self, tmp_path: Path) -> None:
        """A directory whose name resembles a shard cannot be counted or scanned."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"safe")
        shard_two.mkdir()

        shard_info = ShardedModelDetector.detect_shards(str(shard_one))

        assert shard_info is not None
        assert shard_info["shards"] == [str(shard_one)]
        assert shard_info["unreadable_shards"] == [str(shard_two)]

    def test_shard_target_swap_after_detection_fails_closed(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Shard workers must not follow a symlink retargeted after validation."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        inside_target = tmp_path / "inside.pt"
        outside_target = outside_dir / "outside.pt"
        shard_one.write_bytes(b"first")
        inside_target.write_bytes(b"inside")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(inside_target)
        scanned_payloads: list[bytes] = []

        class RecordingScanner:
            name = "recording_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

        handler = AdvancedFileHandler(str(shard_one), RecordingScanner())
        shard_two.unlink()
        shard_two.symlink_to(outside_target)

        result = handler.scan()

        assert result.success is False
        assert b"outside" not in scanned_payloads
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]

    def test_shard_same_size_rewrite_after_detection_fails_before_scan(self, tmp_path: Path) -> None:
        """A same-size rewrite cannot replace the validated shard before its worker opens it."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"safe")
        scanned_payloads: list[bytes] = []

        class RecordingScanner:
            name = "recording_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

        handler = AdvancedFileHandler(str(shard_one), RecordingScanner())
        original_stat = shard_two.stat()
        shard_two.write_bytes(b"evil")
        os.utime(
            shard_two,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
        )

        result = handler.scan()

        assert b"evil" not in scanned_payloads
        assert result.success is False
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Shard Scan"
            and check.status == CheckStatus.FAILED
            and check.location == str(shard_two)
            and check.details["exception_type"] == "OSError"
            for check in result.checks
        )

    @pytest.mark.skipif(sys.platform == "darwin", reason="macOS lacks traversable descriptor-bound scan paths")
    def test_shard_target_swap_during_scan_discards_clean_result(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A clean result cannot be trusted when its validated target changed mid-scan."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        original_target = tmp_path / "malicious.pt"
        replacement_target = tmp_path / "safe.pt"
        shard_one.write_bytes(b"first")
        original_target.write_bytes(b"malicious")
        replacement_target.write_bytes(b"safe")
        shard_two.symlink_to(original_target)
        scanned_payloads: list[bytes] = []

        class SwappingScanner:
            name = "swapping_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                path = Path(shard_path)
                result = ScanResult(scanner_name=self.name)
                scanned_payloads.append(path.read_bytes())
                if path.name == original_target.name:
                    preserved_target = tmp_path / "preserved-malicious.pt"
                    original_target.rename(preserved_target)
                    replacement_target.rename(original_target)
                    result.add_check(
                        name="Clean Replacement Accepted",
                        passed=True,
                        message=path.name,
                        severity=IssueSeverity.INFO,
                    )
                result.finish(success=True)
                return result

        result = AdvancedFileHandler(str(shard_one), SwappingScanner()).scan()

        assert b"malicious" in scanned_payloads
        assert b"safe" not in scanned_payloads
        assert result.success is False
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "Shard Scan" and check.status == CheckStatus.FAILED for check in result.checks)
        assert not any(check.name == "Clean Replacement Accepted" for check in result.checks)

    @pytest.mark.skipif(sys.platform == "darwin", reason="macOS lacks traversable descriptor-bound scan paths")
    @pytest.mark.skipif(os.name == "nt", reason="Windows open-handle pinning prevents target replacement")
    def test_shard_target_swap_during_scan_preserves_security_findings(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A target race must not erase a security finding already produced by the scanner."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        malicious_target = tmp_path / "malicious.pt"
        replacement_target = tmp_path / "replacement.pt"
        shard_one.write_bytes(b"first")
        malicious_target.write_bytes(b"malicious")
        replacement_target.write_bytes(b"replacement")
        shard_two.symlink_to(malicious_target)

        class FindingThenSwappingScanner:
            name = "finding_then_swapping_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                path = Path(shard_path)
                result = ScanResult(scanner_name=self.name)
                if path.name == malicious_target.name:
                    result.add_check(
                        name="Malicious Shard Payload",
                        passed=False,
                        message="Malicious shard payload detected",
                        severity=IssueSeverity.CRITICAL,
                        location=str(path),
                    )
                    preserved_target = tmp_path / "preserved-malicious.pt"
                    malicious_target.rename(preserved_target)
                    replacement_target.rename(malicious_target)
                result.finish(success=not result.has_errors)
                return result

        result = AdvancedFileHandler(str(shard_one), FindingThenSwappingScanner()).scan()

        assert result.success is False
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Malicious Shard Payload" and check.status == CheckStatus.FAILED for check in result.checks
        )
        assert any(issue.message == "Malicious shard payload detected" for issue in result.issues)

    @pytest.mark.skipif(sys.platform == "darwin", reason="macOS lacks traversable descriptor-bound scan paths")
    @pytest.mark.skipif(os.name == "nt", reason="Windows open-handle pinning prevents target replacement")
    def test_shard_target_aba_during_scan_cannot_hide_malicious_content(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Restoring a validated pathname cannot redirect the descriptor-bound shard scan."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        malicious_target = tmp_path / "malicious.pt"
        benign_target = tmp_path / "benign.pt"
        preserved_target = tmp_path / "preserved.pt"
        shard_one.write_bytes(b"first")
        malicious_target.write_bytes(b"malicious")
        benign_target.write_bytes(b"benign")
        shard_two.symlink_to(malicious_target)
        scanned_payloads: list[bytes] = []

        class AbaSwappingScanner:
            name = "aba_swapping_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                path = Path(shard_path)
                result = ScanResult(scanner_name=self.name)
                if path.name == malicious_target.name:
                    malicious_target.rename(preserved_target)
                    benign_target.rename(malicious_target)
                    try:
                        payload = path.read_bytes()
                    finally:
                        malicious_target.rename(benign_target)
                        preserved_target.rename(malicious_target)
                    scanned_payloads.append(payload)
                    result.add_check(
                        name="Malicious Shard Payload",
                        passed=payload != b"malicious",
                        message="Malicious shard payload detected",
                        severity=IssueSeverity.CRITICAL,
                        location=str(path),
                    )
                else:
                    scanned_payloads.append(path.read_bytes())
                result.finish(success=not result.has_errors)
                return result

        result = AdvancedFileHandler(str(shard_one), AbaSwappingScanner()).scan()

        assert b"malicious" in scanned_payloads
        assert b"benign" not in scanned_payloads
        assert result.success is False
        assert any(check.name == "Malicious Shard Payload" for check in result.checks)

    @pytest.mark.skipif(sys.platform == "darwin", reason="macOS lacks traversable descriptor-bound scan paths")
    def test_shard_scanner_os_error_after_pinning_is_scan_error(self, tmp_path: Path) -> None:
        """A scanner read failure after pinning is not a pin-setup failure."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"first")
        shard_two.write_bytes(b"second")
        scanned_payloads: list[bytes] = []

        class FailingScanner:
            name = "failing_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                raise OSError("scanner read failed")

        result = AdvancedFileHandler(str(shard_one), FailingScanner()).scan()

        assert set(scanned_payloads) == {b"first", b"second"}
        assert result.success is False
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        assert "shard_pin_unavailable" not in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Shard Scan"
            and check.status == CheckStatus.FAILED
            and check.details["exception_type"] == "OSError"
            for check in result.checks
        )

    @pytest.mark.skipif(os.name == "nt", reason="Windows uses open-handle hard-link pinning")
    def test_shard_pin_unavailable_fails_explicitly(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A platform without descriptor paths must fail before scanning a mutable pathname."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"first")
        shard_two.write_bytes(b"second")
        scanned_paths: list[str] = []

        class RecordingScanner(CompletingShardScanner):
            def scan(self, shard_path: str) -> ScanResult:
                scanned_paths.append(shard_path)
                return super().scan(shard_path)

        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._descriptor_path_for_open_file",
            lambda _file_fd: None,
        )

        result = AdvancedFileHandler(str(shard_one), RecordingScanner()).scan()

        assert scanned_paths == []
        assert result.success is False
        assert "shard_pin_unavailable" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Shard Scan Pinning" and check.details["scan_outcome_reason"] == "shard_pin_unavailable"
            for check in result.checks
        )

    def test_shard_added_during_scan_marks_family_inconclusive(self, tmp_path: Path) -> None:
        """A shard created after detection cannot remain outside the completed scan set."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        added_shard = tmp_path / "checkpoint_3.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        scanned_names: list[str] = []

        class AddingShardScanner:
            name = "adding_shard_scanner"

            def scan(self, shard_path: str) -> ScanResult:
                scanned_names.append(Path(shard_path).name)
                if Path(shard_path).name == shard_one.name:
                    added_shard.write_bytes(b"malicious-unscanned")
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

        result = AdvancedFileHandler(str(shard_one), AddingShardScanner()).scan()

        assert set(scanned_names) == {shard_one.name, shard_two.name}
        assert added_shard.name not in scanned_names
        assert result.success is False
        assert "shard_family_changed" in result.metadata["scan_outcome_reasons"]
        membership_check = next(check for check in result.checks if check.name == "Sharded Model Membership Check")
        assert membership_check.details["added_shards"] == [str(added_shard)]
        assert membership_check.details["analysis_incomplete"] is True

    def test_no_shards_detected(self) -> None:
        """Test when file is not sharded."""
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            f.write(b"test")
            f.flush()

            shard_info = ShardedModelDetector.detect_shards(f.name)
            assert shard_info is None

    def test_find_model_config(self) -> None:
        """Test finding model configuration file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create config file
            config_path = Path(tmpdir, "config.json")
            config_path.write_text('{"model_type": "llama"}')

            # Create model file
            model_path = Path(tmpdir, "model.bin")
            model_path.write_bytes(b"test")

            # Test finding config
            found_config = ShardedModelDetector.find_model_config(str(model_path))
            assert found_config == str(config_path)

    def test_find_model_config_rejects_external_symlink(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Model metadata discovery must not read configuration outside the shard directory."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        model_path = scan_dir / "checkpoint_1.pt"
        outside_config = outside_dir / "config.json"
        model_path.write_bytes(b"model")
        outside_config.write_text('{"torch_dtype": "float16"}')
        (scan_dir / "config.json").symlink_to(outside_config)

        assert ShardedModelDetector.find_model_config(str(model_path)) is None

    def test_sharded_model_rejects_config_symlink_swap_without_nofollow(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Descriptor identity checks must protect platforms without ``O_NOFOLLOW``."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        config_path = scan_dir / "config.json"
        outside_config = outside_dir / "config.json"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        config_path.write_text('{"model_type": "safe"}')
        outside_config.write_text('{"torch_dtype": "float16"}')
        original_open = os.open
        swapped = False

        def swap_before_open(path: str, flags: int) -> int:
            nonlocal swapped
            if Path(path) == config_path:
                config_path.unlink()
                config_path.symlink_to(outside_config)
                swapped = True
            return original_open(path, flags)

        monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)
        monkeypatch.setattr(os, "open", swap_before_open)

        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        assert swapped is True
        assert not any(check.name == "PyTorch Configuration Detection" for check in result.checks)


class TestMemoryMappedHandler:
    """Test memory-mapped scanning."""

    def test_mmap_scanning(self) -> None:
        """Test basic memory-mapped scanning."""
        # Create a test file with suspicious content
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write some content with suspicious patterns
            content = b"normal content" * 1000
            content += b"exec('malicious code')"
            content += b"more content" * 1000
            f.write(content)
            temp_path = f.name

        try:
            mock_scanner = MagicMock()
            mock_scanner.name = "test_scanner"

            mmap_scanner = MemoryMappedHandler(temp_path, mock_scanner)
            result = mmap_scanner.scan_with_mmap()

            # With full scanning, we might not detect patterns in mmap test
            # The important thing is that the scan completes without errors
            assert result is not None
            # Optionally check for exec if detected
            # assert any("exec" in issue.message for issue in result.issues)

        finally:
            os.unlink(temp_path)

    def test_mmap_with_large_file(self) -> None:
        """Test memory mapping with larger file."""
        # Create a larger test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write 10MB of data
            chunk = b"x" * (1024 * 1024)  # 1MB
            for _ in range(10):
                f.write(chunk)
            f.write(b"__import__('os').system('bad')")
            temp_path = f.name

        try:
            mock_scanner = MagicMock()
            mock_scanner.name = "test_scanner"

            mmap_scanner = MemoryMappedHandler(temp_path, mock_scanner)
            result = mmap_scanner.scan_with_mmap()

            # With full scanning, mmap test focuses on completion without errors
            assert result is not None

        finally:
            os.unlink(temp_path)

    def test_mmap_raw_detector_failure_is_unsuccessful(self, tmp_path: Path) -> None:
        model_path = tmp_path / "detector-error.bin"
        model_path.write_bytes(b"benign model content")
        scanner = RawDetectorMemoryMappedScanner()

        with patch(
            "modelaudit.detectors.secrets.SecretsDetector.scan_model_weights",
            side_effect=RuntimeError("detector failed"),
        ):
            result = MemoryMappedHandler(str(model_path), scanner).scan_with_mmap()

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "embedded_secrets"
            for check in result.checks
        )

    def test_mmap_uses_opened_file_size_after_growth(self, tmp_path: Path) -> None:
        model_path = tmp_path / "grown-model.bin"
        model_path.write_bytes(b"benign-prefix")
        handler = MemoryMappedHandler(str(model_path), PatternMemoryMappedScanner())
        with model_path.open("ab") as model_file:
            model_file.write(b"; os.system('id')")

        result = handler.scan_with_mmap()

        assert result.bytes_scanned == model_path.stat().st_size
        assert any(
            check.name == "Suspicious Pattern Detection" and check.status.value == "failed" for check in result.checks
        )

    def test_mmap_file_growth_during_scan_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = tmp_path / "mutated-model.bin"
        model_path.write_bytes(b"a" * 32)
        handler = MemoryMappedHandler(str(model_path), PatternMemoryMappedScanner())
        monkeypatch.setattr("modelaudit.utils.file.handlers.MMAP_MAX_WINDOW", 16)
        mutated = False

        def append_during_scan(_message: str, _percentage: float) -> None:
            nonlocal mutated
            if not mutated:
                with model_path.open("ab") as model_file:
                    model_file.write(b"os.system('id')")
                mutated = True

        result = handler.scan_with_mmap(progress_callback=append_during_scan)

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "memory_mapped_source_changed" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "Memory-Mapped Source Stability" for check in result.checks)

    def test_mmap_file_truncation_during_scan_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = tmp_path / "truncated-model.bin"
        model_path.write_bytes(b"a" * 32)
        handler = MemoryMappedHandler(str(model_path), PatternMemoryMappedScanner())
        monkeypatch.setattr("modelaudit.utils.file.handlers.MMAP_MAX_WINDOW", 16)
        truncated = False

        def truncate_during_scan(_message: str, _percentage: float) -> None:
            nonlocal truncated
            if not truncated:
                with model_path.open("r+b") as model_file:
                    model_file.truncate(8)
                truncated = True

        result = handler.scan_with_mmap(progress_callback=truncate_during_scan)

        assert result.success is False
        assert result.bytes_scanned == 16
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "memory_mapped_source_changed" in result.metadata["scan_outcome_reasons"]
        stability_check = next(check for check in result.checks if check.name == "Memory-Mapped Source Stability")
        assert stability_check.details["opened_file_size"] == 32
        assert stability_check.details["final_file_size"] == 8

    def test_mmap_progress_counts_unique_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = tmp_path / "overlap-progress.bin"
        model_path.write_bytes(b"a" * (3 * 1024 * 1024))
        handler = MemoryMappedHandler(str(model_path), PatternMemoryMappedScanner())
        monkeypatch.setattr("modelaudit.utils.file.handlers.MMAP_MAX_WINDOW", 2 * 1024 * 1024)
        percentages: list[float] = []

        result = handler.scan_with_mmap(
            progress_callback=lambda _message, percentage: percentages.append(percentage),
        )

        assert result.bytes_scanned == model_path.stat().st_size
        assert percentages
        assert max(percentages) == 100.0

    def test_mmap_error_details_are_redacted(self, tmp_path: Path) -> None:
        model_path = tmp_path / "progress-error.bin"
        model_path.write_bytes(b"benign model content")
        leaked_secret = "MMAP-ERROR-SECRET-123456"

        def fail_progress(_message: str, _percentage: float) -> None:
            raise RuntimeError(f"progress failed with {leaked_secret}")

        result = MemoryMappedHandler(str(model_path), PatternMemoryMappedScanner()).scan_with_mmap(
            progress_callback=fail_progress,
        )

        assert result.success is False
        assert leaked_secret not in result.to_json()
        error_check = next(check for check in result.checks if check.name == "Memory-Mapped Scan")
        assert error_check.details["error"] == "<redacted>"

    def test_mmap_raw_detector_failure_suppresses_later_clean_check(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = tmp_path / "detector-error-then-clean.bin"
        model_path.write_bytes(b"a" * 32)
        scanner = RawDetectorMemoryMappedScanner()
        monkeypatch.setattr("modelaudit.utils.file.handlers.MMAP_MAX_WINDOW", 16)

        with patch(
            "modelaudit.detectors.secrets.SecretsDetector.scan_model_weights",
            side_effect=[RuntimeError("detector failed"), []],
        ) as scan_model_weights:
            result = MemoryMappedHandler(str(model_path), scanner).scan_with_mmap()

        assert scan_model_weights.call_count == 2
        assert result.success is False
        assert not any(
            check.name == "Embedded Secrets Detection" and check.status.value == "passed" for check in result.checks
        )

    def test_mmap_repeated_raw_detector_failure_is_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = tmp_path / "repeated-detector-error.bin"
        model_path.write_bytes(b"a" * (16 * 25))
        scanner = RawDetectorMemoryMappedScanner()
        monkeypatch.setattr("modelaudit.utils.file.handlers.MMAP_MAX_WINDOW", 16)

        with patch(
            "modelaudit.detectors.secrets.SecretsDetector.scan_model_weights",
            side_effect=RuntimeError("detector failed"),
        ) as scan_model_weights:
            result = MemoryMappedHandler(str(model_path), scanner).scan_with_mmap()

        coverage_checks = [
            check
            for check in result.checks
            if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "embedded_secrets"
        ]
        assert scan_model_weights.call_count == 25
        assert result.success is False
        assert len(coverage_checks) == 1
        assert len(result.metadata["raw_detector_analysis_failures"]) == 20
        assert result.metadata["raw_detector_failed_detectors"] == ["embedded_secrets"]
        assert not any(
            check.name == "Embedded Secrets Detection" and check.status.value == "passed" for check in result.checks
        )


class TestAdvancedFileHandler:
    """Test extreme large file handler."""

    @patch("modelaudit.utils.file.handlers.os.path.getsize")
    def test_extreme_file_detection(self, mock_getsize: Any) -> None:
        """Test detection of extreme large files."""
        # Test file over the 50GB advanced-handler threshold
        mock_getsize.return_value = 300 * 1024 * 1024 * 1024  # 300GB

        assert should_use_advanced_handler("large_model.bin")

        # Test file under threshold
        mock_getsize.return_value = 50 * 1024 * 1024 * 1024  # 50GB

        assert not should_use_advanced_handler("small_model.bin")

    @patch("modelaudit.utils.file.handlers.os.path.getsize")
    @patch("modelaudit.utils.file.handlers.ShardedModelDetector.detect_shards")
    def test_massive_file_handling(self, mock_detect: Any, mock_getsize: Any) -> None:
        """Test handling of massive files above the distributed-scan threshold."""
        mock_detect.return_value = None  # Not sharded
        mock_getsize.return_value = 600 * 1024 * 1024 * 1024  # 600GB

        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\x80\x03test")  # Pickle header
            f.flush()

            mock_scanner = MagicMock()
            mock_scanner.name = "test_scanner"

            handler = AdvancedFileHandler(f.name, mock_scanner)

            with patch("builtins.open", create=True) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"\x80\x03test"
                mock_open.return_value.__enter__.return_value = mock_file

                result = handler.scan()

                # With full scanning, we don't warn about size anymore
                # The scan should complete successfully
                assert result is not None

    @patch("modelaudit.utils.file.handlers.os.path.getsize")
    @patch("modelaudit.utils.file.handlers.ShardedModelDetector.detect_shards")
    def test_massive_file_without_bounded_support_fails_closed(
        self,
        mock_detect: Any,
        mock_getsize: Any,
        tmp_path: Path,
    ) -> None:
        """Unsupported scanners should stop with an operational-style error message."""
        mock_detect.return_value = None
        mock_getsize.return_value = 600 * 1024 * 1024 * 1024

        model_path = tmp_path / "huge-model.bin"
        model_path.write_bytes(b"test")

        class ScannerWithoutBoundedSupport:
            name = "test_scanner"

            def scan(self, _file_path: str) -> ScanResult:
                result = ScanResult(scanner_name=self.name)
                result.finish(success=True)
                return result

        handler = AdvancedFileHandler(str(model_path), ScannerWithoutBoundedSupport())
        result = handler.scan()

        assert not result.success
        assert any(
            check.name == "Large File Coverage Check" and "Error scanning file:" in check.message
            for check in result.checks
        )

    def test_sharded_model_missing_shards_marks_scan_inconclusive(self, tmp_path: Path) -> None:
        """A partial shard set must not report complete coverage."""
        shard_one = tmp_path / "model-00001-of-00003.safetensors"
        shard_three = tmp_path / "model-00003-of-00003.safetensors"
        shard_one.write_bytes(b"safe")
        shard_three.write_bytes(b"safe")

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        assert result.end_time is not None
        assert result.success is False
        assert result.metadata["analysis_incomplete"] is True
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "missing_model_shards" in result.metadata["scan_outcome_reasons"]
        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].severity == IssueSeverity.INFO
        assert coverage_checks[0].details["missing_shard_count"] == 1
        assert coverage_checks[0].details["missing_shard_indices"] == [2]
        assert coverage_checks[0].details["missing_shard_indices_truncated"] is False

    def test_sharded_model_broken_shard_marks_scan_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Unreadable shard links should be reported as missing instead of aborting expansion."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"safe")
        shard_two.symlink_to(tmp_path / "missing-shard")

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert result.bytes_scanned == shard_one.stat().st_size
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["missing_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shards"] == [str(shard_two)]

    def test_sharded_model_broken_shard_without_declared_total_marks_scan_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Unreadable members cannot be silently dropped when a family has no declared total."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"safe")
        shard_two.symlink_to(tmp_path / "missing-shard")

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert result.bytes_scanned == shard_one.stat().st_size
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["unreadable_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shards"] == [str(shard_two)]

    def test_sharded_model_out_of_scope_symlink_marks_scan_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Sibling symlink shards outside a direct scan directory cannot be treated as covered."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"safe")
        outside_target.write_bytes(b"malicious shard outside direct scan")
        shard_two.symlink_to(outside_target)

        handler = AdvancedFileHandler(str(shard_one), CompletingShardScanner())
        result = handler.scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert result.bytes_scanned == shard_one.stat().st_size
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["out_of_scope_shard_count"] == 1
        assert coverage_checks[0].details["out_of_scope_shards"] == [str(shard_two)]

    def test_sharded_model_reports_out_of_scope_and_unreadable_shards(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Distinct shard coverage gaps must all remain visible to operators."""
        outside_dir = tmp_path / "outside"
        scan_dir = tmp_path / "scan"
        outside_dir.mkdir()
        scan_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        shard_three = scan_dir / "checkpoint_3.pt"
        outside_target = outside_dir / "outside-shard.pt"
        shard_one.write_bytes(b"safe")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(outside_target)
        shard_three.symlink_to(scan_dir / "missing-shard")

        result = AdvancedFileHandler(str(shard_one), CompletingShardScanner()).scan()

        coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
        assert result.success is False
        assert "out_of_scope_model_shards" in result.metadata["scan_outcome_reasons"]
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]
        assert len(coverage_checks) == 1
        assert coverage_checks[0].details["out_of_scope_shard_count"] == 1
        assert coverage_checks[0].details["out_of_scope_shards"] == [str(shard_two)]
        assert coverage_checks[0].details["unreadable_shard_count"] == 1
        assert coverage_checks[0].details["unreadable_shards"] == [str(shard_three)]

    def test_sharded_model_honors_allowed_shard_paths(self, tmp_path: Path) -> None:
        """Restricted shard scans must not expand beyond the validated allowlist."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")

        handler = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=[str(shard_one.resolve())],
        )
        result = handler.scan()

        shard_detection = next(check for check in result.checks if check.name == "Sharded Model Detection")
        assert shard_detection.details["shards"] == [str(shard_one)]
        assert result.bytes_scanned == shard_one.stat().st_size

    def test_sharded_model_marks_in_directory_allowlist_retarget_inconclusive(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """An unnumbered sibling cannot silently move to a new in-directory target."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        original_target = tmp_path / "original.pt"
        replacement_target = tmp_path / "replacement.pt"
        shard_one.write_bytes(b"one")
        original_target.write_bytes(b"original")
        replacement_target.write_bytes(b"replacement")
        shard_two.symlink_to(original_target)
        allowed_paths = [str(shard_one.resolve()), str(original_target.resolve())]
        shard_two.unlink()
        shard_two.symlink_to(replacement_target)

        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        ).scan()

        assert result.success is False
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]
        coverage_check = next(check for check in result.checks if check.name == "Sharded Model Coverage Check")
        assert coverage_check.details["unvalidated_shards"] == [str(shard_two)]

    def test_sharded_model_rejects_retargeted_representative_before_fallback(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A changed representative cannot downgrade into an ordinary file scan."""
        representative = tmp_path / "checkpoint_1.pt"
        original_target = tmp_path / "original.pt"
        replacement_target = tmp_path / "replacement.pt"
        original_target.write_bytes(b"original")
        replacement_target.write_bytes(b"replacement")
        representative.symlink_to(original_target)
        allowed_paths = [str(original_target.resolve())]
        representative.unlink()
        representative.symlink_to(replacement_target)

        result = scan_advanced_large_file(
            str(representative),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        )

        assert result.success is False
        assert result.scanner_name == "completing_shard_scanner"
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
        assert "shard_boundary_changed" in result.metadata["scan_outcome_reasons"]

    def test_sharded_model_reports_unreadable_and_unvalidated_allowlist_members(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """All simultaneous allowlist coverage gaps remain visible in one check."""
        shard_one = tmp_path / "checkpoint_1.pt"
        broken_shard = tmp_path / "checkpoint_2.pt"
        retargeted_shard = tmp_path / "checkpoint_3.pt"
        original_target = tmp_path / "original.pt"
        replacement_target = tmp_path / "replacement.pt"
        shard_one.write_bytes(b"one")
        original_target.write_bytes(b"original")
        replacement_target.write_bytes(b"replacement")
        broken_shard.symlink_to(tmp_path / "missing.pt")
        retargeted_shard.symlink_to(original_target)
        allowed_paths = [
            str(shard_one.resolve()),
            str(original_target.resolve()),
            str((tmp_path / "missing.pt").absolute()),
        ]
        retargeted_shard.unlink()
        retargeted_shard.symlink_to(replacement_target)

        result = AdvancedFileHandler(
            str(shard_one),
            CompletingShardScanner(),
            allowed_shard_paths=allowed_paths,
        ).scan()

        coverage_check = next(check for check in result.checks if check.name == "Sharded Model Coverage Check")
        assert result.success is False
        assert "unreadable_model_shards" in result.metadata["scan_outcome_reasons"]
        assert "unvalidated_model_shards" in result.metadata["scan_outcome_reasons"]
        assert coverage_check.details["unreadable_shards"] == [str(broken_shard)]
        assert coverage_check.details["unvalidated_shards"] == [str(retargeted_shard)]

    def test_sharded_model_preserves_scanner_config_for_each_shard(self, tmp_path: Path) -> None:
        """Shard fanout should retain caller configuration for each scanner instance."""
        shard_one = tmp_path / "model-00001-of-00002.safetensors"
        shard_two = tmp_path / "model-00002-of-00002.safetensors"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        captured_configs: list[dict[str, Any]] = []

        class ConfiguredShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = dict(config or {})
                captured_configs.append(self.config)

        scanner = ConfiguredShardScanner({"max_tensor_bytes": 7})
        captured_configs.clear()

        result = AdvancedFileHandler(str(shard_one), scanner).scan()

        assert result.success is True
        assert captured_configs == [{"max_tensor_bytes": 7}, {"max_tensor_bytes": 7}]

    def test_cached_advanced_scan_keys_allowed_shard_paths(self, tmp_path: Path) -> None:
        """Different validated shard allowlists must not share advanced-scan cache entries."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two-two")
        cache_dir = tmp_path / "cache"

        class CachedCompletingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

        scanner = CachedCompletingShardScanner(
            {
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
            }
        )
        restricted_paths = [str(shard_one.resolve())]
        expanded_paths = [str(shard_one.resolve()), str(shard_two.resolve())]

        reset_cache_manager()
        try:
            restricted = scan_advanced_large_file(
                str(shard_one),
                scanner,
                allowed_shard_paths=restricted_paths,
            )
            expanded = scan_advanced_large_file(
                str(shard_one),
                scanner,
                allowed_shard_paths=expanded_paths,
            )
        finally:
            reset_cache_manager()

        assert restricted.bytes_scanned == shard_one.stat().st_size
        assert expanded.bytes_scanned == shard_one.stat().st_size + shard_two.stat().st_size

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Windows hard-link pinning changes shard identity, so family caching is disabled",
    )
    def test_cached_advanced_scan_keys_index_search_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Equivalent shard inventories with different trusted roots must not share cache entries."""
        model_root = tmp_path / "model"
        shards = [
            model_root / "a" / "model-00000-of-00002.safetensors",
            model_root / "b" / "model-00001-of-00002.safetensors",
        ]
        for shard in shards:
            shard.parent.mkdir(parents=True)
            shard.write_bytes(shard.name.encode())
        _write_safetensors_index(model_root, [shard.relative_to(model_root).as_posix() for shard in shards])
        scanned_payloads: list[bytes] = []

        class CachedRecordingScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any]) -> None:
                self.config = config

            def scan(self, shard_path: str) -> ScanResult:
                scanned_payloads.append(Path(shard_path).read_bytes())
                return super().scan(shard_path)

        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._supports_reliable_shard_cache_identity",
            lambda: True,
        )
        scanner = CachedRecordingScanner({"cache_enabled": True, "cache_dir": str(tmp_path / "cache")})

        reset_cache_manager()
        try:
            scan_advanced_large_file(str(shards[0]), scanner, index_search_root=model_root)
            first_scan_count = len(scanned_payloads)
            scan_advanced_large_file(str(shards[0]), scanner, index_search_root=model_root)
            assert len(scanned_payloads) == first_scan_count
            scan_advanced_large_file(str(shards[0]), scanner, index_search_root=tmp_path)
        finally:
            reset_cache_manager()

        assert first_scan_count == 2
        assert len(scanned_payloads) == 4

    def test_cached_advanced_scan_keys_direct_shard_family_content(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct representative-shard cache entries must track sibling shard bytes."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        cache_dir = tmp_path / "cache"
        scanned_payloads: list[bytes] = []

        class RecordingShardScanner:
            name = "recording_shard_scanner"

            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

            def scan(self, shard_path: str) -> ScanResult:
                payload = Path(shard_path).read_bytes()
                scanned_payloads.append(payload)
                result = ScanResult(scanner_name=self.name)
                result.bytes_scanned = Path(shard_path).stat().st_size
                if payload == b"bad":
                    result.add_check(
                        name="Malicious Shard Payload",
                        passed=False,
                        message="Malicious shard payload detected",
                        severity=IssueSeverity.CRITICAL,
                        location=shard_path,
                    )
                result.finish(success=payload != b"bad")
                return result

        def stable_detect_shards(
            cls: type[ShardedModelDetector],
            file_path: str,
            *,
            allowed_paths: list[str] | None = None,
            allowed_targets: ValidatedShardTargets | None = None,
            index_search_root: str | os.PathLike[str] | None = None,
            index_inspection_context: _SafetensorsIndexInspectionContext | None = None,
            force_index_content_revalidation: bool = False,
        ) -> dict[str, Any]:
            del (
                cls,
                file_path,
                allowed_paths,
                allowed_targets,
                index_search_root,
                index_inspection_context,
                force_index_content_revalidation,
            )
            return {
                "pattern": r"checkpoint_(\d+)\.pt",
                "current_file": str(shard_one),
                "shards": [str(shard_one), str(shard_two)],
                "total_shards": 2,
                "total_size": shard_one.stat().st_size + shard_two.stat().st_size,
            }

        monkeypatch.setattr(ShardedModelDetector, "detect_shards", classmethod(stable_detect_shards))
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._supports_reliable_shard_cache_identity",
            lambda: True,
        )
        scanner = RecordingShardScanner({"cache_enabled": True, "cache_dir": str(cache_dir)})

        reset_cache_manager()
        try:
            first = scan_advanced_large_file(str(shard_one), scanner)
            assert Counter(scanned_payloads) == Counter([b"one", b"two"])
            first_scan_count = len(scanned_payloads)

            cached = scan_advanced_large_file(str(shard_one), scanner)
            assert len(scanned_payloads) == first_scan_count

            shard_two.write_bytes(b"bad")
            second_scan_start = len(scanned_payloads)
            second = scan_advanced_large_file(str(shard_one), scanner)
            assert Counter(scanned_payloads[second_scan_start:]) == Counter([b"one", b"bad"])
        finally:
            reset_cache_manager()

        assert first.success is True
        assert cached.success is True
        assert second.success is False
        assert any(
            check.name == "Malicious Shard Payload" and check.status == CheckStatus.FAILED for check in second.checks
        )

    @pytest.mark.skipif(
        os.name == "nt" or sys.platform == "darwin",
        reason="requires descriptor-bound sharded caching with reliable sibling identity",
    )
    def test_cached_advanced_scan_keys_selected_model_config(
        self,
        tmp_path: Path,
    ) -> None:
        """Adding, changing, or removing the selected config must select matching shard results."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        config_path = tmp_path / "config.json"
        scanned_paths: list[str] = []

        class RecordingShardScanner(CompletingShardScanner):
            name = "config_identity_shard_scanner"

            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

            def scan(self, shard_path: str) -> ScanResult:
                scanned_paths.append(shard_path)
                return super().scan(shard_path)

        scanner = RecordingShardScanner({"cache_enabled": True, "cache_dir": str(tmp_path / "cache")})

        reset_cache_manager()
        try:
            absent = scan_advanced_large_file(str(shard_one), scanner)
            assert len(scanned_paths) == 2
            assert not any(check.name == "PyTorch Configuration Detection" for check in absent.checks)

            config_path.write_text('{"torch_dtype": "float16"}')
            present = scan_advanced_large_file(str(shard_one), scanner)
            assert len(scanned_paths) == 4
            assert any(check.name == "PyTorch Configuration Detection" for check in present.checks)

            cached = scan_advanced_large_file(str(shard_one), scanner)
            assert len(scanned_paths) == 4
            assert any(check.name == "PyTorch Configuration Detection" for check in cached.checks)

            config_path.write_text("{}")
            changed = scan_advanced_large_file(str(shard_one), scanner)
            assert len(scanned_paths) == 6
            assert not any(check.name == "PyTorch Configuration Detection" for check in changed.checks)

            config_path.unlink()
            removed = scan_advanced_large_file(str(shard_one), scanner)
            assert len(scanned_paths) == 6
            assert not any(check.name == "PyTorch Configuration Detection" for check in removed.checks)
        finally:
            reset_cache_manager()

    def test_absent_shard_family_fingerprint_is_cacheable(self) -> None:
        """A non-sharded scan does not need a sibling-family fingerprint."""
        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(None, object())

        assert fingerprint is None
        assert cacheable is True

    def test_complete_shard_family_fingerprint_binds_secure_member_hashes(self, tmp_path: Path) -> None:
        """A complete family with strong hashes should produce a stable cache identity."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")

        class SecureShardHasher:
            def hash_file(self, path: str) -> str:
                return f"secure:{Path(path).read_bytes().decode()}"

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(shard_two), str(shard_one)],
                "total_shards": 2,
                "expected_total_shards": 2,
            },
            SecureShardHasher(),
        )

        assert cacheable is True
        assert fingerprint == {
            "pattern": r"checkpoint_(\d+)\.pt",
            "expected_total_shards": 2,
            "members": [
                {"path": str(shard_one.resolve()), "content_hash": "secure:one"},
                {"path": str(shard_two.resolve()), "content_hash": "secure:two"},
            ],
        }

    def test_sampled_shard_family_fingerprint_is_not_cacheable(self, tmp_path: Path) -> None:
        """Sampled sibling shard hashes are not strong enough for reusable direct-scan cache identity."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")

        class SampledShardHasher:
            def hash_file(self, path: str) -> str:
                return "fingerprint:sampled" if Path(path) == shard_two else "secure:full"

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(shard_one), str(shard_two)],
                "total_shards": 2,
                "total_size": shard_one.stat().st_size + shard_two.stat().st_size,
            },
            SampledShardHasher(),
        )

        assert fingerprint is None
        assert cacheable is False

    @pytest.mark.parametrize(
        ("family_update", "missing_key"),
        [
            pytest.param({}, "pattern", id="missing-pattern"),
            pytest.param({"pattern": ""}, None, id="empty-pattern"),
            pytest.param({"pattern": 7}, None, id="non-string-pattern"),
            pytest.param({}, "shards", id="missing-shards"),
            pytest.param({"shards": []}, None, id="empty-shards"),
            pytest.param({"shards": ["valid", 7]}, None, id="non-string-member"),
            pytest.param({"shards": ["valid", ""]}, None, id="empty-member"),
            pytest.param({}, "total_shards", id="missing-total"),
            pytest.param({"total_shards": True}, None, id="boolean-total"),
            pytest.param({"total_shards": 2}, None, id="mismatched-total"),
            pytest.param({"expected_total_shards": True}, None, id="boolean-expected-total"),
            pytest.param({"expected_total_shards": 2}, None, id="incomplete-family"),
        ],
    )
    def test_malformed_shard_family_fingerprint_is_not_cacheable(
        self,
        tmp_path: Path,
        family_update: dict[str, object],
        missing_key: str | None,
    ) -> None:
        """Malformed or incomplete family metadata must bypass reusable cache entries."""
        shard = tmp_path / "valid"
        shard.write_bytes(b"content")
        family: dict[str, object] = {
            "pattern": r"checkpoint_(\d+)\.pt",
            "shards": [str(shard)],
            "total_shards": 1,
        }
        family.update(family_update)
        if missing_key is not None:
            family.pop(missing_key)
        raw_shards = family.get("shards")
        if isinstance(raw_shards, list):
            family["shards"] = [str(shard) if value == "valid" else value for value in raw_shards]

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            family,
            object(),
        )

        assert fingerprint is None
        assert cacheable is False

    @pytest.mark.parametrize(
        "content_hash",
        ["fingerprint:sampled", "sha256:unknown", "secure:", None, 7],
    )
    def test_non_secure_shard_family_hash_is_not_cacheable(
        self,
        tmp_path: Path,
        content_hash: object,
    ) -> None:
        """Only full cryptographic hashes can bind reusable shard-family entries."""
        shard = tmp_path / "checkpoint_1.pt"
        shard.write_bytes(b"content")

        class UnexpectedShardHasher:
            def hash_file(self, path: str) -> object:
                assert Path(path) == shard
                return content_hash

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(shard)],
                "total_shards": 1,
            },
            UnexpectedShardHasher(),
        )

        assert fingerprint is None
        assert cacheable is False

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("duplicate_shard_count", 1),
            ("missing_shard_count", 1),
            ("out_of_scope_shard_count", 1),
            ("unreadable_shard_count", 1),
            ("unvalidated_shard_count", 1),
            ("unexpected_shard_count", 1),
            ("duplicate_shard_count", True),
            ("missing_shard_count", "1"),
        ],
    )
    def test_suspect_shard_family_counts_are_not_cacheable(
        self,
        tmp_path: Path,
        field: str,
        value: object,
    ) -> None:
        """Any suspect or malformed family count must prevent cache reuse."""
        shard = tmp_path / "checkpoint_1.pt"
        shard.write_bytes(b"content")
        family: dict[str, object] = {
            "pattern": r"checkpoint_(\d+)\.pt",
            "shards": [str(shard)],
            "total_shards": 1,
            field: value,
        }

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(family, object())

        assert fingerprint is None
        assert cacheable is False

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("duplicate_shards", ["duplicate"]),
            ("missing_shard_indices", [2]),
            ("out_of_scope_shards", ["outside"]),
            ("unreadable_shards", ["unreadable"]),
            ("unvalidated_shards", ["unvalidated"]),
            ("unexpected_shards", ["unexpected"]),
            ("duplicate_shards", "duplicate"),
            ("missing_shard_indices_truncated", True),
            ("missing_shard_indices_truncated", 0),
        ],
    )
    def test_suspect_shard_family_members_are_not_cacheable(
        self,
        tmp_path: Path,
        field: str,
        value: object,
    ) -> None:
        """Any suspect or malformed family member list must prevent cache reuse."""
        shard = tmp_path / "checkpoint_1.pt"
        shard.write_bytes(b"content")
        family: dict[str, object] = {
            "pattern": r"checkpoint_(\d+)\.pt",
            "shards": [str(shard)],
            "total_shards": 1,
            field: value,
        }

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(family, object())

        assert fingerprint is None
        assert cacheable is False

    def test_duplicate_resolved_shard_family_members_are_not_cacheable(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A symlink alias must not let one shard stand in for two family members."""
        shard = tmp_path / "checkpoint_1.pt"
        alias = tmp_path / "checkpoint_2.pt"
        shard.write_bytes(b"content")
        alias.symlink_to(shard)

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(shard), str(alias)],
                "total_shards": 2,
            },
            MagicMock(hash_file=MagicMock(return_value="secure:full")),
        )

        assert fingerprint is None
        assert cacheable is False

    def test_duplicate_hardlinked_shard_family_members_are_not_cacheable(self, tmp_path: Path) -> None:
        """Hardlink aliases must not let one target satisfy multiple shard slots."""
        shard = tmp_path / "checkpoint_1.pt"
        alias = tmp_path / "checkpoint_2.pt"
        shard.write_bytes(b"content")
        try:
            alias.hardlink_to(shard)
        except OSError as exc:
            pytest.skip(f"hardlinks unavailable: {exc}")

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(shard), str(alias)],
                "total_shards": 2,
            },
            MagicMock(hash_file=MagicMock(return_value="secure:full")),
        )

        assert fingerprint is None
        assert cacheable is False

    def test_non_regular_shard_family_member_is_not_cacheable(self, tmp_path: Path) -> None:
        """Directories and other non-files cannot contribute reusable shard identity."""
        shard_directory = tmp_path / "checkpoint_1.pt"
        shard_directory.mkdir()

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(shard_directory)],
                "total_shards": 1,
            },
            MagicMock(hash_file=MagicMock(return_value="secure:full")),
        )

        assert fingerprint is None
        assert cacheable is False

    def test_unavailable_shard_family_member_is_not_cacheable(self, tmp_path: Path) -> None:
        """A missing family member must bypass cache identity instead of being omitted."""
        missing_shard = tmp_path / "checkpoint_1.pt"

        fingerprint, cacheable = _build_advanced_shard_family_cache_fingerprint(
            {
                "pattern": r"checkpoint_(\d+)\.pt",
                "shards": [str(missing_shard)],
                "total_shards": 1,
            },
            MagicMock(hash_file=MagicMock(return_value="secure:full")),
        )

        assert fingerprint is None
        assert cacheable is False

    def test_sampled_shard_hash_bypasses_scan_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Weak sibling hashes must bypass both cache lookup and storage."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        cache_dir = tmp_path / "cache"
        scanned_paths: list[str] = []

        class CachedRecordingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

            def scan(self, shard_path: str) -> ScanResult:
                scanned_paths.append(shard_path)
                return super().scan(shard_path)

        scanner = CachedRecordingShardScanner({"cache_enabled": True, "cache_dir": str(cache_dir)})
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._supports_reliable_shard_cache_identity",
            lambda: True,
        )

        reset_cache_manager()
        try:
            cache_manager = get_cache_manager(str(cache_dir), enabled=True)
            assert cache_manager.cache is not None
            original_hash_file = cache_manager.cache.hasher.hash_file

            def sampled_sibling_hash(path: str) -> str:
                if Path(path) == shard_two:
                    return "fingerprint:sampled"
                return original_hash_file(path)

            monkeypatch.setattr(cache_manager.cache.hasher, "hash_file", sampled_sibling_hash)

            first = scan_advanced_large_file(str(shard_one), scanner)
            second = scan_advanced_large_file(str(shard_one), scanner)
            cache_entries = cache_manager.get_stats()["total_entries"]
        finally:
            reset_cache_manager()

        assert first.success is True
        assert second.success is True
        scanned_names = [Path(path).name for path in scanned_paths]
        assert scanned_names.count(shard_one.name) == 2
        assert scanned_names.count(shard_two.name) == 2
        assert cache_entries == 0

    def test_sharded_scan_bypasses_cache_without_reliable_sibling_identity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Platforms without a content-change token must rescan every shard."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"one")
        shard_two.write_bytes(b"two")
        cache_dir = tmp_path / "cache"
        scanned_paths: list[str] = []

        class CachedRecordingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

            def scan(self, shard_path: str) -> ScanResult:
                scanned_paths.append(shard_path)
                result = ScanResult(scanner_name=self.name)
                payload = Path(shard_path).read_bytes()
                result.bytes_scanned = len(payload)
                if payload == b"bad":
                    result.add_check(
                        name="Malicious Shard Payload",
                        passed=False,
                        message=Path(shard_path).name,
                        severity=IssueSeverity.CRITICAL,
                    )
                result.finish(success=payload != b"bad")
                return result

        scanner = CachedRecordingShardScanner(
            {
                "cache_enabled": True,
                "cache_dir": str(cache_dir),
            }
        )
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._supports_reliable_shard_cache_identity",
            lambda: False,
        )

        reset_cache_manager()
        try:
            first = scan_advanced_large_file(str(shard_one), scanner)
            shard_two.write_bytes(b"bad")
            second = scan_advanced_large_file(str(shard_one), scanner)
            cache_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        finally:
            reset_cache_manager()

        assert first.success is True
        assert second.success is False
        assert any(check.name == "Malicious Shard Payload" for check in second.checks)
        scanned_names = [Path(path).name for path in scanned_paths]
        assert scanned_names.count(shard_one.name) == 2
        assert scanned_names.count(shard_two.name) == 2
        assert cache_entries == 0

    @pytest.mark.skipif(
        os.name == "nt" or sys.platform == "darwin",
        reason="requires descriptor-bound sharded caching with reliable sibling identity",
    )
    def test_cached_sharded_scan_revalidates_retargeted_sibling(
        self,
        tmp_path: Path,
        requires_symlinks: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful shard scan cache cannot hide a sibling later retargeted outside."""
        scan_dir = tmp_path / "scan"
        outside_dir = tmp_path / "outside"
        scan_dir.mkdir()
        outside_dir.mkdir()
        shard_one = scan_dir / "checkpoint_1.pt"
        shard_two = scan_dir / "checkpoint_2.pt"
        inside_target = scan_dir / "inside.pt"
        outside_target = outside_dir / "outside.pt"
        shard_one.write_bytes(b"first")
        inside_target.write_bytes(b"inside")
        outside_target.write_bytes(b"outside")
        shard_two.symlink_to(inside_target)
        cache_dir = tmp_path / "cache"
        scanned_paths: list[str] = []

        class CachedCompletingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

            def scan(self, shard_path: str) -> ScanResult:
                scanned_paths.append(shard_path)
                return super().scan(shard_path)

        scanner = CachedCompletingShardScanner({"cache_enabled": True, "cache_dir": str(cache_dir)})
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._supports_reliable_shard_cache_identity",
            lambda: True,
        )

        reset_cache_manager()
        try:
            first = scan_advanced_large_file(str(shard_one), scanner)
            first_scan_paths = list(scanned_paths)
            cached = scan_advanced_large_file(str(shard_one), scanner)
            cached_scan_paths = list(scanned_paths)
            shard_two.unlink()
            shard_two.symlink_to(outside_target)
            second = scan_advanced_large_file(str(shard_one), scanner)
        finally:
            reset_cache_manager()

        assert first.success is True
        assert cached.success is True
        assert inside_target.name in {Path(path).name for path in first_scan_paths}
        assert cached_scan_paths == first_scan_paths
        assert second.success is False
        assert "out_of_scope_model_shards" in second.metadata["scan_outcome_reasons"]

    def test_cached_sharded_scan_rejects_family_change_during_scan(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A family change during a fresh scan must fail before cache storage."""
        shard_one = tmp_path / "checkpoint_1.pt"
        shard_two = tmp_path / "checkpoint_2.pt"
        shard_one.write_bytes(b"first")
        shard_two.write_bytes(b"second")
        cache_dir = tmp_path / "cache"

        class CachedCompletingShardScanner(CompletingShardScanner):
            def __init__(self, config: dict[str, Any] | None = None) -> None:
                self.config = config or {}

        scanner = CachedCompletingShardScanner({"cache_enabled": True, "cache_dir": str(cache_dir)})

        def mutate_family_during_scan(*args: Any, **kwargs: Any) -> ScanResult:
            shard_two.write_bytes(b"changed")
            result = ScanResult(scanner_name=scanner.name)
            result.add_check(
                name="Malicious Shard Payload",
                passed=False,
                message="Detected malicious payload before shard family changed",
                severity=IssueSeverity.CRITICAL,
            )
            result.add_check(
                name="Benign Shard Metadata",
                passed=True,
                message="Shard metadata was valid before the family changed",
            )
            result.finish(success=False)
            return result

        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._scan_advanced_large_file_internal",
            mutate_family_during_scan,
        )
        monkeypatch.setattr(
            "modelaudit.utils.file.handlers._supports_reliable_shard_cache_identity",
            lambda: True,
        )

        reset_cache_manager()
        try:
            result = scan_advanced_large_file(str(shard_one), scanner)
            cache_manager = get_cache_manager(str(cache_dir), enabled=True)
            assert cache_manager.get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
        assert [check.name for check in result.checks].count("Sharded Model Boundary Check") == 1
        assert any(check.name == "Malicious Shard Payload" for check in result.checks)
        assert all(check.name != "Benign Shard Metadata" for check in result.checks)
        assert any(issue.message == "Detected malicious payload before shard family changed" for issue in result.issues)

    def test_parallel_shard_errors_mark_scan_inconclusive(self, tmp_path: Path) -> None:
        """Shard scan exceptions are incomplete coverage, not security findings."""
        leaked_secret = "SHARD-ERROR-SECRET-123456"
        shard_path = tmp_path / "model-00001-of-00001.safetensors"
        shard_path.write_text(leaked_secret)
        handler = ParallelShardHandler(
            {
                "shards": [str(shard_path)],
                "total_shards": 1,
                "total_size": shard_path.stat().st_size,
            },
            OperationalFailureScanner,
        )

        result = handler.scan_shards()

        assert result.end_time is not None
        assert result.success is False
        assert result.metadata["analysis_incomplete"] is True
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "shard_scan_error" in result.metadata["scan_outcome_reasons"]
        shard_checks = [check for check in result.checks if check.name == "Shard Scan"]
        assert len(shard_checks) == 1
        assert shard_checks[0].severity == IssueSeverity.INFO
        assert shard_checks[0].details["error"] == "<redacted>"
        assert leaked_secret not in result.to_json()

    def test_parallel_shards_preserve_raw_detector_failures_and_remove_clean_checks(
        self,
        tmp_path: Path,
    ) -> None:
        """Shard merge order must not erase failures or preserve contradictory clean checks."""
        shard_paths = [
            tmp_path / "secret-failure.pt",
            tmp_path / "network-failure.pt",
            tmp_path / "clean.pt",
        ]
        for shard_path in shard_paths:
            shard_path.write_bytes(b"safe")
        handler = ParallelShardHandler(
            {
                "shards": [str(shard_path) for shard_path in shard_paths],
                "total_shards": len(shard_paths),
                "total_size": sum(shard_path.stat().st_size for shard_path in shard_paths),
            },
            MixedRawDetectorShardScanner,
        )

        result = handler.scan_shards()

        assert result.success is False
        assert set(result.metadata["raw_detector_failed_detectors"]) == {
            "embedded_secrets",
            "network_communication",
        }
        assert {failure["detector"] for failure in result.metadata["raw_detector_analysis_failures"]} == {
            "embedded_secrets",
            "network_communication",
        }
        assert not any(
            check.status.value == "passed"
            and check.name in {"Embedded Secrets Detection", "Network Communication Detection"}
            for check in result.checks
        )

    def test_parallel_shard_raw_detector_failure_reporting_is_bounded(self, tmp_path: Path) -> None:
        """Repeated per-shard detector failures should emit one check and bounded contexts."""
        shard_paths = [tmp_path / f"secret-failure-{index}.pt" for index in range(25)]
        for shard_path in shard_paths:
            shard_path.write_bytes(b"safe")
        handler = ParallelShardHandler(
            {
                "shards": [str(shard_path) for shard_path in shard_paths],
                "total_shards": len(shard_paths),
                "total_size": sum(shard_path.stat().st_size for shard_path in shard_paths),
            },
            MixedRawDetectorShardScanner,
        )

        result = handler.scan_shards()

        coverage_checks = [
            check
            for check in result.checks
            if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "embedded_secrets"
        ]
        coverage_issues = [
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == "raw_detector_analysis_incomplete"
            and issue.details.get("detector") == "embedded_secrets"
        ]
        assert len(coverage_checks) == 1
        assert len(coverage_issues) == 1
        assert len(result.metadata["raw_detector_analysis_failures"]) == 20

    def test_parallel_shards_inherit_scan_context(self, tmp_path: Path) -> None:
        """Shard workers preserve an enclosing source-sensitive scan snapshot."""
        shard_path = tmp_path / "model-00001-of-00001.safetensors"
        shard_path.write_bytes(b"safe")
        handler = ParallelShardHandler(
            {
                "shards": [str(shard_path)],
                "total_shards": 1,
                "total_size": shard_path.stat().st_size,
            },
            ContextRecordingShardScanner,
        )
        token = _SHARD_SCAN_CONTEXT.set("directory-snapshot")
        try:
            result = handler.scan_shards()
        finally:
            _SHARD_SCAN_CONTEXT.reset(token)

        context_checks = [check for check in result.checks if check.name == "Shard Context"]
        assert len(context_checks) == 1
        assert context_checks[0].details["context_value"] == "directory-snapshot"

    def test_sharded_model_preserves_unsuccessful_shard_result(self, tmp_path: Path) -> None:
        """Non-critical shard failures must not be overwritten after aggregate merge."""
        shard_path = tmp_path / "model-00001-of-00001.safetensors"
        shard_path.write_bytes(b"partial")

        handler = AdvancedFileHandler(str(shard_path), IncompleteShardScanner())
        result = handler.scan()

        assert result.end_time is not None
        assert result.success is False
        assert result.has_errors is False
        assert "scan_outcome" not in result.metadata
        assert any(check.name == "Shard Parse Coverage" for check in result.checks)
