from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.batch_operations import BatchCacheOperations
from modelaudit.cache.optimized_config import (
    ConfigurationExtractor,
    build_cache_version_context,
    get_config_extractor,
    normalize_material_scan_config,
)
from modelaudit.cache.scan_results_cache import AncestorIdentity, ScanResultsCache
from modelaudit.config.rule_config import ModelAuditConfig, get_config, reset_config, set_config
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, ScanResult
from modelaudit.utils.helpers.cache_decorator import cached_scan


@pytest.fixture(autouse=True)
def reset_cache_state() -> Iterator[None]:
    reset_cache_manager()
    reset_config()
    extractor = get_config_extractor()
    extractor._config_cache.clear()
    extractor._result_cache.clear()
    extractor._last_cleanup = time.monotonic()
    yield
    reset_cache_manager()
    reset_config()
    extractor._config_cache.clear()
    extractor._result_cache.clear()
    extractor._last_cleanup = time.monotonic()


def _make_cacheable_file(tmp_path: Path, name: str = "model.cache") -> Path:
    file_path = tmp_path / name
    file_path.write_bytes(b"x" * 2048)
    return file_path


def _identity_kwargs(cache: ScanResultsCache, file_path: str) -> dict[str, Any]:
    file_stat, file_hash, change_token, ancestor_identity = cache.capture_file_identity(file_path)
    return {
        "expected_file_stat": file_stat,
        "expected_file_hash": file_hash,
        "expected_change_token": change_token,
        "expected_ancestor_identity": ancestor_identity,
    }


def test_capture_file_identity_uses_target_filesystem_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    original_device_check = cache._directory_is_on_device

    def simulate_cache_and_system_temp_on_other_devices(directory: Path, device: int) -> bool:
        if directory in {cache.cache_dir, Path(tempfile.gettempdir())}:
            return False
        return original_device_check(directory, device)

    monkeypatch.setattr(cache, "_directory_is_on_device", simulate_cache_and_system_temp_on_other_devices)

    file_stat = file_path.stat()
    probe = cache._get_change_clock_probe(str(file_path), file_stat.st_dev)

    assert os.fstat(probe.fileno()).st_dev == file_stat.st_dev
    assert cache._change_clock_probes[file_stat.st_dev][1] == file_path.parent
    probe.close()
    cache._change_clock_probes.clear()


def test_windows_change_clock_probe_uses_existing_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = ScanResultsCache(str(tmp_path / "cache"))
    msvcrt = ModuleType("msvcrt")
    msvcrt.get_osfhandle = lambda file_descriptor: file_descriptor + 100  # type: ignore[attr-defined]
    observed_handles: list[int] = []

    def record_change_token_handle(handle: int) -> int:
        observed_handles.append(handle)
        return 123

    with tempfile.TemporaryFile(mode="w+b", dir=tmp_path) as probe:
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setattr(os, "utime", lambda *_args, **_kwargs: pytest.fail("probe path was reopened"))
        monkeypatch.setitem(sys.modules, "msvcrt", msvcrt)
        monkeypatch.setattr(
            cache,
            "_get_windows_handle_change_token",
            record_change_token_handle,
        )

        assert cache._touch_change_clock_probe(probe) == 123
        probe.seek(0)
        assert probe.read() == b"\0"
        assert observed_handles == [probe.fileno() + 100]


def test_change_clock_probe_allows_coarse_filesystem_tick(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    clock = {"now": 0.0}
    ancestor_identity = cache._capture_ancestor_identity(str(file_path))
    newest_token = max(1, *(entry[-1] for entry in ancestor_identity))

    monkeypatch.setattr(time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + seconds))
    monkeypatch.setattr(
        cache,
        "_touch_change_clock_probe",
        lambda _probe: newest_token + 1 if clock["now"] >= 0.1 else newest_token,
    )

    with tempfile.TemporaryFile(mode="w+b", dir=tmp_path) as probe:
        cache._advance_change_clock(
            str(file_path),
            probe,
            1,
            ancestor_identity,
        )

    assert clock["now"] >= 0.1


def test_capture_file_identity_advances_clock_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    clock = {"value": 1}
    file_token = {"value": 1}

    def change_token(path: str, _file_stat: os.stat_result) -> int:
        return file_token["value"] if path == str(file_path) else 1

    def advance_probe(_probe: Any) -> int:
        clock["value"] += 1
        return clock["value"]

    def mutate_during_hash(_path: str, _file_stat: os.stat_result) -> str:
        file_token["value"] = clock["value"]
        return "secure:simulated"

    monkeypatch.setattr(cache, "_get_file_change_token", change_token)
    monkeypatch.setattr(cache, "_touch_change_clock_probe", advance_probe)
    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", mutate_during_hash)

    with pytest.raises(ValueError, match=r"File changed while (starting|capturing) cache identity"):
        cache.capture_file_identity(str(file_path))


def test_capture_file_identity_ignores_unrelated_ancestor_churn_during_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    original_hash = cache.hasher.hash_file_with_stat

    class StableMonitor:
        def changed(self) -> bool:
            return False

        def close(self) -> None:
            return None

    def monitor_identity(_file_path: str, identity: AncestorIdentity) -> AncestorIdentity:
        monitored = AncestorIdentity(tuple(identity))
        monitored.monitor = StableMonitor()  # type: ignore[assignment]
        return monitored

    def hash_with_sibling_churn(path: str, file_stat: os.stat_result) -> str:
        (file_path.parent / "unrelated.cache").write_bytes(b"unrelated")
        return original_hash(path, file_stat)

    monkeypatch.setattr(cache, "_monitor_ancestor_identity", monitor_identity)
    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", hash_with_sibling_churn)

    identity = cache.capture_file_identity(str(file_path))

    assert identity[1].startswith("secure:")


def test_nested_identity_capture_does_not_invalidate_outer_identity(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    outer_identity = _identity_kwargs(cache, str(file_path))

    cache.capture_file_identity(str(file_path))

    assert cache.store_result(str(file_path), {"success": True}, **outer_identity) is True


def test_capture_file_identity_excludes_same_filesystem_mount_root(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))

    _file_stat, _file_hash, _change_token, ancestor_identity = cache.capture_file_identity(str(file_path))
    tracked_paths = {entry[0] for entry in ancestor_identity}
    mount_root = file_path.parent
    file_device = file_path.stat().st_dev
    while mount_root.parent != mount_root and mount_root.parent.stat().st_dev == file_device:
        mount_root = mount_root.parent

    assert str(file_path.parent) in tracked_paths
    assert str(mount_root) not in tracked_paths


def test_capture_ancestor_identity_includes_direct_parent_at_device_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    original_stat = os.stat
    parent_of_parent = str(file_path.parent.parent)
    file_device = file_path.stat().st_dev

    def stat_with_device_boundary(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> os.stat_result:
        result = original_stat(path, *args, **kwargs)
        if os.fspath(path) != parent_of_parent:
            return result
        values = list(result)
        values[2] = file_device + 1
        return os.stat_result(values)

    monkeypatch.setattr(os, "stat", stat_with_device_boundary)

    identity = cache._capture_ancestor_identity(str(file_path))

    assert [entry[0] for entry in identity] == [str(file_path.parent)]


def test_cache_identity_rejects_symlink_component_before_parent_traversal(tmp_path: Path) -> None:
    target_parent = tmp_path / "target"
    target_child = target_parent / "child"
    target_child.mkdir(parents=True)
    model_path = _make_cacheable_file(target_parent, name="model.dat")
    link_path = tmp_path / "link"
    try:
        link_path.symlink_to(target_child, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    traversed_path = link_path / ".." / model_path.name
    cache = ScanResultsCache(str(tmp_path / "cache"))

    with pytest.raises(ValueError, match="Symlinked paths are not cacheable"):
        cache.capture_file_identity(str(traversed_path))


def test_cache_path_component_rejects_windows_reparse_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    original_lstat = os.lstat

    def lstat_with_reparse_point(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> Any:
        result = original_lstat(path, *args, **kwargs)
        if Path(path) != file_path.parent:
            return result

        class ReparseStat:
            st_mode = result.st_mode
            st_file_attributes = 0x400

        return ReparseStat()

    monkeypatch.setattr(os, "lstat", lstat_with_reparse_point)

    assert cache._path_has_symlink_component(str(file_path)) is True


@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows sharing semantics")
def test_windows_cache_identity_blocks_path_replacement(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="locked-model.dat")
    replacement = _make_cacheable_file(tmp_path, name="replacement.dat")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    identity = cache.capture_file_identity(str(file_path))

    try:
        with pytest.raises(OSError):
            replacement.replace(file_path)
    finally:
        cache.release_ancestor_identity(identity[-1])

    replacement.replace(file_path)


def test_cached_scan_persists_miss_and_hits_on_second_call(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"call_count": calls["count"], "timeout": config["timeout"]}

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == {"call_count": 1, "timeout": 30}
    assert second == first
    assert calls["count"] == 1

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 1


def test_cache_lookup_rejects_transient_clean_hash_for_malicious_final_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="lookup-race.dat")
    clean_payload = b"clean:" + (b"x" * 2042)
    malicious_payload = b"evil!:" + (b"y" * 2042)
    file_path.write_bytes(clean_payload)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"verdict": "clean"}
    original_stat = file_path.stat()

    assert (
        cache.store_result(
            str(file_path),
            expected,
            version_context=version_context,
            **_identity_kwargs(cache, str(file_path)),
        )
        is True
    )

    file_path.write_bytes(malicious_payload)
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    original_hash = cache.hasher.hash_file_with_stat
    raced = False

    def hash_transient_clean_bytes(path: str, file_stat: os.stat_result) -> str:
        nonlocal raced
        if raced:
            return original_hash(path, file_stat)
        raced = True
        Path(path).write_bytes(clean_payload)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        clean_hash = original_hash(path, Path(path).stat())
        Path(path).write_bytes(malicious_payload)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        return clean_hash

    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", hash_transient_clean_bytes)

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None
    assert file_path.read_bytes() == malicious_payload


def test_cache_manager_reuses_lookup_identity_for_miss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    capture_calls = 0
    original_capture = cache_manager.cache.capture_file_identity

    def capture_once(path: str) -> Any:
        nonlocal capture_calls
        capture_calls += 1
        return original_capture(path)

    monkeypatch.setattr(cache_manager.cache, "capture_file_identity", capture_once)

    result = cache_manager.cached_scan(str(file_path), lambda _path: {"success": True})

    assert result["success"] is True
    assert capture_calls == 1


def test_cached_scan_does_not_store_result_after_post_scan_replacement(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="race.dat")
    clean_payload = b"clean:" + (b"x" * 2042)
    malicious_payload = b"evil!:" + (b"y" * 2042)
    file_path.write_bytes(clean_payload)
    original_stat = file_path.stat()
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    calls = {"count": 0}
    replaced = {"done": False}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        prefix = Path(path).read_bytes()[:6].decode("utf-8")
        if not replaced["done"]:
            Path(path).write_bytes(malicious_payload)
            os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            replaced["done"] = True
        return {"payload_prefix": prefix}

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2


def test_cache_manager_cached_scan_does_not_store_result_after_post_scan_replacement(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="manager-race.dat")
    clean_payload = b"clean:" + (b"x" * 2042)
    malicious_payload = b"evil!:" + (b"y" * 2042)
    file_path.write_bytes(clean_payload)
    original_stat = file_path.stat()
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}
    replaced = {"done": False}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        prefix = Path(path).read_bytes()[:6].decode("utf-8")
        if not replaced["done"]:
            Path(path).write_bytes(malicious_payload)
            os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            replaced["done"] = True
        return {"payload_prefix": prefix}

    first = cache_manager.cached_scan(str(file_path), scan, version_context=version_context)
    second = cache_manager.cached_scan(str(file_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2


def test_cache_manager_cached_scan_does_not_cache_transient_clean_bytes(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="manager-restored-race.dat")
    malicious_payload = b"evil!:" + (b"y" * 2042)
    clean_payload = b"clean:" + (b"x" * 2042)
    file_path.write_bytes(malicious_payload)
    original_stat = file_path.stat()
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    cache = cache_manager.cache
    original_change_token = cache._get_file_change_token(str(file_path), original_stat)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            Path(path).write_bytes(clean_payload)
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            Path(path).write_bytes(malicious_payload)
            os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            deadline = time.monotonic() + 1.2
            while (
                cache._get_file_change_token(path, Path(path).stat()) == original_change_token
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
                Path(path).write_bytes(malicious_payload)
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(file_path), scan, version_context=version_context)
    assert cache._get_file_change_token(str(file_path), file_path.stat()) != original_change_token
    second = cache_manager.cached_scan(str(file_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2


def test_store_result_rejects_changed_generation_when_stat_and_hash_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="change-token.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    file_stat = file_path.stat()
    file_hash = cache.hasher.hash_file_with_stat(str(file_path), file_stat)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    expected_ancestor_identity = cache._capture_ancestor_identity(str(file_path))
    original_get_change_token = cache._get_file_change_token
    change_token = {"value": 1}

    monkeypatch.setattr(
        cache,
        "_get_file_change_token",
        lambda path, stat: change_token["value"] if path == str(file_path) else original_get_change_token(path, stat),
    )
    change_token["value"] = 2

    stored = cache.store_result(
        str(file_path),
        expected,
        10,
        expected_file_stat=file_stat,
        expected_file_hash=file_hash,
        expected_change_token=1,
        expected_ancestor_identity=expected_ancestor_identity,
    )

    assert stored is False
    assert cache.get_cache_stats()["total_entries"] == 0


def test_store_result_rejects_changed_ancestor_identity_when_file_identity_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="parent-change-token.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    file_stat = file_path.stat()
    file_hash = cache.hasher.hash_file_with_stat(str(file_path), file_stat)
    expected_ancestor_identity = cache._capture_ancestor_identity(str(file_path))
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    changed_ancestor_identity = (
        (*expected_ancestor_identity[0][:-1], expected_ancestor_identity[0][-1] + 1),
        *expected_ancestor_identity[1:],
    )
    monkeypatch.setattr(cache, "_capture_ancestor_identity", lambda _path: changed_ancestor_identity)

    stored = cache.store_result(
        str(file_path),
        expected,
        10,
        expected_file_stat=file_stat,
        expected_file_hash=file_hash,
        expected_change_token=cache._get_file_change_token(str(file_path), file_stat),
        expected_ancestor_identity=expected_ancestor_identity,
    )

    assert stored is False
    assert cache.get_cache_stats()["total_entries"] == 0


def test_cache_manager_cached_scan_does_not_cache_transient_path_replacement(tmp_path: Path) -> None:
    model_path = _make_cacheable_file(tmp_path, name="model.dat")
    clean_path = _make_cacheable_file(tmp_path, name="clean.dat")
    backup_path = tmp_path / "model.backup"
    malicious_payload = b"evil!:" + (b"x" * 2042)
    clean_payload = b"clean:" + (b"y" * 2042)
    model_path.write_bytes(malicious_payload)
    clean_path.write_bytes(clean_payload)
    original_stat = model_path.stat()
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    cache = cache_manager.cache
    parent_path = str(model_path.parent)
    original_parent_change_token = cache._get_file_change_token(parent_path, model_path.parent.stat())
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            model_path.rename(backup_path)
            clean_path.rename(model_path)
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            model_path.rename(clean_path)
            backup_path.rename(model_path)
            os.utime(model_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            deadline = time.monotonic() + 1.2
            while (
                cache._get_file_change_token(parent_path, model_path.parent.stat()) == original_parent_change_token
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
                model_path.rename(backup_path)
                clean_path.rename(model_path)
                model_path.rename(clean_path)
                backup_path.rename(model_path)
                os.utime(model_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)
    assert cache._get_file_change_token(parent_path, model_path.parent.stat()) != original_parent_change_token
    second = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires inotify path monitoring")
def test_ancestor_monitor_ignores_unrelated_grandparent_churn(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    model_path = _make_cacheable_file(scan_dir, name="model.dat")
    cache = ScanResultsCache(str(tmp_path / "cache"))

    expected = _identity_kwargs(cache, str(model_path))
    before = expected["expected_ancestor_identity"]
    after = cache._capture_ancestor_identity(str(model_path))
    deadline = time.monotonic() + 1.2
    attempt = 0
    while after == before and time.monotonic() < deadline:
        unrelated = tmp_path / f"unrelated-{attempt}"
        unrelated.mkdir()
        unrelated.rmdir()
        after = cache._capture_ancestor_identity(str(model_path))
        attempt += 1
        time.sleep(0.01)

    assert before != after
    assert not cache._ancestor_identity_matches(before, after)
    assert cache.store_result(str(model_path), {"success": True}, **expected) is True


def test_cache_manager_cached_scan_does_not_cache_symlink_target_swap(tmp_path: Path) -> None:
    malicious_path = _make_cacheable_file(tmp_path, name="malicious.dat")
    clean_path = _make_cacheable_file(tmp_path, name="clean.dat")
    malicious_path.write_bytes(b"evil!:" + (b"x" * 2042))
    clean_path.write_bytes(b"clean:" + (b"y" * 2042))
    model_path = tmp_path / "model.dat"
    try:
        model_path.symlink_to(malicious_path)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")

    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            model_path.unlink()
            model_path.symlink_to(clean_path)
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            model_path.unlink()
            model_path.symlink_to(malicious_path)
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)
    assert cache_manager.get_stats()["total_entries"] == 0
    second = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cache_manager_cached_scan_does_not_cache_ancestor_symlink_swap(tmp_path: Path) -> None:
    malicious_root = tmp_path / "malicious"
    clean_root = tmp_path / "clean"
    malicious_root.mkdir()
    clean_root.mkdir()
    malicious_path = _make_cacheable_file(malicious_root, name="model.dat")
    clean_path = _make_cacheable_file(clean_root, name="model.dat")
    malicious_path.write_bytes(b"evil!:" + (b"x" * 2042))
    clean_path.write_bytes(b"clean:" + (b"y" * 2042))
    ancestor_link = tmp_path / "current"
    try:
        ancestor_link.symlink_to(malicious_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    model_path = ancestor_link / "model.dat"

    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            ancestor_link.unlink()
            ancestor_link.symlink_to(clean_root, target_is_directory=True)
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            ancestor_link.unlink()
            ancestor_link.symlink_to(malicious_root, target_is_directory=True)
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)
    assert cache_manager.get_stats()["total_entries"] == 0
    second = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cache_lookup_bypasses_ancestor_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    target_path = _make_cacheable_file(target_root, name="model.dat")
    ancestor_link = tmp_path / "current"
    try:
        ancestor_link.symlink_to(target_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    model_path = ancestor_link / target_path.name
    cache = ScanResultsCache(str(tmp_path / "cache"))

    monkeypatch.setattr(
        cache,
        "_generate_cache_key",
        lambda *_args, **_kwargs: pytest.fail("symlinked ancestor reached cache-key generation"),
    )

    assert cache.get_cached_result(str(model_path)) is None


def test_batch_lookup_bypasses_symlink_before_key_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    target_path = _make_cacheable_file(target_dir)
    symlink_path = tmp_path / "model.cache"
    try:
        symlink_path.symlink_to(target_path)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")

    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    batch_ops = BatchCacheOperations(cache_manager)
    monkeypatch.setattr(
        cache_manager.cache.key_generator,
        "generate_key_material_with_stat_reuse",
        lambda *_args, **_kwargs: pytest.fail("symlinked batch lookup reached cache-key generation"),
    )

    cached_results = batch_ops.batch_lookup([str(symlink_path)])

    assert cached_results[str(symlink_path)] is None


def test_batch_prefetch_bypasses_symlink_before_key_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    target_path = _make_cacheable_file(target_dir)
    symlink_path = tmp_path / "prefetch.cache"
    try:
        symlink_path.symlink_to(target_path)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")

    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    assert cache_manager.key_generator is not None
    monkeypatch.setattr(
        cache_manager.key_generator,
        "generate_key_with_stat_reuse",
        lambda *_args, **_kwargs: pytest.fail("symlinked prefetch reached cache-key generation"),
    )

    batch_ops.prefetch_cache_metadata([str(symlink_path)])


def test_cache_manager_cached_scan_does_not_cache_ancestor_directory_swap(tmp_path: Path) -> None:
    trees_root = tmp_path / "trees"
    live_root = trees_root / "live"
    decoy_root = trees_root / "decoy"
    live_leaf = live_root / "leaf"
    decoy_leaf = decoy_root / "leaf"
    live_leaf.mkdir(parents=True)
    decoy_leaf.mkdir(parents=True)
    malicious_path = _make_cacheable_file(live_leaf, name="model.dat")
    clean_path = _make_cacheable_file(decoy_leaf, name="model.dat")
    malicious_path.write_bytes(b"evil!:" + (b"x" * 2042))
    clean_path.write_bytes(b"clean:" + (b"y" * 2042))
    held_root = trees_root / "held"

    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}
    swap_blocked = {"value": False}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            try:
                live_root.rename(held_root)
            except PermissionError:
                if os.name != "nt":
                    raise
                swap_blocked["value"] = True
                return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}
            decoy_root.rename(live_root)
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            live_root.rename(decoy_root)
            held_root.rename(live_root)
            churn = live_root / "unrelated"
            churn.mkdir()
            churn.rmdir()
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(malicious_path), scan, version_context=version_context)
    if os.name == "nt":
        assert swap_blocked["value"] is True
        assert cache_manager.get_stats()["total_entries"] == 1
    else:
        assert swap_blocked["value"] is False
        assert cache_manager.get_stats()["total_entries"] == 0
    second = cache_manager.cached_scan(str(malicious_path), scan, version_context=version_context)

    assert first["payload_prefix"] == ("evil!:" if os.name == "nt" else "clean:")
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == (1 if os.name == "nt" else 2)
    assert cache_manager.get_stats()["total_entries"] == 1


def test_cache_manager_cached_scan_runs_when_pre_scan_hashing_fails(tmp_path: Path) -> None:
    file_path = tmp_path / "empty.dat"
    file_path.write_bytes(b"")
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        return {"size": Path(path).stat().st_size}

    result = cache_manager.cached_scan(str(file_path), scan, version_context=version_context)

    assert result["size"] == 0
    assert calls["count"] == 1
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cached_scan_runs_when_pre_scan_hashing_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = _make_cacheable_file(tmp_path, name="hash-failure.dat")
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.cache is not None
    calls = {"count": 0}

    def fail_hash(_path: str, _stat: os.stat_result) -> str:
        raise ValueError("hash unavailable")

    monkeypatch.setattr(cache_manager.cache.hasher, "hash_file_with_stat", fail_hash)

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"size": Path(path).stat().st_size}

    result = scan(str(file_path), config)

    assert result["size"] == 2048
    assert calls["count"] == 1
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cached_scan_invalidates_on_material_scan_config_change(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"call_count": calls["count"], "timeout": config["timeout"]}

    base_config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    changed_config = {**base_config, "timeout": 5}

    first = scan(str(file_path), base_config)
    second = scan(str(file_path), changed_config)
    third = scan(str(file_path), changed_config)

    assert first == {"call_count": 1, "timeout": 30}
    assert second == {"call_count": 2, "timeout": 5}
    assert third == second
    assert calls["count"] == 2


def test_normalize_material_scan_config_ignores_nested_scan_callback() -> None:
    def scan_nested_file(path: str, config: dict[str, Any] | None = None) -> None:
        return None

    assert normalize_material_scan_config(
        {
            "timeout": 30,
            "_archive_nested_scan_callback": scan_nested_file,
        }
    ) == {"timeout": 30}


def test_cached_scan_invalidates_on_rule_config_change(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {"call_count": calls["count"], "suppress_count": len(get_config().suppress)}

    first = scan(str(file_path), config)
    set_config(ModelAuditConfig(suppress={"S710"}))
    second = scan(str(file_path), config)
    third = scan(str(file_path), config)

    assert first == {"call_count": 1, "suppress_count": 0}
    assert second == {"call_count": 2, "suppress_count": 1}
    assert third == second
    assert calls["count"] == 2


def test_cached_scan_skips_persisting_operational_failures(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scan timeout after 1 seconds", "severity": "warning"}],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_operational_failures_from_checks(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [{"message": "Scan timeout after 1 seconds", "status": "failed"}],
            "issues": [],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 0


@pytest.mark.parametrize(
    "metadata",
    [
        {"scan_outcome": INCONCLUSIVE_SCAN_OUTCOME},
        {"analysis_incomplete": True},
        {"operational_error": True},
    ],
)
def test_cached_scan_skips_persisting_incomplete_metadata(
    tmp_path: Path,
    metadata: dict[str, Any],
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [],
            "metadata": metadata,
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_bare_unsuccessful_results(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [],
            "success": False,
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_normalizes_and_skips_persisting_bare_unsuccessful_scan_result(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls["count"] += 1
        result = ScanResult(scanner_name="numpy")
        result.finish(success=False)
        return result

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert isinstance(first, ScanResult)
    assert isinstance(second, ScanResult)
    assert first.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert second.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert first.metadata["scan_outcome_reasons"] == ["scanner_reported_unsuccessful_without_outcome"]
    assert second.metadata["scan_outcome_reasons"] == ["scanner_reported_unsuccessful_without_outcome"]
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_does_not_serialize_known_uncacheable_scan_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.cache is not None
    release_calls = 0
    original_release = cache_manager.cache.release_ancestor_identity

    def release_identity(identity: AncestorIdentity | None) -> None:
        nonlocal release_calls
        release_calls += 1
        original_release(identity)

    monkeypatch.setattr(cache_manager.cache, "release_ancestor_identity", release_identity)

    class UnserializableFailedResult(ScanResult):
        def to_dict(self) -> dict[str, Any]:
            raise AssertionError("known uncacheable results should not be serialized")

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        result = UnserializableFailedResult(scanner_name="pickle")
        result.finish(success=False)
        return result

    result = scan(str(file_path), config)

    assert isinstance(result, ScanResult)
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert cache_manager.get_stats()["total_entries"] == 0
    assert release_calls == 1


def test_cached_scan_skips_persisting_scan_timed_out_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.cache is not None
    release_calls = 0
    original_release = cache_manager.cache.release_ancestor_identity

    def release_identity(identity: AncestorIdentity | None) -> None:
        nonlocal release_calls
        release_calls += 1
        original_release(identity)

    monkeypatch.setattr(cache_manager.cache, "release_ancestor_identity", release_identity)

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scan timed out: metadata helper exceeded limit", "severity": "warning"}],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2
    assert cache_manager.get_stats()["total_entries"] == 0
    assert release_calls == 2


def test_cached_scan_skips_persisting_package_not_installed_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [
                {
                    "message": "paddlepaddle package not installed. Install with 'pip install paddlepaddle'",
                    "status": "failed",
                }
            ],
            "issues": [],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_os_level_errors(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "No such file or directory while opening sidecar", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_scanning_error_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scanning error: failed to read shard 0", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_memory_mapped_scan_errors(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [{"message": "Memory-mapped scan error: invalid mapping", "status": "failed"}],
            "issues": [],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


@pytest.mark.parametrize(
    "message",
    [
        "Associated .bin weights file not found",
        "Not a valid zip file: /tmp/example.zip",
    ],
)
def test_cached_scan_persists_deterministic_validation_findings(tmp_path: Path, message: str) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": message, "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == second
    assert calls["count"] == 1
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 1


def test_configuration_extractor_rebuilds_cached_config_after_mutation() -> None:
    extractor = ConfigurationExtractor()
    config = {"cache_enabled": True, "timeout": 30}

    first, _ = extractor.extract_fast(("file.bin", config), {})
    config["timeout"] = 5
    second, _ = extractor.extract_fast(("file.bin", config), {})

    assert first is not None
    assert second is not None
    assert first is not second
    assert first.get_version_context() != second.get_version_context()


def test_get_cache_manager_reinitializes_for_new_cache_dir(tmp_path: Path) -> None:
    first = get_cache_manager(str(tmp_path / "cache-a"), enabled=True)
    second = get_cache_manager(str(tmp_path / "cache-b"), enabled=True)

    assert first is not second
    assert second.cache is not None
    assert second.cache.cache_dir == tmp_path / "cache-b"


def test_get_cache_manager_reenables_cache_subsystems(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    disabled_manager = get_cache_manager(str(cache_dir), enabled=False)
    assert disabled_manager.enabled is False

    enabled_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(enabled_manager)

    assert enabled_manager.enabled is True
    assert enabled_manager.cache is not None
    assert enabled_manager.key_generator is not None
    assert batch_ops.get_batch_stats()["enabled"] is True


def test_batch_lookup_returns_cached_entries(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    assert cache_manager.cache is not None

    cache_manager.store_result(
        str(file_path),
        expected,
        10,
        version_context=version_context,
        **_identity_kwargs(cache_manager.cache, str(file_path)),
    )

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] == expected


def test_batch_lookup_rejects_transient_clean_hash_for_malicious_final_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="batch-lookup-race.dat")
    clean_payload = b"clean:" + (b"x" * 2042)
    malicious_payload = b"evil!:" + (b"y" * 2042)
    file_path.write_bytes(clean_payload)
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    cache = cache_manager.cache
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"verdict": "clean"}
    original_stat = file_path.stat()

    assert (
        cache_manager.store_result(
            str(file_path),
            expected,
            version_context=version_context,
            **_identity_kwargs(cache, str(file_path)),
        )
        is True
    )

    file_path.write_bytes(malicious_payload)
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    original_hash = cache.hasher.hash_file_with_stat
    raced = False

    def hash_transient_clean_bytes(path: str, file_stat: os.stat_result) -> str:
        nonlocal raced
        if raced:
            return original_hash(path, file_stat)
        raced = True
        Path(path).write_bytes(clean_payload)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        clean_hash = original_hash(path, Path(path).stat())
        Path(path).write_bytes(malicious_payload)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        return clean_hash

    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", hash_transient_clean_bytes)

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] is None
    assert file_path.read_bytes() == malicious_payload


def test_batch_lookup_rejects_stale_cache_entries(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    assert cache_manager.cache is not None

    assert (
        cache_manager.store_result(
            str(file_path),
            expected,
            10,
            version_context=version_context,
            **_identity_kwargs(cache_manager.cache, str(file_path)),
        )
        is True
    )

    cache_key = cache_manager.cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache_manager.cache._get_cache_file_path(cache_key)
    cache_entry = json.loads(cache_file_path.read_text(encoding="utf-8"))
    cache_entry["cache_metadata"]["scanned_at"] = time.time() - (31 * 24 * 60 * 60)
    cache_file_path.write_text(json.dumps(cache_entry, indent=2), encoding="utf-8")

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] is None
    assert not cache_file_path.exists()


def test_batch_store_skips_operational_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.cache is not None
    file_identity = cache_manager.cache.capture_file_identity(str(file_path))
    release_calls = 0
    original_release = cache_manager.cache.release_ancestor_identity

    def release_identity(identity: AncestorIdentity | None) -> None:
        nonlocal release_calls
        release_calls += 1
        original_release(identity)

    monkeypatch.setattr(cache_manager.cache, "release_ancestor_identity", release_identity)
    batch_ops = BatchCacheOperations(cache_manager)

    stored_count = batch_ops.batch_store(
        [
            (
                str(file_path),
                {
                    "scanner": "test",
                    "success": False,
                    "issues": [{"message": "Scan timed out: metadata helper exceeded limit", "severity": "warning"}],
                    "checks": [],
                    "metadata": {},
                },
                10,
            )
        ],
        expected_file_identities={str(file_path): file_identity},
    )

    assert stored_count == 0
    assert cache_manager.get_stats()["total_entries"] == 0
    assert release_calls == 1


def test_batch_store_skips_results_without_scanned_identity(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert batch_ops.batch_store([(str(file_path), expected, 10)]) == 0
    assert cache_manager.get_stats()["total_entries"] == 0


def test_batch_store_persists_bound_result(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    file_identity = cache_manager.cache.capture_file_identity(str(file_path))
    batch_ops = BatchCacheOperations(cache_manager)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert (
        batch_ops.batch_store(
            [(str(file_path), expected, 10)],
            expected_file_identities={str(file_path): file_identity},
        )
        == 1
    )
    assert cache_manager.get_stats()["total_entries"] == 1


def test_batch_store_rejects_replaced_file_identity(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="batch-race.dat")
    clean_payload = b"clean:" + (b"x" * 2042)
    malicious_payload = b"evil!:" + (b"y" * 2042)
    file_path.write_bytes(clean_payload)
    cache_manager = get_cache_manager(str(tmp_path / "cache"), enabled=True)
    assert cache_manager.cache is not None
    file_identity = cache_manager.cache.capture_file_identity(str(file_path))
    file_stat = file_path.stat()
    batch_ops = BatchCacheOperations(cache_manager)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    file_path.write_bytes(malicious_payload)
    os.utime(file_path, ns=(file_stat.st_atime_ns, file_stat.st_mtime_ns))

    assert (
        batch_ops.batch_store(
            [(str(file_path), expected, 10)],
            expected_file_identities={str(file_path): file_identity},
        )
        == 0
    )
    assert cache_manager.get_stats()["total_entries"] == 0


def test_batch_store_counts_only_persisted_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)

    assert cache_manager.cache is not None
    file_identity = cache_manager.cache.capture_file_identity(str(file_path))
    monkeypatch.setattr(cache_manager.cache, "_generate_cache_key_material", lambda *args, **kwargs: (None, None))

    stored_count = batch_ops.batch_store(
        [
            (
                str(file_path),
                {
                    "scanner": "test",
                    "success": True,
                    "issues": [],
                    "checks": [],
                    "metadata": {},
                },
                10,
            )
        ],
        expected_file_identities={str(file_path): file_identity},
    )

    assert stored_count == 0
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cache_entry_omits_raw_version_context(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    version_context = build_cache_version_context({"timeout": 30, "api_token": "super-secret-token"})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    assert cache_manager.cache is not None

    cache_manager.store_result(
        str(file_path),
        expected,
        10,
        version_context=version_context,
        **_identity_kwargs(cache_manager.cache, str(file_path)),
    )

    assert cache_manager.cache is not None
    cache_key = cache_manager.cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache_manager.cache._get_cache_file_path(cache_key)

    raw_cache_text = cache_file_path.read_text(encoding="utf-8")
    cache_entry = json.loads(raw_cache_text)

    assert "super-secret-token" not in raw_cache_text
    assert "version_context" not in cache_entry["version_info"]


def test_cache_key_is_none_when_scanner_versions_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When scanner versions cannot be resolved, caching must be disabled
    entirely to avoid key collisions between different scanner versions."""
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})

    def raise_scanner_versions() -> dict[str, str]:
        raise RuntimeError("scanner registry unavailable")

    monkeypatch.setattr(cache, "_get_scanner_versions", raise_scanner_versions)

    key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert key is None


def test_cache_key_generation_avoids_full_hash_for_medium_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="medium.cache")
    file_path.write_bytes(b"x" * (2 * 1024 * 1024))
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))

    def fail_hash(_: str) -> str:
        raise AssertionError("content hash should not be used for medium-file cache lookups")

    monkeypatch.setattr(cache.key_generator.hasher, "hash_file", fail_hash)

    cache_key = cache.generate_cache_key(str(file_path), version_context=build_cache_version_context({"timeout": 30}))

    assert cache_key is not None


def test_large_file_store_reuses_verified_post_scan_hash_for_cache_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="large-verified.cache")
    file_path.write_bytes(b"x" * (11 * 1024 * 1024))
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    file_stat, expected_hash, expected_change_token, expected_ancestor_identity = cache.capture_file_identity(
        str(file_path)
    )
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    hash_calls = {"count": 0}

    def verified_hash(_path: str, _stat: os.stat_result) -> str:
        hash_calls["count"] += 1
        return expected_hash

    def fail_key_hash(_path: str) -> str:
        raise AssertionError("large-file cache key should reuse the verified post-scan hash")

    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", verified_hash)
    monkeypatch.setattr(cache.key_generator.hasher, "hash_file", fail_key_hash)

    assert (
        cache.store_result(
            str(file_path),
            expected,
            10,
            version_context=version_context,
            expected_file_stat=file_stat,
            expected_file_hash=expected_hash,
            expected_change_token=expected_change_token,
            expected_ancestor_identity=expected_ancestor_identity,
        )
        is True
    )
    assert hash_calls["count"] == 1


def test_store_result_rejects_missing_expected_identity(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="unbound.cache")
    cache_manager = get_cache_manager(str(tmp_path / "scan-cache"), enabled=True)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache_manager.store_result(str(file_path), expected, 10) is False
    assert cache_manager.get_stats()["total_entries"] == 0


@pytest.mark.parametrize("missing_part", ["stat", "hash", "change_token", "ancestor_identity"])
def test_store_result_rejects_incomplete_expected_identity(tmp_path: Path, missing_part: str) -> None:
    file_path = _make_cacheable_file(tmp_path, name="incomplete-identity.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    file_stat, file_hash, change_token, ancestor_identity = cache.capture_file_identity(str(file_path))
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    stored = cache.store_result(
        str(file_path),
        expected,
        10,
        expected_file_stat=None if missing_part == "stat" else file_stat,
        expected_file_hash=None if missing_part == "hash" else file_hash,
        expected_change_token=None if missing_part == "change_token" else change_token,
        expected_ancestor_identity=None if missing_part == "ancestor_identity" else ancestor_identity,
    )

    assert stored is False
    assert cache.get_cache_stats()["total_entries"] == 0


def test_store_result_rechecks_identity_after_verification_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="post-hash-race.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    expected_stat, expected_hash, expected_change_token, expected_ancestor_identity = cache.capture_file_identity(
        str(file_path)
    )
    original_hash_file_with_stat = cache.hasher.hash_file_with_stat
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    def mutate_after_hash(path: str, file_stat: os.stat_result) -> str:
        current_hash = original_hash_file_with_stat(path, file_stat)
        Path(path).write_bytes(b"y" * file_stat.st_size)
        os.utime(path, ns=(file_stat.st_atime_ns, file_stat.st_mtime_ns + 1_000_000_000))
        return current_hash

    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", mutate_after_hash)

    stored = cache.store_result(
        str(file_path),
        expected,
        10,
        expected_file_stat=expected_stat,
        expected_file_hash=expected_hash,
        expected_change_token=expected_change_token,
        expected_ancestor_identity=expected_ancestor_identity,
    )

    assert stored is False
    assert cache.get_cache_stats()["total_entries"] == 0


def test_store_result_publishes_atomically_after_final_identity_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="atomic-publish.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    replace_calls: list[tuple[Path, Path]] = []
    original_replace = os.replace

    def checked_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        assert source_path.suffix == ".tmp"
        assert source_path.is_file()
        assert not destination_path.exists()
        assert json.loads(source_path.read_text(encoding="utf-8"))["scan_result"] == expected
        replace_calls.append((source_path, destination_path))
        original_replace(source, destination)

    monkeypatch.setattr(os, "replace", checked_replace)

    assert cache.store_result(str(file_path), expected, 10, **_identity_kwargs(cache, str(file_path))) is True
    assert len(replace_calls) == 1
    assert not replace_calls[0][0].exists()
    assert replace_calls[0][1].is_file()


def test_store_result_discards_private_entry_when_final_identity_check_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="rejected-publish.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    expected_stat, expected_hash, expected_change_token, expected_ancestor_identity = cache.capture_file_identity(
        str(file_path)
    )
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    token_calls = 0
    private_entry_observed = False
    original_get_file_change_token = cache._get_file_change_token

    def changed_on_final_check(path: str, stat_result: os.stat_result | None = None) -> int:
        nonlocal private_entry_observed, token_calls
        if Path(path) != file_path:
            assert stat_result is not None
            return original_get_file_change_token(path, stat_result)
        token_calls += 1
        private_entry_observed = bool(list(cache.cache_dir.rglob("*.tmp")))
        return expected_change_token + int(private_entry_observed)

    monkeypatch.setattr(cache, "_get_file_change_token", changed_on_final_check)
    monkeypatch.setattr(os, "replace", lambda *_args: pytest.fail("rejected entry must not be published"))

    stored = cache.store_result(
        str(file_path),
        expected,
        10,
        expected_file_stat=expected_stat,
        expected_file_hash=expected_hash,
        expected_change_token=expected_change_token,
        expected_ancestor_identity=expected_ancestor_identity,
    )

    assert stored is False
    assert token_calls >= 3
    assert private_entry_observed is True
    assert cache.get_cache_stats()["total_entries"] == 0
    assert not list(cache.cache_dir.rglob("*.tmp"))


def test_store_result_cleans_private_entry_when_serialization_fails(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="serialization-failure.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    unserializable_result = {"value": object()}

    stored = cache.store_result(
        str(file_path),
        unserializable_result,
        10,
        **_identity_kwargs(cache, str(file_path)),
    )

    assert stored is False
    assert cache.get_cache_stats()["total_entries"] == 0
    assert not list(cache.cache_dir.rglob("*.tmp"))


def test_sampled_large_file_fingerprint_result_is_not_cached(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="sampled-large.cache")
    file_path.write_bytes(b"x" * (16 * 1024 * 1024))
    original_stat = file_path.stat()
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    cache.hasher.full_hash_threshold = 1024
    cache.key_generator.hasher.full_hash_threshold = 1024
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    sampled_fingerprint = cache.key_generator.hasher.hash_file(str(file_path))
    assert sampled_fingerprint.startswith("fingerprint:")
    assert (
        cache.store_result(
            str(file_path),
            expected,
            10,
            version_context=version_context,
            **_identity_kwargs(cache, str(file_path)),
        )
        is False
    )

    with file_path.open("r+b") as f:
        f.seek(6 * 1024 * 1024)
        f.write(b"evil")
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    assert cache.key_generator.hasher.hash_file(str(file_path)) == sampled_fingerprint
    assert cache.generate_cache_key(str(file_path), version_context=version_context) is None
    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_legacy_sampled_large_file_cache_entry_is_rejected_by_key(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="legacy-sampled-large.cache")
    file_path.write_bytes(b"x" * (16 * 1024 * 1024))
    original_stat = file_path.stat()
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    cache.key_generator.hasher.full_hash_threshold = 1024
    sampled_fingerprint = cache.key_generator.hasher.hash_file(str(file_path))
    cache_key = "legacy_sampled_cache_key"
    cache_file_path = cache._get_cache_file_path(cache_key)
    cache_file_path.parent.mkdir(parents=True, exist_ok=True)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}
    cache_file_path.write_text(
        json.dumps(
            {
                "cache_key": cache_key,
                "file_info": {
                    "hash": sampled_fingerprint,
                    "size": original_stat.st_size,
                    "mtime": original_stat.st_mtime,
                    "mtime_ns": original_stat.st_mtime_ns,
                },
                "version_info": {},
                "scan_result": expected,
                "cache_metadata": {
                    "scanned_at": time.time(),
                    "last_access": time.time(),
                    "access_count": 1,
                },
            }
        ),
        encoding="utf-8",
    )

    with file_path.open("r+b") as f:
        f.seek(6 * 1024 * 1024)
        f.write(b"evil")
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    assert cache.key_generator.hasher.hash_file(str(file_path)) == sampled_fingerprint
    assert (
        cache.get_cached_result_by_key(
            cache_key,
            file_path=str(file_path),
            file_stat=file_path.stat(),
        )
        is None
    )
    assert not cache_file_path.exists()


def test_same_size_rewrite_with_high_resolution_mtime_invalidates_cache(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="medium.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert (
        cache.store_result(
            str(file_path),
            expected,
            10,
            version_context=version_context,
            **_identity_kwargs(cache, str(file_path)),
        )
        is True
    )

    original_stat = file_path.stat()
    file_path.write_bytes(b"y" * 2048)
    base_second_ns = (original_stat.st_mtime_ns // 1_000_000_000) * 1_000_000_000
    original_offset_ns = original_stat.st_mtime_ns % 1_000_000_000
    new_offset_ns = 123_456_789 if original_offset_ns != 123_456_789 else 123_456_790
    os.utime(file_path, ns=(original_stat.st_atime_ns, base_second_ns + new_offset_ns))

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)

    assert cached_result is None


def test_same_size_rewrite_with_restored_mtime_invalidates_cache(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="small.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert (
        cache.store_result(
            str(file_path),
            expected,
            10,
            version_context=version_context,
            **_identity_kwargs(cache, str(file_path)),
        )
        is True
    )

    original_stat = file_path.stat()
    file_path.write_bytes(b"y" * 2048)
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)

    assert cached_result is None
