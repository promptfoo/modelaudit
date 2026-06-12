from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import zipfile
from collections.abc import Iterator
from importlib.abc import MetaPathFinder
from importlib.machinery import (
    BYTECODE_SUFFIXES,
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    ExtensionFileLoader,
    FileFinder,
    ModuleSpec,
    PathFinder,
    SourceFileLoader,
    SourcelessFileLoader,
)
from pathlib import Path
from types import FunctionType, ModuleType
from typing import Any
from zipimport import zipimporter

import pytest
from modelaudit_picklescan.call_graph import _import_hook_identity as _picklescan_import_hook_identity
from modelaudit_picklescan.call_graph import _path_hook_resolution_identity as _picklescan_path_hook_resolution_identity
from modelaudit_picklescan.call_graph import (
    _resolution_candidate_fingerprint as _picklescan_resolution_candidate_fingerprint,
)
from modelaudit_picklescan.call_graph import _source_resolution_context as _picklescan_source_resolution_context

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.batch_operations import BatchCacheOperations
from modelaudit.cache.optimized_config import (
    ConfigurationExtractor,
    build_cache_version_context,
    get_config_extractor,
    normalize_material_scan_config,
)
from modelaudit.cache.scan_results_cache import (
    _CALL_GRAPH_REGULAR_FILE_FINGERPRINT,
    AncestorIdentity,
    ScanResultsCache,
    _import_hook_identity,
    _path_hook_resolution_identity,
    _source_resolution_context,
)
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


def _call_graph_fingerprint_metadata(
    fingerprints: dict[str, str | None] | None = None,
    *,
    module_sources: dict[str, str] | None = None,
    loaded_module_sources: dict[str, str] | None = None,
    loaded_package_paths: dict[str, list[str]] | None = None,
    read_fingerprints: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "reusable": True,
        "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
        "resolution_context": _source_resolution_context(),
        "module_sources": module_sources or {},
        "loaded_module_sources": loaded_module_sources or {},
        "loaded_package_paths": loaded_package_paths or {},
        "fingerprints": fingerprints or {},
        "read_fingerprints": read_fingerprints or {},
    }


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


def _identity_kwargs(cache: ScanResultsCache, file_path: str) -> dict[str, Any]:
    file_stat, file_hash, change_token, ancestor_identity = cache.capture_file_identity(file_path)
    return {
        "expected_file_stat": file_stat,
        "expected_file_hash": file_hash,
        "expected_change_token": change_token,
        "expected_ancestor_identity": ancestor_identity,
    }


def test_cache_config_hash_preserves_128_bits(tmp_path: Path) -> None:
    """Attacker-influenced scan context must not collapse to a short cache identity."""
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = {"advanced_shard_family": {"members": ["secure:member-digest"]}}
    serialized_context = json.dumps(version_context, sort_keys=True)

    config_hash = cache._get_config_hash(version_context)

    assert config_hash == hashlib.blake2b(serialized_context.encode(), digest_size=16).hexdigest()
    assert len(config_hash) == 32


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


def test_change_clock_probe_prefers_isolated_directory(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))

    file_stat, _file_hash, _change_token, ancestor_identity = cache.capture_file_identity(str(file_path))

    assert ancestor_identity
    expected_probe_dir = Path(tempfile.gettempdir()) if os.name == "nt" else cache.cache_dir
    assert cache._change_clock_probes[file_stat.st_dev][1] == expected_probe_dir


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
            newest_token,
            ancestor_identity,
        )

    assert clock["now"] >= 0.1


def test_windows_change_clock_barrier_ignores_ancestor_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    ancestor_identity = AncestorIdentity(
        [
            (
                str(file_path.parent),
                file_path.stat().st_dev,
                file_path.parent.stat().st_ino,
                file_path.parent.stat().st_mode,
                file_path.parent.stat().st_mtime_ns,
                10_000,
            )
        ]
    )

    with tempfile.TemporaryFile(mode="w+b", dir=tmp_path) as probe:
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setattr(cache, "_touch_change_clock_probe", lambda _probe: 2)
        assert cache._advance_change_clock(str(file_path), probe, 1, ancestor_identity) == 2


def test_windows_capture_barrier_ignores_ancestor_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    file_stat = file_path.stat()
    ancestor_identity = AncestorIdentity(
        [
            (
                str(file_path.parent),
                file_stat.st_dev,
                file_path.parent.stat().st_ino,
                file_path.parent.stat().st_mode,
                file_path.parent.stat().st_mtime_ns,
                10_000,
            )
        ]
    )

    with tempfile.TemporaryFile(mode="w+b", dir=tmp_path) as probe:
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setattr(cache, "_path_has_symlink_component", lambda _path: False)
        monkeypatch.setattr(cache, "_get_change_clock_probe", lambda _path, _device: probe)
        monkeypatch.setattr(cache, "_get_file_change_token", lambda _path, _stat: 1)
        monkeypatch.setattr(cache, "_capture_ancestor_identity", lambda _path: ancestor_identity)
        monkeypatch.setattr(cache, "_advance_change_clock", lambda *_args: 2)
        monkeypatch.setattr(cache, "_monitor_ancestor_identity", lambda _path, identity: identity)
        monkeypatch.setattr(cache.hasher, "hash_file_with_stat", lambda _path, _stat: "secure:stable")

        captured_identity = cache.capture_file_identity(str(file_path))

    assert captured_identity[0] == file_stat
    assert captured_identity[1:] == ("secure:stable", 1, ancestor_identity)


def test_capture_file_identity_retries_transient_monitor_start_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "cache"))
    original_stat_matches = cache._stat_matches
    comparisons = {"count": 0}

    def transient_stat_mismatch(left: os.stat_result, right: os.stat_result) -> bool:
        comparisons["count"] += 1
        if comparisons["count"] == 1:
            return False
        return original_stat_matches(left, right)

    monkeypatch.setattr(cache, "_stat_matches", transient_stat_mismatch)

    identity = cache.capture_file_identity(str(file_path))
    try:
        assert identity[1].startswith("secure:")
        assert comparisons["count"] > 1
    finally:
        cache.release_ancestor_identity(identity[-1])


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

    with pytest.raises(ValueError, match=r"File (changed|kept changing) while (starting|capturing) cache identity"):
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


def test_missing_file_cache_lookups_return_misses(tmp_path: Path) -> None:
    cache = ScanResultsCache(str(tmp_path / "cache"))
    missing_path = tmp_path / "missing.cache"

    assert cache.get_cached_result(str(missing_path)) is None
    assert cache.get_cached_result_with_identity(str(missing_path)) == (None, None)
    assert cache.get_cached_result_by_key("missing-key", file_path=str(missing_path)) is None
    assert cache._get_cached_result_by_key("missing-key", file_path=str(missing_path)) is None
    assert cache.get_cache_stats()["cache_misses"] == 4


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


@pytest.mark.skipif(sys.platform != "darwin", reason="requires Darwin /private path aliases")
def test_cache_identity_allows_darwin_private_var_and_tmp_aliases(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    alias_path: Path | None = None
    for alias, target in ((Path("/var"), Path("/private/var")), (Path("/tmp"), Path("/private/tmp"))):
        try:
            candidate = alias / file_path.resolve().relative_to(target)
        except ValueError:
            continue
        if alias.is_symlink() and candidate.exists():
            alias_path = candidate
            break
    if alias_path is None:
        pytest.skip("test temp path is not reachable through a Darwin /private alias")

    cache = ScanResultsCache(str(tmp_path / "cache"))

    assert cache._path_has_symlink_component(str(alias_path)) is False
    file_stat, _file_hash, _change_token, ancestor_identity = cache.capture_file_identity(str(alias_path))
    assert file_stat.st_size == file_path.stat().st_size
    assert ancestor_identity


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


def test_cached_scan_restores_private_metadata_for_internal_scan_results(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}
    fingerprint_metadata = _call_graph_fingerprint_metadata()

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        assert config is not None
        calls["count"] += 1
        result = ScanResult(scanner_name="pickle")
        result._private_metadata["call_graph_source_fingerprints"] = fingerprint_metadata
        result.finish()
        return result

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert calls["count"] == 1
    assert first._private_metadata["call_graph_source_fingerprints"] == fingerprint_metadata
    assert second._private_metadata["call_graph_source_fingerprints"] == fingerprint_metadata
    assert "_private_metadata" not in second.to_dict()


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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires inotify path monitoring")
@pytest.mark.parametrize(
    ("model_subdirectory", "cache_subdirectory"),
    [
        (None, "cache"),
        ("sub", "cache"),
        ("sub", None),
    ],
    ids=["direct-parent-probe", "nested-sibling-probe", "intermediate-ancestor-probe"],
)
def test_cache_manager_does_not_cache_higher_ancestor_swap(
    tmp_path: Path,
    model_subdirectory: str | None,
    cache_subdirectory: str | None,
) -> None:
    scan_root = tmp_path / "scan-root"
    model_dir = scan_root / "models"
    model_dir.mkdir(parents=True)
    model_parent = model_dir / model_subdirectory if model_subdirectory is not None else model_dir
    model_parent.mkdir(exist_ok=True)
    model_path = _make_cacheable_file(model_parent, name="model.dat")
    model_path.write_bytes(b"evil!:" + (b"x" * 2042))
    displaced_root = tmp_path / "scan-root-displaced"

    cache_dir = model_dir / cache_subdirectory if cache_subdirectory is not None else model_dir
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    version_context = build_cache_version_context({"timeout": 30})
    calls = {"count": 0}

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            scan_root.rename(displaced_root)
            replacement_dir = scan_root / model_path.parent.relative_to(scan_root)
            replacement_dir.mkdir(parents=True)
            replacement_path = replacement_dir / model_path.name
            replacement_path.write_bytes(b"clean:" + (b"y" * 2042))
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            replacement_path.unlink()
            while replacement_dir != scan_root:
                replacement_dir.rmdir()
                replacement_dir = replacement_dir.parent
            scan_root.rmdir()
            displaced_root.rename(scan_root)
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)
    assert cache_manager.get_stats()["total_entries"] == 0
    second = cache_manager.cached_scan(str(model_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2


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


def test_unmonitored_platform_does_not_cache_higher_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trees_root = tmp_path / "trees"
    live_root = trees_root / "live"
    decoy_root = trees_root / "decoy"
    live_leaf = live_root / "branch" / "leaf"
    decoy_leaf = decoy_root / "branch" / "leaf"
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
    monkeypatch.setattr(sys, "platform", "darwin")

    def scan(path: str) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 1:
            live_root.rename(held_root)
            decoy_root.rename(live_root)
            prefix = Path(path).read_bytes()[:6].decode("utf-8")
            live_root.rename(decoy_root)
            held_root.rename(live_root)
            return {"payload_prefix": prefix}
        return {"payload_prefix": Path(path).read_bytes()[:6].decode("utf-8")}

    first = cache_manager.cached_scan(str(malicious_path), scan, version_context=version_context)
    second = cache_manager.cached_scan(str(malicious_path), scan, version_context=version_context)

    assert first["payload_prefix"] == "clean:"
    assert second["payload_prefix"] == "evil!:"
    assert calls["count"] == 2
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


def test_scan_cache_invalidates_call_graph_source_fingerprint_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_path = source_root / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(source_root))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source_fingerprint = hashlib.sha256(source_path.read_bytes()).hexdigest()
    fingerprint_metadata = _call_graph_fingerprint_metadata(
        {
            str(source_path.absolute()): source_fingerprint,
            str((source_root / "missing.py").absolute()): None,
        },
        module_sources={"helper": str(source_path.absolute())},
    )
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {"call_graph_source_fingerprints": fingerprint_metadata},
    }
    expected_cached_result: dict[str, Any] = {"checks": [], "issues": [], "metadata": {}}

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) == expected_cached_result
    internal_cached_result = cache.get_cached_result(
        str(file_path),
        version_context=version_context,
        include_private_metadata=True,
    )
    assert internal_cached_result is not None
    assert "call_graph_source_fingerprints" not in internal_cached_result["metadata"]
    assert internal_cached_result["_private_metadata"]["call_graph_source_fingerprints"] == fingerprint_metadata

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_when_loaded_module_override_appears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_source = tmp_path / "first" / "cache_switch_module.py"
    second_source = tmp_path / "second" / "cache_switch_module.py"
    first_source.parent.mkdir()
    second_source.parent.mkdir()
    first_source.write_text("def entrypoint():\n    return 1\n")
    second_source.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    monkeypatch.syspath_prepend(str(first_source.parent))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {str(first_source.absolute()): hashlib.sha256(first_source.read_bytes()).hexdigest()},
                module_sources={"cache_switch_module": str(first_source.absolute())},
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    replacement_module = ModuleType("cache_switch_module")
    replacement_module.__spec__ = ModuleSpec("cache_switch_module", loader=None, origin=str(second_source))
    monkeypatch.setitem(sys.modules, "cache_switch_module", replacement_module)

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_when_loaded_parent_package_can_redirect_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_source = tmp_path / "first" / "cache_pkg" / "child.py"
    second_source = tmp_path / "second" / "cache_pkg" / "child.py"
    first_source.parent.mkdir(parents=True)
    second_source.parent.mkdir(parents=True)
    first_source.write_text("def entrypoint():\n    return 1\n")
    second_source.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    monkeypatch.syspath_prepend(str(first_source.parents[1]))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    first_source_path = str(first_source.absolute())
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {first_source_path: hashlib.sha256(first_source.read_bytes()).hexdigest()},
                module_sources={"cache_pkg.child": first_source_path},
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    loaded_parent = ModuleType("cache_pkg")
    loaded_parent.__path__ = [str(second_source.parent)]
    loaded_parent.__spec__ = ModuleSpec("cache_pkg", loader=None, is_package=True)
    monkeypatch.setitem(sys.modules, "cache_pkg", loaded_parent)

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_reuses_matching_loaded_parent_package_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_source = tmp_path / "first" / "cache_pkg" / "child.py"
    second_source = tmp_path / "second" / "cache_pkg" / "child.py"
    first_source.parent.mkdir(parents=True)
    second_source.parent.mkdir(parents=True)
    first_source.write_text("def entrypoint():\n    return 1\n")
    second_source.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")
    loaded_parent = ModuleType("cache_pkg")
    loaded_parent.__path__ = [str(first_source.parent)]
    loaded_parent.__spec__ = ModuleSpec("cache_pkg", loader=None, is_package=True)
    monkeypatch.setitem(sys.modules, "cache_pkg", loaded_parent)
    package_path = str(first_source.parent.absolute())
    standard_finder = FileFinder(
        package_path,
        (ExtensionFileLoader, EXTENSION_SUFFIXES),
        (SourceFileLoader, SOURCE_SUFFIXES),
        (SourcelessFileLoader, BYTECODE_SUFFIXES),
    )
    monkeypatch.setitem(sys.path_importer_cache, package_path, standard_finder)

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    first_source_path = str(first_source.absolute())
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {first_source_path: hashlib.sha256(first_source.read_bytes()).hexdigest()},
                module_sources={"cache_pkg.child": first_source_path},
                loaded_package_paths={"cache_pkg": [package_path]},
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    loaded_parent.__path__ = [str(second_source.parent)]

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_rejects_custom_importer_on_matching_loaded_parent_package_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "runtime" / "cache_pkg" / "child.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("def entrypoint():\n    return 1\n")
    package_path = str(source_path.parent.absolute())
    loaded_parent = ModuleType("cache_pkg")
    loaded_parent.__path__ = [package_path]
    loaded_parent.__spec__ = ModuleSpec("cache_pkg", loader=None, is_package=True)
    monkeypatch.setitem(sys.modules, "cache_pkg", loaded_parent)

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source = str(source_path.absolute())
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {source: hashlib.sha256(source_path.read_bytes()).hexdigest()},
                module_sources={"cache_pkg.child": source},
                loaded_package_paths={"cache_pkg": [package_path]},
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    class CustomFinder:
        pass

    monkeypatch.setitem(sys.path_importer_cache, package_path, CustomFinder())

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_when_loaded_module_disappears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "loaded_then_removed.py"
    source_path.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    loaded_module = ModuleType("loaded_then_removed")
    loaded_module.__spec__ = ModuleSpec("loaded_then_removed", loader=None, origin=str(source_path))
    monkeypatch.setitem(sys.modules, "loaded_then_removed", loaded_module)

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source = str(source_path.absolute())
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {source: hashlib.sha256(source_path.read_bytes()).hexdigest()},
                module_sources={"loaded_then_removed": source},
                loaded_module_sources={"loaded_then_removed": source},
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    monkeypatch.delitem(sys.modules, "loaded_then_removed")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_import_hook_identity_distinguishes_same_qualname_closures() -> None:
    source_hook = FileFinder.path_hook((SourceFileLoader, SOURCE_SUFFIXES))
    equivalent_source_hook = FileFinder.path_hook((SourceFileLoader, SOURCE_SUFFIXES))
    bytecode_hook = FileFinder.path_hook((SourcelessFileLoader, BYTECODE_SUFFIXES))

    assert source_hook.__qualname__ == bytecode_hook.__qualname__
    assert _import_hook_identity(source_hook) == _import_hook_identity(equivalent_source_hook)
    assert _import_hook_identity(source_hook) != _import_hook_identity(bytecode_hook)


def test_import_hook_identity_tracks_function_defaults_and_keyword_defaults() -> None:
    def hook(_path: str, target: str = "safe", *, mode: str = "source") -> tuple[str, str]:
        return target, mode

    identity_functions = (_import_hook_identity, _picklescan_import_hook_identity)
    initial_identities = tuple(identity(hook) for identity in identity_functions)

    hook.__defaults__ = ("malicious",)

    assert all(
        identity(hook) != initial for identity, initial in zip(identity_functions, initial_identities, strict=True)
    )

    hook.__defaults__ = ("safe",)
    default_restored_identities = tuple(identity(hook) for identity in identity_functions)
    hook.__kwdefaults__ = {"mode": "bytecode"}

    assert all(
        identity(hook) != initial
        for identity, initial in zip(identity_functions, default_restored_identities, strict=True)
    )


def test_import_hook_identity_tracks_referenced_global_state() -> None:
    namespace: dict[str, Any] = {"__name__": "modelaudit_hook_identity_test", "target": "safe"}
    exec("def hook(_path):\n    return target\n", namespace)
    hook = namespace["hook"]
    assert isinstance(hook, FunctionType)
    identity_functions = (_import_hook_identity, _picklescan_import_hook_identity)
    initial_identities = tuple(identity(hook) for identity in identity_functions)

    namespace["target"] = "malicious"

    assert all(
        identity(hook) != initial for identity, initial in zip(identity_functions, initial_identities, strict=True)
    )


def test_import_hook_identity_tracks_class_method_state() -> None:
    namespace: dict[str, Any] = {"__name__": "modelaudit_class_hook_identity_test", "target": "safe"}
    exec(
        "class Finder:\n"
        "    root = 'safe'\n"
        "    def find_spec(self, fullname, mode='source'):\n"
        "        return self.root, target, fullname, mode\n",
        namespace,
    )
    finder_type: Any = namespace["Finder"]
    finder = finder_type()
    identity_functions = (_import_hook_identity, _picklescan_import_hook_identity)

    initial_identities = tuple(identity(finder) for identity in identity_functions)
    finder_type.root = "malicious"
    assert all(
        identity(finder) != initial for identity, initial in zip(identity_functions, initial_identities, strict=True)
    )

    finder_type.root = "safe"
    restored_identities = tuple(identity(finder) for identity in identity_functions)
    finder_type.find_spec.__defaults__ = ("bytecode",)
    assert all(
        identity(finder) != restored for identity, restored in zip(identity_functions, restored_identities, strict=True)
    )

    finder_type.find_spec.__defaults__ = ("source",)
    defaults_restored_identities = tuple(identity(finder) for identity in identity_functions)
    namespace["target"] = "malicious"
    assert all(
        identity(finder) != restored
        for identity, restored in zip(identity_functions, defaults_restored_identities, strict=True)
    )

    finder_type.__module__ = PathFinder.__module__
    finder_type.__qualname__ = PathFinder.__qualname__
    assert all(":unreusable:" in identity(finder_type) for identity in identity_functions)


def test_standard_file_finder_hook_identity_invalidates_when_methods_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    standard_hook = next(
        hook
        for hook in sys.path_hooks
        if _picklescan_path_hook_resolution_identity(hook) == "trusted:importlib.machinery.FileFinder.path_hook"
    )
    initial_cache_identity = _path_hook_resolution_identity(standard_hook)
    initial_picklescan_identity = _picklescan_path_hook_resolution_identity(standard_hook)

    def changed_find_spec(self: FileFinder, _fullname: str, _target: object = None) -> None:
        return None

    monkeypatch.setattr(FileFinder, "find_spec", changed_find_spec)

    changed_cache_identity = _path_hook_resolution_identity(standard_hook)
    changed_picklescan_identity = _picklescan_path_hook_resolution_identity(standard_hook)
    assert changed_cache_identity != initial_cache_identity
    assert changed_picklescan_identity != initial_picklescan_identity
    assert ":unreusable:" in changed_cache_identity
    assert ":unreusable:" in changed_picklescan_identity


def test_arbitrary_startup_path_hook_is_never_trusted() -> None:
    class StartupPathHook:
        def __call__(self, _path: str) -> None:
            raise ImportError

    hook = StartupPathHook()

    for identity in (_path_hook_resolution_identity(hook), _picklescan_path_hook_resolution_identity(hook)):
        assert not identity.startswith("trusted:")
        assert ":unreusable:" in identity


def test_import_hook_identity_tracks_bound_method_state() -> None:
    class StatefulHook:
        def __init__(self, target: str) -> None:
            self.target = target

        def find_spec(self, *_args: object) -> str:
            return self.target

    hook = StatefulHook("safe")
    cache_identity = _import_hook_identity(hook.find_spec)
    picklescan_identity = _picklescan_import_hook_identity(hook.find_spec)

    hook.target = "malicious"

    assert _import_hook_identity(hook.find_spec) != cache_identity
    assert _picklescan_import_hook_identity(hook.find_spec) != picklescan_identity


def test_scan_cache_rejects_file_finder_subclass_importer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_entry = str(tmp_path / "custom-import-root")
    Path(path_entry).mkdir()

    class StatefulFileFinder(FileFinder):
        def __init__(self, path: str, state: str) -> None:
            super().__init__(path, (SourceFileLoader, SOURCE_SUFFIXES))
            self.state = state

    finder = StatefulFileFinder(path_entry, "safe")
    monkeypatch.setattr(sys, "path", [path_entry, *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, finder)

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprint_metadata = _call_graph_fingerprint_metadata()
    assert any(path_entry in identity for identity in fingerprint_metadata["resolution_context"]["path_importers"])
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {"call_graph_source_fingerprints": fingerprint_metadata},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    finder.state = "malicious"

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_rejects_custom_file_finder_loader_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_entry = str(tmp_path / "custom-loader-root")
    Path(path_entry).mkdir()

    class SafeLoader(SourceFileLoader):
        pass

    class MaliciousLoader(SourceFileLoader):
        pass

    finder = FileFinder(path_entry, (SafeLoader, SOURCE_SUFFIXES))
    monkeypatch.setattr(sys, "path", [path_entry, *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, finder)

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprint_metadata = _call_graph_fingerprint_metadata()
    assert any(path_entry in identity for identity in fingerprint_metadata["resolution_context"]["path_importers"])
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {"call_graph_source_fingerprints": fingerprint_metadata},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    object.__getattribute__(finder, "__dict__")["_loaders"] = [(suffix, MaliciousLoader) for suffix in SOURCE_SUFFIXES]

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


@pytest.mark.parametrize("descriptor_kind", ["classmethod", "staticmethod"])
def test_import_hook_identity_includes_descriptor_method_code(descriptor_kind: str) -> None:
    def original_find_spec(*_args: object) -> None:
        return None

    def changed_find_spec(*_args: object) -> str:
        return "changed"

    descriptor = classmethod if descriptor_kind == "classmethod" else staticmethod
    original_hook = type("DescriptorFinder", (), {"find_spec": descriptor(original_find_spec)})
    equivalent_hook = type("DescriptorFinder", (), {"find_spec": descriptor(original_find_spec)})
    changed_hook = type("DescriptorFinder", (), {"find_spec": descriptor(changed_find_spec)})

    assert _import_hook_identity(original_hook) == _import_hook_identity(equivalent_hook)
    assert _import_hook_identity(original_hook) != _import_hook_identity(changed_hook)
    assert _picklescan_import_hook_identity(original_hook) == _picklescan_import_hook_identity(equivalent_hook)
    assert _picklescan_import_hook_identity(original_hook) != _picklescan_import_hook_identity(changed_hook)


def test_cache_resolution_context_matches_picklescan_metadata() -> None:
    meta_path, path_hooks, path_importers = _picklescan_source_resolution_context()

    assert _source_resolution_context() == {
        "meta_path": list(meta_path),
        "path_hooks": list(path_hooks),
        "path_importers": list(path_importers),
    }


def test_resolution_context_rejects_mutated_zipimporter_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "modules.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("sample.py", "value = 1\n")

    path_entry = str(archive_path)
    finder = zipimporter(path_entry)
    monkeypatch.setattr(sys, "path", [path_entry, *sys.path])
    monkeypatch.setitem(sys.path_importer_cache, path_entry, finder)

    assert not _source_resolution_context()["path_importers"]
    assert not _picklescan_source_resolution_context()[2]

    object.__getattribute__(finder, "__dict__")["archive"] = str(tmp_path / "other.zip")

    assert any(path_entry in identity for identity in _source_resolution_context()["path_importers"])
    assert any(path_entry in identity for identity in _picklescan_source_resolution_context()[2])


def test_cache_module_validation_does_not_execute_custom_path_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "direct_resolution.py"
    source_path.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))

    class ExplodingPathHook:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, _path: str) -> object:
            self.calls += 1
            raise AssertionError("cache validation executed a custom path hook")

    path_hook = ExplodingPathHook()
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source = str(source_path.absolute())
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {source: hashlib.sha256(source_path.read_bytes()).hexdigest()},
                module_sources={"direct_resolution": source},
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    monkeypatch.setattr(sys, "path_hooks", [path_hook])
    cache_key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_path = cache._get_cache_file_path(cache_key)
    cache_entry = json.loads(cache_path.read_text(encoding="utf-8"))
    cache_entry["cache_metadata"]["call_graph_source_fingerprints"]["resolution_context"] = _source_resolution_context()
    cache_path.write_text(json.dumps(cache_entry), encoding="utf-8")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None
    assert path_hook.calls == 0


def test_scan_cache_invalidates_when_import_resolution_hooks_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_source = tmp_path / "hook_resolved_module.py"
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata({str(missing_source.absolute()): None})
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    class NoopFinder(MetaPathFinder):
        pass

    monkeypatch.setattr(sys, "meta_path", [NoopFinder(), *sys.meta_path])

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_call_graph_missing_source_appears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    missing_path = source_root / "helper.py"
    monkeypatch.syspath_prepend(str(source_root))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata({str(missing_path.absolute()): None})
        },
    }
    expected_cached_result: dict[str, Any] = {"checks": [], "issues": [], "metadata": {}}

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) == expected_cached_result

    missing_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_replaced_large_extension_candidate(tmp_path: Path) -> None:
    extension_path = tmp_path / f"native_module{EXTENSION_SUFFIXES[0]}"
    extension_path.write_bytes(b"x" * (1024 * 1024 + 1))
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    extension_fingerprint = cache._bounded_source_fingerprint(extension_path)
    reusable, picklescan_fingerprint = _picklescan_resolution_candidate_fingerprint(extension_path)
    assert reusable is True
    assert picklescan_fingerprint == extension_fingerprint
    assert isinstance(extension_fingerprint, str)
    assert extension_fingerprint.startswith(f"{_CALL_GRAPH_REGULAR_FILE_FINGERPRINT}:")
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {str(extension_path.absolute()): extension_fingerprint}
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    replacement_path = tmp_path / f"replacement{EXTENSION_SUFFIXES[0]}"
    replacement_path.write_bytes(b"y" * (1024 * 1024 + 1))
    os.replace(replacement_path, extension_path)

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


@pytest.mark.skipif(sys.platform == "win32", reason="Windows prevents replacing an open source file")
def test_source_fingerprint_rejects_path_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "helper.py"
    source_path.write_bytes(b"def entrypoint():\n    return 1\n")
    replacement_path = tmp_path / "replacement.py"
    malicious_source = b"import os\nos.system('id')\n"
    replacement_path.write_bytes(malicious_source)
    displaced_path = tmp_path / "displaced.py"
    original_read = os.read
    replaced = False

    def replace_after_first_read(file_descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(file_descriptor, size)
        if chunk and not replaced:
            replaced = True
            source_path.rename(displaced_path)
            replacement_path.rename(source_path)
        return chunk

    monkeypatch.setattr(os, "read", replace_after_first_read)

    with pytest.raises(ValueError, match="changed while being read"):
        ScanResultsCache._bounded_source_fingerprint(source_path)

    assert source_path.read_bytes() == malicious_source


@pytest.mark.skipif(sys.platform == "win32", reason="Windows prevents replacing an open source file")
def test_read_fingerprint_rejects_path_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "helper.pyc"
    source_path.write_bytes(b"safe bytecode")
    replacement_path = tmp_path / "replacement.pyc"
    malicious_source = b"malicious bytecode"
    replacement_path.write_bytes(malicious_source)
    displaced_path = tmp_path / "displaced.pyc"
    original_read = os.read
    replaced = False

    def replace_after_first_read(file_descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(file_descriptor, size)
        if chunk and not replaced:
            replaced = True
            source_path.rename(displaced_path)
            replacement_path.rename(source_path)
        return chunk

    monkeypatch.setattr(os, "read", replace_after_first_read)

    with pytest.raises(ValueError, match="changed while being read"):
        ScanResultsCache._bounded_read_fingerprint(source_path, 64 * 1024, True)

    assert source_path.read_bytes() == malicious_source


@pytest.mark.skipif(sys.platform == "win32", reason="Windows prevents replacing an open source file")
def test_extension_fingerprint_rejects_path_replacement_during_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_path = tmp_path / f"native_module{EXTENSION_SUFFIXES[0]}"
    extension_path.write_bytes(b"safe extension")
    replacement_path = tmp_path / f"replacement{EXTENSION_SUFFIXES[0]}"
    replacement_path.write_bytes(b"malicious extension")
    displaced_path = tmp_path / f"displaced{EXTENSION_SUFFIXES[0]}"
    original_fstat = os.fstat
    fstat_calls = 0

    def replace_after_second_fstat(file_descriptor: int) -> os.stat_result:
        nonlocal fstat_calls
        file_stat = original_fstat(file_descriptor)
        fstat_calls += 1
        if fstat_calls == 2:
            extension_path.rename(displaced_path)
            replacement_path.rename(extension_path)
        return file_stat

    monkeypatch.setattr(os, "fstat", replace_after_second_fstat)

    with pytest.raises(ValueError, match="changed while being read"):
        ScanResultsCache._bounded_source_fingerprint(extension_path)


def test_scan_cache_invalidates_when_read_fingerprint_directory_changes(tmp_path: Path) -> None:
    bytecode_dir = tmp_path / "__pycache__"
    bytecode_dir.mkdir()
    (bytecode_dir / "helper.cpython-312.pyc").write_bytes(b"first")
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    expected_fingerprint = cache._bounded_read_fingerprint(bytecode_dir, 64 * 1024, True)
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                read_fingerprints={
                    str(bytecode_dir): {
                        "read_limit": 64 * 1024,
                        "require_complete": True,
                        "fingerprint": expected_fingerprint,
                    }
                }
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    (bytecode_dir / "helper.cpython-312.opt-1.pyc").write_bytes(b"second")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_rejects_legacy_fingerprint_metadata_without_read_records(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprint_metadata = _call_graph_fingerprint_metadata()
    fingerprint_metadata.pop("read_fingerprints")
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {"call_graph_source_fingerprints": fingerprint_metadata},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_rejects_oversized_source_fingerprint_sets(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprints: dict[str, str | None] = {str(tmp_path / f"candidate-{index}.py"): None for index in range(4097)}
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {"call_graph_source_fingerprints": _call_graph_fingerprint_metadata(fingerprints)},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_legacy_pickle_call_graph_metadata_without_fingerprints(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [{"module": "helper", "name": "entrypoint"}],
            "callable_invocations": [{"module": "helper", "name": "entrypoint"}],
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_legacy_pytorch_zip_metadata_without_fingerprints(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pt")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "pickle_source": str(file_path),
            "container_type": "pytorch_zip",
            "member_reports": [{"source": "model.pt:data.pkl", "status": "complete", "verdict": "clean"}],
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_accepts_empty_call_graph_source_fingerprint_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(),
        },
    }
    expected_cached_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    assert cache.get_cached_result(str(file_path), version_context=version_context) == expected_cached_result


@pytest.mark.parametrize(
    "metadata_extra",
    (
        {},
        {"container_type": "pytorch_zip", "member_reports": []},
    ),
)
def test_scan_cache_accepts_source_independent_call_graph_metadata_under_unreusable_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_extra: dict[str, object],
) -> None:
    class StatefulPathHook:
        def __init__(self) -> None:
            for index in range(17):
                setattr(self, f"state_{index}", index)

        def __call__(self, _path: str) -> None:
            raise ImportError

    monkeypatch.setattr(sys, "path_hooks", [StatefulPathHook()])
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    metadata = {
        "pickle_report_status": "complete",
        "pickle_verdict": "clean",
        "import_references": [],
        "callable_invocations": [],
        **metadata_extra,
    }
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": metadata,
        "_private_metadata": {"call_graph_source_fingerprints": _source_independent_call_graph_fingerprint_metadata()},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    assert cache.get_cached_result(str(file_path), version_context=version_context) == {
        "checks": [],
        "issues": [],
        "metadata": metadata,
    }


@pytest.mark.parametrize("mutation", ("fingerprints", "resolution_context", "source_independent"))
def test_scan_cache_rejects_malformed_source_independent_call_graph_metadata(
    tmp_path: Path,
    mutation: str,
) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprint_metadata: dict[str, object] = _source_independent_call_graph_fingerprint_metadata()
    if mutation == "fingerprints":
        fingerprint_metadata["fingerprints"] = {str(tmp_path / "helper.py"): None}
    elif mutation == "resolution_context":
        fingerprint_metadata["resolution_context"] = {}
    else:
        fingerprint_metadata["source_independent"] = False
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
        },
        "_private_metadata": {"call_graph_source_fingerprints": fingerprint_metadata},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


@pytest.mark.parametrize(
    "metadata_update",
    (
        {"import_references": [{"module": "helper", "name": "entrypoint"}]},
        {"callable_invocations": [{"module": "helper", "name": "entrypoint"}]},
        {"import_references_truncated": True},
        {"callable_invocations_truncated": True},
        {"non_allowlisted_global_imports_truncated": True},
        {"container_type": "pytorch_zip", "import_references_truncated": True},
    ),
)
def test_scan_cache_rejects_source_independent_marker_with_source_inputs(
    tmp_path: Path,
    metadata_update: dict[str, object],
) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    metadata = {
        "pickle_report_status": "complete",
        "pickle_verdict": "clean",
        "import_references": [],
        "callable_invocations": [],
        **metadata_update,
    }
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": metadata,
        "_private_metadata": {"call_graph_source_fingerprints": _source_independent_call_graph_fingerprint_metadata()},
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_uses_private_call_graph_source_fingerprints_without_returning_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_path = source_root / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(source_root))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source_fingerprint = hashlib.sha256(source_path.read_bytes()).hexdigest()
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [{"module": "helper", "name": "entrypoint"}],
            "callable_invocations": [{"module": "helper", "name": "entrypoint"}],
        },
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {str(source_path.absolute()): source_fingerprint},
                module_sources={"helper": str(source_path.absolute())},
            )
        },
    }
    expected_cached_result = {key: value for key, value in scan_result.items() if key != "_private_metadata"}

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)
    assert cached_result is not None
    assert cached_result == expected_cached_result
    assert "_private_metadata" not in cached_result
    assert "call_graph_source_fingerprints" not in cached_result["metadata"]

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_validates_private_fingerprints_without_public_metadata(tmp_path: Path) -> None:
    source_path = tmp_path / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {str(source_path.absolute()): hashlib.sha256(source_path.read_bytes()).hexdigest()}
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    assert cache.get_cached_result(str(file_path), version_context=version_context) is not None

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_by_key_invalidates_private_call_graph_source_fingerprint_change(tmp_path: Path) -> None:
    source_path = tmp_path / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [{"module": "helper", "name": "entrypoint"}],
            "callable_invocations": [{"module": "helper", "name": "entrypoint"}],
        },
        "_private_metadata": {
            "call_graph_source_fingerprints": _call_graph_fingerprint_metadata(
                {str(source_path.absolute()): hashlib.sha256(source_path.read_bytes()).hexdigest()}
            )
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    cache_key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    assert cache.get_cached_result_by_key(cache_key) is not None

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result_by_key(cache_key) is None


def test_scan_cache_private_metadata_cannot_override_cache_bookkeeping(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprint_metadata = _call_graph_fingerprint_metadata()
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
        },
        "_private_metadata": {
            "call_graph_source_fingerprints": fingerprint_metadata,
            "access_count": "invalid",
            "scanned_at": 0,
            "unrecognized": "private",
        },
    }

    assert cache.store_result(
        str(file_path), scan_result, version_context=version_context, **_identity_kwargs(cache, str(file_path))
    )
    cache_key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_entry = json.loads(cache._get_cache_file_path(cache_key).read_text(encoding="utf-8"))

    assert cache_entry["cache_metadata"]["call_graph_source_fingerprints"] == fingerprint_metadata
    assert cache_entry["cache_metadata"]["access_count"] == 1
    assert cache_entry["cache_metadata"]["scanned_at"] > 0
    assert "unrecognized" not in cache_entry["cache_metadata"]


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
        {"scan_outcome_reason": "bounded_probe_exhausted"},
        {"scan_outcome_reasons": ["bounded_probe_exhausted"]},
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


@pytest.mark.parametrize("collection_name", ["issues", "checks"])
@pytest.mark.parametrize(
    "details",
    [
        {"scan_outcome": INCONCLUSIVE_SCAN_OUTCOME},
        {"analysis_incomplete": True},
        {"scan_outcome_reason": "bounded_probe_exhausted"},
        {"scan_outcome_reasons": ["bounded_probe_exhausted"]},
        {"operational_error": True},
        {"component_count": 2, "findings": [{"analysis_incomplete": True}]},
        {"component_count": 2, "findings": [{"details": {"analysis_incomplete": True}}]},
    ],
)
def test_cached_scan_skips_persisting_incomplete_record_details(
    tmp_path: Path,
    collection_name: str,
    details: dict[str, Any],
) -> None:
    """Issue/check-only incomplete coverage must be rescanned instead of replayed."""
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        record = {
            "message": "Incomplete coverage retained only in record details",
            "status": "failed",
            "details": details,
        }
        result: dict[str, Any] = {
            "checks": [],
            "issues": [],
            "success": True,
            "scan_count": calls["count"],
        }
        result[collection_name] = [record]
        return result

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_persists_skipped_bare_analysis_incomplete_check(tmp_path: Path) -> None:
    """Skipped informational checks without outcome markers are stable enough to cache."""
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
                    "message": "PyTorch runtime version is unknown",
                    "status": "skipped",
                    "details": {"analysis_incomplete": True, "runtime_cve_applicability": "unknown"},
                }
            ],
            "issues": [],
            "metadata": {},
            "scan_count": calls["count"],
            "success": True,
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second == first
    assert calls["count"] == 1
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 1


def test_cached_scan_skips_skipped_check_with_explicit_incomplete_reason(tmp_path: Path) -> None:
    """Skipped checks with explicit outcome markers must still bypass cache."""
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
                    "message": "PyTorch runtime version is unknown",
                    "status": "skipped",
                    "details": {
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "pytorch_runtime_version_unknown",
                    },
                }
            ],
            "issues": [],
            "metadata": {},
            "scan_count": calls["count"],
            "success": True,
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_issue_with_skipped_status_and_bare_analysis_incomplete(tmp_path: Path) -> None:
    """Issue records cannot opt into the skipped-check bare analysis_incomplete exemption."""
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [
                {
                    "message": "DVC output coverage incomplete",
                    "status": "skipped",
                    "details": {"analysis_incomplete": True},
                }
            ],
            "metadata": {},
            "scan_count": calls["count"],
            "success": True,
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_persists_clean_result_with_benign_details(tmp_path: Path) -> None:
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
                    "message": "Synthetic clean coverage check",
                    "status": "passed",
                    "details": {"scan_outcome_reason": "", "scan_outcome_reasons": []},
                }
            ],
            "issues": [],
            "metadata": {},
            "scan_count": calls["count"],
            "success": True,
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second == first
    assert calls["count"] == 1
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 1


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
        def to_dict(self, *, include_private_metadata: bool = False) -> dict[str, Any]:
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


def test_cached_scan_persists_deterministic_validation_findings(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Not a valid zip file: /tmp/example.zip", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == second
    assert calls["count"] == 1
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 1


def test_cached_scan_does_not_persist_missing_associated_weights(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Associated .bin weights file not found", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


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
