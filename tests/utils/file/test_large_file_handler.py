"""Tests for LargeFileHandler chunked scanning."""

from __future__ import annotations

import os
import struct
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.scan_results_cache import _source_resolution_context
from modelaudit.core import scan_file
from modelaudit.scanners import keras_h5_scanner, safetensors_scanner
from modelaudit.scanners.base import ScanResult
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner
from modelaudit.scanners.onnx_scanner import OnnxScanner
from modelaudit.scanners.safetensors_scanner import MAX_HEADER_BYTES, SafeTensorsScanner
from modelaudit.utils.file import handlers as advanced_handlers
from modelaudit.utils.file import large_file_handler
from modelaudit.utils.helpers.cache_decorator import should_bypass_cache_for_zip_entry_preflight
from modelaudit.utils.helpers.secure_hasher import SecureFileHasher
from tests.helpers import create_mock_onnx


class DummyScanner:
    """Minimal scanner that supports chunk analysis."""

    name = "dummy"

    def _analyze_chunk(self, chunk: bytes, bytes_processed: int) -> ScanResult:
        """Return a successful chunk scan result."""
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = len(chunk)
        result.finish(success=True)
        return result


class DummyNonChunkScanner:
    """Minimal scanner without chunk analysis support."""

    name = "dummy_non_chunk"

    def __init__(self) -> None:
        """Track calls to the full scan method."""
        self.scan_calls = 0

    def scan(self, file_path: str) -> ScanResult:
        """Return a successful full-file scan result."""
        self.scan_calls += 1
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = Path(file_path).stat().st_size
        result.finish(success=True)
        return result


class DummyMmapScanner:
    """Minimal scanner that implements custom mmap analysis."""

    name = "dummy_mmap"

    def _scan_with_mmap(self, file_path: str, _progress_callback: object | None = None) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = Path(file_path).stat().st_size
        result.finish(success=True)
        return result


def _write_sparse_oversized_safetensors_candidate(path: Path) -> None:
    header_len = MAX_HEADER_BYTES + 1
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)


@pytest.mark.parametrize("scan_func", [large_file_handler.scan_large_file, advanced_handlers.scan_advanced_large_file])
def test_large_handler_cache_bypasses_oversized_safetensors_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan_func: Callable[..., ScanResult],
) -> None:
    payload = tmp_path / "weights.jpg"
    _write_sparse_oversized_safetensors_candidate(payload)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    scanner = SafeTensorsScanner(config=config)
    hash_attempts = 0

    monkeypatch.setattr(advanced_handlers, "EXTREME_MODEL_THRESHOLD", 1)
    monkeypatch.setattr(advanced_handlers, "LARGE_MODEL_THRESHOLD_200GB", payload.stat().st_size + 1)

    def record_hash_attempt(_self: SecureFileHasher, _path: str) -> str:
        nonlocal hash_attempts
        hash_attempts += 1
        return "unexpected-full-file-hash"

    monkeypatch.setattr(SecureFileHasher, "hash_file", record_hash_attempt)
    monkeypatch.setattr(
        safetensors_scanner.SafeTensorsScanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("bounded SafeTensors failure must not hash inside the scanner"),
    )

    reset_cache_manager()
    try:
        result = scan_func(str(payload), scanner)

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert any(check.name == "Header Size Limit" for check in result.checks)
        assert hash_attempts == 0
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize("scan_func", [large_file_handler.scan_large_file, advanced_handlers.scan_advanced_large_file])
def test_large_handler_cache_bypasses_file_backed_onnx(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan_func: Callable[..., ScanResult],
) -> None:
    pytest.importorskip("onnx")
    model_path = create_mock_onnx(tmp_path / "model.onnx")
    scanner = OnnxScanner(
        config={
            "cache_enabled": True,
            "cache_dir": str(tmp_path / "cache"),
            "onnx_raw_detector_max_bytes": 1,
        }
    )
    monkeypatch.setattr(
        "modelaudit.cache.get_cache_manager",
        lambda *_args, **_kwargs: pytest.fail("file-backed ONNX must bypass the large-file cache"),
    )

    result = scan_func(str(model_path), scanner)

    assert result.metadata["onnx_structure_parse"]["parse_mode"] == "file_backed_structure"


def test_extreme_onnx_route_uses_file_backed_scan_without_cache_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("onnx")
    model_path = create_mock_onnx(tmp_path / "extreme.onnx")
    monkeypatch.setattr(advanced_handlers, "EXTREME_MODEL_THRESHOLD", 1)
    monkeypatch.setattr(advanced_handlers, "LARGE_MODEL_THRESHOLD_200GB", model_path.stat().st_size + 1)
    monkeypatch.setattr(
        "modelaudit.cache.get_cache_manager",
        lambda *_args, **_kwargs: pytest.fail("file-backed ONNX must bypass the advanced-file cache"),
    )

    result = scan_file(
        str(model_path),
        config={
            "cache_enabled": True,
            "cache_dir": str(tmp_path / "cache"),
            "onnx_raw_detector_max_bytes": 1,
        },
    )

    assert result.metadata["onnx_structure_parse"]["parse_mode"] == "file_backed_structure"
    assert result.metadata.get("operational_error_reason") != "unsupported_bounded_large_file_analysis"


@pytest.mark.parametrize(
    ("module", "scan_func", "internal_name"),
    [
        (large_file_handler, large_file_handler.scan_large_file, "_scan_large_file_internal"),
        (advanced_handlers, advanced_handlers.scan_advanced_large_file, "_scan_advanced_large_file_internal"),
    ],
)
def test_large_handler_cache_preserves_private_metadata_for_internal_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    scan_func: Callable[..., ScanResult],
    internal_name: str,
) -> None:
    payload = tmp_path / "model.pkl"
    payload.write_bytes(b"safe")
    cache_dir = tmp_path / "cache"
    scan_calls = 0
    fingerprint_metadata = {
        "reusable": True,
        "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
        "resolution_context": _source_resolution_context(),
        "module_sources": {},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
        "loaded_package_resolution_contexts": {},
        "fingerprints": {},
        "read_fingerprints": {},
    }

    class CachedScanner:
        def __init__(self) -> None:
            self.config = {"cache_enabled": True, "cache_dir": str(cache_dir)}

    def scan_internal(*_args: object, **_kwargs: object) -> ScanResult:
        nonlocal scan_calls
        scan_calls += 1
        result = ScanResult(scanner_name="pickle")
        result._private_metadata["call_graph_source_fingerprints"] = fingerprint_metadata
        result.finish()
        return result

    monkeypatch.setattr(module, internal_name, scan_internal)
    reset_cache_manager()
    try:
        first = scan_func(str(payload), CachedScanner())
        second = scan_func(str(payload), CachedScanner())
    finally:
        reset_cache_manager()

    assert scan_calls == 1
    assert first._private_metadata["call_graph_source_fingerprints"] == fingerprint_metadata
    assert second._private_metadata["call_graph_source_fingerprints"] == fingerprint_metadata
    assert "_private_metadata" not in second.to_dict()


@pytest.mark.parametrize(
    ("scan_func", "handler_module"),
    [
        (large_file_handler.scan_large_file, large_file_handler),
        (advanced_handlers.scan_advanced_large_file, advanced_handlers),
    ],
)
def test_disabled_large_handler_cache_skips_hdf5_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan_func: Callable[..., ScanResult],
    handler_module: object,
) -> None:
    payload = tmp_path / "model.bin"
    payload.write_bytes(b"benign")
    scanner = DummyNonChunkScanner()
    scanner.config = {"cache_enabled": False}  # type: ignore[attr-defined]
    monkeypatch.setattr(
        handler_module,
        "should_bypass_cache_for_unavailable_hdf5_analysis",
        lambda _path: pytest.fail("disabled caches must not probe HDF5"),
    )

    result = scan_func(str(payload), scanner)

    assert result.success is True


@pytest.mark.parametrize(
    ("scan_func", "handler_module", "internal_name"),
    [
        (large_file_handler.scan_large_file, large_file_handler, "_scan_large_file_internal"),
        (advanced_handlers.scan_advanced_large_file, advanced_handlers, "_scan_advanced_large_file_internal"),
    ],
)
def test_large_handler_cache_bypasses_zip_entry_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan_func: Callable[..., ScanResult],
    handler_module: Any,
    internal_name: str,
) -> None:
    payload = tmp_path / "over-entry.zip"
    payload.write_bytes(b"bounded preflight fixture")
    scanner = DummyNonChunkScanner()
    scanner.config = {"cache_enabled": True, "cache_dir": str(tmp_path / "cache")}  # type: ignore[attr-defined]
    internal_calls = 0
    original_internal = getattr(handler_module, internal_name)

    def record_internal(*args: Any, **kwargs: Any) -> ScanResult:
        nonlocal internal_calls
        internal_calls += 1
        return cast(ScanResult, original_internal(*args, **kwargs))

    monkeypatch.setattr(handler_module, "should_bypass_cache_for_zip_entry_preflight", lambda _path, _config: True)
    monkeypatch.setattr(handler_module, internal_name, record_internal)

    reset_cache_manager()
    try:
        result = scan_func(str(payload), scanner)

        assert result.success is True
        assert internal_calls == 1
        assert get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_zip_entry_preflight_cache_bypass_honors_scanner_selection(tmp_path: Path) -> None:
    payload = tmp_path / "selected-scanner.zip"
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    assert not should_bypass_cache_for_zip_entry_preflight(
        str(payload),
        {"scanners": ["pickle"], "max_zip_entries": 1},
    )
    assert should_bypass_cache_for_zip_entry_preflight(
        str(payload),
        {"scanners": ["keras_zip"], "max_zip_entries": 1},
    )
    assert not should_bypass_cache_for_zip_entry_preflight(
        str(payload),
        {"scanners": ["numpy"], "max_zip_entries": 1},
    )

    npz_payload = payload.with_suffix(".npz")
    payload.replace(npz_payload)
    assert should_bypass_cache_for_zip_entry_preflight(
        str(npz_payload),
        {"scanners": ["numpy"], "max_zip_entries": 1},
    )


def test_large_handler_missing_h5py_does_not_return_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h5py = pytest.importorskip("h5py")
    model_path = tmp_path / "model.h5"
    with h5py.File(model_path, "w") as h5_file:
        h5_file.attrs["model_config"] = '{"class_name":"Sequential","config":{"layers":[]}}'

    cache_dir = tmp_path / "large-hdf5-cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    scanner = KerasH5Scanner(config=config)

    reset_cache_manager()
    try:
        clean_result = large_file_handler.scan_large_file(str(model_path), scanner)
        assert clean_result.success is True
        cache_manager = get_cache_manager(str(cache_dir), enabled=True)
        cached_entries = cache_manager.get_stats()["total_entries"]
        assert cached_entries > 0

        monkeypatch.setattr(keras_h5_scanner, "HAS_H5PY", False)
        for _ in range(2):
            result = large_file_handler.scan_large_file(str(model_path), scanner)
            assert result.success is False
            assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]

        assert cache_manager.get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_advanced_handler_missing_h5py_preserves_shard_coverage_without_stale_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h5py = pytest.importorskip("h5py")
    shard_paths = [tmp_path / "model_weights_1.h5", tmp_path / "model_weights_2.h5"]
    for shard_path in shard_paths:
        with h5py.File(shard_path, "w") as h5_file:
            h5_file.attrs["model_config"] = '{"class_name":"Sequential","config":{"layers":[]}}'

    cache_dir = tmp_path / "advanced-hdf5-cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    scanner = KerasH5Scanner(config=config)

    reset_cache_manager()
    try:
        clean_result = advanced_handlers.scan_advanced_large_file(str(shard_paths[0]), scanner)
        assert clean_result.success is True
        cache_manager = get_cache_manager(str(cache_dir), enabled=True)
        cached_entries = cache_manager.get_stats()["total_entries"]
        assert cached_entries > 0

        monkeypatch.setattr(keras_h5_scanner, "HAS_H5PY", False)
        for _ in range(2):
            result = advanced_handlers.scan_advanced_large_file(str(shard_paths[0]), scanner)
            assert result.success is False
            assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]
            shard_check = next(check for check in result.checks if check.name == "Sharded Model Detection")
            assert shard_check.details["total_shards"] == 2

        assert cache_manager.get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_chunked_scan_populates_end_time_and_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure chunked scans set end_time and success."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 50)

    monkeypatch.setattr(large_file_handler, "SMALL_FILE_THRESHOLD", 1)
    monkeypatch.setattr(large_file_handler, "MEDIUM_FILE_THRESHOLD", 100)
    monkeypatch.setattr(large_file_handler, "DEFAULT_CHUNK_SIZE", 10)

    handler = large_file_handler.LargeFileHandler(str(test_file), DummyScanner())
    result = handler.scan()

    assert result.end_time is not None
    assert result.success is True


def test_chunked_scan_falls_back_to_normal_for_non_chunk_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure chunked routing still runs scanner.scan() when chunk analysis is unavailable."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 50)

    monkeypatch.setattr(large_file_handler, "SMALL_FILE_THRESHOLD", 1)
    monkeypatch.setattr(large_file_handler, "MEDIUM_FILE_THRESHOLD", 100)

    scanner = DummyNonChunkScanner()
    handler = large_file_handler.LargeFileHandler(str(test_file), scanner)
    result = handler.scan()

    assert scanner.scan_calls == 1
    assert result.bytes_scanned == 50
    assert result.end_time is not None
    assert result.success is True


def test_advanced_large_file_fails_closed_without_bounded_scanner_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scanners without chunked or mmap support must not claim coverage on huge files."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 64)

    monkeypatch.setattr(advanced_handlers, "LARGE_MODEL_THRESHOLD_200GB", 1)

    scanner = DummyNonChunkScanner()
    handler = advanced_handlers.AdvancedFileHandler(str(test_file), scanner)
    result = handler.scan()

    assert scanner.scan_calls == 0
    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "unsupported_bounded_large_file_analysis"
    assert any("bounded large-file analysis" in issue.message.lower() for issue in result.issues)


def test_advanced_extreme_file_fails_closed_without_bounded_scanner_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unsupported scanners must also fail closed in the 50GB-500GB mmap path."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 64)

    monkeypatch.setattr(advanced_handlers, "EXTREME_MODEL_THRESHOLD", 1)
    monkeypatch.setattr(advanced_handlers, "LARGE_MODEL_THRESHOLD_200GB", 10_000)

    scanner = DummyNonChunkScanner()
    handler = advanced_handlers.AdvancedFileHandler(str(test_file), scanner)
    result = handler.scan()

    assert scanner.scan_calls == 0
    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "unsupported_bounded_large_file_analysis"
    assert any("bounded large-file analysis" in issue.message.lower() for issue in result.issues)


def test_advanced_large_file_uses_supported_bounded_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Chunk-aware or mmap-aware scanners should still scan successfully."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 64)

    monkeypatch.setattr(advanced_handlers, "LARGE_MODEL_THRESHOLD_200GB", 1)

    handler = advanced_handlers.AdvancedFileHandler(str(test_file), DummyMmapScanner())
    result = handler.scan()

    assert result.success is True
    assert result.bytes_scanned == 64
