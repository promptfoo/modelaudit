"""Tests for streaming scan-and-delete functionality."""

import hashlib
import json
import logging
import os
import pickle
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from modelaudit.core import (
    _complete_validated_shard_family_sources,
    _make_trusted_stream_shard_root,
    _reconcile_cross_directory_shard_coverage,
    _snapshot_validated_shard_target,
    _terminal_safetensors_shard_boundary_failures,
    detect_file_format,
    detect_file_format_from_magic,
    determine_exit_code,
    scan_file,
    scan_model_directory_or_file,
    scan_model_streaming,
)
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.models import FileMetadataModel, LicenseInfoModel, create_initial_audit_result
from modelaudit.scanners import safetensors_scanner
from modelaudit.scanners.base import DEFAULT_MAX_FILE_READ_SIZE, CheckStatus, Issue, IssueSeverity, ScanResult
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.detection import PICKLE_ROUTING_INCONCLUSIVE_FORMAT, SAFETENSORS_ROUTING_HEADER_PARSE_BYTES
from modelaudit.utils.file.handlers import (
    ShardedModelDetector,
    _pinned_shard_scan_path,
    _SafetensorsIndexInspectionContext,
)
from modelaudit.utils.file.hdf5 import HDF5_SIGNATURE_SCAN_MAX_BYTES, find_hdf5_signature_offset
from modelaudit.utils.file.streaming import StreamedSourceByteAccounting
from modelaudit.utils.helpers.file_hash import compute_sha256_hash
from modelaudit.utils.helpers.file_iterator import iterate_files_streaming
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash
from modelaudit.utils.sources.huggingface import download_model_streaming
from tests.helpers import (
    create_malicious_pickle,
    create_mock_pytorch_zip,
    create_resource_limited_safetensors_index,
    write_mock_pytorch_zip_metadata,
)


class _StreamingMaliciousPicklePayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("__import__('os').system('echo modelaudit-stream-test')",))


def _create_streaming_pytorch_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        write_mock_pytorch_zip_metadata(archive)
        for member_name, payload in members.items():
            archive.writestr(member_name, payload)
    return path


def _streaming_member_record(metadata: dict[str, Any], path_segments: list[str]) -> dict[str, Any]:
    member_hashes = metadata.get("member_file_hashes")
    assert isinstance(member_hashes, dict)
    records = [
        record
        for record in member_hashes.values()
        if isinstance(record, dict) and record.get("path_segments") == path_segments
    ]
    assert len(records) == 1
    return records[0]


def _scan_explicit_test_source(source: Path, mode: str, scanner: str) -> Any:
    scan_kwargs: dict[str, Any] = {
        "cache_enabled": False,
        "scanners": [scanner],
        "skip_file_types": False,
    }
    if mode == "standard":
        return scan_model_directory_or_file(str(source), **scan_kwargs)
    return scan_model_streaming(
        iter([(source, True)]),
        scan_root=str(source),
        delete_after_scan=False,
        **scan_kwargs,
    )


def _assert_local_source_boundary_failure(result: Any) -> None:
    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert any(
        check.name == "Local Source Boundary Check" and check.status.value == "failed" for check in result.checks
    )


def test_local_source_receipt_is_runtime_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The private dispatch receipt must not reach scanner or cache configuration."""
    from modelaudit import core as core_module

    model_path, _companion_path = _write_openvino_pair(tmp_path)
    receipt = core_module._snapshot_local_source_receipt(tmp_path)
    assert receipt is not None
    original_scan_file = core_module.scan_file
    observed_configs: list[dict[str, Any]] = []

    def capture_scan_config(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        observed_configs.append(dict(config or {}))
        return original_scan_file(path, config=config)

    monkeypatch.setattr(core_module, "scan_file", capture_scan_config)

    result = scan_model_streaming(
        iter([(model_path, True)]),
        scan_root=str(tmp_path),
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["pickle"],
        skip_file_types=False,
        _local_source_receipt=receipt,
    )

    assert result.success is True
    assert observed_configs
    assert all(core_module._LOCAL_SOURCE_RECEIPT_CONFIG_KEY not in config for config in observed_configs)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
def test_bound_regular_source_stages_outside_its_watched_parent() -> None:
    """A file directly under the temp root must not trigger its own parent watcher."""
    from modelaudit import core as core_module

    source = Path(tempfile.gettempdir()) / f"modelaudit-bound-source-{uuid.uuid4().hex}.bin"
    source.write_bytes(b"source")
    guard = core_module._open_bound_local_source(source)
    try:
        assert guard.changed() is False
        assert Path(guard.bound_path).read_bytes() == b"source"
    finally:
        guard.close()
        source.unlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
def test_streaming_retained_regular_file_discovers_companions_from_retained_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Post-binding ancestor swaps cannot replace the retained companion bytes."""
    from modelaudit import core as core_module

    staging = tmp_path / "staging"
    alternate = tmp_path / "alternate"
    staging.mkdir()
    alternate.mkdir()
    source = staging / "model.manifest"
    source.write_text(json.dumps({"layers": ["layer.tar.gz"]}), encoding="utf-8")
    (alternate / source.name).hardlink_to(source)
    malicious_layer = b"malicious retained layer"
    (staging / "layer.tar.gz").write_bytes(malicious_layer)
    (alternate / "layer.tar.gz").write_bytes(b"benign replacement layer")
    swap = tmp_path / "swap"
    observed_layers: list[bytes] = []

    def swap_ancestors() -> None:
        staging.rename(swap)
        alternate.rename(staging)
        swap.rename(alternate)

    def inspect_staged_companion(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        swap_ancestors()
        try:
            observed_layers.append((Path(path).parent / "layer.tar.gz").read_bytes())
        finally:
            swap_ancestors()
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "scan_file", inspect_staged_companion)
    result = scan_model_streaming(
        iter([(source, True)]),
        scan_root=str(source),
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["oci_layer"],
        skip_file_types=False,
    )

    assert observed_layers == [malicious_layer]
    assert determine_exit_code(result) == 0
    assert result.success is True
    assert not any(check.name == "Local Source Boundary Check" for check in result.checks)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_retained_regular_file_detects_companion_substitution_before_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """Sibling ABA around companion discovery must fail the source boundary."""
    from modelaudit import core as core_module

    source = tmp_path / "model.manifest"
    source.write_text(json.dumps({"layers": ["layer.tar.gz"]}), encoding="utf-8")
    layer = tmp_path / "layer.tar.gz"
    held_layer = tmp_path / "held-layer.tar.gz"
    benign_layer = tmp_path / "benign-layer.tar.gz"
    malicious_payload = b"malicious retained layer"
    benign_payload = b"benign replacement layer"
    layer.write_bytes(malicious_payload)
    benign_layer.write_bytes(benign_payload)
    original_discovery = core_module._oci_manifest_layer_companion_paths
    observed_layers: list[bytes] = []
    swapped = False

    def substitute_before_discovery(path: Path) -> tuple[Path, ...]:
        nonlocal swapped
        if not swapped:
            layer.rename(held_layer)
            benign_layer.rename(layer)
            swapped = True
        discovered = original_discovery(path)
        layer.rename(benign_layer)
        held_layer.rename(layer)
        return discovered

    def inspect_then_restore(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        observed_layers.append((Path(path).parent / layer.name).read_bytes())
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.bytes_scanned = Path(path).stat().st_size
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "_oci_manifest_layer_companion_paths", substitute_before_discovery)
    monkeypatch.setattr(core_module, "scan_file", inspect_then_restore)

    result = _scan_explicit_test_source(source, mode, "oci_layer")

    assert observed_layers == []
    assert layer.read_bytes() == malicious_payload
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_retained_regular_file_rejects_nested_companion_without_namespace_receipt(
    tmp_path: Path,
    mode: str,
) -> None:
    """Nested explicit-file companions fail closed without a retained subtree receipt."""
    source = tmp_path / "model.manifest"
    source.write_text(json.dumps({"layers": ["nested/layer.tar.gz"]}), encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "layer.tar.gz").write_bytes(b"layer")

    result = _scan_explicit_test_source(source, mode, "oci_layer")

    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
@pytest.mark.parametrize(
    ("source_name", "companion_name"),
    [
        ("model-0000.params", "model-symbol.json"),
        ("model-symbol.json", "model-0000.params"),
    ],
)
def test_retained_mxnet_companion_symlink_fails_closed(
    tmp_path: Path,
    requires_symlinks: None,
    mode: str,
    source_name: str,
    companion_name: str,
) -> None:
    """Explicit MXNet scans must not read companion targets outside the model directory."""
    model_dir = tmp_path / "model"
    outside_dir = tmp_path / "outside"
    model_dir.mkdir()
    outside_dir.mkdir()
    source = model_dir / source_name
    source.write_bytes(b"selected model bytes")
    external_target = outside_dir / companion_name
    external_target.write_bytes(b"out-of-scope secret bytes")
    (model_dir / companion_name).symlink_to(external_target)

    result = _scan_explicit_test_source(source, mode, "mxnet")

    assert result.bytes_scanned == 0
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
@pytest.mark.parametrize("nested_target", [False, True], ids=["same-parent", "nested"])
def test_retained_openvino_companion_allows_internal_symlink(
    tmp_path: Path,
    requires_symlinks: None,
    mode: str,
    nested_target: bool,
) -> None:
    """Descriptor binding preserves an OpenVINO sidecar symlink that stays under the model directory."""
    del requires_symlinks
    source = tmp_path / "model.xml"
    weights_parent = tmp_path / "weights" if nested_target else tmp_path
    weights_parent.mkdir(exist_ok=True)
    weights = weights_parent / "weights.bin"
    source.write_text("<net version='10'></net>", encoding="utf-8")
    weights.write_bytes(b"safe weights")
    symlink_target = Path(weights_parent.name) / weights.name if nested_target else Path(weights.name)
    (tmp_path / "model.bin").symlink_to(symlink_target)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert determine_exit_code(result) == 0
    assert result.success is True
    assert result.bytes_scanned == source.stat().st_size + weights.stat().st_size
    if mode == "standard":
        assert result.content_hash is not None
    assert not any(check.name == "Local Source Boundary Check" for check in result.checks)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_retained_companion_symlink_rejects_target_aba_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    mode: str,
) -> None:
    """A symlink target substituted only for descriptor opening cannot be attributed to the source path."""
    del requires_symlinks
    from modelaudit import core as core_module

    source = tmp_path / "model.xml"
    target = tmp_path / "actual.bin"
    held = tmp_path / "held.bin"
    benign = tmp_path / "benign.bin"
    source.write_text("<net version='10'></net>", encoding="utf-8")
    target.write_bytes(b"malicious weights")
    benign.write_bytes(b"benign weights")
    (tmp_path / "model.bin").symlink_to(target.name)
    original_open = core_module._open_retained_relative_regular_file
    scan_calls = 0

    def open_during_target_substitution(parent_fd: int, relative_path: Path) -> int:
        target.rename(held)
        benign.rename(target)
        try:
            return original_open(parent_fd, relative_path)
        finally:
            target.rename(benign)
            held.rename(target)

    def track_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        nonlocal scan_calls
        del path, config
        scan_calls += 1
        scan_result = ScanResult(scanner_name="openvino")
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "_open_retained_relative_regular_file", open_during_target_substitution)
    monkeypatch.setattr(core_module, "scan_file", track_scan)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert scan_calls == 0
    assert target.read_bytes() == b"malicious weights"
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
@pytest.mark.parametrize("restore_before_return", [False, True], ids=["persistent", "restored"])
@pytest.mark.parametrize("nested_target", [False, True], ids=["same-parent", "nested"])
def test_retained_companion_symlink_watches_target_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    mode: str,
    restore_before_return: bool,
    nested_target: bool,
) -> None:
    """Pre-discovery receipts retain internal symlink targets through queued mutations."""
    del requires_symlinks
    from modelaudit import core as core_module

    source = tmp_path / "model.xml"
    target_parent = tmp_path / "weights" if nested_target else tmp_path
    target_parent.mkdir(exist_ok=True)
    target = target_parent / "actual.bin"
    held = target_parent / "held.bin"
    benign = target_parent / "benign.bin"
    source.write_text("<net version='10'></net>", encoding="utf-8")
    target.write_bytes(b"malicious weights")
    benign.write_bytes(b"benign weights")
    symlink_target = Path(target_parent.name) / target.name if nested_target else Path(target.name)
    (tmp_path / "model.bin").symlink_to(symlink_target)
    original_discovery = core_module._openvino_xml_weights_companion
    scan_calls = 0

    def discover_during_target_substitution(path: Path) -> Path | None:
        target.rename(held)
        benign.rename(target)
        discovered = original_discovery(path)
        if restore_before_return:
            target.rename(benign)
            held.rename(target)
        return discovered

    def track_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        nonlocal scan_calls
        del path, config
        scan_calls += 1
        scan_result = ScanResult(scanner_name="openvino")
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "_openvino_xml_weights_companion", discover_during_target_substitution)
    monkeypatch.setattr(core_module, "scan_file", track_scan)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert scan_calls == 0
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
@pytest.mark.parametrize("restore_before_return", [False, True], ids=["persistent", "restored"])
def test_retained_companion_symlink_watches_nested_target_parent_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    mode: str,
    restore_before_return: bool,
) -> None:
    """Discovery monitors the first namespace component of an internal symlink target."""
    del requires_symlinks
    from modelaudit import core as core_module

    source = tmp_path / "model.xml"
    weights = tmp_path / "weights"
    alternate = tmp_path / "alternate"
    swap = tmp_path / "swap"
    weights.mkdir()
    alternate.mkdir()
    source.write_text("<net version='10'></net>", encoding="utf-8")
    (weights / "model.bin").write_bytes(b"malicious weights")
    (alternate / "model.bin").write_bytes(b"benign weights")
    (tmp_path / "model.bin").symlink_to(Path(weights.name) / "model.bin")
    original_discovery = core_module._openvino_xml_weights_companion
    scan_calls = 0

    def swap_target_parent() -> None:
        weights.rename(swap)
        alternate.rename(weights)
        swap.rename(alternate)

    def discover_during_parent_substitution(path: Path) -> Path | None:
        swap_target_parent()
        discovered = original_discovery(path)
        if restore_before_return:
            swap_target_parent()
        return discovered

    def track_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        nonlocal scan_calls
        del path, config
        scan_calls += 1
        scan_result = ScanResult(scanner_name="openvino")
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "_openvino_xml_weights_companion", discover_during_parent_substitution)
    monkeypatch.setattr(core_module, "scan_file", track_scan)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert scan_calls == 0
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
@pytest.mark.parametrize("restore_after_arm", [False, True], ids=["persistent", "restored"])
def test_nested_companion_monitor_rejects_target_swap_during_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    mode: str,
    restore_after_arm: bool,
) -> None:
    """Before/after receipts close the gap before nested inotify registration."""
    del requires_symlinks
    from modelaudit import core as core_module

    source = tmp_path / "model.xml"
    weights = tmp_path / "weights"
    weights.mkdir()
    target = weights / "actual.bin"
    held = weights / "held.bin"
    benign = weights / "benign.bin"
    source.write_text("<net version='10'></net>", encoding="utf-8")
    target.write_bytes(b"malicious weights")
    benign.write_bytes(b"benign weights")
    (tmp_path / "model.bin").symlink_to(Path(weights.name) / target.name)
    original_arm = core_module._StagingMutationMonitor.arm
    content_arm_calls = 0
    weights_stat = weights.stat()
    nested_arm_swapped = False
    scan_calls = 0

    def arm_during_target_substitution(
        directory_fds: Any,
        *,
        watch_contents: bool = True,
    ) -> Any:
        nonlocal content_arm_calls, nested_arm_swapped
        descriptors = tuple(directory_fds)
        if watch_contents:
            content_arm_calls += 1
        monitors_weights = any(os.path.samestat(os.fstat(descriptor), weights_stat) for descriptor in descriptors)
        if watch_contents and monitors_weights and not nested_arm_swapped:
            nested_arm_swapped = True
            target.rename(held)
            benign.rename(target)
            monitor = original_arm(descriptors, watch_contents=True)
            if restore_after_arm:
                target.rename(benign)
                held.rename(target)
            return monitor
        return original_arm(descriptors, watch_contents=watch_contents)

    def track_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        nonlocal scan_calls
        del path, config
        scan_calls += 1
        scan_result = ScanResult(scanner_name="openvino")
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(
        core_module._StagingMutationMonitor,
        "arm",
        staticmethod(arm_during_target_substitution),
    )
    monkeypatch.setattr(core_module, "scan_file", track_scan)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert content_arm_calls >= 2
    assert nested_arm_swapped is True
    assert scan_calls == 0
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_dynamically_discovered_nested_symlink_requires_pre_discovery_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    mode: str,
) -> None:
    """A nested ONNX sidecar alias learned after discovery cannot inherit a late receipt."""
    del requires_symlinks
    from modelaudit import core as core_module

    source = tmp_path / "model.onnx"
    weights = tmp_path / "weights"
    weights.mkdir()
    target = weights / "data.bin"
    held = weights / "held.bin"
    benign = weights / "benign.bin"
    alias = tmp_path / "model.onnx_data"
    source.write_bytes(b"model")
    target.write_bytes(b"malicious data")
    benign.write_bytes(b"benign data")
    alias.symlink_to(Path(weights.name) / target.name)
    scan_calls = 0
    swapped = False

    def discover_during_target_substitution(*_args: Any, **_kwargs: Any) -> list[Path]:
        nonlocal swapped
        if not swapped:
            target.rename(held)
            benign.rename(target)
            swapped = True
        return [alias]

    def track_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        nonlocal scan_calls
        del path, config
        scan_calls += 1
        scan_result = ScanResult(scanner_name="onnx")
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(
        core_module,
        "_streamed_onnx_external_data_hash_paths",
        discover_during_target_substitution,
    )
    monkeypatch.setattr(core_module, "scan_file", track_scan)

    result = _scan_explicit_test_source(source, mode, "onnx")

    assert scan_calls == 0
    _assert_local_source_boundary_failure(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_retained_openvino_escaped_symlink_preserves_critical_finding(
    tmp_path: Path,
    requires_symlinks: None,
    mode: str,
) -> None:
    """Descriptor preflight preserves confirmed OpenVINO escape evidence over generic failure."""
    del requires_symlinks
    model_dir = tmp_path / "model"
    outside_dir = tmp_path / "outside"
    model_dir.mkdir()
    outside_dir.mkdir()
    source = model_dir / "model.xml"
    escaped_target = outside_dir / "secret.bin"
    source.write_text("<net version='10'></net>", encoding="utf-8")
    escaped_target.write_bytes(b"secret weights")
    (model_dir / "model.bin").symlink_to(escaped_target)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert determine_exit_code(result) == 1
    assert any(
        check.rule_code == "S701"
        and check.name == "OpenVINO Weights Symlink Boundary Check"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert not any(check.name == "Local Source Boundary Check" for check in result.checks)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires name-bearing inotify events")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_retained_companion_discovery_ignores_unrelated_sibling_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """Discovery monitoring filters sibling events that cannot affect selected inputs."""
    from modelaudit import core as core_module

    source = tmp_path / "model.xml"
    weights = tmp_path / "model.bin"
    unrelated = tmp_path / "unrelated.part"
    renamed = tmp_path / "unrelated.ready"
    source.write_text("<net version='10'></net>", encoding="utf-8")
    weights.write_bytes(b"safe weights")
    unrelated.write_bytes(b"unrelated")
    original_discovery = core_module._openvino_xml_weights_companion

    def rename_unrelated_during_discovery(path: Path) -> Path | None:
        unrelated.rename(renamed)
        renamed.rename(unrelated)
        return original_discovery(path)

    monkeypatch.setattr(core_module, "_openvino_xml_weights_companion", rename_unrelated_during_discovery)

    result = _scan_explicit_test_source(source, mode, "openvino")

    assert determine_exit_code(result) == 0
    assert result.success is True
    assert result.bytes_scanned == source.stat().st_size + weights.stat().st_size
    assert result.content_hash is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_oci_context_layer_contributes_bytes_and_content_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """Changing only a consumed OCI layer must change the full-input aggregate hash."""
    from modelaudit import core as core_module

    source = tmp_path / "model.manifest"
    source.write_text(json.dumps({"layers": ["layer.tar.gz"]}), encoding="utf-8")
    layer = tmp_path / "layer.tar.gz"

    def successful_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.bytes_scanned = Path(path).stat().st_size
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "scan_file", successful_scan)

    def run_scan() -> Any:
        return _scan_explicit_test_source(source, mode, "oci_layer")

    layer.write_bytes(b"A" * 64)
    first = run_scan()
    first_expected_hash = compute_aggregate_hash([compute_sha256_hash(source), compute_sha256_hash(layer)])
    layer.write_bytes(b"B" * 64)
    second = run_scan()
    second_expected_hash = compute_aggregate_hash([compute_sha256_hash(source), compute_sha256_hash(layer)])

    assert first.content_hash == first_expected_hash
    assert second.content_hash == second_expected_hash
    assert first.content_hash != second.content_hash
    assert first.bytes_scanned == source.stat().st_size + layer.stat().st_size
    assert second.bytes_scanned == source.stat().st_size + layer.stat().st_size


def test_oci_filtered_directory_context_contributes_bytes_and_content_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A consumed OCI layer omitted by directory prefiltering remains a hashed input."""
    from modelaudit import core as core_module

    source = tmp_path / "model.manifest"
    source.write_text(json.dumps({"layers": ["layer.tar.gz"]}), encoding="utf-8")
    layer = tmp_path / "layer.tar.gz"
    original_should_skip_file = core_module.should_skip_file

    def skip_layer(path: str, *args: Any, **kwargs: Any) -> bool:
        if Path(path).resolve() == layer.resolve():
            return True
        return original_should_skip_file(path, *args, **kwargs)

    def successful_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.bytes_scanned = Path(path).stat().st_size
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "should_skip_file", skip_layer)
    monkeypatch.setattr(core_module, "scan_file", successful_scan)

    def run_scan() -> Any:
        return scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["oci_layer"],
            skip_file_types=True,
        )

    layer.write_bytes(b"A" * 64)
    first = run_scan()
    first_expected_hash = compute_aggregate_hash([compute_sha256_hash(source), compute_sha256_hash(layer)])
    layer.write_bytes(b"B" * 64)
    second = run_scan()
    second_expected_hash = compute_aggregate_hash([compute_sha256_hash(source), compute_sha256_hash(layer)])

    assert first.content_hash == first_expected_hash
    assert second.content_hash == second_expected_hash
    assert first.content_hash != second.content_hash
    assert first.bytes_scanned == source.stat().st_size + layer.stat().st_size
    assert second.bytes_scanned == source.stat().st_size + layer.stat().st_size


def test_streaming_oci_shared_context_layer_is_hashed_and_counted_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple manifests sharing one retained layer contribute one unique layer input."""
    from modelaudit import core as core_module

    first_manifest = tmp_path / "a.manifest"
    second_manifest = tmp_path / "b.manifest"
    layer = tmp_path / "layer.tar.gz"
    first_manifest.write_text(json.dumps({"name": "a", "layers": [layer.name]}), encoding="utf-8")
    second_manifest.write_text(json.dumps({"name": "b", "layers": [layer.name]}), encoding="utf-8")
    layer.write_bytes(b"shared layer")

    def successful_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.bytes_scanned = Path(path).stat().st_size
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "scan_file", successful_scan)
    unique_input_bytes = first_manifest.stat().st_size + second_manifest.stat().st_size + layer.stat().st_size
    result = scan_model_streaming(
        iter([(first_manifest, True), (second_manifest, True)]),
        scan_root=str(tmp_path),
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["oci_layer"],
        skip_file_types=False,
        max_total_size=unique_input_bytes,
    )

    assert result.content_hash == compute_aggregate_hash(
        [
            compute_sha256_hash(first_manifest),
            compute_sha256_hash(second_manifest),
            compute_sha256_hash(layer),
        ]
    )
    assert result.bytes_scanned == unique_input_bytes


def test_oci_filtered_directory_shared_context_layer_respects_unique_exact_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filtered directory companions share one logical byte budget across manifests."""
    from modelaudit import core as core_module

    first_manifest = tmp_path / "a.manifest"
    second_manifest = tmp_path / "b.manifest"
    layer = tmp_path / "layer.tar.gz"
    first_manifest.write_text(json.dumps({"name": "a", "layers": [layer.name]}), encoding="utf-8")
    second_manifest.write_text(json.dumps({"name": "b", "layers": [layer.name]}), encoding="utf-8")
    layer.write_bytes(b"shared layer")
    original_should_skip_file = core_module.should_skip_file

    def skip_layer(path: str, *args: Any, **kwargs: Any) -> bool:
        if Path(path).resolve() == layer.resolve():
            return True
        return original_should_skip_file(path, *args, **kwargs)

    def successful_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.bytes_scanned = Path(path).stat().st_size
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "should_skip_file", skip_layer)
    monkeypatch.setattr(core_module, "scan_file", successful_scan)
    unique_input_bytes = first_manifest.stat().st_size + second_manifest.stat().st_size + layer.stat().st_size
    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        scanners=["oci_layer"],
        skip_file_types=True,
        max_total_size=unique_input_bytes,
    )

    assert result.content_hash == compute_aggregate_hash(
        [
            compute_sha256_hash(first_manifest),
            compute_sha256_hash(second_manifest),
            compute_sha256_hash(layer),
        ]
    )
    assert result.bytes_scanned == unique_input_bytes


def test_streaming_oci_context_layer_is_not_recounted_as_later_stream_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A consumed OCI layer later yielded for scanning keeps unique-input hash semantics."""
    from modelaudit import core as core_module

    manifest = tmp_path / "model.manifest"
    layer = tmp_path / "layer.tar.gz"
    manifest.write_text(json.dumps({"layers": [layer.name]}), encoding="utf-8")
    layer.write_bytes(b"shared layer")

    def successful_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        scan_result = ScanResult(scanner_name="oci_layer")
        scan_result.bytes_scanned = Path(path).stat().st_size
        scan_result.finish(success=True)
        return scan_result

    monkeypatch.setattr(core_module, "scan_file", successful_scan)
    result = scan_model_streaming(
        iter([(manifest, False), (layer, True)]),
        scan_root=str(tmp_path),
        delete_after_scan=False,
        cache_enabled=False,
        skip_file_types=False,
    )

    assert result.content_hash == compute_aggregate_hash([compute_sha256_hash(manifest), compute_sha256_hash(layer)])
    assert result.bytes_scanned == manifest.stat().st_size + layer.stat().st_size


@pytest.mark.parametrize("mode", ["standard", "streaming"])
def test_oci_missing_layer_does_not_publish_primary_only_content_hash(
    tmp_path: Path,
    mode: str,
) -> None:
    """Incomplete OCI coverage must not be cached under a manifest-only hash."""
    source = tmp_path / "model.manifest"
    source.write_text(json.dumps({"layers": ["missing-layer.tar.gz"]}), encoding="utf-8")

    result = _scan_explicit_test_source(source, mode, "oci_layer")

    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.content_hash is None


@pytest.fixture
def temp_test_files() -> Iterator[list[Path]]:
    """Create temporary test files for streaming."""
    files: list[Path] = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write(f"Test content {i}")
            files.append(Path(tmp.name))
    yield files
    # Cleanup
    for file_path in files:
        if file_path.exists():
            file_path.unlink()


def create_mock_scan_result(bytes_scanned: int = 1024, with_critical_issue: bool = False) -> ScanResult:
    """Create a mock ScanResult for testing."""
    result = ScanResult(scanner_name="test_scanner")
    result.bytes_scanned = bytes_scanned
    result.success = True
    if with_critical_issue:
        result.add_issue("Detected malicious behavior", severity=IssueSeverity.CRITICAL, location="test.pkl")
    return result


def create_external_onnx_payload(tmp_path: Path, external_path: str = "model.onnx_data") -> bytes:
    onnx = pytest.importorskip("onnx")
    from onnx import TensorProto, helper
    from onnx.onnx_ml_pb2 import StringStringEntryProto

    tensor = helper.make_tensor("W", TensorProto.FLOAT, [1], vals=[1.0])
    tensor.data_location = onnx.TensorProto.EXTERNAL
    entry = StringStringEntryProto()
    entry.key = "location"
    entry.value = external_path
    tensor.external_data.append(entry)
    graph = helper.make_graph(
        [helper.make_node("Relu", ["input"], ["output"], name="relu")],
        "streaming_external_data_graph",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])],
        initializer=[tensor],
    )
    model_path = tmp_path / "fixture.onnx"
    onnx.save(helper.make_model(graph), str(model_path))
    return model_path.read_bytes()


def assert_only_onnx_external_schema_validation_skipped(result: Any, *, expected_count: int = 1) -> None:
    schema_issues = [
        issue
        for issue in result.issues
        if issue.details.get("schema_validation_reason") == "onnx_schema_validation_failed"
        and issue.details.get("checker_available") is True
        and issue.details.get("external_data_present") is True
    ]
    assert len(schema_issues) == expected_count
    assert result.issues == schema_issues
    assert determine_exit_code(result) == 2


def write_hf_download_metadata(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "c5ee24cb16019beea0893ab7796b1df96625c6b8\n821d1aa69520101d6e0737f78a042ae25b19e5c0\n1712656091.123\n",
        encoding="utf-8",
    )


def write_hf_cachedir_tag(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Signature: 8a477f597d28d172789f06886806bc55\n"
        "# This file is a cache directory tag created by huggingface_hub.\n"
        "# For information about cache directory tags, see:\n"
        "#\thttps://bford.info/cachedir/\n",
        encoding="utf-8",
    )


def write_large_valid_userblock_keras_hdf5(path: Path) -> int:
    h5py = pytest.importorskip("h5py")
    userblock_size = 16 * 1024 * 1024
    assert userblock_size > HDF5_SIGNATURE_SCAN_MAX_BYTES
    with h5py.File(path, "w", userblock_size=userblock_size) as h5_file:
        h5_file.attrs["model_config"] = json.dumps(
            {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]}},
        )
        h5_file.attrs["keras_version"] = "3.13.2"
    with path.open("ab") as handle:
        handle.truncate(DEFAULT_MAX_FILE_READ_SIZE + 4096)
    return userblock_size


def create_mock_location_scan_result(
    resolved_path: Path,
    *,
    issue_suffix: str = ":payload",
    check_suffix: str = " (weights)",
) -> ScanResult:
    """Create a mock result whose locations are anchored to the resolved target."""
    result = ScanResult(scanner_name="test_scanner")
    result.bytes_scanned = 128
    result.add_check(
        name="Suspicious Payload",
        passed=False,
        message="Detected malicious behavior",
        severity=IssueSeverity.CRITICAL,
        location=f"{resolved_path}{issue_suffix}",
    )
    result.add_check(
        name="Layout Inspection",
        passed=True,
        message="Model structure inspected",
        location=f"{resolved_path}{check_suffix}",
    )
    result.finish(success=True)
    return result


def _write_ordered_hf_tokenizer_json(
    path: Path,
    *,
    late_fields: str = "",
    padding_size: int = 0,
) -> Path:
    padding = f',"padding":"{"x" * padding_size}"' if padding_size else ""
    path.write_text(
        (
            '{"version":"1.0","added_tokens":[],'
            f'"model":{{"type":"BPE","vocab":{{"hello":0}},"merges":[]}}{padding}{late_fields}}}'
        ),
        encoding="utf-8",
    )
    return path


def test_scan_model_directory_or_file_streaming_path() -> None:
    """Ensure stream:// paths route to streaming analysis."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 123
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

        args, kwargs = mock_scanner.call_args
        assert args[0] == "/model.pkl"
        assert "config" in kwargs
        mock_stream.assert_called_once_with(stream_url, dummy_scanner)
        assert result.files_scanned == 1
        assert result.bytes_scanned == 123
    assert determine_exit_code(result) == 0


def test_scan_model_directory_or_file_streaming_path_enforces_max_file_size() -> None:
    """The configured file limit must cap the actual remote stream read."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, False)) as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()) as mock_scanner,
    ):
        scan_model_directory_or_file(f"stream://{stream_url}", max_file_size=4096)

    mock_stream.assert_called_once_with(stream_url, mock_scanner.return_value, max_bytes=4096)


def test_scan_model_directory_or_file_encoded_signed_query_preserves_routing() -> None:
    """Encoded signed queries must not hide the model suffix from scanner routing."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl%3FX-Amz-Signature%3Ddeadbeef%26token%3Dsecret-token"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)) as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()) as mock_scanner,
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    assert mock_scanner.call_args.args[0] == "/model.pkl"
    mock_stream.assert_called_once_with(stream_url, mock_scanner.return_value)
    serialized = result.model_dump_json(exclude_none=True)
    assert "deadbeef" not in serialized
    assert "secret-token" not in serialized


def test_scan_model_directory_or_file_mixed_case_streaming_path() -> None:
    """URI scheme casing must not bypass streaming routing."""
    stream_url = "S3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        scan_model_directory_or_file(f"STREAM://{stream_url}")

    mock_stream.assert_called_once_with(stream_url, dummy_scanner)


def test_scan_model_directory_or_file_incomplete_streaming_path_returns_exit_code_2() -> None:
    """Incomplete stream:// analysis without findings should be explicit and fail closed."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, False)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    metadata = result.file_metadata[stream_url].model_dump()
    assert metadata["scan_outcome"] == "inconclusive"
    assert metadata["analysis_incomplete"] is True
    assert "streaming_analysis_incomplete" in metadata["scan_outcome_reasons"]
    assert "failed closed" in metadata["scan_outcome_message"]
    assert any(
        issue.message == "Streaming analysis incomplete - full scanner coverage was not available"
        for issue in result.issues
    )
    assert result.has_errors is False
    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_directory_or_file_partial_streaming_security_finding_returns_exit_code_1() -> None:
    """Security findings should outrank partial stream:// analysis metadata."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.add_issue(
        "Dangerous payload found in streamed prefix",
        severity=IssueSeverity.CRITICAL,
        location=stream_url,
    )
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, False)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    metadata = result.file_metadata[stream_url].model_dump()
    assert metadata["scan_outcome"] == "inconclusive"
    assert result.success is False
    assert determine_exit_code(result) == 1


def test_streaming_signed_url_is_redacted_from_results_and_sarif() -> None:
    """stream:// scans must preserve raw scanner input but redact persisted output."""
    stream_url = (
        "https://bucket.s3.amazonaws.com/model.pkl?"
        "X-Amz-Credential=AKIASECRET&X-Amz-Signature=deadbeef&token=secret-token"
    )
    safe_url = "https://bucket.s3.amazonaws.com/model.pkl"
    related_url = (
        "https://collector.example/upload?"
        "visible=yes&token=secondary-secret&password=password-secret&opaque=unknown-secret"
    )
    parsed_credentials = {
        "Authorization": "Bearer nested-auth-secret",
        "client_secret": "nested-client-secret",
        "access%252525255Ftoken": "deeply-encoded-token-secret",
        "tokenizer": "sentencepiece",
    }
    fragment_url = "https://collector.example/callback#access_token=fragment-secret"
    legacy_signed_url = (
        "https://bucket.s3.amazonaws.com/related.pkl?"
        "AWSAccessKeyId=AKIARELATED&Expires=123456&Signature=related-signature"
    )
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata.update(
        {
            "source_url": stream_url,
            "related_url": related_url,
            "fragment_url": fragment_url,
            "path_url": Path(related_url),
            "license_info": [LicenseInfoModel(url=related_url)],
            "source_set": {stream_url, related_url},
            "source_bytes": stream_url.encode(),
            "legacy_signed_url": legacy_signed_url,
            "parsed_query": parsed_credentials,
            "nested_model": Issue(message=stream_url, details={"source_bytes": stream_url.encode()}),
        }
    )
    scan_result.add_issue(
        f"Dangerous payload from {stream_url}",
        severity=IssueSeverity.CRITICAL,
        location=f"{stream_url}:payload",
        details={
            "source": stream_url,
            "nested": [stream_url],
            stream_url: {"source": stream_url},
            "related_url": related_url,
            "fragment_url": fragment_url,
            "path_url": Path(related_url),
            "license_info": [LicenseInfoModel(url=related_url)],
            "source_set": {stream_url, related_url},
            "source_bytes": stream_url.encode(),
            "legacy_signed_url": legacy_signed_url,
            "parsed_query": parsed_credentials,
            "nested_model": Issue(message=stream_url, details={"source_bytes": stream_url.encode()}),
        },
    )
    scan_result.add_check(
        name=f"Streaming Payload {stream_url}",
        passed=False,
        message=f"Checked {stream_url}",
        severity=IssueSeverity.CRITICAL,
        location=f"{stream_url} (header)",
        details={
            "source": stream_url,
            stream_url: {"source": stream_url},
            "parsed_query": parsed_credentials,
        },
        why=f"Matched {stream_url}",
    )
    cast(Any, scan_result.issues[0]).source_index = {stream_url: stream_url}
    cast(Any, scan_result.checks[0]).source_index = {stream_url: stream_url}
    cast(Any, scan_result.issues[0]).parsed_query = parsed_credentials
    cast(Any, scan_result.checks[0]).parsed_query = parsed_credentials
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    mock_stream.assert_called_once_with(stream_url, dummy_scanner)
    json_text = result.model_dump_json(exclude_none=True)
    sarif_text = format_sarif_output(result, [f"stream://{stream_url}"])

    for leaked in (
        "AKIASECRET",
        "deadbeef",
        "secret-token",
        "secondary-secret",
        "password-secret",
        "unknown-secret",
        "fragment-secret",
        "AKIARELATED",
        "related-signature",
        "X-Amz-Signature",
        "nested-auth-secret",
        "nested-client-secret",
        "deeply-encoded-token-secret",
    ):
        assert leaked not in json_text
        assert leaked not in sarif_text
    assert "sentencepiece" in json_text
    assert "sentencepiece" in sarif_text
    assert stream_url not in json_text
    assert stream_url not in sarif_text
    assert safe_url in json_text
    assert safe_url in sarif_text
    assert "visible=yes" in json_text
    assert "visible=yes" in sarif_text
    assert "token=<redacted>" in sarif_text
    assert "opaque=<redacted>" in json_text
    assert "opaque=<redacted>" in sarif_text
    assert "https://collector.example/upload<redacted>" not in sarif_text
    assert safe_url in result.file_metadata
    assert all(asset.path != stream_url for asset in result.assets)


def test_streaming_safe_source_still_redacts_related_signed_urls() -> None:
    """Stream record sanitization should not depend on the source URL needing redaction."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl"
    related_url = "https://collector.example/upload?visible=yes&token=secondary-secret&password=password-secret"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata.update({"related_url": related_url})
    scan_result.add_issue(
        f"Related signed URL {related_url}",
        severity=IssueSeverity.WARNING,
        location=stream_url,
        details={"related_url": related_url},
    )
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    mock_stream.assert_called_once_with(stream_url, dummy_scanner)
    json_text = result.model_dump_json(exclude_none=True)
    assert "secondary-secret" not in json_text
    assert "password-secret" not in json_text
    assert "token=<redacted>" in json_text
    assert "visible=yes" in json_text


def test_streaming_transformed_and_escaped_credentials_are_redacted() -> None:
    """Scanner-normalized source diagnostics must not bypass reporting redaction."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl"
    opaque_url = "https://collector.example/callback?OPAQUE-QUERY-SECRET#OPAQUE-FRAGMENT-SECRET"
    escaped_url = r"https:\/\/collector.example\/callback\u003ftoken\u003dENCODED-STREAM-SECRET"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata.update(
        {
            "normalized_query": "token=TRANSFORMED-STREAM-SECRET",
            "opaque_url": opaque_url,
            "escaped_url": escaped_url,
            "authorization_header": "Authorization: Bearer HEADER-STREAM-SECRET",
        }
    )
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    sarif_text = format_sarif_output(result, [f"stream://{stream_url}"])
    for secret in (
        "TRANSFORMED-STREAM-SECRET",
        "OPAQUE-QUERY-SECRET",
        "OPAQUE-FRAGMENT-SECRET",
        "ENCODED-STREAM-SECRET",
        "HEADER-STREAM-SECRET",
    ):
        assert secret not in json_text
        assert secret not in sarif_text
    assert "token=<redacted>" in json_text
    assert "https://collector.example/callback" in json_text


def test_streaming_related_url_safe_key_cannot_hide_encoded_nested_credentials() -> None:
    """Scanner metadata must redact nested credentials hidden under an allowlisted key."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl"
    related_url = "https://collector.example/upload?lang=en%26token%3Dsecondary-secret"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata["related_url"] = related_url
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    sarif_text = format_sarif_output(result, [f"stream://{stream_url}"])
    assert "secondary-secret" not in json_text
    assert "secondary-secret" not in sarif_text
    assert "lang=<redacted>" in json_text


def test_streaming_invalid_utf8_metadata_is_replaced_before_reporting() -> None:
    """Opaque binary metadata must not retain signed URLs or break JSON output."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?token=secret-token"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.metadata["opaque_blob"] = b"\xff" + stream_url.encode()
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert "<binary data>" in json_text
    assert "secret-token" not in json_text


def test_streaming_malformed_port_error_is_redacted() -> None:
    """Malformed stream URLs should produce a safe operational result, not escape error handling."""
    stream_url = "https://user:password@example.com:notaport/model.pkl?token=secret-token"

    result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert determine_exit_code(result) == 2
    assert "stream://<cloud URL redacted>" in json_text
    assert "password" not in json_text
    assert "secret-token" not in json_text


def test_streaming_signed_url_no_scanner_error_is_redacted() -> None:
    """stream:// scanner-routing failures must not persist signed URL material."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"

    with patch("modelaudit.scanners.get_scanner_for_file", return_value=None) as mock_scanner:
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    mock_scanner.assert_called_once()
    json_text = result.model_dump_json(exclude_none=True)
    assert "deadbeef" not in json_text
    assert "secret-token" not in json_text
    assert "X-Amz-Signature" not in json_text
    assert "stream://https://bucket.s3.amazonaws.com/model.pkl" in json_text
    assert all(asset.path != f"stream://{stream_url}" for asset in result.assets)
    assert determine_exit_code(result) == 2


def test_streaming_signed_url_analysis_none_error_is_redacted() -> None:
    """stream:// analysis failures must not persist signed URL material."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(None, False)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert "deadbeef" not in json_text
    assert "secret-token" not in json_text
    assert "X-Amz-Signature" not in json_text
    assert "stream://https://bucket.s3.amazonaws.com/model.pkl" in json_text
    assert all(asset.path != f"stream://{stream_url}" for asset in result.assets)
    assert determine_exit_code(result) == 2


def test_streaming_signed_url_routing_exception_log_is_redacted(caplog: pytest.LogCaptureFixture) -> None:
    """stream:// routing exceptions must not leak signed URLs through tracebacks."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"

    with (
        caplog.at_level(logging.ERROR, logger="modelaudit.core"),
        patch(
            "modelaudit.scanners.get_scanner_for_file",
            side_effect=RuntimeError(f"route failed for {stream_url}"),
        ),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    assert determine_exit_code(result) == 2
    assert "https://bucket.s3.amazonaws.com/model.pkl" in caplog.text
    assert "deadbeef" not in caplog.text
    assert "secret-token" not in caplog.text
    assert "X-Amz-Signature" not in caplog.text


def test_streaming_signed_url_with_invalid_port_fails_closed() -> None:
    """Malformed URL authorities must not make the reporting sanitizer raise or leak."""
    stream_url = "https://example.com:not-a-port/model.pkl?token=secret-token"

    result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert determine_exit_code(result) == 2
    assert "secret-token" not in json_text
    assert "token=" not in json_text
    assert "<cloud URL redacted>" in json_text


def test_streaming_signed_url_without_inner_scheme_fails_closed() -> None:
    """Malformed stream identifiers must not persist their raw query in error assets."""
    stream_url = "bucket/model.pkl?session=secret-token"

    result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert determine_exit_code(result) == 2
    assert "secret-token" not in json_text
    assert "session=" not in json_text
    assert "stream://<cloud URL redacted>" in json_text


def test_scan_model_streaming_basic(temp_test_files: list[Path]) -> None:
    """Test basic streaming scan functionality."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        """Generator that yields (path, is_last) tuples."""
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        # Mock scan_file to return scan results
        mock_scan.side_effect = [create_mock_scan_result(bytes_scanned=100) for _ in temp_test_files]

        # Run streaming scan (don't delete for this test)
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # Verify results
        assert result.bytes_scanned == 300  # 3 files * 100 bytes
        assert result.files_scanned == 3
        assert result.has_errors is False
        assert result.content_hash is not None
        assert len(result.content_hash) == 64  # SHA256 hex string


@patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
@patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
@patch(
    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
    return_value=(["onnx/model.onnx", "onnx/model.onnx_data"], "a" * 40, None),
)
@patch("huggingface_hub.hf_hub_download")
def test_scan_model_streaming_hf_onnx_external_data_sidecar_matches_local_directory(
    mock_hf_hub_download: Any,
    _mock_list_repo_files: Any,
    _mock_get_extensions: Any,
    _mock_detect_content: Any,
    tmp_path: Path,
) -> None:
    """HF streaming should preserve declared ONNX sidecars for the parent scan."""
    payload = create_external_onnx_payload(tmp_path)
    sidecar_bytes = struct.pack("f", 1.0)

    def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
        assert local_dir is not None
        path = Path(local_dir) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload if filename == "onnx/model.onnx" else sidecar_bytes)
        return str(path)

    mock_hf_hub_download.side_effect = download_side_effect
    generator = download_model_streaming(
        "https://huggingface.co/test/model",
        cache_dir=tmp_path / "cache",
        scannable_extensions={".onnx"},
        scannable_scanner_ids={"onnx"},
    )

    result = scan_model_streaming(
        generator,
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "passed"
    ]
    assert failed_external == []
    assert passed_external
    assert_only_onnx_external_schema_validation_skipped(result)
    assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
        "onnx/model.onnx",
        "onnx/model.onnx_data",
    ]


@patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
@patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
@patch(
    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
    return_value=(["onnx/model-a.onnx", "onnx/model-b.onnx", "onnx/shared.onnx_data"], "a" * 40, None),
)
@patch("modelaudit.utils.sources.huggingface._get_huggingface_path_sizes")
@patch("huggingface_hub.hf_hub_download")
def test_scan_model_streaming_hf_shared_onnx_external_data_counts_bytes_once(
    mock_hf_hub_download: Any,
    mock_get_path_sizes: Any,
    _mock_list_repo_files: Any,
    _mock_get_extensions: Any,
    _mock_detect_content: Any,
    tmp_path: Path,
) -> None:
    """A shared context-only ONNX sidecar should count once toward streaming totals."""
    model_a_payload = create_external_onnx_payload(tmp_path, external_path="shared.onnx_data")
    model_b_payload = create_external_onnx_payload(tmp_path, external_path="shared.onnx_data")
    sidecar_payload = struct.pack("f", 1.0)
    remote_payloads = {
        "onnx/model-a.onnx": model_a_payload,
        "onnx/model-b.onnx": model_b_payload,
        "onnx/shared.onnx_data": sidecar_payload,
    }
    remote_sizes = {filename: len(payload) for filename, payload in remote_payloads.items()}
    unique_bytes = sum(remote_sizes.values())
    expected_hash = compute_aggregate_hash(
        [
            hashlib.sha256(model_a_payload).hexdigest(),
            hashlib.sha256(sidecar_payload).hexdigest(),
            hashlib.sha256(model_b_payload).hexdigest(),
        ]
    )

    def get_path_sizes(
        _repo_id: str,
        filenames: list[str],
        **_kwargs: object,
    ) -> tuple[dict[str, int | None], str]:
        return {filename: remote_sizes[filename] for filename in filenames}, "a" * 40

    def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
        assert local_dir is not None
        path = Path(local_dir) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(remote_payloads[filename])
        return str(path)

    mock_get_path_sizes.side_effect = get_path_sizes
    mock_hf_hub_download.side_effect = download_side_effect
    generator = download_model_streaming(
        "https://huggingface.co/test/model",
        cache_dir=tmp_path / "cache",
        max_size=unique_bytes,
        scannable_extensions={".onnx"},
        scannable_scanner_ids={"onnx"},
    )

    result = scan_model_streaming(
        generator,
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        max_total_size=unique_bytes,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert result.bytes_scanned == unique_bytes
    assert result.content_hash == expected_hash
    assert not any("Total scan size limit exceeded" in issue.message for issue in result.issues)
    assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == [
        "onnx/model-a.onnx",
        "onnx/shared.onnx_data",
        "onnx/model-b.onnx",
    ]


@patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
@patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
@patch(
    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
    return_value=(["onnx/model.onnx"], "a" * 40, None),
)
@patch("huggingface_hub.hf_hub_download")
def test_scan_model_streaming_hf_onnx_missing_external_data_still_warns(
    mock_hf_hub_download: Any,
    _mock_list_repo_files: Any,
    _mock_get_extensions: Any,
    _mock_detect_content: Any,
    tmp_path: Path,
) -> None:
    """Missing declared sidecars should remain visible instead of being suppressed."""
    payload = create_external_onnx_payload(tmp_path)

    def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
        assert filename == "onnx/model.onnx"
        assert local_dir is not None
        path = Path(local_dir) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return str(path)

    mock_hf_hub_download.side_effect = download_side_effect
    generator = download_model_streaming(
        "https://huggingface.co/test/model",
        cache_dir=tmp_path / "cache",
        scannable_extensions={".onnx"},
        scannable_scanner_ids={"onnx"},
    )

    result = scan_model_streaming(
        generator,
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    missing_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    assert len(missing_external) == 1
    assert missing_external[0].details["file"] == "model.onnx_data"
    assert determine_exit_code(result) == 1
    assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == ["onnx/model.onnx"]


@patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", return_value=None)
@patch("modelaudit.utils.sources.huggingface._get_model_extensions", return_value={".onnx"})
@patch(
    "modelaudit.utils.sources.huggingface._list_repo_files_with_timeout",
    return_value=(["onnx/model.onnx", "secret.bin"], "a" * 40, None),
)
@patch("huggingface_hub.hf_hub_download")
def test_scan_model_streaming_hf_onnx_escaping_external_data_remains_cve(
    mock_hf_hub_download: Any,
    _mock_list_repo_files: Any,
    _mock_get_extensions: Any,
    _mock_detect_content: Any,
    tmp_path: Path,
) -> None:
    """Escaping sidecars must not be downloaded and made to look safe."""
    payload = create_external_onnx_payload(tmp_path, external_path="../secret.bin")

    def download_side_effect(*, filename: str, local_dir: str | None = None, **_kwargs: object) -> str:
        assert filename == "onnx/model.onnx"
        assert local_dir is not None
        path = Path(local_dir) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return str(path)

    mock_hf_hub_download.side_effect = download_side_effect
    generator = download_model_streaming(
        "https://huggingface.co/test/model",
        cache_dir=tmp_path / "cache",
        scannable_extensions={".onnx"},
        scannable_scanner_ids={"onnx"},
    )

    result = scan_model_streaming(
        generator,
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert any("CVE-2022-25882" in check.name for check in result.checks)
    assert all(
        not (
            check.name == "External Data Reference Check"
            and check.status.value == "failed"
            and check.details.get("file") == "../secret.bin"
        )
        for check in result.checks
    )
    assert determine_exit_code(result) == 1
    assert [call.kwargs["filename"] for call in mock_hf_hub_download.call_args_list] == ["onnx/model.onnx"]


def test_scan_model_directory_hf_cache_onnx_external_data_uses_snapshot_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Local scans over HF cache snapshots should resolve ONNX sidecars beside the snapshot alias."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    (snapshot_dir / "model.onnx").symlink_to(os.path.relpath(model_blob, snapshot_dir))
    (snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    result = scan_model_directory_or_file(
        str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]
    assert failed_external == []
    assert len(passed_external) == 1
    assert_only_onnx_external_schema_validation_skipped(result)


def test_scan_model_directory_hf_cache_onnx_external_data_accepts_symlinked_cache_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Configured HF cache roots reached through symlinks should still trust snapshot aliases."""
    real_hub = tmp_path / "real-hub"
    link_hub = tmp_path / "link-hub"
    real_hub.mkdir()
    link_hub.symlink_to(real_hub, target_is_directory=True)
    monkeypatch.setenv("HF_HUB_CACHE", str(link_hub))

    cache_root = link_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    (snapshot_dir / "model.onnx").symlink_to(os.path.relpath(model_blob, snapshot_dir))
    (snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    result = scan_model_directory_or_file(
        str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]
    symlink_traversal_checks = [
        check for check in result.checks if check.name == "CVE-2026-34447: External Data Symlink Traversal"
    ]

    assert failed_external == []
    assert len(passed_external) == 1
    assert symlink_traversal_checks == []
    assert_only_onnx_external_schema_validation_skipped(result)


def test_scan_model_directory_hf_cache_content_routed_onnx_external_data_accepts_symlinked_cache_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Extensionless ONNX aliases under symlinked HF cache roots should keep snapshot sidecar context."""
    real_hub = tmp_path / "real-hub"
    link_hub = tmp_path / "link-hub"
    real_hub.mkdir()
    link_hub.symlink_to(real_hub, target_is_directory=True)
    monkeypatch.setenv("HF_HUB_CACHE", str(link_hub))

    cache_root = link_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    (snapshot_dir / "renamed").symlink_to(os.path.relpath(model_blob, snapshot_dir))
    (snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    result = scan_model_directory_or_file(
        str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]
    symlink_traversal_checks = [
        check for check in result.checks if check.name == "CVE-2026-34447: External Data Symlink Traversal"
    ]

    assert failed_external == []
    assert len(passed_external) == 1
    assert symlink_traversal_checks == []
    assert_only_onnx_external_schema_validation_skipped(result)


def test_scan_model_directory_hf_cache_onnx_external_data_rejects_nested_cache_lookalike(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Nested models--* directories under a configured hub root must not become trusted cache roots."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    fake_cache_root = cache_hub / "scratch" / "models--test--model"
    blobs_dir = fake_cache_root / "blobs"
    snapshot_dir = fake_cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    (snapshot_dir / "model.onnx").symlink_to(os.path.relpath(model_blob, snapshot_dir))
    (snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    result = scan_model_directory_or_file(
        str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    traversal_issues = [issue for issue in result.issues if "path traversal" in issue.message.lower()]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]

    assert traversal_issues
    assert passed_external == []
    assert determine_exit_code(result) == 1


def test_scan_model_directory_hf_cache_onnx_external_data_keeps_snapshot_alias_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Shared ONNX blobs must scan once per snapshot alias when sidecar aliases differ."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    blobs_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    valid_sidecar_blob = blobs_dir / "sidecar-valid"
    short_sidecar_blob = blobs_dir / "sidecar-short"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    valid_sidecar_blob.write_bytes(struct.pack("f", 1.0))
    short_sidecar_blob.write_bytes(b"\x00")

    valid_snapshot = cache_root / "snapshots" / ("a" * 40) / "onnx"
    missing_snapshot = cache_root / "snapshots" / ("b" * 40) / "onnx"
    short_snapshot = cache_root / "snapshots" / ("c" * 40) / "onnx"
    for snapshot_dir in (valid_snapshot, missing_snapshot, short_snapshot):
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "model.onnx").symlink_to(os.path.relpath(model_blob, snapshot_dir))
    (valid_snapshot / "model.onnx_data").symlink_to(os.path.relpath(valid_sidecar_blob, valid_snapshot))
    (short_snapshot / "model.onnx_data").symlink_to(os.path.relpath(short_sidecar_blob, short_snapshot))

    result = scan_model_directory_or_file(
        str(cache_root / "snapshots"),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]
    failed_sizes = [
        check
        for check in result.checks
        if check.name == "External Data Size Validation" and check.status.value == "failed"
    ]
    assert len(passed_external) == 2
    assert len(failed_external) == 1
    assert failed_external[0].location == str(missing_snapshot / "model.onnx_data")
    assert len(failed_sizes) == 1
    assert failed_sizes[0].details["actual_size"] == 1
    assert determine_exit_code(result) == 1


@pytest.mark.parametrize(
    ("sidecar_name", "skip_file_types"),
    [("model.onnx_data", False), ("weights.txt", True)],
    ids=["scannable-sidecar", "prefiltered-sidecar"],
)
def test_scan_model_directory_hf_cache_onnx_shared_blobs_keep_each_snapshot_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    sidecar_name: str,
    skip_file_types: bool,
) -> None:
    """Shared model and sidecar blobs retain sidecar context beside every logical alias."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    blobs_dir.mkdir(parents=True)
    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path, sidecar_name))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))

    for revision in ("a" * 40, "b" * 40):
        snapshot_dir = cache_root / "snapshots" / revision / "onnx"
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "model.onnx").symlink_to(os.path.relpath(model_blob, snapshot_dir))
        (snapshot_dir / sidecar_name).symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    expected_bytes = (2 * model_blob.stat().st_size) + sidecar_blob.stat().st_size
    result = scan_model_directory_or_file(
        str(cache_root / "snapshots"),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=skip_file_types,
        max_total_size=expected_bytes,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == sidecar_name
    ]
    expected_hash = compute_aggregate_hash([compute_sha256_hash(model_blob), compute_sha256_hash(sidecar_blob)])

    assert failed_external == []
    assert len(passed_external) == 2
    assert result.content_hash == expected_hash
    assert result.bytes_scanned == expected_bytes
    assert_only_onnx_external_schema_validation_skipped(result, expected_count=2)


@pytest.mark.parametrize("delete_after_scan", [False, True])
def test_scan_model_streaming_reconciles_cross_directory_shard_coverage(
    delete_after_scan: bool,
) -> None:
    """A complete streamed family should not fail merely because each shard has its own directory."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 4):
            staging_root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_dir = staging_root / "huggingface" / "models--org--repo" / "snapshots" / "revision"
            shard_dir.mkdir(parents=True)
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=delete_after_scan,
            shard_family_group="trusted-stream:model-a",
            cache_enabled=False,
        )

        assert result.files_scanned == 3
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)
        assert all(
            "missing_model_shards" not in metadata.model_dump().get("scan_outcome_reasons", [])
            for metadata in result.file_metadata.values()
        )
        assert all(
            "scan_outcome_message" not in metadata.model_dump(exclude_none=True)
            for metadata in result.file_metadata.values()
        )


def test_scan_model_streaming_zero_based_family_without_index_fails_closed(tmp_path: Path) -> None:
    """Observed shard names alone must not authorize a zero-based family."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards: list[Path] = []
    for shard_index in range(3):
        shard_dir = tmp_path / f"modelaudit_stream_part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard)

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "unexpected_model_shards" for check in result.checks)


def test_scan_model_streaming_zero_based_family_uses_validated_index(tmp_path: Path) -> None:
    """A stable index may authorize a complete zero-based streaming family."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards: list[Path] = []
    weight_map: dict[str, str] = {}
    for shard_index in range(2):
        shard_dir = tmp_path / f"part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard)
        weight_map[f"tensor-{shard_index}"] = shard.relative_to(tmp_path).as_posix()
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": weight_map}),
        encoding="utf-8",
    )

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        shard_family_group="trusted-stream:model-a",
        _trusted_shard_family_root=_make_trusted_stream_shard_root(str(tmp_path)),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(
        check.details.get("scan_outcome_reason") in {"missing_model_shards", "unexpected_model_shards"}
        for check in result.checks
    )


@pytest.mark.parametrize("start_index", [0, 1], ids=["zero-based", "one-based"])
@pytest.mark.parametrize("delete_after_scan", [False, True], ids=["preserve-source", "delete-source"])
def test_scan_model_streaming_accepts_late_cross_directory_index(
    tmp_path: Path,
    start_index: int,
    delete_after_scan: bool,
) -> None:
    """One late proof coalesces exact members observed under different parents."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards: list[Path] = []
    for offset, shard_index in enumerate(range(start_index, start_index + 2)):
        shard = tmp_path / f"part-{offset}" / f"model-{shard_index:05d}-of-00002.safetensors"
        shard.parent.mkdir()
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard)
    index_path = tmp_path / "model.safetensors.index.json"

    def late_index_stream() -> Iterator[tuple[Path, bool]]:
        yield shards[0], False
        yield shards[1], False
        index_path.write_text(
            json.dumps(
                {
                    "weight_map": {
                        f"tensor-{index}": shard.relative_to(tmp_path).as_posix() for index, shard in enumerate(shards)
                    }
                }
            ),
            encoding="utf-8",
        )
        yield index_path, True

    result = scan_model_streaming(
        file_generator=late_index_stream(),
        timeout=30,
        delete_after_scan=delete_after_scan,
        scan_root=str(tmp_path),
        shard_family_group="trusted-stream:model-a",
        _trusted_shard_family_root=_make_trusted_stream_shard_root(str(tmp_path)),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(
        check.details.get("scan_outcome_reason") in {"missing_model_shards", "unexpected_model_shards"}
        for check in result.checks
    )
    assert index_path.exists() is (not delete_after_scan)


@pytest.mark.skipif(os.name == "nt", reason="Windows retained shard guard prevents the fixture rewrite")
def test_scan_model_streaming_revalidates_preserved_family_members_before_reconciliation(tmp_path: Path) -> None:
    """A previously scanned shard replaced between streamed items cannot certify the final family."""
    original_header = b'{"__metadata__":{"format":"pt"}}'
    replacement_header = b'{"__metadata__":{"format":"tf"}}'
    shards: list[Path] = []
    for shard_index in range(2):
        shard_dir = tmp_path / f"part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard.write_bytes(struct.pack("<Q", len(original_header)) + original_header)
        shards.append(shard)
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps(
            {
                "weight_map": {
                    f"tensor-{index}": shard.relative_to(tmp_path).as_posix() for index, shard in enumerate(shards)
                }
            }
        ),
        encoding="utf-8",
    )
    replacement = struct.pack("<Q", len(replacement_header)) + replacement_header

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shards[0], False
        shards[0].write_bytes(replacement)
        yield shards[1], True

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        shard_family_group="trusted-stream:model-a",
        _trusted_shard_family_root=_make_trusted_stream_shard_root(str(tmp_path)),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert shards[0].read_bytes() == replacement
    assert any(
        check.location == str(shards[0]) and check.details.get("scan_outcome_reason") == "shard_boundary_changed"
        for check in result.checks
    )


def test_scan_model_streaming_index_authority_requires_exact_declared_member_path(tmp_path: Path) -> None:
    """Equivalent numeric shard spellings cannot substitute for an index-declared member."""
    header = b'{"__metadata__":{"format":"pt"}}'
    canonical_zero = tmp_path / "model-00000-of-00002.safetensors"
    alternate_one = tmp_path / "model-1-of-00002.safetensors"
    for shard in (canonical_zero, alternate_one):
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps(
            {
                "weight_map": {
                    "a": canonical_zero.name,
                    "b": "model-00001-of-00002.safetensors",
                }
            }
        ),
        encoding="utf-8",
    )

    result = scan_model_streaming(
        file_generator=iter([(canonical_zero, False), (alternate_one, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        shard_family_group="trusted-stream:model-a",
        _trusted_shard_family_root=_make_trusted_stream_shard_root(str(tmp_path)),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    coverage_reasons = {
        check.details.get("scan_outcome_reason") for check in result.checks if check.details.get("scan_outcome_reason")
    }
    assert {"missing_model_shards", "unexpected_model_shards"}.intersection(coverage_reasons)


@pytest.mark.parametrize(
    ("first_index", "replace_index_between_shards", "expected_success"),
    [(0, False, True), (0, True, False), (1, False, True), (1, True, False)],
    ids=["zero-stable", "zero-aba", "one-stable", "one-aba"],
)
def test_scan_model_streaming_requires_one_index_generation_for_indexed_family(
    tmp_path: Path,
    first_index: int,
    replace_index_between_shards: bool,
    expected_success: bool,
) -> None:
    """Cross-file reconciliation must not combine authority from different index contents."""
    header = b'{"__metadata__":{"format":"pt"}}'

    def create_shard(parent: str, index: int) -> Path:
        shard_dir = tmp_path / parent
        shard_dir.mkdir()
        shard = shard_dir / f"model-{index:05d}-of-00002.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        return shard

    selected_shards = [create_shard("a", first_index), create_shard("b", first_index + 1)]
    decoy_shards = [create_shard("d", first_index), create_shard("c", first_index + 1)]
    index_path = tmp_path / "model.safetensors.index.json"

    def write_index(shards: list[Path]) -> None:
        index_path.write_text(
            json.dumps(
                {
                    "weight_map": {
                        f"tensor-{index}": shard.relative_to(tmp_path).as_posix() for index, shard in enumerate(shards)
                    }
                }
            ),
            encoding="utf-8",
        )

    write_index([selected_shards[0], decoy_shards[1]] if replace_index_between_shards else selected_shards)

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield selected_shards[0], False
        if replace_index_between_shards:
            write_index([decoy_shards[0], selected_shards[1]])
        yield selected_shards[1], True

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        shard_family_group="trusted-stream:model-a",
        _trusted_shard_family_root=_make_trusted_stream_shard_root(str(tmp_path)),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is expected_success
    assert determine_exit_code(result) == (0 if expected_success else 2)
    coverage_reasons = {
        check.details.get("scan_outcome_reason")
        for check in result.checks
        if check.details.get("scan_outcome_reason") in {"missing_model_shards", "unexpected_model_shards"}
    }
    assert bool(coverage_reasons) is not expected_success


@pytest.mark.parametrize("mutation_timing", ["during_scan", "after_final_yield"])
def test_scan_model_streaming_revalidates_index_content_when_stat_identity_is_unreliable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_timing: str,
) -> None:
    """A same-stat index rewrite during streaming must invalidate final shard authority."""
    shard = tmp_path / "model-00000-of-00001.safetensors"
    header = b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    shard.write_bytes(len(header).to_bytes(8, "little") + header + b"\x00" * 4)
    index_path = tmp_path / "model.safetensors.index.json"
    payload_a = b'{"weight_map":{"weight":"model-00000-of-00001.safetensors"}}'
    payload_b = b'{"weight_map":{"decoyx":"model-00000-of-00001.safetensors"}}'
    assert len(payload_a) == len(payload_b)
    index_path.write_bytes(payload_a)

    def mutate_index_during_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        del config
        index_path.write_bytes(payload_b)
        result = ScanResult(scanner_name="safetensors")
        result.bytes_scanned = Path(path).stat().st_size
        result.finish(success=True)
        return result

    if mutation_timing == "during_scan":
        monkeypatch.setattr("modelaudit.core.scan_file", mutate_index_during_scan)
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._safetensors_index_requires_content_revalidation",
        lambda: True,
    )
    monkeypatch.setattr(
        "modelaudit.utils.file.handlers._safetensors_index_observation_prefix",
        lambda *_args: ("stable-stat-identity",),
    )

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, True
        if mutation_timing == "after_final_yield":
            index_path.write_bytes(payload_b)

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert index_path.read_bytes() == payload_b
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


def test_scan_model_streaming_rechecks_index_authority_for_every_shard_parent(tmp_path: Path) -> None:
    """A closer index appearing under a later streamed parent must invalidate the root proof."""
    header = b'{"__metadata__":{"format":"pt"}}'
    first = tmp_path / "a" / "model-00000-of-00002.safetensors"
    second = tmp_path / "b" / "model-00001-of-00002.safetensors"
    for shard in (first, second):
        shard.parent.mkdir()
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps(
            {
                "weight_map": {
                    "first": first.relative_to(tmp_path).as_posix(),
                    "second": second.relative_to(tmp_path).as_posix(),
                }
            }
        ),
        encoding="utf-8",
    )

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield first, False
        yield second, True
        replacement = second.parent / "c" / "model-00000-of-00002.safetensors"
        replacement.parent.mkdir()
        replacement.write_bytes(struct.pack("<Q", len(header)) + header)
        (second.parent / "model.safetensors.index.json").write_text(
            json.dumps(
                {
                    "weight_map": {
                        "replacement": replacement.relative_to(second.parent).as_posix(),
                        "second": second.name,
                    }
                }
            ),
            encoding="utf-8",
        )

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


def test_scan_model_streaming_rechecks_index_after_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A final index swap during reconciliation cannot certify previously scanned shards."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards = [tmp_path / f"model-{index:05d}-of-00002.safetensors" for index in range(2)]
    for shard in shards:
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"

    def write_index(prefix: str) -> None:
        index_path.write_text(
            json.dumps({"weight_map": {f"{prefix}-{index}": shard.name for index, shard in enumerate(shards)}}),
            encoding="utf-8",
        )

    write_index("initial")
    original_reconcile = _reconcile_cross_directory_shard_coverage
    reconciliation_count = 0

    def replace_index_after_reconciliation(*args: Any, **kwargs: Any) -> bool:
        nonlocal reconciliation_count
        result = original_reconcile(*args, **kwargs)
        reconciliation_count += 1
        write_index("replacement")
        return result

    monkeypatch.setattr(
        "modelaudit.core._reconcile_cross_directory_shard_coverage",
        replace_index_after_reconciliation,
    )

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert reconciliation_count == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    outcome_reasons = {check.details.get("scan_outcome_reason") for check in result.checks}
    assert "shard_boundary_changed" in outcome_reasons, outcome_reasons


def test_scan_model_streaming_stable_windows_index_uses_one_terminal_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid many-shard Windows family performs one bounded terminal content reread."""
    from modelaudit.utils.file import handlers as handlers_module

    header = b'{"__metadata__":{"format":"pt"}}'
    shard_count = 33
    shards: list[Path] = []
    weight_map: dict[str, str] = {}
    for shard_index in range(1, shard_count + 1):
        shard = tmp_path / f"model-{shard_index:05d}-of-{shard_count:05d}.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard)
        weight_map[f"tensor-{shard_index}"] = shard.name
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(json.dumps({"weight_map": weight_map}), encoding="utf-8")

    monkeypatch.setattr(handlers_module, "_safetensors_index_requires_content_revalidation", lambda: True)
    monkeypatch.setattr(
        handlers_module,
        "MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES",
        index_path.stat().st_size * 2,
    )

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


@pytest.mark.parametrize("create_index_after_yield", [False, True], ids=["stable-unindexed", "new-index"])
@pytest.mark.parametrize("delete_after_scan", [False, True], ids=["preserve-source", "delete-source"])
def test_scan_model_streaming_rechecks_unindexed_authority_after_final_yield(
    tmp_path: Path,
    create_index_after_yield: bool,
    delete_after_scan: bool,
) -> None:
    """An unindexed family stays clean only while no governing index appears."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, True
        if create_index_after_yield:
            index_path.write_text(
                json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
                encoding="utf-8",
            )

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=delete_after_scan,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is (not create_index_after_yield)
    assert determine_exit_code(result) == (2 if create_index_after_yield else 0)
    assert index_path.is_file() is create_index_after_yield
    assert (
        any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)
        is create_index_after_yield
    )


@pytest.mark.parametrize("delete_after_scan", [False, True], ids=["preserve-source", "delete-source"])
def test_scan_model_streaming_accepts_late_consistent_index(
    tmp_path: Path,
    delete_after_scan: bool,
) -> None:
    """A complete index arriving after its shard is accepted when it declares the same family."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"

    def late_index_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, False
        index_path.write_text(
            json.dumps({"weight_map": {"tensor": shard.name}}),
            encoding="utf-8",
        )
        yield index_path, True

    result = scan_model_streaming(
        file_generator=late_index_stream(),
        timeout=30,
        delete_after_scan=delete_after_scan,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)
    assert index_path.exists() is (not delete_after_scan)


@pytest.mark.parametrize("delete_after_scan", [False, True], ids=["preserve-source", "delete-source"])
def test_scan_model_streaming_accepts_late_consistent_zero_based_index(
    tmp_path: Path,
    delete_after_scan: bool,
) -> None:
    """A complete late index promotes zero-based authority before reconciliation."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards = [tmp_path / f"model-{index:05d}-of-00002.safetensors" for index in range(2)]
    for shard in shards:
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"

    def late_index_stream() -> Iterator[tuple[Path, bool]]:
        yield shards[0], False
        yield shards[1], False
        index_path.write_text(
            json.dumps({"weight_map": {f"tensor-{index}": shard.name for index, shard in enumerate(shards)}}),
            encoding="utf-8",
        )
        yield index_path, True

    result = scan_model_streaming(
        file_generator=late_index_stream(),
        timeout=30,
        delete_after_scan=delete_after_scan,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(
        check.details.get("scan_outcome_reason") in {"missing_model_shards", "unexpected_model_shards"}
        for check in result.checks
    )
    assert index_path.exists() is (not delete_after_scan)


def test_scan_model_streaming_closes_generator_before_terminal_index_validation(tmp_path: Path) -> None:
    """Generator cleanup cannot recreate contradictory authority after terminal checks."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(json.dumps({"weight_map": {"tensor": shard.name}}), encoding="utf-8")

    class RecreatingIndexIterator(Iterator[tuple[Path, bool]]):
        def __init__(self) -> None:
            self.items = iter([(index_path, False), (shard, True)])
            self.closed = False

        def __next__(self) -> tuple[Path, bool]:
            return next(self.items)

        def close(self) -> None:
            self.closed = True
            index_path.write_text(
                json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
                encoding="utf-8",
            )

    stream = RecreatingIndexIterator()
    result = scan_model_streaming(
        file_generator=stream,
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert stream.closed is True
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


@pytest.mark.parametrize("recreate_index", [False, True], ids=["remains-deleted", "recreated-unrelated"])
def test_scan_model_streaming_revalidates_program_deleted_index(
    tmp_path: Path,
    recreate_index: bool,
) -> None:
    """A deleted authority is accepted only while its path remains absent."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": shard.name}}),
        encoding="utf-8",
    )

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, False
        yield index_path, True
        if recreate_index:
            index_path.write_text(
                json.dumps(
                    {
                        "weight_map": {
                            "a": "model-00001-of-00002.safetensors",
                            "b": "model-00002-of-00002.safetensors",
                        }
                    }
                ),
                encoding="utf-8",
            )

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is (not recreate_index)
    assert determine_exit_code(result) == (2 if recreate_index else 0)
    assert not shard.exists()
    assert index_path.is_file() is recreate_index
    assert (
        any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)
        is recreate_index
    )


def test_scan_model_streaming_rejects_swapped_index_before_program_deletion(tmp_path: Path) -> None:
    """Deleting a replacement index cannot make stale shard authority look stable."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00000-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"initial": shard.name}}),
        encoding="utf-8",
    )

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, False
        index_path.write_text(
            json.dumps({"weight_map": {"replacement": shard.name}}),
            encoding="utf-8",
        )
        yield index_path, True

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert not index_path.exists()
    assert any(
        check.name == "Sharded Model Boundary Check"
        and check.location == str(shard)
        and check.details.get("reason") == "shard_index_changed_after_scan"
        and check.details.get("scan_outcome_reason") == "shard_boundary_changed"
        for check in result.checks
    )


@pytest.mark.parametrize("replace_declared_shard", [False, True], ids=["stable", "replaced"])
def test_terminal_safetensors_proof_requires_selected_paths_to_remain_declared(
    tmp_path: Path,
    replace_declared_shard: bool,
) -> None:
    """A refreshed proof cannot retain an alias after its declared target is replaced."""
    header = b'{"__metadata__":{"format":"pt"}}'
    selected_dir = tmp_path / "selected"
    declared_dir = tmp_path / "declared"
    selected_dir.mkdir()
    declared_dir.mkdir()
    declared_first = declared_dir / "model-00001-of-00002.safetensors"
    selected_first = selected_dir / declared_first.name
    selected_second = selected_dir / "model-00002-of-00002.safetensors"
    declared_first.write_bytes(struct.pack("<Q", len(header)) + header)
    selected_second.write_bytes(struct.pack("<Q", len(header)) + header)
    os.link(declared_first, selected_first)
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps(
            {
                "weight_map": {
                    "first": declared_first.relative_to(tmp_path).as_posix(),
                    "second": selected_second.relative_to(tmp_path).as_posix(),
                }
            }
        ),
        encoding="utf-8",
    )
    selected_paths = [str(selected_first), str(selected_second)]
    initial_proof, authority_present = ShardedModelDetector.refresh_safetensors_index_proofs(
        selected_paths,
        expected_total=2,
        index_search_root=tmp_path,
        index_inspection_context=_SafetensorsIndexInspectionContext(),
        force_content_revalidation=True,
        require_declared_files=True,
    )
    assert initial_proof is not None
    assert authority_present is True

    if replace_declared_shard:
        declared_first.unlink()
        declared_first.write_bytes(struct.pack("<Q", len(header)) + header)

    loose_proof, loose_authority = ShardedModelDetector.refresh_safetensors_index_proofs(
        selected_paths,
        expected_total=2,
        index_search_root=tmp_path,
        index_inspection_context=_SafetensorsIndexInspectionContext(),
        force_content_revalidation=True,
        require_declared_files=False,
    )
    strict_proof, strict_authority = ShardedModelDetector.refresh_safetensors_index_proofs(
        selected_paths,
        expected_total=2,
        index_search_root=tmp_path,
        index_inspection_context=_SafetensorsIndexInspectionContext(),
        force_content_revalidation=True,
        require_declared_files=True,
    )
    assert loose_proof == initial_proof
    assert loose_authority is True
    assert strict_proof == (None if replace_declared_shard else initial_proof)
    assert strict_authority is True

    validated_targets = {}
    for selected_path in selected_paths:
        validated_targets.update(
            _snapshot_validated_shard_target(
                selected_path,
                authoritative_shard_index_base=initial_proof[0],
                authoritative_shard_index_path=initial_proof[1],
                authoritative_shard_index_fingerprint=initial_proof[2],
                authoritative_shard_index_generation=initial_proof[3],
            )
        )
    failures = _terminal_safetensors_shard_boundary_failures(
        validated_targets,
        index_search_root=tmp_path,
        index_inspection_context=_SafetensorsIndexInspectionContext(),
    )

    assert failures == (
        dict.fromkeys(selected_paths, "shard_index_changed_after_scan") if replace_declared_shard else {}
    )


def test_scan_model_streaming_deletes_non_index_payload_with_index_suffix_immediately(tmp_path: Path) -> None:
    """Content-routed payloads do not accumulate merely because their names resemble indexes."""
    payloads = [tmp_path / f"evil-{index}.safetensors.index.json" for index in range(2)]
    for payload in payloads:
        payload.write_bytes(b"not a SafeTensors index")
    first_deleted_before_second_yield = False

    def payload_stream() -> Iterator[tuple[Path, bool]]:
        nonlocal first_deleted_before_second_yield
        yield payloads[0], False
        first_deleted_before_second_yield = not payloads[0].exists()
        yield payloads[1], True

    result = scan_model_streaming(
        file_generator=payload_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert result.success is True
    assert first_deleted_before_second_yield is True
    assert not any(payload.exists() for payload in payloads)


def test_scan_model_streaming_deletes_content_routed_index_suffix_beside_unrelated_shard(tmp_path: Path) -> None:
    """A shard-shaped neighbor cannot retain positively content-routed model payloads."""
    payload = create_external_onnx_payload(tmp_path)
    payloads = [tmp_path / f"evil-{index}.safetensors.index.json" for index in range(2)]
    for payload_path in payloads:
        payload_path.write_bytes(payload)
    (tmp_path / "unrelated-00001-of-00001.safetensors").write_bytes(b"unrelated")
    first_deleted_before_second_yield = False

    def payload_stream() -> Iterator[tuple[Path, bool]]:
        nonlocal first_deleted_before_second_yield
        yield payloads[0], False
        first_deleted_before_second_yield = not payloads[0].exists()
        yield payloads[1], True

    scan_model_streaming(
        file_generator=payload_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["onnx"],
    )

    assert first_deleted_before_second_yield is True
    assert not any(payload_path.exists() for payload_path in payloads)


@pytest.mark.parametrize("mutation", ["replacement", "same-inode-rewrite"])
def test_scan_model_streaming_rejects_index_swap_at_content_routed_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Atomic quarantine cannot erase an index swapped in after content classification."""
    import modelaudit.core as core_module

    onnx = pytest.importorskip("onnx")
    from onnx import TensorProto, helper

    graph = helper.make_graph(
        [helper.make_node("Relu", ["input"], ["output"])],
        "cleanup_swap_graph" * 64,
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])],
    )
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_bytes(helper.make_model(graph).SerializeToString())
    replacement = tmp_path / "replacement-index.json"
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    original_rename = core_module.os.rename
    original_replace = core_module.os.replace
    swapped = False

    def install_replacement() -> None:
        nonlocal swapped
        if not swapped:
            if mutation == "replacement":
                replacement.write_text(
                    json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
                    encoding="utf-8",
                )
                original_replace(replacement, index_path)
            else:
                original_stat = index_path.stat()
                malicious_pickle = pickle.dumps(_StreamingMaliciousPicklePayload())
                assert len(malicious_pickle) <= original_stat.st_size
                index_path.write_bytes(malicious_pickle.ljust(original_stat.st_size, b"\0"))
                os.utime(index_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            swapped = True

    def swap_before_bound_rename(*args: Any, **kwargs: Any) -> None:
        source_name = os.fspath(args[0]) if args else ""
        if source_name == index_path.name:
            install_replacement()
        original_rename(*args, **kwargs)

    def swap_before_fallback_replace(*args: Any, **kwargs: Any) -> None:
        source_path = Path(args[0]) if args else Path()
        if source_path == index_path:
            install_replacement()
        original_replace(*args, **kwargs)

    monkeypatch.setattr(core_module.os, "rename", swap_before_bound_rename)
    monkeypatch.setattr(core_module.os, "replace", swap_before_fallback_replace)

    def payload_then_shard() -> Iterator[tuple[Path, bool]]:
        yield index_path, False
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    result = scan_model_streaming(
        file_generator=payload_then_shard(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["onnx", "safetensors"],
    )

    assert swapped is True
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_changed_before_cleanup"
        for issue in result.issues
    )


def test_scan_model_streaming_tracks_present_invalid_weight_map_before_shard(tmp_path: Path) -> None:
    """A present malformed weight_map is not proven unrelated content."""
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps(
            {
                "version": [1, 7, 4],
                "learner": {"gradient_booster": {}},
                "weight_map": None,
            }
        ),
        encoding="utf-8",
    )
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'

    def payload_then_shard() -> Iterator[tuple[Path, bool]]:
        yield index_path, False
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    result = scan_model_streaming(
        file_generator=payload_then_shard(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        check.details.get("reason") == "safetensors_index_deleted_before_shard_validation" for check in result.checks
    )


def test_scan_model_streaming_bounds_structural_index_probe_after_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Index classification cannot allocate bytes added after its size snapshot."""
    import modelaudit.core as core_module

    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": "model-00001-of-00001.safetensors"}}),
        encoding="utf-8",
    )
    initial_size = index_path.stat().st_size
    original_os_pread = os.pread
    index_stat = index_path.stat()
    grew = False
    read_sizes: list[int] = []

    def grow_before_classification_read(file_descriptor: int, size: int, offset: int) -> bytes:
        nonlocal grew
        descriptor_stat = os.fstat(file_descriptor)
        if not grew and (descriptor_stat.st_dev, descriptor_stat.st_ino) == (index_stat.st_dev, index_stat.st_ino):
            with index_path.open("ab") as handle:
                handle.write(b"x" * (1024 * 1024))
            grew = True
            read_sizes.append(size)
        return original_os_pread(file_descriptor, size, offset)

    monkeypatch.setattr(core_module.os, "pread", grow_before_classification_read)

    scan_model_streaming(
        file_generator=iter([(index_path, True)]),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert grew is True
    assert read_sizes == [initial_size + 1]
    assert not index_path.exists()


def test_scan_model_streaming_index_retention_overflow_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful cleanup cannot erase an index-retention resource failure."""
    from modelaudit import core as core_module

    monkeypatch.setattr(core_module, "MAX_SAFETENSORS_SHARD_INDEX_FILES", 1)
    indexes = [tmp_path / f"model-{index}.safetensors.index.json" for index in range(2)]
    for index_path in indexes:
        index_path.write_text(
            json.dumps({"weight_map": {"tensor": "model-00001-of-00001.safetensors"}}),
            encoding="utf-8",
        )

    result = scan_model_streaming(
        file_generator=iter((path, index == len(indexes) - 1) for index, path in enumerate(indexes)),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert not any(path.exists() for path in indexes)
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_retention_limit_exceeded"
        for issue in result.issues
    )


def test_scan_model_streaming_rejects_index_disappearing_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A classified index disappearing before cleanup remains a durable failure."""
    import modelaudit.utils.helpers.assets as assets_module

    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
        encoding="utf-8",
    )
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    original_asset_from_scan_result = assets_module.asset_from_scan_result
    removed = False

    def remove_after_classification(*args: Any, **kwargs: Any) -> Any:
        nonlocal removed
        asset = original_asset_from_scan_result(*args, **kwargs)
        if Path(str(args[0])) == index_path and index_path.exists():
            index_path.unlink()
            removed = True
        return asset

    def stream() -> Iterator[tuple[Path, bool]]:
        yield index_path, False
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    monkeypatch.setattr(assets_module, "asset_from_scan_result", remove_after_classification)
    result = scan_model_streaming(
        file_generator=stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata", "safetensors"],
    )

    assert removed is True
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_disappeared_before_cleanup"
        for issue in result.issues
    )


def test_scan_model_streaming_rejects_index_disappearing_while_binding_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure to bind the classified index generation cannot become a clean scan."""
    import modelaudit.core as core_module

    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
        encoding="utf-8",
    )
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    original_snapshot = core_module._snapshot_file_identity
    index_snapshot_calls = 0
    removed = False

    def remove_on_retention_bind(path: Path) -> Any:
        nonlocal index_snapshot_calls, removed
        if Path(path) == index_path:
            index_snapshot_calls += 1
            if index_snapshot_calls == 3:
                index_path.unlink()
                removed = True
        return original_snapshot(path)

    def stream() -> Iterator[tuple[Path, bool]]:
        yield index_path, False
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    monkeypatch.setattr(core_module, "_snapshot_file_identity", remove_on_retention_bind)
    result = scan_model_streaming(
        file_generator=stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata", "safetensors"],
    )

    assert removed is True
    assert index_snapshot_calls >= 3
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_disappeared_before_retention"
        for issue in result.issues
    )


def test_scan_model_streaming_preserved_index_cannot_disappear_before_later_shard(tmp_path: Path) -> None:
    """Preserved index authority remains bound until all streamed shards are reconciled."""
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
        encoding="utf-8",
    )
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'

    def stream() -> Iterator[tuple[Path, bool]]:
        yield index_path, False
        index_path.unlink()
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    result = scan_model_streaming(
        file_generator=stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata", "safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_changed_before_deferred_deletion"
        for issue in result.issues
    )


def test_scan_model_streaming_large_non_json_index_suffix_deletes_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded prefix can prove large non-JSON content is not index authority."""
    from modelaudit import core as core_module

    monkeypatch.setattr(core_module, "MAX_SAFETENSORS_SHARD_INDEX_BYTES", 8)
    payload = tmp_path / "large.safetensors.index.json"
    payload.write_bytes(b"X" * 32)

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert not payload.exists()
    assert result.success is True
    assert determine_exit_code(result) == 0


def test_scan_model_streaming_indeterminate_index_probe_budget_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Probe exhaustion cannot turn a later governing index into content-routed cleanup."""
    from modelaudit import core as core_module

    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    unrelated_index = tmp_path / "adapter.safetensors.index.json"
    governing_index = tmp_path / "model.safetensors.index.json"
    unrelated_payload = json.dumps({"weight_map": {"adapter": "adapter.safetensors"}})
    governing_payload = json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}})
    monkeypatch.setattr(
        core_module,
        "MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES",
        len(unrelated_payload.encode()) + 1,
    )

    def delayed_indexes() -> Iterator[tuple[Path, bool]]:
        yield shard, False
        unrelated_index.write_text(unrelated_payload, encoding="utf-8")
        yield unrelated_index, False
        governing_index.write_text(governing_payload, encoding="utf-8")
        yield governing_index, True

    result = scan_model_streaming(
        file_generator=delayed_indexes(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_retention_limit_exceeded"
        for issue in result.issues
    )


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "mkfifo"), reason="POSIX FIFO semantics required")
def test_scan_model_streaming_index_suffix_fifo_fails_promptly(tmp_path: Path) -> None:
    """Index classification never performs a blocking read from a special file."""
    fifo_path = tmp_path / "fifo.safetensors.index.json"
    os.mkfifo(fifo_path)
    started = time.monotonic()

    result = scan_model_streaming(
        file_generator=iter([(fifo_path, True)]),
        timeout=1,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert time.monotonic() - started < 2
    assert not fifo_path.exists()
    assert result.success is False
    assert determine_exit_code(result) == 2


@pytest.mark.parametrize("index_first", [False, True], ids=["shard-first", "index-first"])
@pytest.mark.parametrize("delete_after_scan", [False, True], ids=["preserve-source", "delete-source"])
def test_scan_model_streaming_retains_contradictory_index_through_terminal_validation(
    tmp_path: Path,
    index_first: bool,
    delete_after_scan: bool,
) -> None:
    """Cleanup cannot erase an index that disproves the streamed shard family."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
        encoding="utf-8",
    )
    ordered_paths = [index_path, shard] if index_first else [shard, index_path]

    result = scan_model_streaming(
        file_generator=iter((path, index == len(ordered_paths) - 1) for index, path in enumerate(ordered_paths)),
        timeout=30,
        delete_after_scan=delete_after_scan,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert index_path.exists() is (not delete_after_scan)
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
@pytest.mark.parametrize("symlinked", [False, True], ids=["regular", "symlink"])
def test_scan_model_streaming_rebinds_family_members_to_retained_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
    symlinked: bool,
) -> None:
    """Shard and index reads must originate from the retained directory tree."""
    del requires_symlinks
    from modelaudit import core as core_module

    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    target_dir = tmp_path / "targets"
    if symlinked:
        target_dir.mkdir()
    shard_target = target_dir / shard.name if symlinked else shard
    shard_target.write_bytes(struct.pack("<Q", len(header)) + header)
    if symlinked:
        shard.symlink_to(shard_target.relative_to(tmp_path))
    index_path = tmp_path / "model.safetensors.index.json"
    index_target = target_dir / index_path.name if symlinked else index_path
    index_target.write_text(
        json.dumps({"weight_map": {"tensor": shard.name}}),
        encoding="utf-8",
    )
    if symlinked:
        index_path.symlink_to(index_target.relative_to(tmp_path))
    retained_descriptors: dict[str, bool] = {}
    original_dup = os.dup

    def record_retained_dup(source_fd: int) -> int:
        source_stat = os.fstat(source_fd)
        for original_path in (shard, index_path):
            if os.path.samestat(source_stat, original_path.stat()):
                retained_descriptors[original_path.name] = True
        return original_dup(source_fd)

    monkeypatch.setattr(core_module.os, "dup", record_retained_dup)

    stream_paths = [shard, index_path]
    if symlinked:
        stream_paths.extend((shard_target, index_target))
    result = scan_model_streaming(
        file_generator=iter((path, index == len(stream_paths) - 1) for index, path in enumerate(stream_paths)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        skip_file_types=True,
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert retained_descriptors == {shard.name: True, index_path.name: True}


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor traversal")
def test_scan_model_streaming_rejects_replaced_retained_symlink_target(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """A restored symlink target cannot hide a pre-open replacement generation."""
    del requires_symlinks
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    target_dir = tmp_path / "targets"
    target_dir.mkdir()
    shard_target = target_dir / shard.name
    original_payload = struct.pack("<Q", len(header)) + header
    shard_target.write_bytes(original_payload)
    shard.symlink_to(shard_target.relative_to(tmp_path))
    original_generation = target_dir / "original-generation"

    def replace_then_restore_target() -> Iterator[tuple[Path, bool]]:
        shard_target.rename(original_generation)
        shard_target.write_bytes(original_payload)
        yield shard, False
        shard_target.unlink()
        original_generation.rename(shard_target)
        yield shard_target, True

    result = scan_model_streaming(
        file_generator=replace_then_restore_target(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        skip_file_types=True,
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(check.details.get("reason") == "local_source_changed_during_scan" for check in result.checks)
    assert shard_target.read_bytes() == original_payload


def test_scan_model_streaming_fails_if_deleted_index_suffix_precedes_created_shard(tmp_path: Path) -> None:
    """A later shard cannot silently benefit from an already-cleaned index candidate."""
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_bytes(b"not a SafeTensors index")
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    index_deleted_before_shard = False

    def delayed_shard_stream() -> Iterator[tuple[Path, bool]]:
        nonlocal index_deleted_before_shard
        yield index_path, False
        index_deleted_before_shard = not index_path.exists()
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    result = scan_model_streaming(
        file_generator=delayed_shard_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert index_deleted_before_shard is True
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        check.details.get("reason") == "safetensors_index_deleted_before_shard_validation"
        and check.details.get("scan_outcome_reason") == "shard_boundary_changed"
        for check in result.checks
    )


def test_scan_model_streaming_tracks_deleted_index_scope_through_symlink(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Deleted index receipts and later shard scopes use the same resolved parent."""
    real_root = tmp_path / "real"
    alias_root = tmp_path / "alias"
    real_root.mkdir()
    alias_root.symlink_to(real_root, target_is_directory=True)
    index_path = alias_root / "model.safetensors.index.json"
    index_path.write_bytes(b"not a SafeTensors index")
    shard = alias_root / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    index_deleted_before_shard = False

    def delayed_shard_stream() -> Iterator[tuple[Path, bool]]:
        nonlocal index_deleted_before_shard
        yield index_path, False
        index_deleted_before_shard = not index_path.exists()
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    result = scan_model_streaming(
        file_generator=delayed_shard_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(alias_root),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert index_deleted_before_shard is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        check.details.get("reason") == "safetensors_index_deleted_before_shard_validation" for check in result.checks
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory descriptor semantics required")
def test_scan_model_streaming_rejects_retargeted_symlink_parent_receipt(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Reusing one lexical path cannot replace its initial physical scope receipt."""
    roots = [tmp_path / name for name in ("a", "b")]
    for root in roots:
        root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(roots[0], target_is_directory=True)
    index_path = alias / "model.safetensors.index.json"
    shard = alias / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'

    def reused_alias_stream() -> Iterator[tuple[Path, bool]]:
        (roots[0] / index_path.name).write_bytes(b"not an index")
        yield index_path, False
        alias.unlink()
        alias.symlink_to(roots[1], target_is_directory=True)
        (roots[1] / index_path.name).write_bytes(b"still not an index")
        yield index_path, False
        alias.unlink()
        alias.symlink_to(roots[0], target_is_directory=True)
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        yield shard, True

    result = scan_model_streaming(
        file_generator=reused_alias_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata", "safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.name == "Local Source Boundary Check" for check in result.checks)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory descriptor semantics required")
def test_scan_model_streaming_rejects_same_lexical_index_in_retargeted_symlink_parent(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """A reused alias cannot introduce a second physical index authority."""
    roots = [tmp_path / name for name in ("a", "b")]
    for root in roots:
        root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(roots[0], target_is_directory=True)
    index_path = alias / "model.safetensors.index.json"
    payload = json.dumps({"weight_map": {"tensor": "model-00001-of-00001.safetensors"}})

    def reused_alias_stream() -> Iterator[tuple[Path, bool]]:
        (roots[0] / index_path.name).write_text(payload, encoding="utf-8")
        yield index_path, False
        alias.unlink()
        alias.symlink_to(roots[1], target_is_directory=True)
        (roots[1] / index_path.name).write_text(payload, encoding="utf-8")
        yield index_path, True
        alias.unlink()
        alias.symlink_to(roots[0], target_is_directory=True)

    result = scan_model_streaming(
        file_generator=reused_alias_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.name == "Local Source Boundary Check" for check in result.checks)


def test_scan_model_streaming_retains_valid_index_symlink_before_shard(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Index-first cleanup supports a stable in-root symlinked authority."""
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_blob = tmp_path / "index-blob.json"
    index_blob.write_text(
        json.dumps({"weight_map": {"tensor": shard.name}}),
        encoding="utf-8",
    )
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.symlink_to(index_blob.name)

    result = scan_model_streaming(
        file_generator=iter([(index_path, False), (shard, True)]),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not index_path.exists()
    assert index_blob.exists()


def test_scan_model_streaming_retains_index_created_after_deleted_shard(tmp_path: Path) -> None:
    """A later contradictory index remains available for terminal shard validation."""
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    shard_deleted_before_index = False

    def delayed_index_stream() -> Iterator[tuple[Path, bool]]:
        nonlocal shard_deleted_before_index
        yield shard, False
        shard_deleted_before_index = not shard.exists()
        index_path.write_text(
            json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
            encoding="utf-8",
        )
        yield index_path, True

    result = scan_model_streaming(
        file_generator=delayed_index_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert shard_deleted_before_index is True
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert not index_path.exists()
    assert any(
        check.details.get("reason") == "shard_index_changed_after_scan"
        and check.details.get("scan_outcome_reason") == "shard_boundary_changed"
        for check in result.checks
    )


def test_scan_model_streaming_rejects_retained_index_deleted_after_final_yield(tmp_path: Path) -> None:
    """A retained authority disappearing before terminal cleanup is a durable failure."""
    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"

    def disappearing_index_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, False
        index_path.write_text(
            json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
            encoding="utf-8",
        )
        yield index_path, True
        index_path.unlink()

    result = scan_model_streaming(
        file_generator=disappearing_index_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_changed_before_deferred_deletion"
        for issue in result.issues
    )


def test_scan_model_streaming_rejects_retained_index_rewrite_at_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deferred cleanup verifies index bytes after an equal-size in-place rewrite."""
    import modelaudit.core as core_module

    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    original_payload = json.dumps({"weight_map": {"tensor": shard.name}}, sort_keys=True)
    replacement_payload = json.dumps(
        {"weight_map": {"tensor": "model-00000-of-00001.safetensors"}},
        sort_keys=True,
    )
    assert len(original_payload) == len(replacement_payload)
    index_path.write_text(original_payload, encoding="utf-8")
    original_stat = index_path.stat()
    original_rename = core_module.os.rename
    original_replace = core_module.os.replace
    rewritten = False

    def rewrite_index() -> None:
        nonlocal rewritten
        if not rewritten:
            index_path.write_text(replacement_payload, encoding="utf-8")
            os.utime(index_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            rewritten = True

    def rewrite_before_bound_rename(*args: Any, **kwargs: Any) -> None:
        if args and os.fspath(args[0]) == index_path.name:
            rewrite_index()
        original_rename(*args, **kwargs)

    def rewrite_before_fallback_replace(*args: Any, **kwargs: Any) -> None:
        if args and Path(args[0]) == index_path:
            rewrite_index()
        original_replace(*args, **kwargs)

    monkeypatch.setattr(core_module.os, "rename", rewrite_before_bound_rename)
    monkeypatch.setattr(core_module.os, "replace", rewrite_before_fallback_replace)

    result = scan_model_streaming(
        file_generator=iter([(index_path, False), (shard, True)]),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert rewritten is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_changed_before_cleanup"
        for issue in result.issues
    )


def test_scan_model_streaming_rejects_index_recreated_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replacement appearing after tombstone deletion cannot restore clean authority."""
    import modelaudit.core as core_module

    shard = tmp_path / "model-00001-of-00001.safetensors"
    header = b'{"__metadata__":{"format":"pt"}}'
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_text(
        json.dumps({"weight_map": {"tensor": shard.name}}),
        encoding="utf-8",
    )
    original_unlink = core_module.os.unlink
    tombstone_unlinks = 0
    recreated = False

    def recreate_after_tombstone_unlink(*args: Any, **kwargs: Any) -> None:
        nonlocal recreated, tombstone_unlinks
        target_name = Path(os.fspath(args[0])).name if args else ""
        original_unlink(*args, **kwargs)
        if target_name.startswith(".modelaudit-index-delete-"):
            tombstone_unlinks += 1
            final_unlink_count = 1 if os.name == "nt" else 2
            if tombstone_unlinks == final_unlink_count:
                index_path.write_text(
                    json.dumps({"weight_map": {"tensor": "model-00000-of-00001.safetensors"}}),
                    encoding="utf-8",
                )
                recreated = True

    monkeypatch.setattr(core_module.os, "unlink", recreate_after_tombstone_unlink)

    result = scan_model_streaming(
        file_generator=iter([(index_path, False), (shard, True)]),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert recreated is True
    assert index_path.exists()
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_recreated_during_cleanup"
        for issue in result.issues
    )


def test_scan_model_streaming_quarantine_rename_failure_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed bound rename cannot disappear with its cleaned tombstone."""
    import modelaudit.core as core_module

    index_path = tmp_path / "model.safetensors.index.json"
    index_path.write_bytes(b"not an index")
    original_rename = core_module.os.rename
    original_replace = core_module.os.replace

    def fail_bound_rename(*args: Any, **kwargs: Any) -> None:
        if args and os.fspath(args[0]) == index_path.name:
            raise OSError("forced bound rename failure")
        original_rename(*args, **kwargs)

    def fail_fallback_replace(*args: Any, **kwargs: Any) -> None:
        if args and Path(args[0]) == index_path:
            raise OSError("forced fallback rename failure")
        original_replace(*args, **kwargs)

    monkeypatch.setattr(core_module.os, "rename", fail_bound_rename)
    monkeypatch.setattr(core_module.os, "replace", fail_fallback_replace)

    result = scan_model_streaming(
        file_generator=iter([(index_path, True)]),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["metadata"],
    )

    assert index_path.exists()
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert any(
        issue.details.get("scan_outcome_reason") == "safetensors_index_cleanup_failed" for issue in result.issues
    )


def test_scan_model_streaming_rejects_recreated_program_deleted_shard(tmp_path: Path) -> None:
    """Recreating a program-deleted shard after its final yield must fail terminal identity validation."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, True
        shard.write_bytes(b"MALICIOUS REPLACEMENT")

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert shard.read_bytes() == b"MALICIOUS REPLACEMENT"
    assert any(
        check.location == str(shard)
        and check.details.get("reason") == "shard_target_recreated_after_scan"
        and check.details.get("scan_outcome_reason") == "shard_boundary_changed"
        for check in result.checks
    )


def test_scan_model_streaming_rejects_relinked_program_deleted_shard(tmp_path: Path) -> None:
    """A retained hard link cannot restore a program-deleted shard as trusted."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    original_bytes = struct.pack("<Q", len(header)) + header
    shard.write_bytes(original_bytes)
    hidden_link = tmp_path / "retained-shard.bin"
    try:
        os.link(shard, hidden_link)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    def shard_stream() -> Iterator[tuple[Path, bool]]:
        yield shard, True
        hidden_link.write_bytes(b"X" * len(original_bytes))
        os.link(hidden_link, shard)

    result = scan_model_streaming(
        file_generator=shard_stream(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert shard.read_bytes() == b"X" * len(original_bytes)
    assert any(
        check.location == str(shard)
        and check.details.get("reason") == "shard_target_recreated_after_scan"
        and check.details.get("scan_outcome_reason") == "shard_boundary_changed"
        for check in result.checks
    )


def test_scan_model_streaming_preserves_max_total_size_failure_after_shard_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completing a shard family must not erase an independent aggregate size failure."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"modelaudit_stream_part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard_path)

    monkeypatch.setattr("modelaudit.core.tempfile.gettempdir", lambda: str(tmp_path))
    max_total_size = sum(shard.stat().st_size for shard in shards) - 1
    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        max_total_size=max_total_size,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
    assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)
    assert any(issue.details.get("max_total_size") == max_total_size for issue in result.issues)
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_selected_safetensors_reconciles_pickle_inconclusive_overlap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Explicit SafeTensors streaming should not keep stale shard gaps from an excluded pickle probe."""
    header = b'{"__metadata__":{"format":"pt"}}'
    original_detect_file_format = detect_file_format
    original_detect_file_format_from_magic = detect_file_format_from_magic

    def fake_detect_file_format(path: str) -> str:
        if path.endswith("model-00002-of-00002.safetensors"):
            return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        return original_detect_file_format(path)

    def fake_detect_file_format_from_magic(path: str) -> str:
        if path.endswith("model-00002-of-00002.safetensors"):
            return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        return original_detect_file_format_from_magic(path)

    monkeypatch.setattr("modelaudit.core.detect_file_format", fake_detect_file_format)
    monkeypatch.setattr("modelaudit.core.detect_file_format_from_magic", fake_detect_file_format_from_magic)
    monkeypatch.setattr("modelaudit.core.tempfile.gettempdir", lambda: str(tmp_path))

    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"modelaudit_stream_part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard_path)

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
    assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)
    assert all(
        "missing_model_shards" not in metadata.model_dump().get("scan_outcome_reasons", [])
        for metadata in result.file_metadata.values()
    )


def test_selected_safetensors_overlap_scans_malicious_peer_shard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Resolving a representative overlap must retain advanced family expansion."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = b'{"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    shards = [
        tmp_path / "model-00001-of-00002.safetensors",
        tmp_path / "model-00002-of-00002.safetensors",
    ]
    shards[0].write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
    shards[1].write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header)
    original_detect_file_format = detect_file_format
    original_detect_file_format_from_magic = detect_file_format_from_magic

    def fake_detect_file_format(path: str) -> str:
        return (
            PICKLE_ROUTING_INCONCLUSIVE_FORMAT if path.endswith(shards[0].name) else original_detect_file_format(path)
        )

    def fake_detect_file_format_from_magic(path: str) -> str:
        return (
            PICKLE_ROUTING_INCONCLUSIVE_FORMAT
            if path.endswith(shards[0].name)
            else original_detect_file_format_from_magic(path)
        )

    monkeypatch.setattr("modelaudit.core.detect_file_format", fake_detect_file_format)
    monkeypatch.setattr("modelaudit.core.detect_file_format_from_magic", fake_detect_file_format_from_magic)

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.files_scanned == 2
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert determine_exit_code(result) == 1
    assert result.bytes_scanned == sum(shard.stat().st_size for shard in shards)


def test_scan_model_streaming_total_one_mixed_base_family_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A streamed total-1 SafeTensors family cannot contain both zero- and one-based members."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = b'{"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    shards: list[Path] = []
    for shard_index in (0, 1):
        shard_dir = tmp_path / f"modelaudit_stream_part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00001.safetensors"
        header = malicious_header if shard_index == 1 else safe_header
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard_path)

    def run_scan() -> Any:
        return scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:model-a",
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
        )

    monkeypatch.setattr("modelaudit.core.tempfile.gettempdir", lambda: str(tmp_path))
    result = run_scan()
    cached_result = run_scan()

    coverage_check = next(
        check for check in result.checks if check.details.get("scan_outcome_reason") == "unexpected_model_shards"
    )
    assert coverage_check.status == CheckStatus.FAILED
    assert "outside the expected family inventory" in coverage_check.message
    assert coverage_check.details["scan_outcome"] == "inconclusive"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert cached_result.success is False
    assert determine_exit_code(cached_result) == 2
    assert "unexpected_model_shards" in result.file_metadata[str(shards[0])].model_dump().get(
        "scan_outcome_reasons", []
    )


def test_scan_model_streaming_total_one_zero_based_without_index_scans_payload(tmp_path: Path) -> None:
    """Fail-closed zero-based coverage must not suppress payload findings."""
    malicious_header = b'{"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    shard = tmp_path / "model-00000-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header)

    result = scan_model_streaming(
        file_generator=iter([(shard, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(check.details.get("scan_outcome_reason") == "unexpected_model_shards" for check in result.checks)
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_total_one_duplicate_index_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One trusted family cannot contain two sources for its only shard index."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shards: list[Path] = []
    for source_number in range(2):
        shard_dir = tmp_path / f"modelaudit_stream_source-{source_number}"
        shard_dir.mkdir(mode=0o700)
        shard = shard_dir / "model-00001-of-00001.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
        shards.append(shard)

    monkeypatch.setattr("modelaudit.core.tempfile.gettempdir", lambda: str(tmp_path))
    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    coverage_check = next(
        check for check in result.checks if check.details.get("scan_outcome_reason") == "unexpected_model_shards"
    )
    assert coverage_check.status == CheckStatus.FAILED
    assert coverage_check.details["unexpected_shard_count"] == 1


@pytest.mark.parametrize(
    "index_payload, expected_reason",
    [
        ("{not-json", "unvalidated_model_shards"),
        (
            json.dumps({"weight_map": {"tensor": "model-00001-of-00001.safetensors"}}),
            "unexpected_model_shards",
        ),
    ],
    ids=["malformed", "different-indexed-shard"],
)
def test_scan_model_streaming_total_one_consults_authoritative_index(
    tmp_path: Path,
    index_payload: str,
    expected_reason: str,
) -> None:
    """Streaming total-one scans must preserve local index fail-closed coverage."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00000-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    (tmp_path / "model.safetensors.index.json").write_text(index_payload, encoding="utf-8")

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(str(tmp_path)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        skip_file_types=True,
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        expected_reason in metadata.model_dump().get("scan_outcome_reasons", [])
        for metadata in result.file_metadata.values()
    )


@pytest.mark.parametrize(
    "authority_case",
    ["byte-limit", "token-limit", "hardlink-alias", "identity-cap", "broken-targets"],
)
def test_scan_model_streaming_rejects_indeterminate_ancestor_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_case: str,
) -> None:
    """Terminal streaming reconciliation must retain bounded and alias authority."""
    from modelaudit.utils.file import handlers as handlers_module

    header = b'{"__metadata__":{"format":"pt"}}'
    selected_dir = tmp_path / "aa"
    omitted_dir = tmp_path / "cc"
    selected_dir.mkdir()
    omitted_dir.mkdir()
    selected = [selected_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
    omitted = omitted_dir / "model-00002-of-00002.safetensors"
    for shard in (*selected, omitted):
        shard.write_bytes(struct.pack("<Q", len(header)) + header)
    weight_map = {
        "selected": selected[0].relative_to(tmp_path).as_posix(),
        "omitted": omitted.relative_to(tmp_path).as_posix(),
    }
    index_path = tmp_path / "model.safetensors.index.json"
    if authority_case == "byte-limit":
        create_resource_limited_safetensors_index(
            index_path,
            weight_map,
            max_bytes=handlers_module.MAX_SAFETENSORS_SHARD_INDEX_BYTES,
        )
    elif authority_case == "token-limit":
        create_resource_limited_safetensors_index(
            index_path,
            weight_map,
            max_tokens=handlers_module.MAX_SAFETENSORS_SHARD_INDEX_JSON_TOKENS,
        )
    elif authority_case == "hardlink-alias":
        alias_dir = tmp_path / "aliases"
        alias_dir.mkdir()
        alias = alias_dir / selected[0].name
        os.link(selected[0], alias)
        weight_map["selected"] = alias.relative_to(tmp_path).as_posix()
        index_path.write_text(json.dumps({"weight_map": weight_map}), encoding="utf-8")
    else:
        if authority_case == "broken-targets" and os.name == "nt":
            pytest.skip("requires portable symlink creation")
        base_dir = tmp_path / "base"
        base_dir.mkdir()
        base_targets = [base_dir / f"model-{index:05d}-of-00002.safetensors" for index in (1, 2)]
        for target in base_targets:
            if authority_case == "broken-targets":
                target.symlink_to(base_dir / f"missing-{target.name}")
            else:
                target.write_bytes(struct.pack("<Q", len(header)) + header)
        weight_map = {
            "selected": base_targets[0].relative_to(tmp_path).as_posix(),
            "omitted": base_targets[1].relative_to(tmp_path).as_posix(),
        }
        if authority_case == "identity-cap":
            monkeypatch.setattr(handlers_module, "MAX_SAFETENSORS_SHARD_ALIAS_IDENTITY_CHECKS", 1)
        index_path.write_text(json.dumps({"weight_map": weight_map}), encoding="utf-8")

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(selected) - 1) for index, shard in enumerate(selected)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        skip_file_types=True,
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    outcome_reasons = {check.details.get("scan_outcome_reason") for check in result.checks}
    expected_reason = "unexpected_model_shards" if authority_case == "hardlink-alias" else "shard_boundary_changed"
    assert expected_reason in outcome_reasons, outcome_reasons


def test_scan_model_streaming_total_one_rebases_pinned_result_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Descriptor-bound scans must report the original streamed shard path."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00000-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps({"weight_map": {"tensor": shard.name}}),
        encoding="utf-8",
    )
    pinned_dir = tmp_path.parent / f"{tmp_path.name}-alternate-pinned-path"
    pinned_dir.mkdir()

    @contextmanager
    def alternate_pinned_path(
        _resolved_path: str,
        _target: dict[str, int | str],
        **kwargs: Any,
    ) -> Iterator[Any]:
        source_fd = kwargs.get("source_fd")
        assert isinstance(source_fd, int)
        source_size = os.fstat(source_fd).st_size
        logical_path = Path(kwargs.get("logical_path") or _resolved_path)
        current_pinned_path = pinned_dir / logical_path.name
        pinned_dir.mkdir(exist_ok=True)
        current_pinned_path.write_bytes(os.pread(source_fd, source_size, 0))
        try:
            yield SimpleNamespace(path=str(current_pinned_path), changed_during_scan=False)
        finally:
            current_pinned_path.unlink(missing_ok=True)
            if pinned_dir.exists() and not any(pinned_dir.iterdir()):
                pinned_dir.rmdir()

    monkeypatch.setattr("modelaudit.core._pinned_shard_scan_path", alternate_pinned_path)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(str(tmp_path)),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        skip_file_types=True,
        cache_enabled=False,
        scanners=["safetensors"],
    )

    shard_detection = next(check for check in result.checks if check.name == "Sharded Model Detection")
    path_checks = [check for check in result.checks if check.name in {"Path Exists", "Path Readable"}]
    assert shard_detection.details["shards"] == [str(shard)]
    assert path_checks
    assert all(check.details["path"] == str(shard) for check in path_checks)
    assert result.success is True
    assert determine_exit_code(result) == 0


@pytest.mark.skipif(os.name == "nt", reason="Windows open-handle pinning prevents source replacement")
def test_scan_model_streaming_total_one_source_change_after_pinning_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A total-one source replaced after its pinned scan cannot reconcile cleanly."""
    header = b'{"__metadata__":{"format":"pt"}}'
    replacement_header = b'{"__metadata__":{"format":"tf"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    replacement = tmp_path / "replacement.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    replacement.write_bytes(struct.pack("<Q", len(replacement_header)) + replacement_header)
    real_scan_file = scan_file

    def replace_source_after_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        result = real_scan_file(path, config=config)
        replacement.replace(shard)
        return result

    monkeypatch.setattr("modelaudit.core.scan_file", replace_source_after_scan)

    result = scan_model_streaming(
        file_generator=iter([(shard, True)]),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


def test_scan_model_streaming_total_one_ctime_change_after_pinning_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-target ctime change after unpinning must invalidate reconciliation."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)
    real_snapshot = _snapshot_validated_shard_target
    source_snapshot_calls = 0

    def snapshot_with_final_ctime_change(path: str, *args: Any, **kwargs: Any) -> Any:
        nonlocal source_snapshot_calls
        snapshot = real_snapshot(path, *args, **kwargs)
        if Path(path) == shard:
            source_snapshot_calls += 1
            if source_snapshot_calls == 4 and snapshot:
                target = next(iter(snapshot.values()))
                ctime_ns = target.get("ctime_ns")
                assert isinstance(ctime_ns, int)
                target["ctime_ns"] = ctime_ns + 1
        return snapshot

    monkeypatch.setattr("modelaudit.core._snapshot_validated_shard_target", snapshot_with_final_ctime_change)

    result = scan_model_streaming(
        file_generator=iter([(shard, True)]),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert source_snapshot_calls >= 4
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


def test_scan_model_streaming_total_one_pinned_descriptor_change_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A descriptor-observed content change must invalidate an otherwise stable source path."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(struct.pack("<Q", len(header)) + header)

    @contextmanager
    def changed_pinned_path(
        resolved_path: str,
        target: dict[str, int | str],
        **kwargs: Any,
    ) -> Iterator[Any]:
        with _pinned_shard_scan_path(resolved_path, target, **kwargs) as pinned_scan:
            yield pinned_scan
        pinned_scan.changed_during_scan = True

    monkeypatch.setattr("modelaudit.core._pinned_shard_scan_path", changed_pinned_path)

    result = scan_model_streaming(
        file_generator=iter([(shard, True)]),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "shard_boundary_changed" for check in result.checks)


@pytest.mark.parametrize("start_index", [0, 1], ids=["zero-based", "one-based"])
def test_scan_model_streaming_preserves_malicious_cross_directory_shard_findings(
    start_index: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coverage reconciliation must not suppress a malicious finding from a complete family."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = (
        b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    )
    shards: list[Path] = []
    for offset, shard_index in enumerate(range(start_index, start_index + 3)):
        shard_dir = tmp_path / f"modelaudit_stream_part-{shard_index}"
        shard_dir.mkdir(mode=0o700)
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
        header = malicious_header if offset == 1 else safe_header
        tensor_data = b"\x00" if offset == 1 else b""
        shard_path.write_bytes(struct.pack("<Q", len(header)) + header + tensor_data)
        shards.append(shard_path)

    monkeypatch.setattr("modelaudit.core.tempfile.gettempdir", lambda: str(tmp_path))
    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.files_scanned == 3
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert determine_exit_code(result) == (2 if start_index == 0 else 1)
    if start_index == 0:
        assert any(check.details.get("scan_outcome_reason") == "unexpected_model_shards" for check in result.checks)
        assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
    else:
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)


def test_streaming_shard_alias_aba_cannot_hide_malicious_content() -> None:
    """Scanning must stay bound to the shard target selected before inspection."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = (
        b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    )
    with ExitStack() as stack:
        shards: list[Path] = []
        swaps: dict[str, tuple[Path, Path, Path]] = {}
        for shard_index in range(1, 3):
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            malicious = root / "malicious.safetensors"
            safe = root / "safe.safetensors"
            malicious.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header + b"\0")
            safe.write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
            alias = root / f"model-{shard_index:05d}-of-00002.safetensors"
            alias.symlink_to(malicious.name)
            shards.append(alias)
            swaps[str(alias)] = (alias, malicious, safe)

        real_scan_file = scan_file

        def swap_during_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            entry = swaps.get(path)
            if entry is None:
                return real_scan_file(path, config=config)
            alias, _malicious, safe = entry
            alias.unlink()
            alias.symlink_to(safe.name)
            try:
                return real_scan_file(path, config=config)
            finally:
                alias.unlink()
                alias.symlink_to("malicious.safetensors")

        with patch("modelaudit.core.scan_file", side_effect=swap_during_scan):
            result = scan_model_streaming(
                file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert all(shard.resolve().name == "malicious.safetensors" for shard in shards)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(result) == 1


def test_streaming_total_one_shard_alias_aba_cannot_hide_malicious_content(tmp_path: Path) -> None:
    """Total-one streaming remains bound to the shard target selected before scanning."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = b'{"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    malicious = tmp_path / "malicious.safetensors"
    safe = tmp_path / "safe.safetensors"
    malicious.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header)
    safe.write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
    alias = tmp_path / "model-00001-of-00001.safetensors"
    alias.symlink_to(malicious.name)
    real_scan_file = scan_file

    def swap_during_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        if path != str(alias):
            return real_scan_file(path, config=config)
        alias.unlink()
        alias.symlink_to(safe.name)
        try:
            return real_scan_file(path, config=config)
        finally:
            alias.unlink()
            alias.symlink_to(malicious.name)

    with patch("modelaudit.core.scan_file", side_effect=swap_during_scan):
        result = scan_model_streaming(
            file_generator=iter([(alias, True)]),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:model-a",
            cache_enabled=False,
        )

    assert alias.resolve() == malicious
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert determine_exit_code(result) == 1


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir() and not Path("/dev/fd").is_dir(),
    reason="descriptor-relative scan paths are unavailable",
)
def test_streaming_shard_staging_directory_aba_cannot_hide_malicious_content() -> None:
    """Replacing the staging pathname cannot redirect a descriptor-bound shard scan."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = (
        b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    )
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 3):
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard = root / f"model-{shard_index:05d}-of-00002.safetensors"
            shard.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header + b"\0")
            shards.append(shard)

        real_scan_file = scan_file

        def exchange_staging_directory(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            scan_path = Path(path)
            if not path.startswith(("/proc/self/fd/", "/dev/fd/")):
                return real_scan_file(path, config=config)
            staging_directory = Path(os.readlink(scan_path.parent))
            preserved_directory = staging_directory.with_name(f"{staging_directory.name}.preserved")
            staging_directory.rename(preserved_directory)
            staging_directory.mkdir(mode=0o700)
            benign_path = staging_directory / scan_path.name
            benign_path.write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
            try:
                return real_scan_file(path, config=config)
            finally:
                shutil.rmtree(staging_directory)
                preserved_directory.rename(staging_directory)

        with patch("modelaudit.core.scan_file", side_effect=exchange_staging_directory):
            result = scan_model_streaming(
                file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert all(b"SECRET_METADATA_TOKEN" in shard.read_bytes() for shard in shards)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(result) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor pinning does not require hard links")
def test_streaming_shard_scan_does_not_require_hard_link_support() -> None:
    """Descriptor-bound shard scans must work on filesystems without hard links."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard)

        with patch("modelaudit.utils.file.handlers.os.link", side_effect=OSError("hard links unavailable")):
            result = scan_model_streaming(
                file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert result.success is True
        assert result.has_errors is False
        assert determine_exit_code(result) == 0
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses open-handle hard-link pinning")
def test_streaming_shard_pin_failure_is_explicit_operational_error() -> None:
    """Platforms without descriptor paths must report the pin failure explicitly."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as shard_directory:
        shard = Path(shard_directory) / "model-00001-of-00002.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)

        with patch("modelaudit.utils.file.handlers._descriptor_path_for_open_file", return_value=None):
            result = scan_model_streaming(
                file_generator=iter([(shard, True)]),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert result.success is False
        assert result.has_errors is True
        assert determine_exit_code(result) == 2
        assert any(check.details.get("scan_outcome_reason") == "shard_pin_unavailable" for check in result.checks)
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)


def test_scan_model_streaming_does_not_reconcile_distinct_remote_model_directories() -> None:
    """One remote stream must not combine complementary shards from distinct logical parents."""
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as staging_directory:
        staging_root = Path(staging_directory)
        shards: list[Path] = []
        for shard_index, model_id in ((1, "model-a"), (2, "model-b")):
            shard_dir = staging_root / model_id
            shard_dir.mkdir()
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            header = f'{{"__metadata__":{{"format":"pt","model_id":"{model_id}"}}}}'.encode()
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:remote-repo",
            cache_enabled=False,
        )

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)


def test_scan_model_streaming_keeps_hf_snapshot_symlink_families_separate(
    requires_symlinks: None,
) -> None:
    """Logical model directories must not merge through one shared HF blobs parent."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as staging_directory:
        staging_root = Path(staging_directory)
        blobs_dir = staging_root / "huggingface" / "models--org--repo" / "blobs"
        blobs_dir.mkdir(parents=True)
        shards: list[Path] = []
        for shard_index, model_id in ((1, "model-a"), (2, "model-b")):
            blob_path = blobs_dir / f"blob-{shard_index}"
            blob_path.write_bytes(struct.pack("<Q", len(header)) + header)
            logical_dir = staging_root / "snapshots" / model_id
            logical_dir.mkdir(parents=True)
            shard_path = logical_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.symlink_to(blob_path)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:remote-repo",
            cache_enabled=False,
        )

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)


def test_stream_staging_family_groups_are_scoped_to_nested_logical_parent() -> None:
    """Nested trusted staging paths must not combine unrelated remote model directories."""
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as staging_directory:
        staging_root = Path(staging_directory)
        snapshots = []
        for shard_index, model_id in ((1, "model-a"), (2, "model-b")):
            shard_dir = staging_root / "remote" / model_id
            shard_dir.mkdir(parents=True)
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            snapshots.append(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:remote-repo",
                    family_group_policy="stream_staging",
                )
            )

    family_groups = [next(iter(snapshot.values())).get("family_group") for snapshot in snapshots]
    assert all(isinstance(family_group, str) for family_group in family_groups)
    assert family_groups[0] != family_groups[1]


def test_stream_staging_complete_nested_families_do_not_collide(tmp_path: Path) -> None:
    """Complete same-named families in separate logical directories remain independent."""
    header = b'{"__metadata__":{"format":"pt"}}'
    staging_root = tmp_path / "stream-root"
    staging_root.mkdir(mode=0o700)
    shards: list[Path] = []
    for model_id in ("base", "adapter"):
        logical_dir = staging_root / "remote" / model_id
        logical_dir.mkdir(parents=True)
        for shard_index in (1, 2):
            shard_path = logical_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard_path)

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:remote-repo",
        _trusted_shard_family_root=_make_trusted_stream_shard_root(str(staging_root)),
        cache_enabled=False,
        scanners=["safetensors"],
    )

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any(check.details.get("scan_outcome_reason") == "unexpected_model_shards" for check in result.checks)


def test_stream_staging_family_group_rejects_nested_prefix_lookalike(tmp_path: Path) -> None:
    """A prefixed directory outside the direct temp root must not gain trusted grouping."""
    shard_dir = tmp_path / "modelaudit_stream_untrusted" / "remote" / "model-a"
    shard_dir.mkdir(parents=True)
    shard_path = shard_dir / "model-00001-of-00002.safetensors"
    shard_path.write_bytes(b"shard")

    snapshot = _snapshot_validated_shard_target(
        str(shard_path),
        family_group="attacker-controlled",
        family_group_policy="stream_staging",
    )

    assert snapshot
    assert "family_group" not in next(iter(snapshot.values()))


def test_stream_staging_family_group_rejects_plain_persistent_root(tmp_path: Path) -> None:
    """A caller-provided path must not act as a trusted persistent stream root."""
    shard_path = tmp_path / "model-00001-of-00002.safetensors"
    shard_path.write_bytes(b"shard")

    snapshot = _snapshot_validated_shard_target(
        str(shard_path),
        family_group="attacker-controlled",
        family_group_policy="stream_staging",
        trusted_root_marker=tmp_path,
    )

    assert snapshot
    assert "family_group" not in next(iter(snapshot.values()))


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes are required")
def test_stream_staging_family_group_rejects_publicly_writable_temp_root(tmp_path: Path) -> None:
    """A forgeable temp prefix must not authorize a publicly mutable shard family."""
    shard_dir = Path(tempfile.gettempdir()) / f"modelaudit_stream_public_{uuid.uuid4().hex}"
    shard_dir.mkdir(mode=0o777)
    shard_dir.chmod(0o777)
    try:
        shard_path = shard_dir / "model-00001-of-00002.safetensors"
        shard_path.write_bytes(b"shard")

        snapshot = _snapshot_validated_shard_target(
            str(shard_path),
            family_group="attacker-controlled",
            family_group_policy="stream_staging",
        )

        assert snapshot
        assert "family_group" not in next(iter(snapshot.values()))
    finally:
        shutil.rmtree(shard_dir)


def test_cross_directory_shard_reconciliation_bounds_untrusted_expected_total() -> None:
    """An attacker-controlled shard count must not allocate the declared range."""
    script = "\n".join(
        (
            "from modelaudit.core import _complete_validated_shard_family_sources",
            "total = '9' * 100",
            "source = f'/tmp/part-1/model-00001-of-{total}.safetensors'",
            "targets = {source: {'resolved_path': '/tmp/one', 'device': 1, 'inode': 1}}",
            "assert _complete_validated_shard_family_sources(targets) == set()",
        )
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0, completed.stderr


def test_cross_directory_shard_reconciliation_distinguishes_reused_inode_generations() -> None:
    """Sequential streamed files may legitimately reuse an inode after deletion."""
    shard_one = "/tmp/part-1/model-00001-of-00002.safetensors"
    shard_two = "/tmp/part-2/model-00002-of-00002.safetensors"
    targets: dict[str, dict[str, int | str]] = {
        shard_one: {
            "resolved_path": "/tmp/part-1/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 100,
            "ctime_ns": 100,
            "nlink": 1,
            "family_group": "stream-staging:test",
        },
        shard_two: {
            "resolved_path": "/tmp/part-2/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 200,
            "ctime_ns": 200,
            "nlink": 1,
            "family_group": "stream-staging:test",
        },
    }

    expected_sources = {
        os.path.normcase(os.path.normpath(os.path.abspath(shard_one))),
        os.path.normcase(os.path.normpath(os.path.abspath(shard_two))),
    }
    assert _complete_validated_shard_family_sources(targets) == expected_sources


def test_cross_directory_shard_reconciliation_rejects_sequential_hardlinks() -> None:
    """Deleting one hardlink must not make its peer look like a reused inode generation."""
    shard_one = "/tmp/part-1/model-00001-of-00002.safetensors"
    shard_two = "/tmp/part-2/model-00002-of-00002.safetensors"
    targets: dict[str, dict[str, int | str]] = {
        shard_one: {
            "resolved_path": "/tmp/part-1/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 100,
            "ctime_ns": 100,
            "nlink": 2,
            "family_group": "stream-staging:test",
        },
        shard_two: {
            "resolved_path": "/tmp/part-2/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 100,
            "ctime_ns": 200,
            "nlink": 1,
            "family_group": "stream-staging:test",
        },
    }

    assert _complete_validated_shard_family_sources(targets) == set()


def test_cross_directory_shard_reconciliation_updates_stale_scalar_reason() -> None:
    """Removing one reason must leave scalar outcome metadata aligned with the remaining reason."""
    with ExitStack() as stack:
        shards: list[Path] = []
        validated_targets = {}
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            shards.append(shard_path)
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )

        result = create_initial_audit_result()
        result.success = False
        for shard in shards:
            result.file_metadata[str(shard)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards", "shard_scan_error"],
            )

        assert _reconcile_cross_directory_shard_coverage(result, validated_targets) is True
        assert result.success is False
        for metadata_model in result.file_metadata.values():
            metadata = metadata_model.model_dump()
            assert metadata["scan_outcome_reasons"] == ["shard_scan_error"]
            assert metadata["scan_outcome_reason"] == "shard_scan_error"
            assert metadata["analysis_incomplete"] is True
            assert metadata["scan_outcome"] == "inconclusive"


def test_cross_directory_shard_reconciliation_preserves_secondary_coverage_failure() -> None:
    """Disproving missing peers must retain another incomplete-coverage explanation."""
    with ExitStack() as stack:
        shards: list[Path] = []
        validated_targets = {}
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            shards.append(shard_path)
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )

        source_result = ScanResult(scanner_name="safetensors")
        source_result.add_check(
            name="Sharded Model Coverage Check",
            passed=False,
            message="Missing 1 expected model shard(s); scan coverage is incomplete.",
            severity=IssueSeverity.INFO,
            location=str(shards[0]),
            details={
                "missing_shard_count": 1,
                "unreadable_shard_count": 1,
                "unreadable_shards": [str(shards[0].with_name("unreadable.safetensors"))],
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "missing_model_shards",
                "scan_outcome_reasons": ["missing_model_shards", "unreadable_model_shards"],
                "scan_outcome_message": "Missing model shards prevented complete analysis.",
            },
        )
        result = create_initial_audit_result()
        result.success = False
        result.checks = list(source_result.checks)
        result.issues = list(source_result.issues)
        for shard in shards:
            result.file_metadata[str(shard)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards", "unreadable_model_shards"],
            )

        assert _reconcile_cross_directory_shard_coverage(result, validated_targets) is True
        assert result.success is False
        assert len(result.checks) == 1
        assert result.checks[0].details["scan_outcome_reason"] == "unreadable_model_shards"
        assert result.checks[0].details["scan_outcome_reasons"] == ["unreadable_model_shards"]
        assert "scan_outcome_message" not in result.checks[0].details
        assert "Unable to read 1 model shard(s)" in result.checks[0].message
        assert len(result.issues) == 1
        assert result.issues[0].details["scan_outcome_reason"] == "unreadable_model_shards"
        assert result.issues[0].details["scan_outcome_reasons"] == ["unreadable_model_shards"]
        assert "scan_outcome_message" not in result.issues[0].details
        assert "Unable to read 1 model shard(s)" in result.issues[0].message


def test_cross_directory_shard_reconciliation_clears_stale_outcome_message() -> None:
    """Removing the final inconclusive reason must remove its stale explanation."""
    with ExitStack() as stack:
        shards: list[Path] = []
        validated_targets = {}
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            shards.append(shard_path)
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )

        result = create_initial_audit_result()
        result.success = False
        for shard in shards:
            result.file_metadata[str(shard)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
                scan_outcome_message="Scan analysis incomplete; failed closed because full coverage was not available.",
            )

        assert _reconcile_cross_directory_shard_coverage(result, validated_targets) is True
        assert result.success is True
        for metadata_model in result.file_metadata.values():
            metadata = metadata_model.model_dump(exclude_none=True)
            assert "analysis_incomplete" not in metadata
            assert "scan_outcome" not in metadata
            assert "scan_outcome_reason" not in metadata
            assert "scan_outcome_reasons" not in metadata
            assert "scan_outcome_message" not in metadata


def test_cross_directory_shard_reconciliation_clears_stale_operational_error_state() -> None:
    """A disproven missing-shard failure must not leave the aggregate at exit code 2."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
                missing_shard_errors_only=True,
            )
            is True
        )
        assert result.has_errors is False
        assert result.success is True
        assert determine_exit_code(result) == 0


def test_cross_directory_shard_reconciliation_preserves_retained_aggregate_failure() -> None:
    """A retained incomplete-analysis issue must keep the aggregate at exit code 2."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )
        result.issues.append(
            Issue(
                message="Total scan size limit exceeded",
                severity=IssueSeverity.INFO,
                details={"max_total_size": 1, "analysis_incomplete": True},
            )
        )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
                missing_shard_errors_only=True,
            )
            is True
        )
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_cross_directory_shard_reconciliation_preserves_unattributed_runtime_failure() -> None:
    """Caller provenance must preserve a runtime failure without durable result evidence."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
            )
            is True
        )
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_cross_directory_shard_reconciliation_preserves_independent_operational_error() -> None:
    """Clearing a shard gap must retain an unrelated explicit operational failure."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 3
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )
        result.file_metadata["failed-download"] = FileMetadataModel(
            operational_error=True,
            operational_error_reason="download_failed",
        )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
                missing_shard_errors_only=True,
            )
            is True
        )
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_scan_model_streaming_does_not_reconcile_duplicate_shard_targets(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Two shard indices resolving to one target must remain incomplete."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shared_target = tmp_path / "shared-target"
    shared_target.write_bytes(struct.pack("<Q", len(header)) + header)
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"part-{shard_index}"
        shard_dir.mkdir()
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.symlink_to(shared_target)
        shards.append(shard_path)

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)


def _write_openvino_pair(model_dir: Path, *, stem: str = "model", xml_content: str | None = None) -> tuple[Path, Path]:
    xml_path = model_dir / f"{stem}.xml"
    bin_path = model_dir / f"{stem}.bin"
    xml_path.write_text(xml_content or "<net version='10'></net>", encoding="utf-8")
    bin_path.write_bytes(b"\x00" * 16)
    return xml_path, bin_path


def test_scan_model_streaming_preserves_openvino_companion_when_bin_arrives_first(tmp_path: Path) -> None:
    """A streamed OpenVINO .bin sidecar must not be deleted before its XML owner is scanned."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)

    result = scan_model_streaming(
        file_generator=iter([(bin_path, False), (xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 0
    assert "pytorch_binary" not in result.scanner_names
    assert not xml_path.exists()
    assert not bin_path.exists()
    assert result.file_metadata[str(xml_path)]["bin_size"] == 16
    assert not any(check.rule_code == "S701" for check in result.checks)
    assert not any(check.rule_code == "S901" for check in result.checks)


def test_scan_model_streaming_preserves_executable_openvino_bin_sidecar_route(tmp_path: Path) -> None:
    """Executable same-stem .bin content must not be consumed only by OpenVINO XML scanning."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    create_mock_pytorch_zip(bin_path, malicious=True)

    result = scan_model_streaming(
        file_generator=iter([(bin_path, False), (xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        skip_file_types=True,
    )

    assert determine_exit_code(result) == 1
    assert result.files_scanned == 2
    assert "openvino" in result.scanner_names
    assert "pytorch_zip" in result.scanner_names
    assert not xml_path.exists()
    assert not bin_path.exists()
    assert result.file_metadata[str(xml_path)]["bin_size"] > 0
    assert any(
        issue.location and str(bin_path) in issue.location and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


def test_scan_model_streaming_executable_openvino_sidecar_counts_once_for_max_total_size(tmp_path: Path) -> None:
    """Independently routed OpenVINO .bin sidecars must not be double-counted by XML accounting."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    create_mock_pytorch_zip(bin_path, malicious=False)
    max_total_size = xml_path.stat().st_size + bin_path.stat().st_size

    result = scan_model_streaming(
        file_generator=iter([(bin_path, False), (xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        skip_file_types=True,
        max_total_size=max_total_size,
    )

    assert determine_exit_code(result) == 0
    assert result.success is True
    assert result.files_scanned == 2
    assert "openvino" in result.scanner_names
    assert "pytorch_zip" in result.scanner_names
    assert result.bytes_scanned <= max_total_size
    assert result.file_metadata[str(xml_path)]["bin_size"] == bin_path.stat().st_size
    assert not any("Total scan size limit exceeded" in issue.message for issue in result.issues)


def test_scan_model_streaming_keeps_benign_openvino_sidecar_accounting(tmp_path: Path) -> None:
    """Benign OpenVINO weights remain accounted without standalone .bin scanner routing."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    expected_hash = compute_aggregate_hash([compute_sha256_hash(xml_path), compute_sha256_hash(bin_path)])

    result = scan_model_streaming(
        file_generator=iter([(bin_path, False), (xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        skip_file_types=True,
    )

    assert determine_exit_code(result) == 0
    assert result.scanner_names == ["openvino"]
    assert result.file_metadata[str(xml_path)]["bin_size"] == bin_path.stat().st_size
    assert result.bytes_scanned == xml_path.stat().st_size + bin_path.stat().st_size
    assert result.content_hash == expected_hash


def test_scan_model_streaming_preserves_path_sensitive_openvino_companions_with_duplicate_basenames(
    tmp_path: Path,
) -> None:
    """Duplicate basenames in nested dirs must preserve and delete each exact sidecar."""
    encoder_dir = tmp_path / "models" / "encoder"
    decoder_dir = tmp_path / "models" / "decoder"
    encoder_dir.mkdir(parents=True)
    decoder_dir.mkdir(parents=True)
    encoder_xml, encoder_bin = _write_openvino_pair(encoder_dir)
    decoder_xml, decoder_bin = _write_openvino_pair(decoder_dir)
    encoder_bin.write_bytes(b"e" * 11)
    decoder_bin.write_bytes(b"d" * 23)

    result = scan_model_streaming(
        file_generator=iter(
            [
                (encoder_bin, False),
                (decoder_bin, False),
                (encoder_xml, False),
                (decoder_xml, True),
            ]
        ),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 0
    assert "pytorch_binary" not in result.scanner_names
    assert not encoder_xml.exists()
    assert not encoder_bin.exists()
    assert not decoder_xml.exists()
    assert not decoder_bin.exists()
    assert result.file_metadata[str(encoder_xml)]["bin_size"] == 11
    assert result.file_metadata[str(decoder_xml)]["bin_size"] == 23
    assert not any(check.rule_code == "S701" for check in result.checks)
    assert not any(check.rule_code == "S901" for check in result.checks)


def test_scan_model_streaming_openvino_xml_with_prefetched_companion(tmp_path: Path) -> None:
    """HF-style streaming can yield only XML after pre-staging the .bin companion."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 0
    assert result.scanner_names == ["openvino"]
    assert not xml_path.exists()
    assert not bin_path.exists()
    assert result.file_metadata[str(xml_path)]["bin_size"] == 16
    assert not any("weights file not found" in check.message.lower() for check in result.checks)


def test_scan_model_streaming_openvino_prefetched_companion_contributes_content_hash(tmp_path: Path) -> None:
    """A staged OpenVINO .bin sidecar must remain part of the streaming aggregate hash."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    expected_hash = compute_aggregate_hash([compute_sha256_hash(xml_path), compute_sha256_hash(bin_path)])

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 0
    assert result.content_hash == expected_hash


def test_scan_model_streaming_openvino_prefetched_companion_changes_content_hash(tmp_path: Path) -> None:
    """HF-style XML-only yields must include staged OpenVINO weights in the aggregate hash."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    first_result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=True,
    )

    bin_path.write_bytes(b"\x01" * 16)
    second_result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=True,
    )

    assert first_result.content_hash is not None
    assert second_result.content_hash is not None
    assert first_result.content_hash != second_result.content_hash


def test_scan_model_streaming_onnx_external_data_contributes_content_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged ONNX external_data sidecar must remain part of the streaming aggregate hash."""
    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_path.write_bytes(struct.pack("f", 1.0))
    expected_hash = compute_aggregate_hash([compute_sha256_hash(model_path), compute_sha256_hash(sidecar_path)])
    onnx = pytest.importorskip("onnx")
    monkeypatch.setattr(
        onnx,
        "load",
        lambda *_args, **_kwargs: pytest.fail("streaming sidecar discovery must not preload ONNX"),
    )

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert_only_onnx_external_schema_validation_skipped(result)
    assert result.content_hash == expected_hash

    sidecar_path.write_bytes(struct.pack("f", 2.0))
    changed_hash = compute_aggregate_hash([compute_sha256_hash(model_path), compute_sha256_hash(sidecar_path)])
    changed_result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert_only_onnx_external_schema_validation_skipped(changed_result)
    assert changed_result.content_hash == changed_hash
    assert changed_result.content_hash != result.content_hash


def test_streamed_onnx_sidecar_discovery_invokes_interrupt_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit import core
    from modelaudit.scanners import onnx_scanner

    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    onnx = pytest.importorskip("onnx")
    parsed_model = onnx.load_model_from_string(model_path.read_bytes())
    callback_invocations = 0

    def cancel() -> None:
        nonlocal callback_invocations
        callback_invocations += 1
        if callback_invocations == 3:
            raise KeyboardInterrupt

    def load_without_invoking_callback(
        _path: str,
        _file_size: int,
        _interrupt_check: Any,
        *,
        expected_stat: os.stat_result,
    ) -> Any:
        assert expected_stat.st_size == model_path.stat().st_size
        return parsed_model, object()

    monkeypatch.setattr(core, "check_interrupted", cancel)
    monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", load_without_invoking_callback)

    with pytest.raises(KeyboardInterrupt):
        core._streamed_onnx_external_data_hash_paths(model_path)
    assert callback_invocations == 3


def test_streamed_onnx_sidecar_discovery_honors_scan_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit import core
    from modelaudit.scanners import onnx_scanner

    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))

    def invoke_interrupt_check(
        _path: str,
        _file_size: int,
        interrupt_check: Any,
        *,
        expected_stat: os.stat_result,
    ) -> Any:
        assert expected_stat.st_size == model_path.stat().st_size
        interrupt_check()
        pytest.fail("expired ONNX discovery should stop before parsing")

    monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", invoke_interrupt_check)

    with pytest.raises(TimeoutError, match="external_data discovery exceeded"):
        core._streamed_onnx_external_data_hash_paths(model_path, deadline=time.time() - 1)


def test_scan_model_streaming_onnx_sidecar_discovery_enforces_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.scanners import onnx_scanner

    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))

    def delay_until_deadline(
        _path: str,
        _file_size: int,
        interrupt_check: Any,
        *,
        expected_stat: os.stat_result,
    ) -> Any:
        assert expected_stat.st_size == model_path.stat().st_size
        time.sleep(1.05)
        interrupt_check()
        pytest.fail("expired ONNX discovery should not return a parsed model")

    monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", delay_until_deadline)

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=1,
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert result.success is False
    assert result.has_errors is True
    assert result.content_hash is None


def test_scan_model_streaming_defers_hash_when_onnx_sidecar_discovery_is_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.scanners import onnx_scanner

    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_path.write_bytes(struct.pack("f", 1.0))

    def fail_bounded_discovery(*_args: Any, **_kwargs: Any) -> Any:
        raise onnx_scanner._OnnxStructureParseError(
            "retained_object_limit_exceeded",
            "bounded discovery exhausted its retained-object budget",
        )

    monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", fail_bounded_discovery)

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert result.content_hash is None


def test_scan_model_streaming_defers_file_backed_onnx_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.utils.helpers import file_hash as file_hash_module

    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_path.write_bytes(struct.pack("f", 1.0))
    hashed_paths: list[Path] = []

    def record_hash(path: Path) -> str:
        hashed_paths.append(path)
        return "a" * 64

    monkeypatch.setattr(file_hash_module, "compute_sha256_hash", record_hash)

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=True,
        scanners=["onnx"],
        skip_file_types=False,
        onnx_raw_detector_max_bytes=1,
    )

    assert result.content_hash is None
    assert hashed_paths == []
    assert result.bytes_scanned == model_path.stat().st_size + sidecar_path.stat().st_size
    assert result.file_metadata[str(model_path)]["onnx_structure_parse"]["parse_mode"] == "file_backed_structure"
    assert any(
        check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
        for check in result.checks
    )


def test_scan_model_streaming_onnx_external_data_refetch_does_not_duplicate_content_hash(
    tmp_path: Path,
) -> None:
    """A selected sidecar later re-fetched as ONNX context should stay one aggregate member."""
    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    model_payload = create_external_onnx_payload(tmp_path)
    sidecar_payload = struct.pack("f", 1.0)

    model_path.write_bytes(model_payload)
    sidecar_path.write_bytes(sidecar_payload)
    expected_hash = compute_aggregate_hash([compute_sha256_hash(sidecar_path), compute_sha256_hash(model_path)])
    model_path.unlink()
    sidecar_path.unlink()

    def refetched_sidecar_generator() -> Iterator[tuple[Path, bool]]:
        sidecar_path.write_bytes(sidecar_payload)
        yield sidecar_path, False
        model_path.write_bytes(model_payload)
        sidecar_path.write_bytes(sidecar_payload)
        yield model_path, True

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=1)
        result = scan_model_streaming(
            file_generator=refetched_sidecar_generator(),
            timeout=30,
            delete_after_scan=True,
            cache_enabled=False,
            scanners=["onnx"],
            skip_file_types=False,
        )

    assert result.content_hash == expected_hash
    assert result.bytes_scanned == 2
    assert mock_scan.call_args_list[0].args[0] == str(sidecar_path)
    assert mock_scan.call_args_list[1].args[0] == str(model_path)


def test_scan_model_streaming_onnx_external_data_counts_toward_max_total_size(tmp_path: Path) -> None:
    """Staged ONNX external_data sidecars must count against total streaming caps."""
    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    sidecar_size = 64
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_path.write_bytes(b"\x00" * sidecar_size)
    max_total_size = model_path.stat().st_size + sidecar_size - 1

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        max_total_size=max_total_size,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert determine_exit_code(result) == 2
    assert result.bytes_scanned > max_total_size
    assert result.bytes_scanned >= model_path.stat().st_size + sidecar_size
    assert result.content_hash is None
    assert any("Total scan size limit exceeded" in issue.message for issue in result.issues)


def test_scan_model_streaming_onnx_external_data_over_total_cap_skips_sidecar_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Oversized ONNX external_data context must not be read for aggregate hashing."""
    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    sidecar_size = 64
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_path.write_bytes(b"\x00" * sidecar_size)
    max_total_size = model_path.stat().st_size + sidecar_size - 1
    hashed_paths: list[Path] = []

    def track_hash(path: Path) -> str:
        hashed_paths.append(path)
        if path == sidecar_path:
            pytest.fail("streaming ONNX external_data sidecar must not be hashed past max_total_size")
        return "a" * 64

    monkeypatch.setattr("modelaudit.utils.helpers.file_hash.compute_sha256_hash", track_hash)

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        max_total_size=max_total_size,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert model_path in hashed_paths
    assert sidecar_path not in hashed_paths
    assert result.bytes_scanned > max_total_size
    assert result.content_hash is None
    assert any("Total scan size limit exceeded" in issue.message for issue in result.issues)
    assert any(
        check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
        for check in result.checks
    )
    assert not any(
        check.name == "External Data Reference Check"
        and check.status.value == "failed"
        and check.details.get("file") == "model.onnx_data"
        for check in result.checks
    )


def test_scan_model_streaming_hashes_reused_path_file_instances(tmp_path: Path) -> None:
    """A streaming source may reuse one staging path for multiple distinct files."""
    stage_path = tmp_path / "stage.txt"
    first_payload = b"first streamed file"
    second_payload = b"second streamed file"
    stage_path.write_bytes(first_payload)
    first_hash = compute_sha256_hash(stage_path)
    stage_path.write_bytes(second_payload)
    second_hash = compute_sha256_hash(stage_path)

    def reused_path_generator() -> Iterator[tuple[Path, bool]]:
        stage_path.write_bytes(first_payload)
        yield stage_path, False
        stage_path.write_bytes(second_payload)
        yield stage_path, True

    result = scan_model_streaming(
        file_generator=reused_path_generator(),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 0
    assert result.content_hash == compute_aggregate_hash([first_hash, second_hash])


def test_scan_model_streaming_openvino_prefetched_companion_counts_toward_max_total_size(tmp_path: Path) -> None:
    """HF-style XML-only yields must count staged OpenVINO weights against total scan caps."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(b"\x00" * 64)

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        max_total_size=32,
    )

    assert determine_exit_code(result) == 2
    assert result.bytes_scanned > 32
    assert result.content_hash is None
    assert any("Total scan size limit exceeded" in issue.message for issue in result.issues)


def test_scan_model_streaming_rejects_local_companion_stage_before_total_size_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A local source over the total cap must fail before copying source or companion bytes."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(b"\x00" * (2 * 1024 * 1024))

    def fail_copy(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("over-budget local files must not be copied into private staging")

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", fail_copy)

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        max_total_size=1,
    )

    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert any(
        issue.details.get("projected_total_size", 0) > 1 and issue.details.get("max_total_size") == 1
        for issue in result.issues
    )


def test_scan_model_streaming_rejects_local_stage_before_max_file_size_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A local source over its file cap must fail before staging source or companion bytes."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(b"\x00" * (2 * 1024 * 1024))

    def fail_copy(*_args: Any, **_kwargs: Any) -> str:
        pytest.fail("over-budget local files must not be copied into private staging")

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", fail_copy)

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
        max_file_size=1,
    )

    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert any(issue.message.startswith("File too large to scan") for issue in result.issues)


@pytest.mark.parametrize("stream", [False, True], ids=["standard", "streaming"])
def test_local_scan_rejects_oversized_companion_before_private_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stream: bool,
) -> None:
    """A small primary cannot stage an oversized companion past max_file_size."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(b"\x00" * (2 * 1024 * 1024))

    def fail_copy(*_args: Any, **_kwargs: Any) -> str:
        pytest.fail("an oversized companion must fail before any private staging copy")

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", fail_copy)
    if stream:
        result = scan_model_streaming(
            iter([(xml_path, True)]),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            max_file_size=1024,
            scanners=["openvino"],
            skip_file_types=False,
        )
    else:
        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            max_file_size=1024,
            scanners=["openvino"],
            skip_file_types=False,
        )

    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert any(
        issue.message.startswith("File too large to scan") and issue.details.get("file_size") == bin_path.stat().st_size
        for issue in result.issues
    )


@pytest.mark.parametrize("stream", [False, True], ids=["standard", "streaming"])
def test_explicit_openvino_xml_retains_malicious_weights_companion(
    tmp_path: Path,
    stream: bool,
) -> None:
    """Binding one XML file must retain its adjacent executable weights context."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    create_malicious_pickle(bin_path)

    if stream:
        result = scan_model_streaming(
            iter([(xml_path, True)]),
            scan_root=str(xml_path),
            delete_after_scan=False,
            cache_enabled=False,
            skip_file_types=False,
        )
    else:
        result = scan_model_directory_or_file(
            str(xml_path),
            cache_enabled=False,
            skip_file_types=False,
        )

    assert determine_exit_code(result) == 1
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and ("dangerous global" in issue.message.lower() or "system" in issue.message.lower())
        for issue in result.issues
    )
    assert not any(check.name == "OpenVINO Weights File Check" for check in result.checks)


@pytest.mark.parametrize("stream", [False, True], ids=["standard", "streaming"])
def test_explicit_onnx_retains_external_data_companion(
    tmp_path: Path,
    stream: bool,
) -> None:
    """Binding one ONNX file must retain its declared external-data sidecar."""
    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "model.onnx_data"
    model_path.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_path.write_bytes(struct.pack("f", 1.0))

    if stream:
        result = scan_model_streaming(
            iter([(model_path, True)]),
            scan_root=str(model_path),
            delete_after_scan=False,
            cache_enabled=False,
            scanners=["onnx"],
            skip_file_types=False,
        )
    else:
        result = scan_model_directory_or_file(
            str(model_path),
            cache_scan_results=False,
            scanners=["onnx"],
            skip_file_types=False,
        )

    assert not any(
        check.name == "External Data Reference Check" and check.status.value == "failed" for check in result.checks
    )
    assert any(
        check.name == "External Data Reference Check" and check.status.value == "passed" for check in result.checks
    )
    assert result.bytes_scanned == model_path.stat().st_size + sidecar_path.stat().st_size
    assert result.content_hash == compute_aggregate_hash(
        [compute_sha256_hash(model_path), compute_sha256_hash(sidecar_path)]
    )


def test_standard_openvino_companion_identity_counts_once_under_exact_total_budget(tmp_path: Path) -> None:
    """A sidecar scanned independently and as XML context consumes one aggregate byte budget."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    unique_bytes = xml_path.stat().st_size + bin_path.stat().st_size

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        max_total_size=unique_bytes,
        scanners=["openvino", "pickle"],
        skip_file_types=False,
    )

    assert result.bytes_scanned == unique_bytes
    assert not any("Total scan size limit exceeded" in issue.message for issue in result.issues)
    assert determine_exit_code(result) == 0


def test_standard_local_scan_rejects_total_budget_before_private_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A standard directory scan enforces max_total_size before staging its first file."""
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    def fail_copy(*_args: Any, **_kwargs: Any) -> str:
        pytest.fail("an over-budget source must fail before any private staging copy")

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", fail_copy)
    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        max_total_size=1,
        scanners=["pickle"],
        skip_file_types=False,
    )

    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert any(
        "Total scan size limit exceeded" in issue.message and issue.details.get("projected_total_size", 0) > 1
        for issue in result.issues
    )


@pytest.mark.parametrize("stream", [False, True], ids=["standard", "streaming"])
def test_local_private_copy_rejects_post_preflight_source_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stream: bool,
) -> None:
    """A source cannot grow past its validated size while a private copy is starting."""
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    initial_size = model_path.stat().st_size
    source_inode = model_path.stat().st_ino
    observed_limits: list[int | None] = []
    from modelaudit.utils.file import handlers

    original_copy = handlers._copy_pinned_file_descriptor

    def grow_before_copy(source_fd: int, destination: Path | str, **kwargs: Any) -> str:
        if os.fstat(source_fd).st_ino == source_inode:
            observed_limits.append(kwargs.get("max_bytes"))
            model_path.write_bytes(b"x" * (2 * 1024 * 1024))
        return original_copy(source_fd, destination, **kwargs)

    monkeypatch.setattr(handlers, "_copy_pinned_file_descriptor", grow_before_copy)
    if stream:
        result = scan_model_streaming(
            iter([(model_path, True)]),
            scan_root=str(tmp_path),
            delete_after_scan=False,
            cache_enabled=False,
            max_file_size=1024,
            max_total_size=1024,
            scanners=["pickle"],
            skip_file_types=False,
        )
    else:
        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            max_file_size=1024,
            max_total_size=1024,
            scanners=["pickle"],
            skip_file_types=False,
        )

    assert observed_limits == [initial_size]
    assert determine_exit_code(result) == 2
    assert result.content_hash is None


def test_local_stream_rejects_initial_index_generation_replacement(tmp_path: Path) -> None:
    """An index present in the initial namespace cannot be replaced before it is yielded."""
    index_path = tmp_path / "payload.safetensors.index.json"
    index_path.write_bytes(pickle.dumps(_StreamingMaliciousPicklePayload()))

    def replace_before_yield() -> Iterator[tuple[Path, bool]]:
        index_path.write_text("{}", encoding="utf-8")
        yield index_path, True

    result = scan_model_streaming(
        replace_before_yield(),
        scan_root=str(tmp_path),
        delete_after_scan=True,
        cache_enabled=False,
        scanners=["pickle", "metadata", "safetensors"],
        skip_file_types=False,
    )

    assert determine_exit_code(result) == 2
    assert result.success is False
    assert result.content_hash is None
    assert any(check.name == "Local Source Boundary Check" for check in result.checks)


def test_scan_model_streaming_openvino_missing_companion_still_reports_s701(tmp_path: Path) -> None:
    """Missing OpenVINO weights must not be suppressed by companion-preservation logic."""
    xml_path = tmp_path / "model.xml"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
    )

    assert any(
        check.rule_code == "S701" and "weights file not found" in check.message.lower() for check in result.checks
    )


def test_scan_model_streaming_openvino_symlink_escape_fails_closed(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """A streamed OpenVINO weights symlink escaping the model dir remains a critical finding."""
    model_dir = tmp_path / "model"
    outside_dir = tmp_path / "outside"
    model_dir.mkdir()
    outside_dir.mkdir()
    xml_path = model_dir / "model.xml"
    bin_path = model_dir / "model.bin"
    escaped_weights = outside_dir / "secret.bin"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")
    escaped_weights.write_bytes(b"secret-weights")
    bin_path.symlink_to(escaped_weights)

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 1
    assert result.content_hash is None
    assert not xml_path.exists()
    assert not bin_path.exists()
    assert escaped_weights.exists()
    assert any(
        check.name == "OpenVINO Weights Symlink Boundary Check"
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("resolved_path") == str(escaped_weights.resolve())
        for check in result.checks
    )


def test_scan_model_streaming_openvino_companion_swap_fails_closed(tmp_path: Path) -> None:
    """A sidecar changed during XML scanning makes the streamed result operationally incomplete."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    real_scan_file = scan_file

    def swap_companion(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        if Path(path) == xml_path:
            bin_path.write_bytes(b"changed")
        return real_scan_file(path, config=config)

    with patch("modelaudit.core.scan_file", side_effect=swap_companion):
        result = scan_model_streaming(
            file_generator=iter([(xml_path, True)]),
            timeout=30,
            delete_after_scan=False,
            cache_enabled=False,
        )

    assert determine_exit_code(result) == 2
    assert any(
        check.name == "OpenVINO Weights Companion Stability"
        and check.details.get("scan_outcome_reason") == "openvino_weights_changed_during_xml_scan"
        for check in result.checks
    )


def test_scan_model_streaming_openvino_bin_without_yielded_xml_fails_closed(tmp_path: Path) -> None:
    """A bin-first stream cannot mark weights covered unless its OpenVINO XML is yielded."""
    _xml_path, bin_path = _write_openvino_pair(tmp_path)
    create_malicious_pickle(bin_path)

    result = scan_model_streaming(
        file_generator=iter([(bin_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 1
    assert "pickle" in result.scanner_names
    assert any(issue.location == str(bin_path) and issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_model_streaming_openvino_pickle_sidecar_reports_payload(tmp_path: Path) -> None:
    """A yielded OpenVINO XML must still surface pickle payloads in its owned weights."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    create_malicious_pickle(bin_path)

    result = scan_model_streaming(
        file_generator=iter([(xml_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 1
    assert result.scanner_names == ["openvino"]
    assert result.file_metadata[str(xml_path)]["openvino_weights_pickle_payload_scanned"] is True
    assert "pickle" in result.file_metadata[str(xml_path)]["scanner_dependency_ids"]
    assert any(issue.location == str(bin_path) and issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_model_streaming_selected_openvino_preserves_bin_before_skip_filter(tmp_path: Path) -> None:
    """OpenVINO-only streaming must defer bin-first sidecars before extension filtering."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)

    result = scan_model_streaming(
        file_generator=iter([(bin_path, False), (xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        skip_file_types=True,
        scanners=["openvino"],
    )

    assert determine_exit_code(result) == 0
    assert result.scanner_names == ["openvino"]
    assert not xml_path.exists()
    assert not bin_path.exists()
    assert result.file_metadata[str(xml_path)]["bin_size"] == 16
    assert not any("weights file not found" in check.message.lower() for check in result.checks)
    assert not any(check.rule_code == "S701" for check in result.checks)


def test_scan_model_streaming_openvino_case_variant_companion(tmp_path: Path) -> None:
    """OpenVINO companion ownership should allow one unambiguous suffix case variant."""
    stem = "OpenVINO_Mod\u00e8le"
    xml_path = tmp_path / f"{stem}.XML"
    bin_path = tmp_path / f"{stem}.BIN"
    xml_path.write_text("<net version='10'></net>", encoding="utf-8")
    bin_path.write_bytes(b"\x00" * 16)

    result = scan_model_streaming(
        file_generator=iter([(bin_path, False), (xml_path, True)]),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        skip_file_types=True,
        scanners=["openvino"],
    )

    assert determine_exit_code(result) == 0
    assert result.scanner_names == ["openvino"]
    assert not xml_path.exists()
    assert not bin_path.exists()
    assert result.file_metadata[str(xml_path)]["bin_size"] == 16
    assert not any(check.rule_code == "S701" for check in result.checks)
    assert not any(check.name == "Scanner Selection" and check.location == str(bin_path) for check in result.checks)


def test_scan_model_directory_or_file_openvino_bin_sidecar_not_pytorch(tmp_path: Path) -> None:
    """Local directory scans should not route declared OpenVINO weights as PyTorch binaries."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=True)

    assert determine_exit_code(result) == 0
    assert "pytorch_binary" not in result.scanner_names
    assert result.file_metadata[str(xml_path)]["bin_size"] == bin_path.stat().st_size
    assert not any(check.rule_code == "S901" for check in result.checks)


def test_scan_model_directory_or_file_selected_openvino_sidecar_changes_content_hash(tmp_path: Path) -> None:
    """OpenVINO-only directory scans must hash selected same-stem weights sidecars."""
    xml_path, bin_path = _write_openvino_pair(tmp_path)
    first_result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        skip_file_types=True,
        scanners=["openvino"],
    )
    bin_path.write_bytes(b"\x01" * 16)
    second_result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        skip_file_types=True,
        scanners=["openvino"],
    )

    assert determine_exit_code(first_result) == 0
    assert determine_exit_code(second_result) == 0
    assert first_result.files_scanned == 2
    assert second_result.files_scanned == 2
    assert first_result.file_metadata[str(xml_path)]["bin_size"] == 16
    assert second_result.file_metadata[str(xml_path)]["bin_size"] == 16
    assert first_result.content_hash is not None
    assert second_result.content_hash is not None
    assert first_result.content_hash != second_result.content_hash
    assert str(bin_path) in first_result.file_metadata


def test_scan_model_directory_or_file_selected_openvino_sidecar_counts_toward_max_total_size(tmp_path: Path) -> None:
    """OpenVINO-only directory scans must count selected same-stem weights against total caps."""
    _xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(b"\x00" * 64)

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        skip_file_types=True,
        scanners=["openvino"],
        max_total_size=32,
    )

    assert determine_exit_code(result) == 2
    assert result.bytes_scanned == 0
    assert result.content_hash is None
    assert any(
        "Total scan size limit exceeded" in issue.message and issue.details.get("projected_total_size", 0) > 32
        for issue in result.issues
    )


def test_openvino_bin_sidecar_respects_selected_pytorch_binary_scanner(tmp_path: Path) -> None:
    """A filtered OpenVINO XML must not hide a selected malicious .bin scanner route."""
    _xml_path, bin_path = _write_openvino_pair(tmp_path)
    bin_path.write_bytes(b"\x00" * 128 + b"eval('1 + 1')" + b"\x00" * 128)

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        skip_file_types=True,
        scanners=["pytorch_binary"],
    )

    assert determine_exit_code(result) == 1
    assert "pytorch_binary" in result.scanner_names
    assert any(
        issue.location and issue.location.startswith(str(bin_path)) and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_openvino_bin_sidecar_respects_excluded_openvino_scanner(tmp_path: Path) -> None:
    """A standalone .bin scanner must still run when OpenVINO is excluded."""
    _xml_path, bin_path = _write_openvino_pair(tmp_path)
    create_malicious_pickle(bin_path)

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_enabled=False,
        skip_file_types=True,
        exclude_scanners=["openvino"],
    )

    assert determine_exit_code(result) == 1
    assert "openvino" not in result.scanner_names
    assert "pickle" in result.scanner_names
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "openvino"
        for check in result.checks
    )
    assert any(issue.location == str(bin_path) and issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_non_openvino_xml_near_match_does_not_hide_malicious_bin(tmp_path: Path) -> None:
    """A same-stem .bin remains independently scanned when the XML is not OpenVINO."""
    xml_path = tmp_path / "document.xml"
    xml_path.write_text("<project><model name='not-openvino'/></project>", encoding="utf-8")
    bin_path = create_malicious_pickle(tmp_path / "document.bin")

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=True)

    assert determine_exit_code(result) == 1
    assert "openvino" not in result.scanner_names
    assert any(issue.location == str(bin_path) and issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_model_streaming_skips_non_model_files(tmp_path: Path) -> None:
    """Streaming directory scans should honor the normal skip_file_types policy."""
    ignored_file = tmp_path / "notes.log"
    ignored_file.write_text("debug output")
    model_file = tmp_path / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100)

        result = scan_model_streaming(
            file_generator=iter([(ignored_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=True,
        )

    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(model_file)
    assert mock_scan.call_args.kwargs["config"]["skip_file_types"] is True
    assert result.files_scanned == 1


def test_scan_model_streaming_tokenizer_json_late_chat_template_after_structure_budget_reports_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=',"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"',
        padding_size=256,
    )

    result = scan_model_streaming(
        file_generator=iter([(tokenizer_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_scan_results=False,
        skip_file_types=False,
    )

    assert result.files_scanned == 1
    assert determine_exit_code(result) == 1
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_model_streaming_preserves_license_metadata_when_skipped(tmp_path: Path) -> None:
    """Skipped license files should still populate file metadata in streaming mode."""
    license_file = tmp_path / "license.txt"
    license_file.write_text("MIT License\nCopyright 2026 Example")

    with patch("modelaudit.core.scan_file") as mock_scan:
        result = scan_model_streaming(
            file_generator=iter([(license_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=True,
        )

    mock_scan.assert_not_called()
    assert result.files_scanned == 0
    assert str(license_file) in result.file_metadata
    metadata = result.file_metadata[str(license_file)].model_dump()
    assert "license_info" in metadata
    assert "copyright_notices" in metadata


def test_scan_model_streaming_skip_file_types_preserves_malicious_findings(tmp_path: Path) -> None:
    """Prefiltering should skip non-model files without dropping model security findings."""
    ignored_file = tmp_path / "notes.log"
    ignored_file.write_text("debug output")
    model_file = tmp_path / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100, with_critical_issue=True)

        result = scan_model_streaming(
            file_generator=iter([(ignored_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=True,
        )

    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(model_file)
    assert result.files_scanned == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_keeps_non_model_files_when_skip_disabled(tmp_path: Path) -> None:
    """The skip_file_types flag should remain opt-out for streaming scans."""
    ignored_file = tmp_path / "notes.log"
    ignored_file.write_text("debug output")
    model_file = tmp_path / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100)

        result = scan_model_streaming(
            file_generator=iter([(ignored_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=False,
        )

    assert [call.args[0] for call in mock_scan.call_args_list] == [str(ignored_file), str(model_file)]
    assert result.files_scanned == 2


def test_scan_model_streaming_skips_huggingface_cache_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming scans should skip HF bookkeeping metadata like regular scans."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    snapshots_dir = hf_home / "hub" / "models--test-model" / "snapshots" / "abc123"
    snapshots_dir.mkdir(parents=True)

    metadata_file = snapshots_dir / "config.json.metadata"
    write_hf_download_metadata(metadata_file)
    model_file = snapshots_dir / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)
    scanned_source_matches: list[bool] = []

    with patch("modelaudit.core.scan_file") as mock_scan:

        def record_scan(path: str, config: dict[str, Any]) -> ScanResult:
            del config
            scanned_source_matches.append(
                Path(path).name == model_file.name and Path(path).read_bytes() == model_file.read_bytes()
            )
            return create_mock_scan_result(bytes_scanned=100)

        mock_scan.side_effect = record_scan

        result = scan_model_streaming(
            file_generator=iter([(metadata_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(snapshots_dir),
            cache_enabled=False,
        )

    mock_scan.assert_called_once()
    assert scanned_source_matches == [True]
    assert result.files_scanned == 1


def test_scan_model_streaming_skips_local_download_sidecars(tmp_path: Path) -> None:
    """Streaming directory scans should skip snapshot_download(local_dir=...) sidecars."""
    model_dir = tmp_path / "downloaded-model"
    model_dir.mkdir()
    config_path = model_dir / "config.json"
    config_path.write_text('{"model_type":"bert"}', encoding="utf-8")
    vocab_path = model_dir / "vocab.txt"
    vocab_path.write_text("[PAD]\n[UNK]\n", encoding="utf-8")

    download_root = model_dir / ".cache" / "huggingface" / "download"
    config_metadata = download_root / "config.json.metadata"
    config_lock = download_root / "config.json.lock"
    vocab_metadata = download_root / "vocab.txt.metadata"
    cachedir_tag = model_dir / ".cache" / "huggingface" / "CACHEDIR.TAG"
    write_hf_download_metadata(config_metadata)
    config_lock.touch()
    write_hf_download_metadata(vocab_metadata)
    write_hf_cachedir_tag(cachedir_tag)
    scanned_source_matches: list[bool] = []
    expected_by_name = {path.name: path for path in (config_path, vocab_path)}

    with patch("modelaudit.core.scan_file") as mock_scan:

        def record_scan(path: str, config: dict[str, Any]) -> ScanResult:
            del config
            expected_path = expected_by_name[Path(path).name]
            scanned_source_matches.append(Path(path).read_bytes() == expected_path.read_bytes())
            return create_mock_scan_result(bytes_scanned=100)

        mock_scan.side_effect = record_scan

        result = scan_model_streaming(
            file_generator=iter(
                [
                    (config_metadata, False),
                    (config_lock, False),
                    (vocab_metadata, False),
                    (cachedir_tag, False),
                    (config_path, False),
                    (vocab_path, True),
                ]
            ),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(model_dir),
            skip_file_types=True,
            cache_enabled=False,
        )
    assert scanned_source_matches == [True, True]
    assert result.files_scanned == 2


def test_scan_model_streaming_local_download_sidecars_end_to_end_inventory(tmp_path: Path) -> None:
    """Streaming local-dir scans should exclude HF sidecars from inventory and hashes."""
    model_dir = tmp_path / "downloaded-model"
    model_dir.mkdir()
    config_path = model_dir / "config.json"
    config_path.write_text('{"model_type":"bert"}', encoding="utf-8")
    vocab_path = model_dir / "vocab.txt"
    vocab_path.write_text("[PAD]\n[UNK]\n", encoding="utf-8")

    download_root = model_dir / ".cache" / "huggingface" / "download"
    write_hf_download_metadata(download_root / "config.json.metadata")
    (download_root / "config.json.lock").touch()
    write_hf_download_metadata(download_root / "vocab.txt.metadata")
    write_hf_cachedir_tag(model_dir / ".cache" / "huggingface" / "CACHEDIR.TAG")

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(model_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(model_dir),
        skip_file_types=True,
        cache_enabled=False,
    )
    cache_fragment = ".cache/huggingface"
    expected_hash = compute_aggregate_hash([compute_sha256_hash(config_path), compute_sha256_hash(vocab_path)])

    assert result.files_scanned == 2
    assert {Path(asset.path).relative_to(model_dir).as_posix() for asset in result.assets} == {
        "config.json",
        "vocab.txt",
    }
    assert not any(cache_fragment in path for path in result.file_metadata)
    assert not any(cache_fragment in (check.location or "") for check in result.checks)
    assert not any(cache_fragment in (issue.location or "") for issue in result.issues)
    assert result.content_hash == expected_hash


def test_scan_model_streaming_local_download_json_metadata_payload_is_scanned(tmp_path: Path) -> None:
    """Streaming scans must not trust arbitrary JSON objects as HF download metadata."""
    model_dir = tmp_path / "downloaded-model"
    model_dir.mkdir()
    config_path = model_dir / "config.json"
    config_path.write_text('{"model_type":"bert"}', encoding="utf-8")
    sidecar = model_dir / ".cache" / "huggingface" / "download" / "config.json.metadata"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(
        '{"chat_template": "{{ cycler.__init__.__globals__.os.popen(\\"id\\").read() }}"}',
        encoding="utf-8",
    )

    result = scan_model_streaming(
        file_generator=iter([(sidecar, False), (config_path, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(model_dir),
        skip_file_types=True,
        cache_enabled=False,
    )

    assert result.files_scanned == 2
    assert str(sidecar) in result.file_metadata


def test_scan_model_streaming_hf_snapshot_metadata_symlink_payload_is_scanned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Streaming scans must not skip a model payload with a snapshot sidecar-like name."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_root = hf_home / "hub" / "models--org--repo"
    snapshot_root = cache_root / "snapshots" / "abc123"
    blobs_root = cache_root / "blobs"
    snapshot_root.mkdir(parents=True)
    blobs_root.mkdir()
    blob = blobs_root / "blob123"
    create_malicious_pickle(blob)
    payload_alias = snapshot_root / "payload.pkl.metadata"
    payload_alias.symlink_to(Path("../../blobs") / blob.name)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshot_root),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshot_root),
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert any(issue.rule_code == "S201" for issue in result.issues)


def test_scan_model_streaming_hf_no_exist_marker_skips_only_empty_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming scans skip empty negative-cache markers but scan contentful entries."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    no_exist_root = hf_home / "hub" / "models--org--repo" / ".no_exist" / "abc123"
    empty_marker = no_exist_root / "missing.safetensors"
    malicious_marker = no_exist_root / "payload.pkl"
    empty_marker.parent.mkdir(parents=True)
    empty_marker.touch()
    create_malicious_pickle(malicious_marker)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(hf_home / "hub" / "models--org--repo"),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(hf_home / "hub" / "models--org--repo"),
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert str(malicious_marker) in result.file_metadata
    assert str(empty_marker) not in result.file_metadata
    assert any(issue.rule_code == "S201" and issue.location == str(malicious_marker) for issue in result.issues)


def test_scan_model_streaming_scans_local_file_named_main(tmp_path: Path) -> None:
    """A local payload named like an HF ref must still be scanned in streaming mode."""
    payload = tmp_path / "main"
    payload.write_bytes(b"\x80\x02cos\nsystem\n.")

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert any(issue.severity == IssueSeverity.CRITICAL and "system" in issue.message for issue in result.issues)
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_symlink_outside_directory_matches_normal_scan(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Local streaming scans should reject symlinks that escape the requested directory."""
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with (base_dir / "safe.pkl").open("wb") as f:
        pickle.dump({"data": "safe"}, f)
    with (outside_dir / "secret.pkl").open("wb") as f:
        pickle.dump({"data": "secret"}, f)

    symlink_path = base_dir / "link.pkl"
    symlink_path.symlink_to(outside_dir / "secret.pkl")

    normal_result = scan_model_directory_or_file(str(base_dir), cache_enabled=False)
    streaming_result = scan_model_streaming(
        file_generator=iterate_files_streaming(base_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(base_dir),
        cache_enabled=False,
    )

    normal_traversal_issues = [i for i in normal_result.issues if "path traversal" in i.message.lower()]
    streaming_traversal_issues = [i for i in streaming_result.issues if "path traversal" in i.message.lower()]

    assert len(normal_traversal_issues) == 1
    assert len(streaming_traversal_issues) == 1
    assert normal_traversal_issues[0].location == str(symlink_path)
    assert streaming_traversal_issues[0].location == str(symlink_path)
    assert streaming_traversal_issues[0].severity == IssueSeverity.CRITICAL
    assert normal_result.files_scanned == 1
    assert streaming_result.files_scanned == 1


def test_scan_model_streaming_symlink_outside_directory_without_safe_files_returns_security_exit_code(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Traversal findings should keep the security exit code even when no files were scanned."""
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with (outside_dir / "secret.pkl").open("wb") as f:
        pickle.dump({"data": "secret"}, f)

    symlink_path = base_dir / "link.pkl"
    symlink_path.symlink_to(outside_dir / "secret.pkl")

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(base_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(base_dir),
        cache_enabled=False,
    )

    traversal_issues = [issue for issue in result.issues if "path traversal" in issue.message.lower()]

    assert result.files_scanned == 0
    assert result.has_errors is False
    assert len(traversal_issues) == 1
    assert traversal_issues[0].location == str(symlink_path)
    assert traversal_issues[0].severity == IssueSeverity.CRITICAL
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_fifo_cache_tag_fails_closed_without_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming scans should reject special files yielded by a source generator before hashing."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo unavailable")
    fifo = tmp_path / ".cache" / "huggingface" / "CACHEDIR.TAG"
    fifo.parent.mkdir(parents=True)
    os.mkfifo(fifo)
    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("special streamed entries must not be opened for hashing"),
    )

    result = scan_model_streaming(
        file_generator=iter([(fifo, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(tmp_path),
        cache_enabled=False,
    )

    assert result.files_scanned == 0
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.location == str(fifo) and issue.details.get("scan_outcome_reason") == "directory_special_file_unscanned"
        for issue in result.issues
    )


def test_scan_model_streaming_hf_cache_symlink_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Local streaming scans should preserve HuggingFace cache symlink handling."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)

    blob_path = blobs_dir / "blob123"
    with blob_path.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    model_link = snapshots_dir / "model.pkl"
    os.symlink(os.path.relpath(blob_path, model_link.parent), model_link)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshots_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshots_dir),
        cache_enabled=False,
    )

    path_traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
    assert result.files_scanned == 1
    assert len(path_traversal_issues) == 0


def test_scan_model_streaming_hf_cache_alias_rejects_post_scan_blob_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """A trusted snapshot alias remains bound to the blob generation that was scanned."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)
    blob_path = blobs_dir / "blob123"
    blob_path.write_bytes(pickle.dumps({"data": "safe"}))
    malicious_blob = blobs_dir / "malicious"
    create_malicious_pickle(malicious_blob)
    model_link = snapshots_dir / "model.pkl"
    model_link.symlink_to(os.path.relpath(blob_path, model_link.parent))

    def replacing_stream() -> Iterator[tuple[Path, bool]]:
        yield model_link, False
        malicious_blob.replace(blob_path)

    result = scan_model_streaming(
        file_generator=replacing_stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshots_dir),
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 2
    assert result.success is False
    assert any(check.name == "Local Source Boundary Check" for check in result.checks)


def test_scan_model_streaming_hf_cache_alias_rejects_pre_open_blob_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Deleting an alias cannot hide a blob generation swapped before its retained open."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)
    blob_path = blobs_dir / "blob123"
    create_malicious_pickle(blob_path)
    original_generation = blobs_dir / "original-generation"
    model_link = snapshots_dir / "model.pkl"
    model_link.symlink_to(os.path.relpath(blob_path, model_link.parent))

    def replace_then_restore_blob() -> Iterator[tuple[Path, bool]]:
        blob_path.rename(original_generation)
        blob_path.write_bytes(pickle.dumps({"data": "safe"}))
        try:
            yield model_link, True
        finally:
            blob_path.unlink(missing_ok=True)
            original_generation.rename(blob_path)

    result = scan_model_streaming(
        file_generator=replace_then_restore_blob(),
        timeout=30,
        delete_after_scan=True,
        scan_root=str(snapshots_dir),
        cache_enabled=False,
    )

    assert determine_exit_code(result) == 2
    assert result.success is False
    assert any(check.name == "Local Source Boundary Check" for check in result.checks)
    assert blob_path.exists()
    assert not model_link.exists()


def test_scan_model_streaming_hf_home_cache_symlink_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Custom HF_HOME cache roots should preserve symlink handling in streaming scans."""
    monkeypatch.setenv("HF_HOME", str(tmp_path / "custom-hf-home"))
    cache_dir = tmp_path / "custom-hf-home" / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)

    blob_path = blobs_dir / "blob123"
    with blob_path.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    model_link = snapshots_dir / "model.pkl"
    os.symlink(os.path.relpath(blob_path, model_link.parent), model_link)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshots_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshots_dir),
        cache_enabled=False,
    )

    path_traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
    assert result.files_scanned == 1
    assert len(path_traversal_issues) == 0


def test_scan_model_streaming_symlink_reports_source_path_consistently(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Streaming scans should report source paths even when scanning a resolved symlink target."""
    base_dir = tmp_path / "base"
    nested_dir = base_dir / "nested"
    nested_dir.mkdir(parents=True)

    resolved_target = nested_dir / "model.pkl"
    with resolved_target.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    source_link = base_dir / "link.pkl"
    source_link.symlink_to(resolved_target.relative_to(source_link.parent))

    scanned_source_matches: list[bool] = []
    with patch("modelaudit.core.scan_file") as mock_scan:

        def record_scan(path: str, config: dict[str, Any]) -> ScanResult:
            del config
            scanned_source_matches.append(
                Path(path).name == source_link.name and Path(path).read_bytes() == resolved_target.read_bytes()
            )
            return create_mock_location_scan_result(resolved_target)

        mock_scan.side_effect = record_scan

        result = scan_model_streaming(
            file_generator=iter([(source_link, True)]),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(base_dir),
            cache_enabled=False,
        )

    assert scanned_source_matches == [True]
    assert result.files_scanned == 1
    assert result.assets[0].path == str(source_link)
    assert result.assets[0].size == resolved_target.stat().st_size

    metadata = result.file_metadata[str(source_link)].model_dump()
    assert metadata["source_path"] == str(source_link)
    assert metadata["resolved_path"] == str(resolved_target)

    assert result.issues[0].location == f"{source_link}:payload"
    check_locations = {check.name: check.location for check in result.checks}
    assert check_locations["Suspicious Payload"] == f"{source_link}:payload"
    assert check_locations["Layout Inspection"] == f"{source_link} (weights)"


def test_scan_model_streaming_hf_cache_symlink_reports_snapshot_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """HuggingFace cache symlinks should keep snapshot paths in streamed results."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)

    blob_path = blobs_dir / "blob123"
    with blob_path.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    model_link = snapshots_dir / "model.pkl"
    os.symlink(os.path.relpath(blob_path, model_link.parent), model_link)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_location_scan_result(blob_path, issue_suffix="", check_suffix=":tensor")

        result = scan_model_streaming(
            file_generator=iterate_files_streaming(snapshots_dir),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(snapshots_dir),
            cache_enabled=False,
        )

    assert Path(mock_scan.call_args[0][0]).name == model_link.name
    assert result.files_scanned == 1
    assert result.assets[0].path == str(model_link)

    metadata = result.file_metadata[str(model_link)].model_dump()
    assert metadata["source_path"] == str(model_link)
    assert metadata["resolved_path"] == str(blob_path)

    assert result.issues[0].location == str(model_link)
    check_locations = {check.name: check.location for check in result.checks}
    assert check_locations["Suspicious Payload"] == str(model_link)
    assert check_locations["Layout Inspection"] == f"{model_link}:tensor"


def test_scan_model_streaming_hf_cache_onnx_external_data_uses_snapshot_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Streaming scans over trusted HF cache aliases should keep ONNX sidecar context."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    model_link = snapshot_dir / "model.onnx"
    sidecar_link = snapshot_dir / "model.onnx_data"
    model_link.symlink_to(os.path.relpath(model_blob, snapshot_dir))
    sidecar_link.symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshot_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    failed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check" and check.status.value == "failed"
    ]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]
    symlink_traversal_checks = [
        check for check in result.checks if check.name == "CVE-2026-34447: External Data Symlink Traversal"
    ]

    assert failed_external == []
    assert len(passed_external) == 1
    assert symlink_traversal_checks == []
    assert_only_onnx_external_schema_validation_skipped(result)


def test_scan_model_streaming_hf_cache_rejects_onnx_stage_before_total_size_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Trusted HF aliases must enforce projected total size before private staging copies."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(b"\x00" * (2 * 1024 * 1024))
    model_link = snapshot_dir / "model.onnx"
    sidecar_link = snapshot_dir / "model.onnx_data"
    model_link.symlink_to(os.path.relpath(model_blob, snapshot_dir))
    sidecar_link.symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    def fail_copy(*_args: Any, **_kwargs: Any) -> str:
        pytest.fail("over-budget HF files must not be copied into private staging")

    monkeypatch.setattr("modelaudit.utils.file.handlers._copy_pinned_file_descriptor", fail_copy)

    result = scan_model_streaming(
        file_generator=iter([(model_link, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshot_dir),
        cache_enabled=False,
        max_total_size=1,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert determine_exit_code(result) == 2
    assert result.content_hash is None
    assert any(
        issue.details.get("projected_total_size", 0) > 1 and issue.details.get("max_total_size") == 1
        for issue in result.issues
    )


def test_scan_model_streaming_hf_cache_onnx_external_data_dedupes_yielded_alias_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """A yielded HF sidecar alias should count once when also used as ONNX context."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    model_link = snapshot_dir / "model.onnx"
    sidecar_link = snapshot_dir / "model.onnx_data"
    model_link.symlink_to(os.path.relpath(model_blob, snapshot_dir))
    sidecar_link.symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    yielded_paths = {path for path, _is_last in iterate_files_streaming(snapshot_dir)}
    assert yielded_paths == {model_link, sidecar_link}

    unique_bytes = model_blob.stat().st_size + sidecar_blob.stat().st_size
    expected_hash = compute_aggregate_hash([compute_sha256_hash(model_link), compute_sha256_hash(sidecar_link)])

    def scan_file_side_effect(path: str, config: dict[str, Any]) -> ScanResult:
        return create_mock_scan_result(bytes_scanned=Path(path).stat().st_size)

    with patch("modelaudit.core.scan_file", side_effect=scan_file_side_effect):
        result = scan_model_streaming(
            file_generator=iterate_files_streaming(snapshot_dir),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(snapshot_dir),
            cache_enabled=False,
            max_total_size=unique_bytes,
            scanners=["onnx"],
            skip_file_types=False,
        )

    assert result.bytes_scanned == unique_bytes
    assert result.content_hash == expected_hash
    assert not any("Total scan size limit exceeded" in issue.message for issue in result.issues)
    assert determine_exit_code(result) == 0


def test_scan_model_streaming_hf_cache_replaced_onnx_sidecar_is_reaccounted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Path reuse cannot exempt a new external-data generation from the total-size budget."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blobs = [blobs_dir / f"model-{index}-blob" for index in range(2)]
    for model_blob in model_blobs:
        model_blob.write_bytes(create_external_onnx_payload(tmp_path, external_path="shared.onnx_data"))
    sidecar_blob = blobs_dir / "sidecar-blob"
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    model_links = [snapshot_dir / f"model-{index}.onnx" for index in range(2)]
    for model_link, model_blob in zip(model_links, model_blobs, strict=True):
        model_link.symlink_to(os.path.relpath(model_blob, snapshot_dir))
    sidecar_link = snapshot_dir / "shared.onnx_data"
    sidecar_link.symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))
    initial_budget = sum(path.stat().st_size for path in [*model_blobs, sidecar_blob])

    def replacing_stream() -> Iterator[tuple[Path, bool]]:
        yield model_links[0], False
        sidecar_blob.write_bytes(b"x" * (4 * 1024 * 1024))
        yield model_links[1], True

    result = scan_model_streaming(
        file_generator=replacing_stream(),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshot_dir),
        cache_enabled=False,
        max_total_size=initial_budget,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert determine_exit_code(result) == 2
    assert result.bytes_scanned <= initial_budget
    assert any(
        "Total scan size limit exceeded" in issue.message
        and issue.details.get("projected_total_size", 0) > initial_budget
        for issue in result.issues
    )


def test_scan_model_streaming_scans_consumed_scannable_onnx_external_data_alias(tmp_path: Path) -> None:
    """A consumed ONNX sidecar alias must still dispatch to an enabled scanner."""
    model_path = tmp_path / "model.onnx"
    sidecar_path = tmp_path / "payload.bin"
    model_path.write_bytes(create_external_onnx_payload(tmp_path, external_path=sidecar_path.name))
    create_malicious_pickle(sidecar_path)
    expected_hash = compute_aggregate_hash([compute_sha256_hash(model_path), compute_sha256_hash(sidecar_path)])
    duplicate_sidecar_hash = compute_aggregate_hash(
        [compute_sha256_hash(model_path), compute_sha256_hash(sidecar_path), compute_sha256_hash(sidecar_path)]
    )

    result = scan_model_streaming(
        file_generator=iter([(model_path, False), (sidecar_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
        scanners=["onnx", "pickle"],
    )

    pickle_issues = [
        issue
        for issue in result.issues
        if issue.location == str(sidecar_path) and issue.severity == IssueSeverity.CRITICAL
    ]
    assert any("system" in issue.message.lower() for issue in pickle_issues)
    assert result.content_hash == expected_hash
    assert result.content_hash != duplicate_sidecar_hash


def test_scan_model_streaming_hf_cache_context_only_onnx_external_data_contributes_hash_and_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Trusted HF snapshot sidecar aliases should be hashed even when yielded only as context."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    cache_root = cache_hub / "models--test--model"
    blobs_dir = cache_root / "blobs"
    snapshot_dir = cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    model_link = snapshot_dir / "model.onnx"
    sidecar_link = snapshot_dir / "model.onnx_data"
    model_link.symlink_to(os.path.relpath(model_blob, snapshot_dir))
    sidecar_link.symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))
    expected_hash = compute_aggregate_hash([compute_sha256_hash(model_link), compute_sha256_hash(sidecar_link)])

    result = scan_model_streaming(
        file_generator=iter([(model_link, True)]),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    assert_only_onnx_external_schema_validation_skipped(result)
    assert result.files_scanned == 1
    assert result.content_hash == expected_hash
    assert result.bytes_scanned >= model_blob.stat().st_size + sidecar_blob.stat().st_size


def test_scan_model_streaming_hf_cache_onnx_external_data_rejects_nested_cache_lookalike(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Nested models--* lookalikes must not gain trusted HF cache alias handling."""
    cache_hub = tmp_path / "hf-hub"
    monkeypatch.setenv("HF_HUB_CACHE", str(cache_hub))
    fake_cache_root = cache_hub / "scratch" / "models--test--model"
    blobs_dir = fake_cache_root / "blobs"
    snapshot_dir = fake_cache_root / "snapshots" / ("a" * 40) / "onnx"
    blobs_dir.mkdir(parents=True)
    snapshot_dir.mkdir(parents=True)

    model_blob = blobs_dir / "model-blob"
    sidecar_blob = blobs_dir / "sidecar-blob"
    model_blob.write_bytes(create_external_onnx_payload(tmp_path))
    sidecar_blob.write_bytes(struct.pack("f", 1.0))
    (snapshot_dir / "model.onnx").symlink_to(os.path.relpath(model_blob, snapshot_dir))
    (snapshot_dir / "model.onnx_data").symlink_to(os.path.relpath(sidecar_blob, snapshot_dir))

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshot_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshot_dir),
        cache_enabled=False,
        scanners=["onnx"],
        skip_file_types=False,
    )

    traversal_issues = [issue for issue in result.issues if "path traversal" in issue.message.lower()]
    passed_external = [
        check
        for check in result.checks
        if check.name == "External Data Reference Check"
        and check.status.value == "passed"
        and check.details.get("file") == "model.onnx_data"
    ]

    assert traversal_issues
    assert passed_external == []
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_with_deletion(temp_test_files: list[Path]) -> None:
    """Test that files are deleted after scanning in streaming mode."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [create_mock_scan_result(bytes_scanned=100) for _ in temp_test_files]

        # Verify files exist before scan
        for f in temp_test_files:
            assert f.exists()

        # Run streaming scan with deletion
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=True,
        )

        # Verify files were deleted
        for f in temp_test_files:
            assert not f.exists()

    # Verify scan completed
    assert result.files_scanned == 3
    assert result.content_hash is not None


def test_scan_model_streaming_precomputed_remote_result_does_not_delete_local_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Precomputed remote scans must not unlink same-named local files."""
    monkeypatch.chdir(tmp_path)
    local_match = Path("model.safetensors")
    local_match.write_bytes(b"local file that was never streamed")
    remote_path = "hf://test/model@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/model.safetensors"
    precomputed = ScanResult(scanner_name="safetensors")
    precomputed.bytes_scanned = 32
    precomputed.metadata.update(
        {
            "remote_header_only": True,
            "remote_source_path": remote_path,
            "source_path": remote_path,
        }
    )
    precomputed.add_check(
        name="Remote SafeTensors Header Integrity",
        passed=True,
        message="Remote SafeTensors header was scanned with bounded range reads",
        severity=IssueSeverity.INFO,
        location=remote_path,
    )
    precomputed.finish(success=True)

    result = scan_model_streaming(
        file_generator=iter([(local_match, True, precomputed)]),
        timeout=30,
        delete_after_scan=True,
    )

    assert local_match.exists()
    assert result.files_scanned == 1
    assert result.file_metadata[remote_path].model_dump()["remote_header_only"] is True
    assert result.assets


def test_scan_model_streaming_preserves_precomputed_inconclusive_failure_without_cache_write() -> None:
    """A failed source-native result must remain an operational failure and bypass local caching."""
    source_path = "hf://test/model@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/model.safetensors"
    precomputed = ScanResult(scanner_name="safetensors")
    precomputed.bytes_scanned = 8
    precomputed.metadata.update(
        {
            "remote_header_only": True,
            "remote_source_path": source_path,
            "source_path": source_path,
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "remote_safetensors_header_range_failed",
            "scan_outcome_reasons": ["remote_safetensors_header_range_failed"],
            "operational_error": True,
            "operational_error_reason": "remote_safetensors_header_range_failed",
        }
    )
    precomputed.add_check(
        name="Remote SafeTensors Header Acquisition",
        passed=False,
        message="Remote SafeTensors header could not be acquired",
        severity=IssueSeverity.INFO,
        location=source_path,
        details={
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "remote_safetensors_header_range_failed",
            "operational_error": True,
        },
    )
    precomputed.finish(success=False)

    with (
        patch("modelaudit.core.scan_file") as mock_scan_file,
        patch("modelaudit.cache.scan_results_cache.ScanResultsCache.store_result") as mock_cache_store,
    ):
        result = scan_model_streaming(
            file_generator=iter([(Path("model.safetensors"), True, precomputed)]),
            timeout=30,
            delete_after_scan=True,
            cache_enabled=True,
        )

    assert result.success is False
    assert result.has_errors is True
    assert result.files_scanned == 1
    assert result.bytes_scanned == 8
    assert determine_exit_code(result) == 2
    assert result.file_metadata[source_path].model_dump()["scan_outcome"] == "inconclusive"
    mock_scan_file.assert_not_called()
    mock_cache_store.assert_not_called()


def test_scan_model_streaming_critical_findings_do_not_set_operational_errors(
    temp_test_files: list[Path],
) -> None:
    """Security findings in streaming mode should still return the security exit code."""

    def file_generator():
        yield (temp_test_files[0], True)

    finding = ScanResult(scanner_name="test_scanner")
    finding.bytes_scanned = 1024
    finding.success = True
    finding.add_issue(
        "Detected malicious payload",
        severity=IssueSeverity.CRITICAL,
        location=str(temp_test_files[0]),
    )

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = finding

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    assert result.files_scanned == 1
    assert len(result.issues) == 1
    assert result.issues[0].message == "Detected malicious payload"
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].location == str(temp_test_files[0])
    assert result.has_errors is False
    assert result.success is True
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_late_source_failure_preserves_critical_findings(tmp_path: Path) -> None:
    streamed_file = tmp_path / "synthetic-malicious.pkl"
    streamed_file.write_bytes(b"synthetic pickle payload")

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield streamed_file, False
        raise RuntimeError("late synthetic stream failure")

    finding = ScanResult(scanner_name="pickle")
    finding.bytes_scanned = streamed_file.stat().st_size
    finding.add_issue(
        "Detected malicious payload before stream failure",
        severity=IssueSeverity.CRITICAL,
        location=str(streamed_file),
    )
    finding.finish(success=True)

    with patch("modelaudit.core.scan_file", return_value=finding):
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    interruption_issues = [issue for issue in result.issues if issue.type == "streaming_source_interrupted"]
    assert result.files_scanned == 1
    assert result.bytes_scanned == streamed_file.stat().st_size
    assert any(
        issue.message == "Detected malicious payload before stream failure"
        and issue.severity == IssueSeverity.CRITICAL
        and issue.location == str(streamed_file)
        for issue in result.issues
    )
    assert len(interruption_issues) == 1
    interruption_details = interruption_issues[0].details
    assert interruption_details["operational_error"] is True
    assert interruption_details["scan_outcome"] == "inconclusive"
    assert interruption_details["scan_outcome_reason"] == "streaming_source_interrupted"
    assert interruption_details["files_scanned_before_failure"] == 1
    assert "huggingface_acquisition_error" not in interruption_details.get("scan_outcome_reasons", [])
    assert not any(issue.details.get("acquisition_error") is True for issue in result.issues)
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_late_source_failure_after_benign_prefix_fails_closed(tmp_path: Path) -> None:
    streamed_file = tmp_path / "synthetic-benign.pkl"
    streamed_file.write_bytes(b"synthetic benign payload")

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield streamed_file, False
        raise OSError("late synthetic stream failure")

    clean_result = ScanResult(scanner_name="pickle")
    clean_result.bytes_scanned = streamed_file.stat().st_size
    clean_result.finish(success=True)

    with patch("modelaudit.core.scan_file", return_value=clean_result):
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    interruption_issues = [issue for issue in result.issues if issue.type == "streaming_source_interrupted"]
    assert result.files_scanned == 1
    assert result.bytes_scanned == streamed_file.stat().st_size
    assert str(streamed_file) in result.file_metadata
    assert len(interruption_issues) == 1
    assert interruption_issues[0].severity == IssueSeverity.INFO
    assert interruption_issues[0].details["operational_error"] is True
    assert interruption_issues[0].details["scan_outcome"] == "inconclusive"
    assert interruption_issues[0].details["scan_outcome_reason"] == "streaming_source_interrupted"
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    assert not any(issue.details.get("acquisition_error") is True for issue in result.issues)
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_informational_failed_scan_does_not_set_operational_errors(
    temp_test_files: list[Path],
) -> None:
    """Informational failed scans should not override security findings with exit code 2."""

    def file_generator():
        yield (temp_test_files[0], False)
        yield (temp_test_files[1], True)

    info_result = ScanResult(scanner_name="numpy")
    info_result.add_issue(
        "Object-dtype payload contains trailing bytes after the embedded pickle stream",
        severity=IssueSeverity.INFO,
        location="trailing.npy",
    )
    info_result.finish(success=False)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [info_result, create_mock_scan_result(with_critical_issue=True)]

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    assert result.files_scanned == 2
    assert result.success is False
    assert result.has_errors is False
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_bare_failed_scan_fails_closed(
    temp_test_files: list[Path],
) -> None:
    """Streaming dict aggregation should preserve bare failed-scan inconclusive metadata."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield (temp_test_files[0], True)

    info_result = ScanResult(scanner_name="numpy")
    info_result.add_issue(
        "Object-dtype payload contains trailing bytes after the embedded pickle stream",
        severity=IssueSeverity.INFO,
        location=str(temp_test_files[0]),
    )
    info_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=info_result):
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    metadata = result.file_metadata[str(temp_test_files[0])]
    assert metadata["scan_outcome"] == "inconclusive"
    assert "scanner_reported_unsuccessful_without_outcome" in metadata["scan_outcome_reasons"]
    assert result.has_errors is False
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_operational_info_failure_sets_exit_code_2(
    temp_test_files: list[Path],
) -> None:
    """Informational coverage failures must still fail closed when flagged as operational."""

    def file_generator():
        yield (temp_test_files[0], True)

    info_result = ScanResult(scanner_name="pickle")
    info_result.add_check(
        name="Large File Coverage Check",
        passed=False,
        message=(
            "Error scanning file: scanner pickle does not support bounded large-file analysis "
            "for this file size; aborting to avoid partial coverage."
        ),
        severity=IssueSeverity.INFO,
        location=str(temp_test_files[0]),
    )
    info_result.metadata["operational_error"] = True
    info_result.metadata["operational_error_reason"] = "unsupported_bounded_large_file_analysis"
    info_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=info_result):
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    assert result.files_scanned == 1
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_oversized_renamed_safetensors_fails_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "weights.jpg"
    header_len = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1
    with payload.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)

    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("streaming bounded SafeTensors failure must not hash the artifact"),
    )
    monkeypatch.setattr(
        safetensors_scanner.SafeTensorsScanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("streaming bounded SafeTensors failure must not run scanner hashes"),
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert "safetensors" in result.scanner_names
    assert any(check.name == "Header Size Limit" for check in result.checks)


def test_scan_model_streaming_defers_hash_for_large_valid_hdf5_userblock_beyond_signature_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "large-userblock-model.h5"
    userblock_size = write_large_valid_userblock_keras_hdf5(payload)
    assert find_hdf5_signature_offset(str(payload)) == userblock_size

    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("streaming large file-backed HDF5 artifact must not be whole-file hashed"),
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    metadata = result.file_metadata[str(payload)]
    assert result.files_scanned == 1
    assert result.content_hash is None
    assert "keras_h5" in result.scanner_names
    assert metadata["file_backed_scan"] is True
    assert metadata["file_hashes"] is None
    assert "hdf5_userblock_zip_probe_incomplete" in metadata["scan_outcome_reasons"]
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_does_not_hash_files_over_max_file_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "oversized.pkl"
    payload.write_bytes(b"X" * 128)

    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("streaming oversized file must not be hashed before rejection"),
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        max_file_size=64,
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(issue.message.startswith("File too large to scan") for issue in result.issues)


def test_scan_model_streaming_preserves_pretransferred_bytes_across_max_file_size(tmp_path: Path) -> None:
    """A selected source rejected by max-file-size must retain its earlier transfer accounting."""
    payload = tmp_path / "selected-index.json"
    payload.write_bytes(b"X" * 128)
    accounting = StreamedSourceByteAccounting(
        pretransferred_bytes=payload.stat().st_size,
        source_bytes_preaccounted=payload.stat().st_size,
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True, None, accounting)]),
        timeout=30,
        delete_after_scan=False,
        max_file_size=64,
        cache_enabled=False,
    )

    assert result.bytes_scanned == payload.stat().st_size
    assert result.files_scanned == 1
    assert result.success is False
    assert any(issue.message.startswith("File too large to scan") for issue in result.issues)


def test_scan_model_streaming_preserves_pretransferred_bytes_for_lfs_pointer(tmp_path: Path) -> None:
    """A selected Git LFS pointer must not erase bytes transferred before local routing."""
    payload = tmp_path / "model.safetensors.index.json"
    payload.write_text(f"version https://git-lfs.github.com/spec/v1\noid sha256:{'a' * 64}\nsize 123456\n")
    payload_size = payload.stat().st_size
    accounting = StreamedSourceByteAccounting(
        pretransferred_bytes=payload_size,
        source_bytes_preaccounted=payload_size,
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True, None, accounting)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert result.bytes_scanned == payload_size
    assert result.files_scanned == 1
    assert result.success is True
    assert determine_exit_code(result) == 1
    assert any(check.name == "Git LFS Pointer Detection" for check in result.checks)


@pytest.mark.parametrize(
    ("pretransferred_bytes", "source_bytes_preaccounted"),
    [(True, 0), (-1, 0), (0, True), (0, -1)],
)
def test_streamed_source_byte_accounting_rejects_invalid_values(
    pretransferred_bytes: object,
    source_bytes_preaccounted: object,
) -> None:
    with pytest.raises(ValueError, match="must be a non-negative integer"):
        StreamedSourceByteAccounting(
            pretransferred_bytes=cast(Any, pretransferred_bytes),
            source_bytes_preaccounted=cast(Any, source_bytes_preaccounted),
        )


@pytest.mark.parametrize("source_path", ["", 1])
def test_streamed_source_byte_accounting_rejects_invalid_source_path(source_path: object) -> None:
    with pytest.raises(ValueError, match="source_path must be a non-empty string"):
        StreamedSourceByteAccounting(source_path=cast(Any, source_path))


def test_scan_model_streaming_fails_closed_after_max_total_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "oversized.pkl"
    payload.write_bytes(pickle.dumps({"safe": True}) + b"X" * 128)
    later = tmp_path / "later.pkl"
    later.write_bytes(pickle.dumps({"safe": "later"}))
    scan_result = ScanResult(scanner_name="bounded_test")
    scan_result.bytes_scanned = 128
    scan_result.finish(success=True)
    hashed_paths: list[Path] = []
    file_hash = "a" * 64

    def track_hash(path: Path) -> str:
        hashed_paths.append(path)
        return file_hash

    monkeypatch.setattr("modelaudit.utils.helpers.file_hash.compute_sha256_hash", track_hash)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: scan_result)

    result = scan_model_streaming(
        file_generator=iter([(payload, False), (later, True)]),
        timeout=30,
        delete_after_scan=False,
        max_total_size=64,
        cache_enabled=False,
    )

    assert hashed_paths == [payload]
    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(issue.message.startswith("Total scan size limit exceeded") for issue in result.issues)
    assert result.content_hash is None


def test_scan_model_streaming_stops_hashing_at_max_total_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.pkl"
    first.write_bytes(b"A" * 32)
    second = tmp_path / "second.pkl"
    second.write_bytes(b"B" * 33)
    third = tmp_path / "third.pkl"
    third.write_bytes(b"C")
    hashed_paths: list[Path] = []
    first_hash = "a" * 64

    def track_hash(path: Path) -> str:
        hashed_paths.append(path)
        return first_hash

    monkeypatch.setattr("modelaudit.utils.helpers.file_hash.compute_sha256_hash", track_hash)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result(bytes_scanned=1))

    result = scan_model_streaming(
        file_generator=iter([(first, False), (second, False), (third, True)]),
        timeout=30,
        delete_after_scan=False,
        max_total_size=64,
        cache_enabled=False,
    )

    assert hashed_paths == [first, second]
    assert result.files_scanned == 3
    assert result.content_hash is None
    assert result.success is True


def test_scan_model_streaming_content_hash_deterministic():
    """Test that content hash is deterministic for same files."""
    # Create two files with same content
    files1 = []
    files2 = []

    for _i in range(2):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("Same content")
            files1.append(Path(tmp.name))

    for _i in range(2):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("Same content")
            files2.append(Path(tmp.name))

    try:

        def gen1():
            for i, f in enumerate(files1):
                yield (f, i == len(files1) - 1)

        def gen2():
            for i, f in enumerate(files2):
                yield (f, i == len(files2) - 1)

        with patch("modelaudit.core.scan_file") as mock_scan:
            mock_scan.side_effect = [create_mock_scan_result() for _ in files1 + files2]

            result1 = scan_model_streaming(file_generator=gen1(), timeout=30, delete_after_scan=False)
            result2 = scan_model_streaming(file_generator=gen2(), timeout=30, delete_after_scan=False)

            # Same content should produce same hash
            assert result1.content_hash == result2.content_hash

    finally:
        for file_path in files1 + files2:
            if file_path.exists():
                file_path.unlink()


def test_scan_model_streaming_keeps_member_hashes_separate_from_parent(tmp_path: Path) -> None:
    benign_payload = pickle.dumps({"safe": "stream"})
    malicious_payload = pickle.dumps(_StreamingMaliciousPicklePayload())
    model_path = _create_streaming_pytorch_zip(
        tmp_path / "streamed.pt",
        {
            "data.pkl": benign_payload,
            "evil.pkl": malicious_payload,
        },
    )
    outer_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    malicious_hash = hashlib.sha256(malicious_payload).hexdigest()

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    metadata = result.file_metadata[str(model_path)].model_dump(mode="json", exclude_none=True)
    assert result.content_hash == compute_aggregate_hash([outer_hash])
    assert metadata["file_hashes"]["sha256"] == outer_hash
    malicious_record = _streaming_member_record(metadata, ["evil.pkl"])
    assert malicious_record["file_hashes"]["sha256"] == malicious_hash
    assert malicious_record["file_hashes"]["sha256"] != outer_hash
    assert any(
        issue.location is not None
        and ":evil.pkl" in issue.location
        and issue.details.get("pickle_filename") == "evil.pkl"
        for issue in result.issues
    )


def test_scan_model_streaming_empty_generator():
    """Test streaming scan with empty file generator."""

    def empty_generator():
        return
        yield  # Make it a generator

    result = scan_model_streaming(
        file_generator=empty_generator(),
        timeout=30,
        delete_after_scan=True,
    )

    # Should complete without errors but with no results
    assert result.files_scanned == 0
    assert result.bytes_scanned == 0
    assert result.content_hash is None or result.content_hash == compute_aggregate_hash([])


def test_scan_model_streaming_timeout_closes_generator_and_deletes_yielded_file(tmp_path: Path) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    generator_closed = False
    clock_calls = 0

    def fake_time() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 1.0

    def file_generator() -> Iterator[tuple[Path, bool]]:
        nonlocal generator_closed
        try:
            yield (streamed_file, True)
        finally:
            generator_closed = True

    retained_generator = file_generator()
    with (
        patch("modelaudit.core.time.time", side_effect=fake_time),
        patch("modelaudit.core.scan_file") as mock_scan,
    ):
        result = scan_model_streaming(
            file_generator=retained_generator,
            timeout=0,
            delete_after_scan=True,
        )

    assert result.has_errors is True
    assert result.success is False
    assert generator_closed is True
    assert not streamed_file.exists()
    mock_scan.assert_not_called()


def test_scan_model_streaming_timeout_omits_successful_prefix_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.pkl"
    second = tmp_path / "second.pkl"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    now = [0.0]

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield first, False
        now[0] = 2.0
        yield second, True

    monkeypatch.setattr("modelaudit.core.time.time", lambda: now[0])
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result())

    result = scan_model_streaming(
        file_generator=file_generator(),
        timeout=1,
        delete_after_scan=False,
    )

    assert result.files_scanned == 1
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert result.content_hash is None


def test_scan_model_streaming_interruption_closes_generator_and_deletes_yielded_file(tmp_path: Path) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    generator_closed = False

    def file_generator() -> Iterator[tuple[Path, bool]]:
        nonlocal generator_closed
        try:
            yield (streamed_file, True)
        finally:
            generator_closed = True

    retained_generator = file_generator()
    with (
        patch("modelaudit.core.check_interrupted", side_effect=KeyboardInterrupt("interrupted")),
        pytest.raises(KeyboardInterrupt, match="interrupted"),
    ):
        scan_model_streaming(
            file_generator=retained_generator,
            delete_after_scan=True,
        )

    assert generator_closed is True
    assert not streamed_file.exists()


def test_scan_model_streaming_delete_failure_is_operational_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    original_unlink = Path.unlink

    def fail_streamed_unlink(path: Path, missing_ok: bool = False) -> None:
        if path == streamed_file:
            raise PermissionError("delete denied")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_streamed_unlink)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result())

    result = scan_model_streaming(
        file_generator=iter([(streamed_file, True)]),
        delete_after_scan=True,
    )

    assert streamed_file.exists()
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.location == str(streamed_file)
        and issue.details.get("operational_error") is True
        and "delete denied" in issue.message
        for issue in result.issues
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX retained descriptor cleanup semantics")
def test_scan_model_streaming_cleanup_rejects_pre_unlink_generation_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleanup cannot mark a replacement deletion as the scanned generation."""
    source_root = tmp_path / "source"
    source_root.mkdir()
    streamed_file = source_root / "streamed.pkl"
    streamed_file.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    held_original = tmp_path / "held-original.pkl"
    replacement_payload = pickle.dumps({"weights": [4, 5, 6]})
    original_unlink = Path.unlink
    swapped = False

    def swap_before_unlink(path: Path, missing_ok: bool = False) -> None:
        nonlocal swapped
        same_source = False
        if not swapped:
            with suppress(OSError):
                same_source = os.path.samefile(path, streamed_file)
        if same_source:
            streamed_file.rename(held_original)
            streamed_file.write_bytes(replacement_payload)
            swapped = True
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", swap_before_unlink)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(str(source_root)),
        scan_root=str(source_root),
        timeout=30,
        delete_after_scan=True,
        cache_enabled=False,
        scanners=["pickle"],
        skip_file_types=False,
    )

    assert swapped is True
    assert held_original.exists()
    assert not streamed_file.exists()
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.name == "Local Source Boundary Check" for check in result.checks)


def test_scan_model_streaming_accepts_generator_fallback_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    original_unlink = Path.unlink

    def file_generator() -> Iterator[tuple[Path, bool]]:
        try:
            yield streamed_file, True
        finally:
            original_unlink(streamed_file)

    def fail_streamed_unlink(path: Path, missing_ok: bool = False) -> None:
        if path == streamed_file:
            raise PermissionError("delete denied")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_streamed_unlink)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result())

    result = scan_model_streaming(
        file_generator=file_generator(),
        delete_after_scan=True,
    )

    assert not streamed_file.exists()
    assert result.has_errors is False
    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any("Failed to delete streamed source" in issue.message for issue in result.issues)


def test_scan_model_streaming_close_failure_is_operational_error(tmp_path: Path) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")

    class CloseFails(Iterator[tuple[Path, bool]]):
        def __init__(self) -> None:
            self.yielded = False

        def __next__(self) -> tuple[Path, bool]:
            if self.yielded:
                raise StopIteration
            self.yielded = True
            return streamed_file, True

        def close(self) -> None:
            raise OSError("close failed")

    with patch("modelaudit.core.scan_file", return_value=create_mock_scan_result()):
        result = scan_model_streaming(
            file_generator=CloseFails(),
            delete_after_scan=False,
        )

    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.message == "Failed to close streaming file generator: close failed"
        and issue.details.get("operational_error") is True
        for issue in result.issues
    )


def test_scan_model_streaming_scan_error_handling(temp_test_files: list[Path]) -> None:
    """Test that scan errors are handled gracefully in streaming mode."""

    def file_generator():
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        # First file succeeds, second fails, third succeeds
        mock_scan.side_effect = [
            create_mock_scan_result(),
            Exception("Scan failed"),
            create_mock_scan_result(),
        ]

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # Should have errors flag set
        assert result.has_errors is True
        # Should have scanned 2 files (1st and 3rd)
        assert result.files_scanned == 2
        assert result.content_hash is None


@pytest.mark.slow
def test_scan_model_streaming_timeout():
    """Test that timeout is respected in streaming mode."""
    # Create multiple files to trigger timeout between scans
    temp_files = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(f"Test {i}")
            temp_files.append(Path(f.name))

    try:

        def slow_generator():
            for i, f in enumerate(temp_files):
                yield (f, i == len(temp_files) - 1)

        with patch("modelaudit.core.scan_file") as mock_scan:
            # Make each scan take 0.5 seconds (3 files = 1.5s total)
            def slow_scan(*args, **kwargs):
                time.sleep(0.5)
                return create_mock_scan_result()

            mock_scan.side_effect = slow_scan

            # Set timeout to 1 second (should complete 1-2 files, then timeout)
            result = scan_model_streaming(
                file_generator=slow_generator(),
                timeout=1,  # 1 second timeout
                delete_after_scan=False,
            )

            # Should timeout and have errors
            assert result.has_errors is True
            # Should have scanned at least 1 file but not all 3
            assert 1 <= result.files_scanned < 3

    finally:
        for file_path in temp_files:
            if file_path.exists():
                file_path.unlink()


def test_compute_aggregate_hash_empty_list():
    """Test aggregate hash computation with empty list."""
    result = compute_aggregate_hash([])
    # Should return hash of empty string
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert result == expected


def test_compute_aggregate_hash_single_hash():
    """Test aggregate hash computation with single hash."""
    file_hash = "a" * 64  # Mock SHA256 hash
    result = compute_aggregate_hash([file_hash])
    assert len(result) == 64
    assert result != file_hash  # Should be different (hash of hash)


def test_compute_aggregate_hash_multiple_hashes():
    """Test aggregate hash computation with multiple hashes."""
    hashes = [
        "a" * 64,
        "b" * 64,
        "c" * 64,
    ]
    result = compute_aggregate_hash(hashes)
    assert len(result) == 64


def test_compute_aggregate_hash_order_independence():
    """Test that aggregate hash is order-independent (sorted)."""
    hashes = ["aaa", "bbb", "ccc"]
    reversed_hashes = ["ccc", "bbb", "aaa"]

    result1 = compute_aggregate_hash(hashes)
    result2 = compute_aggregate_hash(reversed_hashes)

    # Should be the same (sorted internally)
    assert result1 == result2


def test_scan_model_streaming_progress_callback(temp_test_files: list[Path]) -> None:
    """Test that progress callback is called during streaming scan."""
    progress_calls: list[tuple[str, float]] = []

    def progress_callback(message: str, percentage: float) -> None:
        progress_calls.append((message, percentage))

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for i, file_path in enumerate(temp_test_files):
            yield (file_path, i == len(temp_test_files) - 1)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [create_mock_scan_result() for _ in temp_test_files]

        scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            progress_callback=progress_callback,
            delete_after_scan=False,
        )

        # Should have received progress updates
        assert len(progress_calls) > 0
        # Should have both hashing and scanning messages
        messages = [msg for msg, _ in progress_calls]
        assert any("Hashing" in msg for msg in messages)
        assert any("Scanning" in msg for msg in messages)


def test_scan_model_streaming_asset_creation(temp_test_files: list[Path]) -> None:
    """Test that assets are created during streaming scan."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for i, file_path in enumerate(temp_test_files):
            yield (file_path, i == len(temp_test_files) - 1)

    with (
        patch("modelaudit.core.scan_file") as mock_scan,
        patch("modelaudit.utils.helpers.assets.asset_from_scan_result") as mock_asset,
    ):
        mock_scan.side_effect = [create_mock_scan_result() for _ in temp_test_files]

        # Mock asset creation
        mock_asset.return_value = {
            "path": "test",
            "type": "test",
            "size": 100,
        }

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # asset_from_scan_result should be called for each file
        assert result.success is True
        assert result.files_scanned == len(temp_test_files)
        assert mock_asset.call_count == 3
        assert result.assets
        assert all(asset.is_streamed is True for asset in result.assets)
