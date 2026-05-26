import bz2
import gzip
import importlib
import io
import json
import lzma
import pickle
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import cast

import pytest

from modelaudit.scanner_registry_metadata import get_extension_format_map
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.detection import (
    FLAX_MSGPACK_STRUCTURE_READ_BYTES,
    NEMO_ROUTING_INCONCLUSIVE_FORMAT,
    PROTO0_1_MAX_PROBE_BYTES,
    XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
    detect_file_format,
    detect_file_format_for_skip_filter,
    detect_file_format_from_magic,
    detect_format_from_extension,
    find_sharded_files,
    is_zipfile,
    validate_file_type,
)
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from tests.helpers import create_mock_mxnet_symbol, create_mock_onnx
from tests.helpers.file_creators import create_v7_tar_archive


def _ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def _ubjson_string(value: bytes) -> bytes:
    return b"SL" + len(value).to_bytes(8, byteorder="big", signed=True) + value


def _create_mar_archive(
    tmp_path: Path,
    manifest_bytes: bytes | None,
    *,
    filename: str = "model.mar",
) -> Path:
    mar_path = tmp_path / filename
    with zipfile.ZipFile(mar_path, "w") as archive:
        if manifest_bytes is not None:
            archive.writestr("MAR-INF/MANIFEST.json", manifest_bytes)
        archive.writestr("handler.py", b"def handle(data, context):\n    return data\n")
        archive.writestr("weights.bin", b"weights")
    return mar_path


def _build_tf_metagraph_bytes() -> bytes:
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph.meta_info_def.meta_graph_version = "test_meta_graph"
    metagraph.meta_info_def.tags.append("serve")
    node = metagraph.graph_def.node.add()
    node.name = "const_node"
    node.op = "Const"
    return cast(bytes, metagraph.SerializeToString())


def test_detect_file_format_directory(tmp_path):
    """Test detecting a directory format."""
    # Create a regular directory
    regular_dir = tmp_path / "regular_dir"
    regular_dir.mkdir()

    # Create a TensorFlow SavedModel directory
    tf_dir = tmp_path / "tf_dir"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    # Test detection
    assert detect_file_format(str(regular_dir)) == "directory"
    assert detect_file_format(str(tf_dir)) == "tensorflow_directory"


def test_detect_file_format_large_directory(tmp_path):
    """Ensure detection short-circuits in directories with many files."""
    tf_dir = tmp_path / "tf_large"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    for i in range(1000):
        (tf_dir / f"file_{i}.txt").write_text("x")

    assert detect_file_format(str(tf_dir)) == "tensorflow_directory"


def test_detect_file_format_zip(tmp_path):
    """Test detecting a ZIP file format."""
    # Create a ZIP file
    zip_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("test.txt", "test content")

    assert detect_file_format(str(zip_path)) == "zip"


def test_detect_large_renamed_flax_msgpack_by_later_root_without_promoting_generic_map(tmp_path: Path) -> None:
    msgpack = pytest.importorskip("msgpack")
    disguised_checkpoint = tmp_path / "checkpoint.jpg"
    generic_map = tmp_path / "metadata.jpg"
    large_metadata = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
    disguised_checkpoint.write_bytes(
        msgpack.packb({"metadata": large_metadata, "params": {"w": [1, 2, 3]}}, use_bin_type=True)
    )
    generic_map.write_bytes(
        msgpack.packb(
            {"metadata": large_metadata, "state": {"selected": True}, "__reduce__": "os.system"}, use_bin_type=True
        )
    )

    assert detect_file_format_from_magic(str(disguised_checkpoint)) == "flax_msgpack"
    assert detect_file_format_for_skip_filter(str(disguised_checkpoint)) == "flax_msgpack"
    assert detect_file_format(str(disguised_checkpoint)) == "flax_msgpack"
    assert detect_file_format_from_magic(str(generic_map)) == "unknown"
    assert detect_file_format_for_skip_filter(str(generic_map)) == "unknown"
    assert detect_file_format(str(generic_map)) == "unknown"


def test_detect_renamed_flax_state_wrapper_with_checkpoint_root_without_promoting_generic_state(tmp_path: Path) -> None:
    msgpack = pytest.importorskip("msgpack")
    disguised_checkpoint = tmp_path / "checkpoint.jpg"
    generic_map = tmp_path / "metadata.jpg"
    disguised_checkpoint.write_bytes(
        msgpack.packb({"state": {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}}, use_bin_type=True)
    )
    generic_map.write_bytes(msgpack.packb({"state": {"selected": True}, "__reduce__": "os.system"}, use_bin_type=True))

    assert detect_file_format_from_magic(str(disguised_checkpoint)) == "flax_msgpack"
    assert detect_file_format_for_skip_filter(str(disguised_checkpoint)) == "flax_msgpack"
    assert detect_file_format(str(disguised_checkpoint)) == "flax_msgpack"
    assert detect_file_format_from_magic(str(generic_map)) == "unknown"
    assert detect_file_format_for_skip_filter(str(generic_map)) == "unknown"
    assert detect_file_format(str(generic_map)) == "unknown"


def test_detect_python_source_member_does_not_route_as_renamed_flax_msgpack(tmp_path: Path) -> None:
    source_near_match = tmp_path / "handler.py"
    source_near_match.write_text("import os\nos.system('echo hidden')\n" + ("# pad\n" * 10_000), encoding="utf-8")

    assert detect_file_format_from_magic(str(source_near_match)) == "unknown"
    assert detect_file_format_for_skip_filter(str(source_near_match)) == "unknown"
    assert detect_file_format(str(source_near_match)) == "unknown"


def test_detect_large_inline_scalar_stream_does_not_route_as_renamed_flax_msgpack(tmp_path: Path) -> None:
    ordinary_data = tmp_path / "bulk-data.dat"
    ordinary_data.write_bytes(b"A" * FLAX_MSGPACK_STRUCTURE_READ_BYTES)

    assert detect_file_format_from_magic(str(ordinary_data)) == "unknown"
    assert detect_file_format_for_skip_filter(str(ordinary_data)) == "unknown"
    assert detect_file_format(str(ordinary_data)) == "unknown"


def test_detect_file_format_rejects_pk_prefix_near_match(tmp_path: Path) -> None:
    near_match = tmp_path / "not-a-zip.dat"
    near_match.write_bytes(b"PKNOPE harmless text")

    assert is_zipfile(str(near_match)) is False
    assert detect_file_format_from_magic(str(near_match)) == "unknown"
    assert detect_file_format(str(near_match)) == "unknown"


def test_detect_file_format_accepts_prefixed_zip_with_central_directory_stub(tmp_path: Path) -> None:
    prefixed_zip = tmp_path / "prefixed.zip"
    with zipfile.ZipFile(prefixed_zip, "w") as archive:
        archive.writestr("payload.txt", "hello")
    prefixed_zip.write_bytes(b"PK\x01\x02stub-prefix" + prefixed_zip.read_bytes())

    assert is_zipfile(str(prefixed_zip)) is True
    assert detect_file_format_from_magic(str(prefixed_zip)) == "zip"
    assert detect_file_format(str(prefixed_zip)) == "zip"


def test_detect_valid_torchserve_mar_by_magic_and_validation(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        b'{"model":{"handler":"handler.py","serializedFile":"weights.bin"}}',
    )

    assert detect_file_format(str(mar_path)) == "torchserve_mar"
    assert detect_file_format_from_magic(str(mar_path)) == "torchserve_mar"
    assert validate_file_type(str(mar_path)) is True


def test_detect_non_torchserve_mar_falls_back_to_zip_validation(tmp_path: Path) -> None:
    mar_path = _create_mar_archive(
        tmp_path,
        b'{"model":{"handler":"handler.py","serializedFile":"weights.bin"',
        filename="invalid_manifest.mar",
    )

    assert detect_file_format(str(mar_path)) == "zip"
    assert detect_file_format_from_magic(str(mar_path)) == "zip"
    assert validate_file_type(str(mar_path)) is False


def test_detect_file_format_by_extension(tmp_path):
    """Test detecting file format by extension."""
    extensions = {
        ".pt": "pickle",  # .pt files are now treated as pickle files
        ".pth": "pickle",  # .pth files are now treated as pickle files
        ".bin": "pytorch_binary",  # .bin files with generic content are now pytorch_binary
        ".ckpt": "pickle",  # .ckpt files are now treated as pickle files
        ".pkl": "pickle",
        ".pickle": "pickle",
        ".dill": "pickle",  # .dill files are treated as pickle files
        # CNTK detection is signature-based to avoid misclassifying arbitrary .dnn/.cmf files
        ".dnn": "unknown",
        ".cmf": "unknown",
        ".msgpack": "flax_msgpack",
        ".params": "mxnet",
        ".h5": "hdf5",
        ".pb": "protobuf",
        ".tflite": "tflite",
        ".mar": "unknown",
        ".cbm": "catboost",
        ".mlmodel": "coreml",
        ".llamafile": "llamafile",
        ".rknn": "rknn",
        ".rds": "r_serialized",
        ".rda": "r_serialized",
        ".rdata": "r_serialized",
        ".rar": "unknown",
        ".unknown": "unknown",
    }

    for ext, expected_format in extensions.items():
        test_file = tmp_path / f"test{ext}"
        test_file.write_bytes(b"test content")
        assert detect_file_format(str(test_file)) == expected_format


def test_detect_file_format_hdf5(tmp_path):
    """Test detecting HDF5 format by magic bytes."""
    # Create a file with HDF5 magic bytes
    hdf5_path = tmp_path / "test.dat"
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    hdf5_path.write_bytes(hdf5_magic + b"additional content")

    assert detect_file_format(str(hdf5_path)) == "hdf5"


def test_detect_file_format_from_magic_valid_safetensors_structure(tmp_path: Path) -> None:
    metadata = b'{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    safetensors_path = tmp_path / "model.unknown"
    safetensors_path.write_bytes(struct.pack("<Q", len(metadata)) + metadata + b"\x00\x00\x00\x00")

    assert detect_file_format_from_magic(str(safetensors_path)) == "safetensors"


def test_detect_file_format_from_magic_metadata_only_safetensors_structure(tmp_path: Path) -> None:
    metadata = b"{}"
    safetensors_path = tmp_path / "metadata-only.unknown"
    safetensors_path.write_bytes(struct.pack("<Q", len(metadata)) + metadata)

    assert detect_file_format_from_magic(str(safetensors_path)) == "safetensors"
    assert detect_file_format(str(safetensors_path)) == "safetensors"


def test_detect_file_format_from_magic_json_not_misrouted_as_safetensors(tmp_path: Path) -> None:
    json_path = tmp_path / "config.unknown"
    json_path.write_text('{"name":"model","version":1}', encoding="utf-8")

    assert detect_file_format_from_magic(str(json_path)) == "unknown"
    assert detect_file_format(str(json_path)) == "unknown"


def test_detect_file_format_from_magic_proto0_pickle_not_misrouted_as_safetensors(tmp_path: Path) -> None:
    pickle_path = tmp_path / "payload.unknown"
    pickle_path.write_bytes(b"{cposix\nsystem\n(S'echo pwned'\ntR.")

    assert detect_file_format_from_magic(str(pickle_path)) != "safetensors"
    assert detect_file_format(str(pickle_path)) != "safetensors"


def test_detect_file_format_from_magic_malformed_safetensors_header_len_rejected(tmp_path: Path) -> None:
    malformed_path = tmp_path / "malformed.unknown"
    malformed_path.write_bytes(struct.pack("<Q", 100 * 1024 * 1024) + b'{"x":1}' + b"\x00" * 16)

    assert detect_file_format_from_magic(str(malformed_path)) == "unknown"


def test_detect_file_format_from_magic_invalid_safetensors_json_rejected(tmp_path: Path) -> None:
    malformed_path = tmp_path / "invalid-header.unknown"
    malformed_path.write_bytes(struct.pack("<Q", 1) + b"{" + b"\x00")

    assert detect_file_format_from_magic(str(malformed_path)) == "unknown"


def test_detect_file_format_coreml_validation_passthrough(tmp_path: Path) -> None:
    """CoreML extension routing should remain scanner-level validated."""
    model_path = tmp_path / "model.mlmodel"
    model_path.write_bytes(b"not-a-real-protobuf")

    assert detect_file_format(str(model_path)) == "coreml"
    assert detect_format_from_extension(str(model_path)) == "coreml"
    assert validate_file_type(str(model_path)) is True


def test_detect_file_format_onnx_pb_content_hint_preempts_protobuf_extension(tmp_path: Path) -> None:
    """ONNX protobuf payloads renamed to .pb should route to ONNX, not TensorFlow protobuf."""
    pytest.importorskip("onnx")
    model_path = tmp_path / "model.pb"
    create_mock_onnx(model_path)

    assert detect_file_format(str(model_path)) == "onnx"
    assert detect_file_format_from_magic(str(model_path)) == "onnx"
    assert validate_file_type(str(model_path)) is True


def test_detect_file_format_rejects_incidental_onnx_pb_string(tmp_path: Path) -> None:
    """A generic protobuf string value mentioning ONNX must not route as ONNX."""
    model_path = tmp_path / "metadata.pb"
    model_path.write_bytes(bytes([0x0A, 0x04]) + b"onnx" + b"\x00" * 16)

    assert detect_file_format(str(model_path)) == "protobuf"
    assert detect_file_format_from_magic(str(model_path)) == "unknown"
    assert validate_file_type(str(model_path)) is True


def test_detect_file_format_rejects_benign_onnx_token_near_match(tmp_path: Path) -> None:
    """Plain text mentioning ONNX must not route to the ONNX scanner."""
    model_path = tmp_path / "note.payload"
    model_path.write_bytes(b"this documentation mentions onnx but is not a model")

    assert detect_file_format(str(model_path)) == "unknown"
    assert detect_file_format_from_magic(str(model_path)) == "unknown"
    assert validate_file_type(str(model_path)) is True


def test_detect_file_format_rar_magic(tmp_path: Path) -> None:
    """RAR archives should be recognized for fail-closed scanner routing."""
    rar4_path = tmp_path / "archive-rar4.payload"
    rar4_path.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 32)
    rar5_path = tmp_path / "archive-rar5.payload"
    rar5_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)

    assert detect_file_format(str(rar4_path)) == "rar"
    assert detect_file_format_from_magic(str(rar4_path)) == "rar"
    assert detect_file_format(str(rar5_path)) == "rar"
    assert detect_file_format_from_magic(str(rar5_path)) == "rar"


def test_detect_file_format_rejects_rar_magic_near_match(tmp_path: Path) -> None:
    """RAR routing should require a complete RAR4/RAR5 signature."""
    near_match = tmp_path / "archive.payload"
    near_match.write_bytes(b"Rar!\x1a\x07ZZ" + b"\x00" * 32)

    assert detect_file_format(str(near_match)) == "unknown"
    assert detect_file_format_from_magic(str(near_match)) == "unknown"


def test_detect_format_from_extension_mxnet_symbol(tmp_path: Path) -> None:
    """MXNet symbol files should be detected by filename pattern."""
    symbol_path = tmp_path / "resnet-symbol.json"
    symbol_path.write_text('{"nodes":[{"op":"null","name":"data","inputs":[]}],"arg_nodes":[0],"heads":[[0,0,0]]}')

    assert detect_format_from_extension(str(symbol_path)) == "mxnet"


def test_detect_file_format_routes_renamed_mxnet_symbol_and_rejects_near_match(tmp_path: Path) -> None:
    model_path = create_mock_mxnet_symbol(tmp_path / "model.jpg")
    near_match = tmp_path / "graph.jpg"
    near_match.write_text(
        '{"nodes":[{"op":"Custom"}],"arg_nodes":[],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    assert detect_file_format(str(model_path)) == "mxnet"
    assert detect_file_format_from_magic(str(model_path)) == "mxnet"
    assert detect_file_format_for_skip_filter(str(model_path)) == "mxnet"
    assert detect_file_format(str(near_match)) == "unknown"
    assert detect_file_format_from_magic(str(near_match)) == "unknown"
    assert detect_file_format_for_skip_filter(str(near_match)) == "unknown"


def test_detect_file_format_routes_renamed_mxnet_after_leading_whitespace(tmp_path: Path) -> None:
    model_path = tmp_path / "whitespace.jpg"
    model_path.write_text(
        (" " * 1024) + '{"nodes":[{"op":"null","name":"data"}],"arg_nodes":[0],"heads":[[0,0,0]]}',
        encoding="utf-8",
    )

    assert detect_file_format(str(model_path)) == "mxnet"
    assert detect_file_format_for_skip_filter(str(model_path)) == "mxnet"


def test_detect_oversized_renamed_mxnet_requires_top_level_graph_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
    padding = "x" * 256
    delayed_nodes = tmp_path / "delayed-nodes.jpg"
    delayed_nodes.write_text(
        '{"arg_nodes":[0],"heads":[[0,0,0]],"nodes":[{"attrs":"' + padding + '","op":"Custom","name":"load"}]}',
        encoding="utf-8",
    )
    unrelated = tmp_path / "unrelated.jpg"
    unrelated.write_text(
        '{"nodes":[],"op":"Custom","name":"load","attrs":"' + padding + '"}',
        encoding="utf-8",
    )
    nested_markers = tmp_path / "nested-markers.jpg"
    nested_markers.write_text(
        '{"metadata":{"nodes":[],"arg_nodes":[],"heads":[]},"padding":"' + padding + '"}',
        encoding="utf-8",
    )
    string_markers = tmp_path / "string-markers.jpg"
    string_markers.write_text(
        '{"description":"\\"nodes\\": [] \\"arg_nodes\\": [] \\"heads\\": []","padding":"' + padding + '"}',
        encoding="utf-8",
    )

    assert detect_file_format(str(delayed_nodes)) == "mxnet"
    assert detect_file_format_for_skip_filter(str(delayed_nodes)) == "mxnet"
    assert detect_file_format(str(unrelated)) == "unknown"
    assert detect_file_format_for_skip_filter(str(unrelated)) == "unknown"
    assert detect_file_format(str(nested_markers)) == "unknown"
    assert detect_file_format_for_skip_filter(str(nested_markers)) == "unknown"
    assert detect_file_format(str(string_markers)) == "unknown"
    assert detect_file_format_for_skip_filter(str(string_markers)) == "unknown"


def test_detect_r_serialized_magic_headers(tmp_path: Path) -> None:
    rds = tmp_path / "model.rds"
    rds.write_bytes(b"RDX3\n" + b"\x00" * 20)
    assert detect_file_format_from_magic(str(rds)) == "r_serialized"
    assert detect_file_format(str(rds)) == "r_serialized"
    assert validate_file_type(str(rds)) is True


def test_detect_cntk_formats_by_signature(tmp_path: Path) -> None:
    legacy_path = tmp_path / "legacy.dnn"
    legacy_path.write_bytes(
        b"B\x00C\x00N\x00\x00\x00" + b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00" + b"inputs outputs"
    )
    assert detect_format_from_extension(str(legacy_path)) == "cntk"
    assert detect_file_format(str(legacy_path)) == "cntk"
    assert detect_file_format_from_magic(str(legacy_path)) == "cntk"

    v2_path = tmp_path / "graph.cmf"
    v2_path.write_bytes(
        b"\x0a\x07version\x12\x031.0\x12\x09\x0a\x03uid\x12\x02ab CompositeFunction primitive_functions"
    )
    assert detect_format_from_extension(str(v2_path)) == "cntk"
    assert detect_file_format(str(v2_path)) == "cntk"
    assert detect_file_format_from_magic(str(v2_path)) == "cntk"


def test_detect_renamed_cntk_by_strict_signature_only(tmp_path: Path) -> None:
    renamed = tmp_path / "graph.jpg"
    renamed.write_bytes(
        b"\x0a\x07version\x12\x031.0\x12\x09\x0a\x03uid\x12\x02ab CompositeFunction primitive_functions"
    )
    near_match = tmp_path / "notes.jpg"
    near_match.write_bytes(b"\x0a\x07version\x12\x031.0\x12\x09\x0a\x03uid\x12\x02ab")

    assert detect_file_format(str(renamed)) == "cntk"
    assert detect_file_format_from_magic(str(renamed)) == "cntk"
    assert detect_file_format(str(near_match)) == "unknown"
    assert detect_file_format_from_magic(str(near_match)) == "unknown"


def test_detect_cntk_model_extension_remains_excluded_for_xgboost_overlap(tmp_path: Path) -> None:
    deferred = tmp_path / "deferred.model"
    deferred.write_bytes(
        b"\x0a\x07version\x12\x031.0\x12\x09\x0a\x03uid\x12\x02ab CompositeFunction primitive_functions"
    )
    legacy_deferred = tmp_path / "legacy.model"
    legacy_deferred.write_bytes(
        b"B\x00C\x00N\x00\x00\x00" + b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00" + b"inputs outputs"
    )

    assert detect_file_format(str(deferred)) != "cntk"
    assert detect_file_format_from_magic(str(deferred)) != "cntk"
    assert detect_file_format(str(legacy_deferred)) != "cntk"
    assert detect_file_format_from_magic(str(legacy_deferred)) != "cntk"


def test_detect_renamed_lightgbm_by_strict_signature_only(tmp_path: Path) -> None:
    renamed = tmp_path / "tree.jpg"
    renamed.write_text(
        "tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        "tree_sizes=12\nTree=0\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n",
        encoding="utf-8",
    )
    near_match = tmp_path / "tree-notes.jpg"
    near_match.write_text("tree=0\nversion=v4\nnum_class=1\n", encoding="utf-8")

    assert detect_file_format(str(renamed)) == "lightgbm"
    assert detect_file_format_from_magic(str(renamed)) == "lightgbm"
    assert detect_file_format(str(near_match)) == "unknown"
    assert detect_file_format_from_magic(str(near_match)) == "unknown"


def test_detect_renamed_lightgbm_does_not_promote_embedded_model_text(tmp_path: Path) -> None:
    model_text = (
        "tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
        "tree_sizes=12\nTree=0\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"example": model_text}), encoding="utf-8")
    safetensors_path = tmp_path / "model.safetensors"
    header = json.dumps({"__metadata__": {"example": model_text}}).encode()
    safetensors_path.write_bytes(struct.pack("<Q", len(header)) + header)

    assert detect_file_format(str(config_path)) == "unknown"
    assert detect_file_format(str(safetensors_path)) == "safetensors"


def test_detect_tf_metagraph_by_strict_parse(tmp_path: Path) -> None:
    """Detect TensorFlow MetaGraph `.meta` files through strict protobuf parsing."""
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")

    metagraph_path = tmp_path / "graph.meta"
    metagraph_path.write_bytes(_build_tf_metagraph_bytes())

    assert detect_format_from_extension(str(metagraph_path)) == "tf_metagraph"
    assert detect_file_format(str(metagraph_path)) == "tf_metagraph"
    assert detect_file_format_from_magic(str(metagraph_path)) == "tf_metagraph"
    assert validate_file_type(str(metagraph_path)) is True


def test_detect_tf_metagraph_rejects_renamed_non_protobuf(tmp_path: Path) -> None:
    """Reject text or arbitrary data renamed with `.meta` extension."""
    fake_metagraph = tmp_path / "not_meta.meta"
    fake_metagraph.write_text("not a tensorflow metagraph", encoding="utf-8")

    assert detect_format_from_extension(str(fake_metagraph)) == "tf_metagraph"
    assert detect_file_format(str(fake_metagraph)) == "unknown"
    assert detect_file_format_from_magic(str(fake_metagraph)) == "unknown"
    assert validate_file_type(str(fake_metagraph)) is False


def test_detect_rknn_format_by_signature(tmp_path: Path) -> None:
    rknn_path = tmp_path / "model.rknn"
    rknn_path.write_bytes(b"RKNN\x01\x00\x00\x00runtime=rockchip\n")

    assert detect_format_from_extension(str(rknn_path)) == "rknn"
    assert detect_file_format(str(rknn_path)) == "rknn"
    assert detect_file_format_from_magic(str(rknn_path)) == "rknn"
    assert validate_file_type(str(rknn_path)) is True

    bad_rknn = tmp_path / "bad.rknn"
    bad_rknn.write_bytes(b"not-rknn-content")
    assert detect_file_format(str(bad_rknn)) == "rknn"
    assert detect_file_format_from_magic(str(bad_rknn)) == "unknown"
    assert validate_file_type(str(bad_rknn)) is False


def test_detect_torch7_formats_by_signature(tmp_path: Path) -> None:
    torch7_path = tmp_path / "model.t7"
    torch7_path.write_bytes(b"T7\x00\x00torch.FloatTensor nn.Sequential\n")

    assert detect_format_from_extension(str(torch7_path)) == "torch7"
    assert detect_file_format(str(torch7_path)) == "torch7"
    assert detect_file_format_from_magic(str(torch7_path)) == "torch7"
    assert validate_file_type(str(torch7_path)) is True


def test_torch7_magic_rejects_pytorch_source_markers(tmp_path: Path) -> None:
    source_path = tmp_path / "model.py"
    source_path.write_text("import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n")

    assert detect_file_format_from_magic(str(source_path)) == "unknown"


def test_torch7_magic_routes_ascii_serialized_models(tmp_path: Path) -> None:
    torch7_path = tmp_path / "ascii-model.t7"
    torch7_path.write_bytes(b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n")

    assert detect_file_format(str(torch7_path)) == "torch7"
    assert detect_file_format_from_magic(str(torch7_path)) == "torch7"
    assert validate_file_type(str(torch7_path)) is True


def test_torch7_content_routes_renamed_ascii_serialized_models(tmp_path: Path) -> None:
    torch7_path = tmp_path / "payload.jpg"
    torch7_path.write_bytes(b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n")
    near_match = tmp_path / "source.jpg"
    near_match.write_text("import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n")

    assert detect_file_format(str(torch7_path)) == "torch7"
    assert detect_file_format_from_magic(str(torch7_path)) == "torch7"
    assert detect_file_format(str(near_match)) == "unknown"
    assert detect_file_format_from_magic(str(near_match)) == "unknown"


@pytest.mark.parametrize("filename", ["payload.onnx", "payload.pt", "payload.gz", "payload.tar.gz"])
def test_torch7_content_takes_priority_over_recognized_suffix(tmp_path: Path, filename: str) -> None:
    torch7_path = tmp_path / filename
    torch7_path.write_bytes(b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n")

    assert detect_file_format(str(torch7_path)) == "torch7"
    assert detect_file_format_from_magic(str(torch7_path)) == "torch7"


@pytest.mark.parametrize(
    "embedded_signature",
    [
        b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
        + b" CompositeFunction primitive_functions ",
        (
            b"\x00tree=0\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=2\n"
            b"tree_sizes=12\nnum_leaves=2\nsplit_feature=0\nleaf_value=0.1 0.2\n"
        ),
    ],
    ids=["cntk", "lightgbm"],
)
def test_torch7_content_takes_priority_over_embedded_content_signatures(
    tmp_path: Path,
    embedded_signature: bytes,
) -> None:
    torch7_path = tmp_path / "mixed-payload.jpg"
    torch7_path.write_bytes(
        b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n" + embedded_signature
    )

    assert detect_file_format(str(torch7_path)) == "torch7"
    assert detect_file_format_from_magic(str(torch7_path)) == "torch7"


def test_torch7_magic_rejects_malformed_ascii_version_header(tmp_path: Path) -> None:
    source_path = tmp_path / "malformed-header.py"
    source_path.write_bytes(b"4\n1\n9\nV payload\n13\nnn.Sequential\n")

    assert detect_file_format_from_magic(str(source_path)) == "unknown"


def test_torch7_magic_keeps_binary_marker_only_routing(tmp_path: Path) -> None:
    torch7_path = tmp_path / "renamed.bin"
    torch7_path.write_bytes(b"\x01\x00torch.FloatTensor nn.Sequential\n")

    assert detect_file_format_from_magic(str(torch7_path)) == "torch7"


def test_torch7_markers_in_gzip_header_do_not_override_tar_archive(tmp_path: Path) -> None:
    tar_payload = io.BytesIO()
    with tarfile.open(fileobj=tar_payload, mode="w") as archive:
        info = tarfile.TarInfo("weights.bin")
        info.size = len(b"safe weights")
        archive.addfile(info, io.BytesIO(b"safe weights"))

    archive_path = tmp_path / "weights.tar.gz"
    with (
        archive_path.open("wb") as target,
        gzip.GzipFile(filename="torch_tensor", mode="wb", fileobj=target) as compressed,
    ):
        compressed.write(tar_payload.getvalue())

    assert detect_file_format(str(archive_path)) == "tar"


def test_detect_executorch_binary_requires_valid_flatbuffer_structure(tmp_path: Path) -> None:
    executorch_path = tmp_path / "program.pte"
    executorch_path.write_bytes(b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00")

    assert detect_file_format(str(executorch_path)) == "executorch"
    assert detect_file_format_from_magic(str(executorch_path)) == "executorch"
    assert validate_file_type(str(executorch_path)) is True

    fake_executorch_path = tmp_path / "fake-program.pte"
    fake_executorch_path.write_bytes(b"JUNKET12notflatbufferatall")

    assert detect_file_format(str(fake_executorch_path)) == "executorch"
    assert detect_file_format_from_magic(str(fake_executorch_path)) == "unknown"
    assert validate_file_type(str(fake_executorch_path)) is False

    fake_torch7 = tmp_path / "fake.t7"
    fake_torch7.write_text("not torch7")
    assert detect_file_format(str(fake_torch7)) == "unknown"
    assert detect_file_format_from_magic(str(fake_torch7)) == "unknown"
    assert validate_file_type(str(fake_torch7)) is False


def test_validate_executorch_rejects_polyglot_binary_zip(tmp_path: Path) -> None:
    polyglot_path = tmp_path / "polyglot.pte"
    polyglot_path.write_bytes(b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00")
    with zipfile.ZipFile(polyglot_path, "a") as archive:
        archive.writestr("payload.py", "print('evil')")

    assert detect_file_format(str(polyglot_path)) == "executorch"
    assert detect_file_format_from_magic(str(polyglot_path)) == "executorch"
    assert validate_file_type(str(polyglot_path)) is False


def test_detect_file_format_proto0_pickle_with_text_extension(tmp_path: Path) -> None:
    """Protocol 0 pickle payloads should be detected even with non-model extensions."""
    payload = tmp_path / "payload.txt"
    payload.write_bytes(b'cos\nsystem\n(S"echo pwned"\ntR.')

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_accepts_forward_compatible_binary_pickle_protocol(tmp_path: Path) -> None:
    """Future binary pickle protocol bumps should not fail extension validation."""
    payload = tmp_path / "future-protocol.pkl"
    payload.write_bytes(b"\x80\x06}.")

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"
    assert validate_file_type(str(payload)) is True


@pytest.mark.parametrize("filename", ["protocol1-binary-header", "protocol1-binary-header.bin"])
def test_detect_file_format_accepts_protocol1_binary_pickle_header(
    tmp_path: Path,
    filename: str,
) -> None:
    """Crafted protocol-1 PROTO headers should route to pickle scanning without suffix help."""
    payload = tmp_path / filename
    payload.write_bytes(b"\x80\x01}.")

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"
    assert validate_file_type(str(payload)) is True


def test_detect_file_format_proto0_pickle_with_single_comment_token_prefix(tmp_path: Path) -> None:
    """A single leading comment token should not suppress proto0 detection."""
    payload = tmp_path / "comment-prefixed-payload.txt"
    payload.write_bytes(b"#" + b'cos\nsystem\n(S"echo pwned"\ntR.')

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_proto0_mark_prefix_requires_structure(tmp_path: Path) -> None:
    """MARK + GLOBAL/INST prefixes should only match when structure is pickle-like."""
    non_pickle_payload = tmp_path / "not-pickle.txt"
    non_pickle_payload.write_bytes(b"(cat this is plain text")
    assert detect_file_format(str(non_pickle_payload)) != "pickle"
    assert detect_file_format_from_magic(str(non_pickle_payload)) != "pickle"

    pickle_like_payload = tmp_path / "mark-prefixed-pickle.txt"
    pickle_like_payload.write_bytes(b'(cos\nsystem\n(S"echo pwned"\ntR.')
    assert detect_file_format(str(pickle_like_payload)) == "pickle"
    assert detect_file_format_from_magic(str(pickle_like_payload)) == "pickle"


def test_detect_file_format_proto0_prefixed_pickle_with_extended_probe(tmp_path: Path) -> None:
    """Valid protocol 0 streams with non-trivial prefixes should still be detected."""
    payload = tmp_path / "prefixed-pickle.txt"
    payload.write_bytes(b'(lp0\n0cos\nsystem\n(S"echo pwned"\ntR.')

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_proto1_binint1_pop_prefixed_pickle(tmp_path: Path) -> None:
    """Protocol 1 BININT1/POP prefixes should not suppress pickle detection."""
    payload = tmp_path / "proto1-prefixed-pickle.txt"
    payload.write_bytes(b"K\x000cos\nsystem\n.")

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_prefixed_proto0_pickle_with_trailing_junk(tmp_path: Path) -> None:
    """Valid pickle streams with trivial prefixes stay detectable when junk follows STOP."""
    pickle_stream = b'(l0cos\nsystem\n(S"echo pwned"\ntR.JUNK'
    payload = tmp_path / "prefixed-proto0-trailing-junk.dat"
    payload.write_bytes(pickle_stream)

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_opcode_budget_padded_proto0_pickle(tmp_path: Path) -> None:
    """Large balanced trivial prefixes should not hide a later dangerous opcode."""
    pickle_stream = b"I0\n0" * 5000 + b'cos\nsystem\n(S"echo pwned"\ntR.'
    payload = tmp_path / "opcode-budget-padded-proto0-pickle.dat"
    payload.write_bytes(pickle_stream)

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_probe_boundary_prefixed_proto0_pickle(tmp_path: Path) -> None:
    """A valid pickle stream should stay detectable when STOP lands beyond the probe window."""
    pickle_stream = b"(t0" + b"I0\n0" * (PROTO0_1_MAX_PROBE_BYTES // 4 + 1) + b'cos\nsystem\n(S"echo pwned"\ntR.'
    payload = tmp_path / "probe-boundary-prefixed-proto0-pickle.dat"
    payload.write_bytes(pickle_stream)

    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_trivial_probe_boundary_prefix_not_pickle(tmp_path: Path) -> None:
    """Large no-STOP scalar opcode prefixes should not be treated as pickle by themselves."""
    payload = tmp_path / "probe-boundary-trivial-prefix-notes.txt"
    payload.write_bytes(b"I0\n0" * (PROTO0_1_MAX_PROBE_BYTES // 4 + 1))

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_exact_probe_boundary_prefix_without_stop_not_pickle(tmp_path: Path) -> None:
    """Exact-size malformed prefixes without STOP should not become pickle positives."""
    payload = tmp_path / "probe-boundary-prefix-without-stop.dat"
    payload.write_bytes(b"I0\n0" * (PROTO0_1_MAX_PROBE_BYTES // 4))

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_safe_proto1_pickle_with_trailing_junk_still_loads(tmp_path: Path) -> None:
    """Python ignores junk after STOP, so the probe should still classify these streams as pickle."""
    pickle_stream = pickle.dumps({"safe": 1}, protocol=1) + b"JUNK"
    payload = tmp_path / "safe-proto1-trailing-junk.dat"
    payload.write_bytes(pickle_stream)

    assert pickle.loads(pickle_stream) == {"safe": 1}
    assert detect_file_format(str(payload)) == "pickle"
    assert detect_file_format_from_magic(str(payload)) == "pickle"


def test_detect_file_format_plain_text_global_prefix_not_pickle(tmp_path: Path) -> None:
    """Plain text that begins with GLOBAL-like bytes should not be treated as pickle."""
    payload = tmp_path / "notes.txt"
    payload.write_bytes(b"c\nthis is plain text\nnot a pickle stream")

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_plain_text_binint1_prefix_not_pickle(tmp_path: Path) -> None:
    """Short plain text with a BININT1-looking prefix should not be treated as pickle."""
    payload = tmp_path / "binint1-prefixed-notes.txt"
    payload.write_bytes(b"K\x00not a pickle stream")

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_proto1_scalar_with_trailing_text_not_pickle(tmp_path: Path) -> None:
    """A trivial scalar pickle prefix with trailing text should not force pickle detection."""
    payload = tmp_path / "proto1-scalar-prefixed-notes.txt"
    payload.write_bytes(b"K\x00.not a pickle stream")

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_empty_tuple_with_trailing_text_not_pickle(tmp_path: Path) -> None:
    """A trivial tuple pickle prefix with trailing text should not force pickle detection."""
    payload = tmp_path / "empty-tuple-prefixed-notes.txt"
    payload.write_bytes(b").trailing text")

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_list_prefix_with_trailing_text_not_pickle(tmp_path: Path) -> None:
    """A trivial list preamble followed by plain text should remain a non-pickle near-match."""
    payload = tmp_path / "list-prefixed-notes.txt"
    payload.write_bytes(b"(l0.not a pickle stream")

    assert detect_file_format(str(payload)) != "pickle"
    assert detect_file_format_from_magic(str(payload)) != "pickle"


def test_detect_file_format_small_file(tmp_path):
    """Test detecting format of a very small file."""
    small_file = tmp_path / "small.dat"
    small_file.write_bytes(b"123")  # Less than 4 bytes

    assert detect_file_format(str(small_file)) == "unknown"


def test_is_zipfile(tmp_path):
    """Test the is_zipfile function."""
    # Create a ZIP file
    zip_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("test.txt", "test content")

    # Create a non-ZIP file
    non_zip_path = tmp_path / "not_a_zip.txt"
    non_zip_path.write_bytes(b"This is not a ZIP file")

    assert is_zipfile(str(zip_path)) is True
    assert is_zipfile(str(non_zip_path)) is False
    assert is_zipfile("nonexistent_file.zip") is False


def test_detect_file_format_tar(tmp_path):
    """Detect tar archives by signature without extra I/O."""
    tar_path = tmp_path / "archive.tar"
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name="test.txt")
        tar.addfile(info, io.BytesIO(b"content"))

    assert detect_file_format_from_magic(str(tar_path)) == "tar"
    assert detect_file_format(str(tar_path)) == "tar"


def test_detect_file_format_extensionless_legacy_tar_without_ustar(tmp_path: Path) -> None:
    """Legacy TAR headers without ustar magic should still route by checksum."""
    tar_path = create_v7_tar_archive(tmp_path / "legacy-archive")

    assert tar_path.read_bytes()[257:262] == b"\0" * 5
    assert tarfile.is_tarfile(tar_path) is True
    assert detect_file_format_from_magic(str(tar_path)) == "tar"
    assert detect_file_format(str(tar_path)) == "tar"


def test_detect_file_format_sevenzip(tmp_path: Path) -> None:
    """Detect 7z archives by signature and validate .7z extensions."""
    sevenzip_path = tmp_path / "archive.7z"
    sevenzip_path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)

    assert detect_file_format_from_magic(str(sevenzip_path)) == "sevenzip"
    assert detect_file_format(str(sevenzip_path)) == "sevenzip"
    assert detect_format_from_extension(str(sevenzip_path)) == "sevenzip"
    assert validate_file_type(str(sevenzip_path)) is True


def test_detect_file_format_compressed_wrappers(tmp_path: Path) -> None:
    gzip_path = tmp_path / "model.pkl.gz"
    gzip_path.write_bytes(gzip.compress(b"pickle-payload"))
    assert detect_file_format(str(gzip_path)) == "compressed"
    assert detect_file_format_from_magic(str(gzip_path)) == "gzip"
    assert detect_format_from_extension(str(gzip_path)) == "compressed"

    bz2_path = tmp_path / "model.bin.bz2"
    bz2_path.write_bytes(bz2.compress(b"weights"))
    assert detect_file_format(str(bz2_path)) == "compressed"
    assert detect_file_format_from_magic(str(bz2_path)) == "bzip2"

    xz_path = tmp_path / "model.bin.xz"
    xz_path.write_bytes(lzma.compress(b"weights"))
    assert detect_file_format(str(xz_path)) == "compressed"
    assert detect_file_format_from_magic(str(xz_path)) == "xz"

    zlib_path = tmp_path / "model.bin.zlib"
    zlib_path.write_bytes(zlib.compress(b"weights"))
    assert detect_file_format(str(zlib_path)) == "compressed"
    assert detect_file_format_from_magic(str(zlib_path)) == "zlib"


def test_detect_file_format_rejects_invalid_zlib_header_near_match(tmp_path: Path) -> None:
    zlib_path = tmp_path / "model.bin.zlib"
    zlib_path.write_bytes(b"\x78\x00not-a-zlib-stream")

    assert detect_file_format(str(zlib_path)) == "unknown"
    assert detect_file_format_from_magic(str(zlib_path)) == "unknown"
    assert validate_file_type(str(zlib_path)) is False


def test_detect_file_format_tar_wrappers_preserve_tar_routing(tmp_path: Path) -> None:
    tar_gz = tmp_path / "archive.tar.gz"
    tar_gz.write_bytes(gzip.compress(b"fake tar payload"))
    assert detect_file_format(str(tar_gz)) == "tar"
    assert detect_file_format_from_magic(str(tar_gz)) == "gzip"
    assert detect_format_from_extension(str(tar_gz)) == "tar"
    assert validate_file_type(str(tar_gz)) is True


def test_detect_file_format_disguised_compressed_tar_by_content(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive.bin"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("payload.bin")
        payload = b"payload"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    assert detect_file_format(str(archive_path)) == "tar"
    assert detect_file_format_from_magic(str(archive_path)) == "gzip"
    assert validate_file_type(str(archive_path)) is False


@pytest.mark.parametrize("config_name", ["model_config.yaml", "./model_config.yaml", "configs/../model_config.yaml"])
def test_detect_file_format_routes_renamed_nemo_archive_by_root_config(tmp_path: Path, config_name: str) -> None:
    archive_path = tmp_path / "model.jpg"
    with tarfile.open(archive_path, "w") as archive:
        info = tarfile.TarInfo(config_name)
        payload = b"model:\n  _target_: os.system\n"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    assert detect_file_format(str(archive_path)) == "nemo"
    assert detect_file_format_from_magic(str(archive_path)) == "nemo"
    assert detect_file_format_for_skip_filter(str(archive_path)) == "nemo"


@pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
@pytest.mark.parametrize(
    ("config_name", "payload_name"),
    [("model_config.yaml", "payload.txt"), ("configs/../model_config.yaml", "configs/../payload.txt")],
)
def test_detect_file_format_routes_renamed_nemo_archive_by_linked_root_config(
    tmp_path: Path,
    link_type: bytes,
    config_name: str,
    payload_name: str,
) -> None:
    archive_path = tmp_path / "linked-model.jpg"
    with tarfile.open(archive_path, "w") as archive:
        payload = b"model:\n  _target_: os.system\n"
        payload_info = tarfile.TarInfo(payload_name)
        payload_info.size = len(payload)
        archive.addfile(payload_info, io.BytesIO(payload))
        link_info = tarfile.TarInfo(config_name)
        link_info.type = link_type
        link_info.linkname = "payload.txt"
        archive.addfile(link_info)

    assert detect_file_format(str(archive_path)) == "nemo"
    assert detect_file_format_from_magic(str(archive_path)) == "nemo"
    assert detect_file_format_for_skip_filter(str(archive_path)) == "nemo"


def test_detect_file_format_keeps_forward_hardlink_root_config_on_tar_route(tmp_path: Path) -> None:
    archive_path = tmp_path / "forward-hardlink-model.jpg"
    with tarfile.open(archive_path, "w") as archive:
        link_info = tarfile.TarInfo("model_config.yaml")
        link_info.type = tarfile.LNKTYPE
        link_info.linkname = "payload.txt"
        archive.addfile(link_info)
        payload = b"model:\n  _target_: os.system\n"
        payload_info = tarfile.TarInfo("payload.txt")
        payload_info.size = len(payload)
        archive.addfile(payload_info, io.BytesIO(payload))

    assert detect_file_format(str(archive_path)) == "tar"
    assert detect_file_format_from_magic(str(archive_path)) == "tar"
    assert detect_file_format_for_skip_filter(str(archive_path)) == "tar"


@pytest.mark.parametrize(
    "config_name",
    [
        "docs/model_config.yaml",
        "/model_config.yaml",
        "../model_config.yaml",
        " model_config.yaml",
        "model_config.yaml ",
    ],
)
def test_detect_file_format_keeps_non_root_config_names_on_tar_route(tmp_path: Path, config_name: str) -> None:
    archive_path = tmp_path / "generic.jpg"
    with tarfile.open(archive_path, "w") as archive:
        info = tarfile.TarInfo(config_name)
        payload = b"model:\n  _target_: os.system\n"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    assert detect_file_format(str(archive_path)) == "tar"
    assert detect_file_format_from_magic(str(archive_path)) == "tar"
    assert detect_file_format_for_skip_filter(str(archive_path)) == "tar"


def test_detect_file_format_keeps_unsafe_linked_root_config_on_tar_route(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe-linked-generic.jpg"
    with tarfile.open(archive_path, "w") as archive:
        link_info = tarfile.TarInfo("model_config.yaml")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "../payload.txt"
        archive.addfile(link_info)

    assert detect_file_format(str(archive_path)) == "tar"
    assert detect_file_format_from_magic(str(archive_path)) == "tar"
    assert detect_file_format_for_skip_filter(str(archive_path)) == "tar"


def test_detect_file_format_bounds_late_linked_root_config_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.utils.file.detection._NEMO_ROUTE_MAX_ENTRIES", 2)
    archive_path = tmp_path / "late-linked-model.jpg"
    with tarfile.open(archive_path, "w") as archive:
        link_info = tarfile.TarInfo("model_config.yaml")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "payload.txt"
        archive.addfile(link_info)
        filler_info = tarfile.TarInfo("assets/filler.bin")
        filler_info.size = 1
        archive.addfile(filler_info, io.BytesIO(b"x"))
        payload = b"model:\n  _target_: os.system\n"
        payload_info = tarfile.TarInfo("payload.txt")
        payload_info.size = len(payload)
        archive.addfile(payload_info, io.BytesIO(payload))

    assert detect_file_format(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT


def test_detect_file_format_fails_closed_when_nemo_route_probe_limit_is_reached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.utils.file.detection._NEMO_ROUTE_MAX_ENTRIES", 2)
    archive_path = tmp_path / "large-generic.jpg"
    with tarfile.open(archive_path, "w") as archive:
        for name in ("one.bin", "two.bin", "three.bin"):
            info = tarfile.TarInfo(name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))

    assert detect_file_format(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT


def test_detect_file_format_propagates_inconclusive_compressed_nemo_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.utils.file.detection._NEMO_ROUTE_MAX_ENTRIES", 2)
    archive_path = tmp_path / "payload.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for name in ("one.bin", "two.bin", "model_config.yaml"):
            payload = b"x"
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    assert detect_file_format(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(archive_path)) == NEMO_ROUTING_INCONCLUSIVE_FORMAT


def test_detect_file_format_disguised_llamafile_by_content(tmp_path: Path) -> None:
    disguised_llamafile = tmp_path / "payload.jpg"
    disguised_llamafile.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"llamafile runtime")
    near_match = tmp_path / "tool.jpg"
    near_match.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"llama-file runtime")

    assert detect_file_format(str(disguised_llamafile)) == "llamafile"
    assert detect_file_format_from_magic(str(disguised_llamafile)) == "llamafile"
    assert detect_file_format(str(near_match)) == "unknown"
    assert detect_file_format_from_magic(str(near_match)) == "unknown"


def test_detect_file_format_routes_extensionless_xgboost_ubjson_by_structure(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + _ubjson_key(b"version")
        + b"[]"
        + b"}"
    )

    assert detect_file_format(str(model_file)) == "xgboost"
    assert detect_file_format_from_magic(str(model_file)) == "xgboost"
    assert detect_file_format_for_skip_filter(str(model_file)) == "xgboost"


def test_detect_file_format_routes_extensionless_xgboost_ubjson_with_noop_before_learner(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{"
        + _ubjson_key(b"learner")
        + b"N{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + _ubjson_key(b"version")
        + b"[]"
        + b"}"
    )

    assert detect_file_format(str(model_file)) == "xgboost"
    assert detect_file_format_from_magic(str(model_file)) == "xgboost"
    assert detect_file_format_for_skip_filter(str(model_file)) == "xgboost"


def test_detect_file_format_routes_extensionless_xgboost_ubjson_with_noop_before_counted_root_header(
    tmp_path: Path,
) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{N#U\x02"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + _ubjson_key(b"version")
        + b"[]"
    )

    assert detect_file_format(str(model_file)) == "xgboost"
    assert detect_file_format_from_magic(str(model_file)) == "xgboost"
    assert detect_file_format_for_skip_filter(str(model_file)) == "xgboost"


def test_detect_file_format_fails_closed_for_bounded_extensionless_xgboost_candidate(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"metadata")
        + _ubjson_string(b"x" * (256 * 1024))
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + b"}"
    )

    assert detect_file_format(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT


def test_detect_file_format_fails_closed_when_extensionless_xgboost_learner_is_past_budget(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{"
        + _ubjson_key(b"metadata")
        + _ubjson_string(b"x" * (256 * 1024))
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + b"}"
    )

    assert detect_file_format(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT


def test_detect_file_format_does_not_treat_plain_extensionless_json_as_xgboost_ubjson(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_text('{"kind":"manifest","safe":true}', encoding="utf-8")

    assert detect_file_format(str(model_file)) == "unknown"
    assert detect_file_format_from_magic(str(model_file)) == "unknown"
    assert detect_file_format_for_skip_filter(str(model_file)) == "unknown"


def test_detect_file_format_fails_closed_for_ubjson_noops_before_late_learner(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{"
        + (b"N" * (256 * 1024))
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + b"}"
    )

    assert detect_file_format(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT


def test_detect_file_format_fails_closed_for_ubjson_header_truncated_at_budget(tmp_path: Path) -> None:
    model_file = tmp_path / "model"
    model_file.write_bytes(
        b"{"
        + (b"N" * ((256 * 1024) - 2))
        + b"#U\x01"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
    )

    assert detect_file_format(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_from_magic(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    assert detect_file_format_for_skip_filter(str(model_file)) == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT


def test_zip_magic_variants(tmp_path):
    """Ensure alternate PK signatures are detected as ZIP."""
    for sig in (b"PK\x06\x06", b"PK\x06\x07"):
        path = tmp_path / f"file_{sig.hex()}.zip"
        path.write_bytes(sig + b"extra")
        assert is_zipfile(str(path)) is True
        assert detect_file_format(str(path)) == "zip"


def test_find_sharded_files(tmp_path):
    """Test finding sharded model files."""
    # Create directory with sharded files
    shard_dir = tmp_path / "model_dir"
    shard_dir.mkdir()

    # Create sharded files
    (shard_dir / "pytorch_model-00001-of-00005.bin").write_bytes(b"shard1")
    (shard_dir / "pytorch_model-00002-of-00005.bin").write_bytes(b"shard2")
    (shard_dir / "pytorch_model-00003-of-00005.bin").write_bytes(b"shard3")

    # Create non-shard files
    (shard_dir / "config.json").write_bytes(b"{}")
    (shard_dir / "other_file.bin").write_bytes(b"other")

    # Test finding shards
    shards = find_sharded_files(str(shard_dir))

    assert len(shards) == 3
    assert all("pytorch_model-0000" in shard for shard in shards)
    assert shards[0].endswith("pytorch_model-00001-of-00005.bin")
    assert shards[1].endswith("pytorch_model-00002-of-00005.bin")
    assert shards[2].endswith("pytorch_model-00003-of-00005.bin")


def test_find_sharded_files_relative_path(tmp_path, monkeypatch):
    """Sharded files should be discovered using relative paths without duplication."""
    shard_dir = tmp_path / "model_dir"
    shard_dir.mkdir()

    (shard_dir / "pytorch_model-00001-of-00005.bin").write_bytes(b"shard1")
    (shard_dir / "pytorch_model-00002-of-00005.bin").write_bytes(b"shard2")

    monkeypatch.chdir(tmp_path)
    shards = find_sharded_files("model_dir")

    expected = [
        str((shard_dir / "pytorch_model-00001-of-00005.bin").resolve()),
        str((shard_dir / "pytorch_model-00002-of-00005.bin").resolve()),
    ]
    assert shards == expected


def test_detect_format_from_extension(tmp_path):
    """Test extension-only format detection."""
    file_path = tmp_path / "model.pt"
    file_path.write_bytes(b"abc")
    assert detect_format_from_extension(str(file_path)) == "pickle"

    dir_path = tmp_path / "saved_model"
    dir_path.mkdir()
    (dir_path / "saved_model.pb").write_bytes(b"d")
    assert detect_format_from_extension(str(dir_path)) == "tensorflow_directory"

    skops_path = tmp_path / "pipeline.skops"
    skops_path.write_bytes(b"PK\x03\x04")
    assert detect_format_from_extension(str(skops_path)) == "skops"


@pytest.mark.parametrize("extension", [".tar.xz", ".ggmf", ".params", ".skops", ".npz"])
def test_detect_format_from_extension_uses_descriptor_owned_policy(tmp_path: Path, extension: str) -> None:
    path = tmp_path / f"model{extension}"
    path.write_bytes(b"abc")

    assert detect_format_from_extension(str(path)) == get_extension_format_map()[extension]


def test_detect_gguf_ggml_formats(tmp_path):
    """Test detection of GGUF and GGML formats by magic bytes."""
    # Test GGUF format
    gguf_path = tmp_path / "model.gguf"
    gguf_path.write_bytes(b"GGUF" + b"\x00" * 20)
    assert detect_file_format(str(gguf_path)) == "gguf"
    assert detect_format_from_extension(str(gguf_path)) == "gguf"

    # Test GGML format
    ggml_path = tmp_path / "model.ggml"
    ggml_path.write_bytes(b"GGML" + b"\x00" * 20)
    assert detect_file_format(str(ggml_path)) == "ggml"
    assert detect_format_from_extension(str(ggml_path)) == "ggml"

    # Test GGUF extension with wrong magic (should fall back to extension)
    fake_gguf_path = tmp_path / "fake.gguf"
    fake_gguf_path.write_bytes(b"FAKE" + b"\x00" * 20)
    assert detect_file_format(str(fake_gguf_path)) == "gguf"  # Falls back to extension
    assert detect_format_from_extension(str(fake_gguf_path)) == "gguf"


def test_detect_ggml_variant_formats(tmp_path):
    """Ensure GGML variants are recognized."""
    variants = [b"GGMF", b"GGJT"]
    for magic in variants:
        path = tmp_path / f"model_{magic.decode().lower()}.ggml"
        path.write_bytes(magic + b"\x00" * 20)
        assert detect_file_format(str(path)) == "ggml"
        assert detect_format_from_extension(str(path)) == "ggml"


def test_validate_file_type(tmp_path):
    """Validate files using magic numbers."""
    # Valid ZIP-based PyTorch file
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("test.txt", "data")
    assert validate_file_type(str(zip_path)) is True

    # Invalid HDF5 file with .h5 extension
    invalid_h5 = tmp_path / "bad.h5"
    invalid_h5.write_bytes(b"not real hdf5")
    assert validate_file_type(str(invalid_h5)) is False

    # Valid HDF5 file
    valid_h5 = tmp_path / "good.h5"
    hdf5_magic = b"\x89HDF\r\n\x1a\n"
    valid_h5.write_bytes(hdf5_magic + b"hdf5 data")
    assert validate_file_type(str(valid_h5)) is True

    # Valid pickle file
    pickle_path = tmp_path / "model.pkl"
    pickle_path.write_bytes(b"\x80\x03" + b"pickle data")
    assert validate_file_type(str(pickle_path)) is True

    # Valid GGUF file
    gguf_path = tmp_path / "model.gguf"
    gguf_path.write_bytes(b"GGUF" + b"\x00" * 20)
    assert validate_file_type(str(gguf_path)) is True

    # Invalid GGUF file (wrong magic)
    bad_gguf = tmp_path / "bad.gguf"
    bad_gguf.write_bytes(b"FAKE" + b"\x00" * 20)
    assert validate_file_type(str(bad_gguf)) is False

    # NumPy .npz file (ZIP archive by design)
    npz_path = tmp_path / "arrays.npz"
    # .npz files are ZIP archives - this is correct, not spoofing
    npz_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    assert validate_file_type(str(npz_path)) is True

    skops_path = tmp_path / "pipeline.skops"
    skops_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    assert validate_file_type(str(skops_path)) is True

    # NumPy .npy file should have numpy magic
    npy_path = tmp_path / "array.npy"
    npy_path.write_bytes(b"\x93NUMPY" + b"\x00" * 20)
    assert validate_file_type(str(npy_path)) is True

    # NeMo .nemo files are TAR archives by design
    nemo_path = tmp_path / "model.nemo"
    with tarfile.open(nemo_path, "w") as tar:
        info = tarfile.TarInfo(name="model_config.yaml")
        content = b"model: test\n"
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    assert validate_file_type(str(nemo_path)) is True

    # Small file should be valid (can't determine magic bytes)
    small_file = tmp_path / "small.h5"
    small_file.write_bytes(b"hi")
    assert validate_file_type(str(small_file)) is True

    # Unknown extension should be valid
    unknown_ext = tmp_path / "file.unknown"
    unknown_ext.write_bytes(b"some data")
    assert validate_file_type(str(unknown_ext)) is True

    # SafeTensors file with framed JSON header
    safetensors_path = tmp_path / "model.safetensors"
    safetensors_header = b'{"__metadata__": {}, "tensor": {"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    safetensors_path.write_bytes(struct.pack("<Q", len(safetensors_header)) + safetensors_header + b"\x00\x00\x00\x00")
    assert validate_file_type(str(safetensors_path)) is True

    # PyTorch binary (.bin) that's actually a ZIP (valid case)
    bin_zip = tmp_path / "model.bin"
    with zipfile.ZipFile(bin_zip, "w") as zipf:
        zipf.writestr("weights.pt", "data")
    assert validate_file_type(str(bin_zip)) is True

    # PyTorch binary (.bin) that's actually pickle (valid case)
    bin_pickle = tmp_path / "weights.bin"
    bin_pickle.write_bytes(b"\x80\x03" + b"pickle data")
    assert validate_file_type(str(bin_pickle)) is True

    # TorchServe archives are zip-based .mar files.
    mar_path = tmp_path / "model.mar"
    with zipfile.ZipFile(mar_path, "w") as mar:
        mar.writestr("MAR-INF/MANIFEST.json", '{"model":{"serializedFile":"weights.bin","handler":"handler.py"}}')
        mar.writestr("weights.bin", b"weights")
        mar.writestr("handler.py", b"def handle(data, context):\n    return data\n")
    assert validate_file_type(str(mar_path)) is True

    # ExecuTorch binaries require a valid FlatBuffers layout in addition to the file identifier.
    executorch_path = tmp_path / "program.pte"
    executorch_path.write_bytes(b"\x0c\x00\x00\x00ET13\x04\x00\x04\x00\x04\x00\x00\x00")
    assert detect_file_format_from_magic(str(executorch_path)) == "executorch"
    assert validate_file_type(str(executorch_path)) is True

    invalid_executorch_path = tmp_path / "invalid-program.pte"
    invalid_executorch_path.write_bytes(b"\x0c\x00\x00\x00ETAA\x04\x00\x04\x00\x04\x00\x00\x00")
    assert detect_file_format_from_magic(str(invalid_executorch_path)) == "unknown"
    assert validate_file_type(str(invalid_executorch_path)) is False

    # Llamafile extensions remain eligible for scanner-level executable and marker checks.
    llamafile_path = tmp_path / "model.llamafile"
    llamafile_path.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"llamafile")
    assert validate_file_type(str(llamafile_path)) is True

    # MXNet params files do not expose stable magic bytes and validate by extension.
    mxnet_params = tmp_path / "model-0000.params"
    mxnet_params.write_bytes(struct.pack("<4f", 0.1, 0.2, 0.3, 0.4))
    assert validate_file_type(str(mxnet_params)) is True

    # MXNet symbol JSON files follow a filename contract, not magic-byte signatures.
    mxnet_symbol = tmp_path / "model-symbol.json"
    mxnet_symbol.write_text('{"nodes":[{"op":"null","name":"data","inputs":[]}],"arg_nodes":[0],"heads":[[0,0,0]]}')
    assert validate_file_type(str(mxnet_symbol)) is True


def test_detect_file_format_from_magic_oserror(tmp_path, monkeypatch):
    """Return 'unknown' when reading magic bytes fails."""
    file_path = tmp_path / "unreadable.bin"
    file_path.write_bytes(b"\x89HDF")

    def open_raise(self, *args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "open", open_raise)
    assert detect_file_format_from_magic(str(file_path)) == "unknown"


def test_detect_openvino_xml_format(tmp_path):
    """Test detecting OpenVINO XML files by magic bytes."""
    # Create an OpenVINO XML file with standard XML header
    xml_path = tmp_path / "openvino_model.xml"
    xml_content = b'<?xml version="1.0"?>\n<net name="Model0" version="11">\n</net>'
    xml_path.write_bytes(xml_content)

    # Test magic byte detection
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"

    # Test extension detection
    assert detect_format_from_extension(str(xml_path)) == "openvino"

    # Test file type validation should pass (no mismatch)
    assert validate_file_type(str(xml_path)) is True


def test_detect_pmml_xml_format(tmp_path):
    """Test detecting PMML XML files by magic bytes."""
    # Create a PMML XML file with standard XML header
    pmml_path = tmp_path / "model.pmml"
    pmml_content = b'<?xml version="1.0"?>\n<PMML version="4.4">\n</PMML>'
    pmml_path.write_bytes(pmml_content)

    # Test magic byte detection should now recognize PMML
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"

    # Test extension detection
    assert detect_format_from_extension(str(pmml_path)) == "pmml"

    # Test file type validation should pass (no mismatch)
    assert validate_file_type(str(pmml_path)) is True


def test_msgpack_validation_valid_format(tmp_path):
    """Test that valid MessagePack files pass validation (regression test for false positive)."""
    # Create a valid MessagePack file with real Flax model header
    # 0x81 = fixmap with 1 element
    # 0xab = fixstr with 11 characters
    # Following bytes spell "transformer"
    msgpack_path = tmp_path / "model.msgpack"
    msgpack_content = (
        bytes(
            [
                0x81,
                0xAB,  # fixmap(1), fixstr(11)
                0x74,
                0x72,
                0x61,
                0x6E,
                0x73,
                0x66,
                0x6F,
                0x72,
                0x6D,
                0x65,
                0x72,  # "transformer"
                0x84,  # fixmap(4) for nested data
            ]
        )
        + b"\x00" * 100
    )  # Additional data

    msgpack_path.write_bytes(msgpack_content)

    # Test that extension detection returns flax_msgpack
    assert detect_format_from_extension(str(msgpack_path)) == "flax_msgpack"

    # Test that validation passes (this was the bug - it was failing before)
    assert validate_file_type(str(msgpack_path)) is True


def test_catboost_validation_valid_and_invalid_files(tmp_path: Path) -> None:
    """Valid CatBoost files pass validation; spoofed ones fail."""
    catboost_path = tmp_path / "model.cbm"
    catboost_path.write_bytes(b"CBM1" + b"\x04\x00\x00\x00" + b"core")
    assert detect_file_format(str(catboost_path)) == "catboost"
    assert detect_format_from_extension(str(catboost_path)) == "catboost"
    assert validate_file_type(str(catboost_path)) is True

    bad_catboost = tmp_path / "bad_model.cbm"
    bad_catboost.write_bytes(b"FAKE" + b"\x00" * 20)
    assert validate_file_type(str(bad_catboost)) is False


def test_cntk_validation_valid_and_invalid_files(tmp_path: Path) -> None:
    """Valid CNTK signatures pass validation; misnamed files fail."""
    cntk_legacy = tmp_path / "legacy.dnn"
    cntk_legacy.write_bytes(
        b"B\x00C\x00N\x00\x00\x00" + b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00" + b"inputs outputs"
    )
    assert validate_file_type(str(cntk_legacy)) is True

    cntk_v2 = tmp_path / "graph.cmf"
    cntk_v2.write_bytes(
        b"\x0a\x07version\x12\x031.0\x12\x09\x0a\x03uid\x12\x02ab CompositeFunction primitive_functions"
    )
    assert validate_file_type(str(cntk_v2)) is True

    bad_cntk = tmp_path / "not_cntk.dnn"
    bad_cntk.write_text("not a cntk model")
    assert validate_file_type(str(bad_cntk)) is False


def test_compressed_validation_valid_and_invalid_files(tmp_path: Path) -> None:
    """Standalone compressed wrappers must match declared codecs."""
    gzip_payload = tmp_path / "payload.pkl.gz"
    gzip_payload.write_bytes(gzip.compress(b"payload"))
    assert validate_file_type(str(gzip_payload)) is True

    bad_gzip_payload = tmp_path / "payload_bad.pkl.gz"
    bad_gzip_payload.write_bytes(bz2.compress(b"payload"))
    assert validate_file_type(str(bad_gzip_payload)) is False


def test_detect_generic_xml_format(tmp_path):
    """Test that generic XML files don't get misdetected as OpenVINO."""
    # Create a generic XML file (SVG, config, etc.)
    xml_path = tmp_path / "config.xml"
    xml_content = b'<?xml version="1.0"?>\n<configuration>\n<setting>value</setting>\n</configuration>'
    xml_path.write_bytes(xml_content)

    # Magic detection should return unknown (no <net> tag)
    assert detect_file_format_from_magic(str(xml_path)) == "unknown"


def test_detect_openvino_xml_net_beyond_64_bytes(tmp_path: Path) -> None:
    """Test that bounded XML root parsing still detects late OpenVINO roots."""
    # Create XML where <net> appears after 64 bytes
    xml_path = tmp_path / "late_net.xml"
    # Padding to push <net> beyond 64 bytes
    padding = b" " * 50
    xml_content = b'<?xml version="1.0"?>\n' + padding + b'\n<net name="Model0">\n</net>'
    xml_path.write_bytes(xml_content)

    assert detect_file_format_from_magic(str(xml_path)) == "openvino"


def test_detect_openvino_xml_short_file(tmp_path):
    """Test OpenVINO detection with file smaller than 64 bytes."""
    # Create a short OpenVINO XML file
    xml_path = tmp_path / "short.xml"
    xml_content = b'<?xml version="1.0"?>\n<net/>'
    xml_path.write_bytes(xml_content)

    # Should still detect as openvino (file is small but contains <net>)
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"


def test_detect_xml_with_net_in_comment(tmp_path: Path) -> None:
    """Test that <net> in XML comments does not trigger model routing."""
    # Create XML with <net> inside a comment
    xml_path = tmp_path / "commented.xml"
    xml_content = b'<?xml version="1.0"?>\n<!-- <net> -->\n<root/>'
    xml_path.write_bytes(xml_content)

    assert detect_file_format_from_magic(str(xml_path)) == "unknown"


def test_xml_detection_boundary_conditions(tmp_path):
    """Test XML detection at exact 64-byte boundary."""
    # Create XML where <net> is at exactly byte 60 (within 64 bytes)
    xml_path = tmp_path / "boundary.xml"
    # Position <net> to be just within the 64-byte limit
    xml_content = b'<?xml version="1.0"?>' + (b" " * 17) + b'<net name="M"/>'
    xml_path.write_bytes(xml_content)

    # Should detect as openvino
    assert detect_file_format_from_magic(str(xml_path)) == "openvino"


def test_detect_pmml_xml_beyond_64_bytes(tmp_path: Path) -> None:
    """Test that bounded XML root parsing still detects late PMML roots."""
    # Create XML where <PMML> appears after 64 bytes
    pmml_path = tmp_path / "late_pmml.pmml"
    # Padding to push <PMML> beyond 64 bytes
    padding = b" " * 50
    pmml_content = b'<?xml version="1.0"?>\n' + padding + b'\n<PMML version="4.4">\n</PMML>'
    pmml_path.write_bytes(pmml_content)

    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"


def test_detect_pmml_xml_with_oversized_doctype_subset(tmp_path: Path) -> None:
    """Incomplete bounded XML prologs should fail closed instead of guessing a PMML root."""
    pmml_path = tmp_path / "oversized_doctype_pmml.txt"
    pmml_path.write_text(
        "<?xml version='1.0'?><!DOCTYPE PMML [" + ("x" * ((1024 * 1024) + 64)) + "]><PMML/>",
        encoding="utf-8",
    )

    assert detect_file_format_from_magic(str(pmml_path)) == "xml_model_inconclusive"


def test_detect_pmml_xml_short_file(tmp_path):
    """Test PMML detection with file smaller than 64 bytes."""
    # Create a short PMML XML file
    pmml_path = tmp_path / "short.pmml"
    pmml_content = b'<?xml version="1.0"?>\n<PMML/>'
    pmml_path.write_bytes(pmml_content)

    # Should still detect as pmml (file is small but contains <PMML>)
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"


def test_detect_xml_with_pmml_in_comment(tmp_path: Path) -> None:
    """Test that <PMML> in XML comments does not trigger model routing."""
    # Create XML with <PMML> inside a comment
    xml_path = tmp_path / "commented.pmml"
    xml_content = b'<?xml version="1.0"?>\n<!-- <PMML> -->\n<root/>'
    xml_path.write_bytes(xml_content)

    assert detect_file_format_from_magic(str(xml_path)) == "unknown"


def test_pmml_detection_boundary_conditions(tmp_path):
    """Test PMML detection at exact 64-byte boundary."""
    # Create XML where <PMML> is just within the 64-byte limit
    pmml_path = tmp_path / "boundary.pmml"
    # Position <PMML> to be just within the 64-byte limit
    pmml_content = b'<?xml version="1.0"?>' + (b" " * 16) + b'<PMML version="4"/>'
    pmml_path.write_bytes(pmml_content)

    # Should detect as pmml
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"


def test_openvino_vs_pmml_detection(tmp_path):
    """Test that OpenVINO and PMML formats are detected independently."""
    # OpenVINO file
    openvino_path = tmp_path / "model.xml"
    openvino_content = b'<?xml version="1.0"?>\n<net name="Model0" version="11">\n</net>'
    openvino_path.write_bytes(openvino_content)

    # PMML file
    pmml_path = tmp_path / "model.pmml"
    pmml_content = b'<?xml version="1.0"?>\n<PMML version="4.4" xmlns="http://www.dmg.org/PMML-4_4">\n</PMML>'
    pmml_path.write_bytes(pmml_content)

    # Each should be detected correctly
    assert detect_file_format_from_magic(str(openvino_path)) == "openvino"
    assert detect_file_format_from_magic(str(pmml_path)) == "pmml"

    # Validation should pass for both
    assert validate_file_type(str(openvino_path)) is True
    assert validate_file_type(str(pmml_path)) is True
