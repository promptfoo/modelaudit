"""Tests for file filtering functionality."""

import importlib
import json
import pickle
import struct
import zipfile
from pathlib import Path
from typing import cast

import pytest

from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file import filtering
from modelaudit.utils.file.detection import (
    EXECUTABLE_ZIP_POLYGLOT_FORMAT,
    FLAX_MSGPACK_STRUCTURE_READ_BYTES,
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    MEDIA_ROUTE_READ_BYTES,
    MXNET_SYMBOL_SIGNATURE_READ_BYTES,
    PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
    PROTOBUF_MODEL_CANDIDATE_FORMAT,
    SAFETENSORS_ROUTING_HEADER_PARSE_BYTES,
    TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
    detect_file_format_for_skip_filter,
)
from modelaudit.utils.file.filtering import (
    _ZIP_MEMBER_SNIFF_LIMIT,
    should_skip_file,
)
from modelaudit.utils.file.hdf5 import HDF5_MAGIC, hdf5_metadata_checksum
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from tests.helpers.file_creators import (
    create_mock_mxnet_symbol,
    create_mock_onnx,
    create_v7_tar_archive,
    malicious_pickle_bytes,
    prefix_mock_onnx_with_unknown_field,
    valid_jpeg_bytes,
    valid_png_bytes,
)


def _require_tf_protos() -> None:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")


def _build_tf_metagraph_bytes() -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    node = metagraph.graph_def.node.add()
    node.name = "const_node"
    node.op = "Const"
    return cast(bytes, metagraph.SerializeToString())


def _build_tf_savedmodel_bytes() -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    saved_model_pb2 = importlib.import_module("tensorflow.core.protobuf.saved_model_pb2")
    saved_model = saved_model_pb2.SavedModel()
    saved_model.saved_model_schema_version = 1
    metagraph = saved_model.meta_graphs.add()
    node = metagraph.graph_def.node.add()
    node.name = "const_node"
    node.op = "Const"
    return cast(bytes, saved_model.SerializeToString())


def _write_sparse_oversized_safetensors_candidate(path: Path) -> None:
    header_len = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)


def _write_hdf5_userblock_candidate(path: Path, *, valid_checksum: bool) -> None:
    signature_offset = 512
    file_size = signature_offset + 64
    superblock = bytearray(HDF5_MAGIC + b"\x03\x08\x08\x00")
    superblock.extend(signature_offset.to_bytes(8, "little"))
    superblock.extend(b"\xff" * 8)
    superblock.extend(file_size.to_bytes(8, "little"))
    superblock.extend((signature_offset + 48).to_bytes(8, "little"))
    checksum = hdf5_metadata_checksum(bytes(superblock))
    if not valid_checksum:
        checksum ^= 1
    superblock.extend(checksum.to_bytes(4, "little"))
    path.write_bytes(
        bytes(signature_offset) + bytes(superblock) + bytes(file_size - signature_offset - len(superblock))
    )


def _printable_unknown_proto_prefix(min_bytes: int) -> bytes:
    field = b"z " + (b"x" * 32)
    return field * ((min_bytes // len(field)) + 1)


def _build_lightgbm_text() -> str:
    return "\n".join(
        [
            "tree=0",
            "version=v4",
            "num_class=1",
            "num_tree_per_iteration=1",
            "max_feature_idx=2",
            "feature_names=f0 f1 f2",
            "tree_sizes=12",
            "num_leaves=2",
            "split_feature=0",
            "leaf_value=0.1 0.2",
        ]
    )


def _write_cntkv2(path: Path, include_structure: bool = True) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    path.write_bytes(prefix + structure + b" inputs outputs ")


def _corrupt_zip_member_crc(path: Path, member_name: str) -> None:
    """Patch a ZIP member CRC so reading the member raises BadZipFile."""
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(member_name)
        bad_crc = ((info.CRC + 1) & 0xFFFFFFFF).to_bytes(4, "little")
        local_offset = info.header_offset

    data = bytearray(path.read_bytes())
    assert data[local_offset : local_offset + 4] == b"PK\x03\x04"
    data[local_offset + 14 : local_offset + 18] = bad_crc

    member_name_bytes = member_name.encode("utf-8")
    central_offset = 0
    while True:
        central_offset = data.find(b"PK\x01\x02", central_offset)
        assert central_offset >= 0
        name_length = int.from_bytes(data[central_offset + 28 : central_offset + 30], "little")
        extra_length = int.from_bytes(data[central_offset + 30 : central_offset + 32], "little")
        comment_length = int.from_bytes(data[central_offset + 32 : central_offset + 34], "little")
        name_start = central_offset + 46
        name_end = name_start + name_length
        if data[name_start:name_end] == member_name_bytes:
            data[central_offset + 16 : central_offset + 20] = bad_crc
            break
        central_offset = name_end + extra_length + comment_length

    path.write_bytes(data)


class TestFileFilter:
    """Test file filtering functionality."""

    def test_metadata_routing_reuses_lowered_filename(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class CountingFilename(str):
            lower_calls = 0

            def lower(self) -> str:
                self.lower_calls += 1
                return super().lower()

        filename = CountingFilename("README.notes.txt")
        monkeypatch.setattr(filtering.os.path, "basename", lambda _path: filename)

        assert should_skip_file("/ignored/path.txt", metadata_scanner_available=True) is False
        assert filename.lower_calls == 1

    def test_skip_common_extensions(self):
        """Test that common non-model extensions are skipped."""
        skip_files = [
            # Note: README.md is now scanned by MetadataScanner for security
            "test.txt",
            "script.py",
            "style.css",
            "index.html",
            "config.ini",
            "data.log",
            "image.jpg",
            "video.mp4",
            "backup.bak",
        ]

        for file in skip_files:
            assert should_skip_file(file), f"Should skip {file}"

    @pytest.mark.parametrize(
        ("filename", "payload"),
        [
            ("preview.png", valid_png_bytes()),
            ("preview.jpg", valid_jpeg_bytes()),
            ("preview.jpeg", valid_jpeg_bytes()),
        ],
        ids=["png", "jpg", "jpeg"],
    )
    def test_valid_media_stays_skipped_by_default_prefilter(
        self,
        tmp_path: Path,
        filename: str,
        payload: bytes,
    ) -> None:
        media_path = tmp_path / filename
        media_path.write_bytes(payload)

        assert detect_file_format_for_skip_filter(str(media_path)) == "unknown"
        assert should_skip_file(str(media_path)) is True

    @pytest.mark.parametrize(
        ("filename", "payload"),
        [("polyglot.png", valid_png_bytes()), ("polyglot.jpg", valid_jpeg_bytes())],
        ids=["png", "jpg"],
    )
    def test_media_pickle_polyglot_bypasses_default_prefilter(
        self,
        tmp_path: Path,
        filename: str,
        payload: bytes,
    ) -> None:
        media_path = tmp_path / filename
        media_path.write_bytes(payload + malicious_pickle_bytes())

        assert detect_file_format_for_skip_filter(str(media_path)) == "pickle"
        assert should_skip_file(str(media_path)) is False

    def test_padded_media_pickle_polyglot_bypasses_default_prefilter(self, tmp_path: Path) -> None:
        media_path = tmp_path / "padded-polyglot.png"
        media_path.write_bytes(valid_png_bytes() + (b"\0" * (MEDIA_ROUTE_READ_BYTES + 2)) + malicious_pickle_bytes())

        assert detect_file_format_for_skip_filter(str(media_path)) == PICKLE_ROUTING_INCONCLUSIVE_FORMAT
        assert should_skip_file(str(media_path)) is False

    def test_allow_model_extensions(self):
        """Test that model extensions are not skipped."""
        model_files = [
            "model.pkl",
            "weights.pt",
            "checkpoint.pth",
            "model.h5",
            "saved.ckpt",
            "data.bin",
            "archive.zip",
            "config.json",
            "params.yaml",
            "settings.yml",
            "model.safetensors",
            "data.npz",
            "weights.onnx",
            "archive.tar",
            "archive.tar.gz",
            "archive.gz",
            "archive.bz2",
            "archive.xz",
            "archive.7z",
            "model.metadata",
        ]

        for file in model_files:
            assert not should_skip_file(file), f"Should not skip {file}"

    def test_skip_hidden_files(self):
        """Test that hidden files are skipped except for model extensions."""
        # These should be skipped
        assert should_skip_file(".DS_Store")
        assert should_skip_file(".gitignore")
        assert should_skip_file(".env")

        # These model files should not be skipped even if hidden
        assert not should_skip_file(".model.pkl")
        assert not should_skip_file(".weights.pt")
        assert not should_skip_file(".checkpoint.h5")
        assert not should_skip_file(".weights.onnx")

    def test_skip_specific_filenames(self):
        """Test that specific filenames are skipped."""
        # Note: README is now scanned by MetadataScanner for security
        skip_names = ["Makefile", "requirements.txt", "package.json"]

        for name in skip_names:
            assert should_skip_file(name), f"Should skip {name}"

    def test_custom_skip_extensions(self):
        """Test custom skip extensions."""
        # Default behavior - .dat files are not skipped
        assert not should_skip_file("data.dat")

        # With custom skip extensions including .dat
        custom_skip = {".dat", ".custom"}
        assert should_skip_file("data.dat", skip_extensions=custom_skip)
        assert should_skip_file("file.custom", skip_extensions=custom_skip)

        # But .pkl should still be allowed (not in custom set)
        assert not should_skip_file("model.pkl", skip_extensions=custom_skip)

    def test_custom_skip_filenames(self):
        """Test custom skip filenames."""
        # Default behavior
        assert not should_skip_file("LICENSE")
        assert not should_skip_file("CUSTOM_FILE")

        # With custom skip filenames
        custom_names = {"CUSTOM_FILE", "SPECIAL"}
        assert should_skip_file("CUSTOM_FILE", skip_filenames=custom_names)
        assert should_skip_file("SPECIAL", skip_filenames=custom_names)

        # But LICENSE should not be skipped (not in custom set)
        assert not should_skip_file("LICENSE", skip_filenames=custom_names)

    def test_disable_hidden_file_skip(self):
        """Test disabling hidden file skipping."""
        # Default behavior - skip hidden files
        assert should_skip_file(".hidden")

        # With skip_hidden=False
        assert not should_skip_file(".hidden", skip_hidden=False)

        # But extension-based skipping still works
        assert should_skip_file(".hidden.txt", skip_hidden=False)

    def test_path_handling(self):
        """Test that the function handles full paths correctly."""
        # Should extract filename and check extension
        # Note: README.md is now scanned by MetadataScanner, so not skipped
        assert not should_skip_file("/path/to/README.md", metadata_scanner_available=True)
        assert should_skip_file("./relative/path/script.py")
        assert not should_skip_file("/models/checkpoint.pkl")
        assert not should_skip_file("data/model.h5")

    def test_case_sensitivity(self):
        """Test that extension checking is case-insensitive."""
        # Note: README.MD is now scanned by MetadataScanner, so not skipped
        assert not should_skip_file("README.MD", metadata_scanner_available=True)
        assert should_skip_file("script.PY")
        assert should_skip_file("IMAGE.JPG")

        # Model extensions should work regardless of case
        assert not should_skip_file("MODEL.PKL")
        assert not should_skip_file("WEIGHTS.PT")

    def test_content_recognized_payloads_bypass_extension_skip(self, tmp_path: Path) -> None:
        """Disguised model/archive files should survive directory prefiltering."""
        disguised_pickle = tmp_path / "payload.jpg"
        disguised_pickle.write_bytes(pickle.dumps({"safe": True}))

        disguised_protocol0_pickle = tmp_path / "payload-protocol0.jpg"
        disguised_protocol0_pickle.write_bytes(pickle.dumps({"safe": True}, protocol=0))

        disguised_zip = tmp_path / "archive.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            archive.writestr("payload.pkl", pickle.dumps({"safe": True}))

        disguised_legacy_tar = create_v7_tar_archive(tmp_path / "legacy-tar.jpg")

        real_image = tmp_path / "cover.jpg"
        real_image.write_bytes(b"\xff\xd8\xff\xe0" + b"jpeg")

        assert not should_skip_file(str(disguised_pickle))
        assert not should_skip_file(str(disguised_protocol0_pickle))
        assert not should_skip_file(str(disguised_zip))
        assert not should_skip_file(str(disguised_legacy_tar))
        assert should_skip_file(str(real_image))

    @pytest.mark.parametrize("suffix", [".txt", ".py", ".jpg"])
    def test_hdf5_userblock_bypasses_extension_skip(self, tmp_path: Path, suffix: str) -> None:
        disguised_hdf5 = tmp_path / f"weights{suffix}"
        _write_hdf5_userblock_candidate(disguised_hdf5, valid_checksum=True)

        assert not should_skip_file(str(disguised_hdf5))

    def test_corrupt_hdf5_userblock_checksum_does_not_bypass_extension_skip(self, tmp_path: Path) -> None:
        near_match = tmp_path / "weights.jpg"
        _write_hdf5_userblock_candidate(near_match, valid_checksum=False)

        assert should_skip_file(str(near_match))

    def test_disguised_jax_json_checkpoint_bypasses_skip_without_routing_ajax_near_match(self, tmp_path: Path) -> None:
        checkpoint_path = tmp_path / "checkpoint.jpg"
        near_match_path = tmp_path / "ajax.jpg"
        checkpoint_path.write_text(
            (" " * 1024) + json.dumps({"framework": "jax", "orbax_version": "0.1.0"}),
            encoding="utf-8",
        )
        near_match_path.write_text(json.dumps({"framework": "ajax", "format": "checkpoint"}), encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(checkpoint_path)) == "jax_checkpoint"
        assert not should_skip_file(str(checkpoint_path))
        assert detect_file_format_for_skip_filter(str(near_match_path)) == "unknown"
        assert should_skip_file(str(near_match_path))

    def test_oversized_disguised_jax_json_checkpoint_bypasses_skip_after_late_identity(self, tmp_path: Path) -> None:
        checkpoint_path = tmp_path / "large-checkpoint.jpg"
        near_match_path = tmp_path / "large-ajax.jpg"
        padding = "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)
        checkpoint_path.write_text(json.dumps({"padding": padding, "framework": "jax"}), encoding="utf-8")
        near_match_path.write_text(json.dumps({"padding": padding, "framework": "ajax"}), encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(checkpoint_path)) == "jax_checkpoint"
        assert not should_skip_file(str(checkpoint_path))
        assert detect_file_format_for_skip_filter(str(near_match_path)) == "unknown"
        assert should_skip_file(str(near_match_path))

    def test_large_disguised_flax_checkpoint_bypasses_skip_without_promoting_generic_msgpack_map(
        self, tmp_path: Path
    ) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_checkpoint = tmp_path / "checkpoint.jpg"
        generic_map = tmp_path / "metadata.jpg"
        large_metadata = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
        disguised_checkpoint.write_bytes(
            msgpack.packb({"metadata": large_metadata, "params": {"w": [1, 2, 3]}}, use_bin_type=True)
        )
        generic_map.write_bytes(
            msgpack.packb(
                {"metadata": large_metadata, "state": {"selected": True}, "__reduce__": "os.system"},
                use_bin_type=True,
            )
        )

        assert detect_file_format_for_skip_filter(str(disguised_checkpoint)) == "flax_msgpack"
        assert not should_skip_file(str(disguised_checkpoint))
        assert detect_file_format_for_skip_filter(str(generic_map)) == "unknown"
        assert should_skip_file(str(generic_map))

    @pytest.mark.parametrize("suffix", [".txt", ".md", ".markdown", ".rst", ".ini", ".cfg", ".toml", ".conf"])
    def test_flax_checkpoint_under_default_skipped_suffix_bypasses_skip(
        self,
        tmp_path: Path,
        suffix: str,
    ) -> None:
        msgpack = pytest.importorskip("msgpack")
        checkpoint = tmp_path / f"checkpoint{suffix}"
        generic_map = tmp_path / f"metadata{suffix}"
        checkpoint.write_bytes(
            msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )
        generic_map.write_bytes(
            msgpack.packb({"state": {"selected": True}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        assert detect_file_format_for_skip_filter(str(checkpoint)) == "flax_msgpack"
        assert not should_skip_file(str(checkpoint))
        assert detect_file_format_for_skip_filter(str(generic_map)) == "unknown"
        if suffix in {".txt", ".rst"}:
            assert should_skip_file(str(generic_map))

    def test_oversized_ambiguous_text_suffix_fails_closed_as_flax(self, tmp_path: Path) -> None:
        document = tmp_path / "notes.txt"
        document.write_bytes(b" " * (2 * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 1) + 2))

        assert detect_file_format_for_skip_filter(str(document)) == "flax_msgpack"
        assert not should_skip_file(str(document))

    def test_small_plain_text_document_stays_skipped_instead_of_routing_as_flax(self, tmp_path: Path) -> None:
        document = tmp_path / "notes.txt"
        document.write_text("ordinary project documentation\n", encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(document)) == "unknown"
        assert should_skip_file(str(document))

    def test_xml_looking_scalar_flax_checkpoint_bypasses_skip(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        checkpoint = tmp_path / "xml-looking-scalar.txt"
        checkpoint.write_bytes(
            msgpack.packb(60, use_bin_type=True)
            + msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        assert detect_file_format_for_skip_filter(str(checkpoint)) == "flax_msgpack"
        assert not should_skip_file(str(checkpoint))

    def test_inconclusive_document_suffix_flax_candidate_bypasses_skip(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        checkpoint = tmp_path / "delayed-root.txt"
        checkpoint.write_bytes(
            msgpack.packb(None, use_bin_type=True) * 4097
            + msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        assert detect_file_format_for_skip_filter(str(checkpoint)) == "flax_msgpack"
        assert not should_skip_file(str(checkpoint))

    def test_large_json_array_under_skipped_suffix_is_preserved_fail_closed(self, tmp_path: Path) -> None:
        json_array = tmp_path / "metadata.jpg"
        json_array.write_bytes(b"[" + b"0," * ((MXNET_SYMBOL_SIGNATURE_READ_BYTES // 2) + 100) + b"0]")

        assert detect_file_format_for_skip_filter(str(json_array)) == "flax_msgpack"
        assert not should_skip_file(str(json_array))

    def test_incomplete_disguised_flax_probe_bypasses_skip_filter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        checkpoint = tmp_path / "unavailable.jpg"
        checkpoint.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
        monkeypatch.setattr(
            "modelaudit.utils.file.detection._probe_flax_msgpack_checkpoint_file",
            lambda _path: None,
        )

        assert detect_file_format_for_skip_filter(str(checkpoint)) == "flax_msgpack"
        assert not should_skip_file(str(checkpoint))

    def test_pk_prefix_near_match_stays_skipped(self, tmp_path: Path) -> None:
        near_match = tmp_path / "pknope.jpg"
        near_match.write_bytes(b"PKNO harmless text")

        assert should_skip_file(str(near_match))

    @pytest.mark.parametrize("filename", ["graph.jpg", "graph.py", "graph.pyw"])
    def test_disguised_tf_metagraph_bypasses_skip_without_promoting_generic_protobuf(
        self,
        tmp_path: Path,
        filename: str,
    ) -> None:
        disguised_metagraph = tmp_path / filename
        generic_protobuf = tmp_path / "generic.jpg"
        disguised_metagraph.write_bytes(b"\xa2\x06\x80\x08" + (b"x" * 1024) + _build_tf_metagraph_bytes())
        generic_protobuf.write_bytes(b"\x12\x02\x08\x01")

        assert detect_file_format_for_skip_filter(str(disguised_metagraph)) == "tf_metagraph"
        assert not should_skip_file(str(disguised_metagraph))
        assert detect_file_format_for_skip_filter(str(generic_protobuf)) == "unknown"
        assert should_skip_file(str(generic_protobuf))

    def test_disguised_tf_metagraph_after_printable_unknown_prefix_bypasses_skip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES", 64)
        disguised_metagraph = tmp_path / "prefixed-graph.jpg"
        disguised_metagraph.write_bytes(_printable_unknown_proto_prefix(65) + _build_tf_metagraph_bytes())

        assert detect_file_format_for_skip_filter(str(disguised_metagraph)) == "tf_metagraph"
        assert not should_skip_file(str(disguised_metagraph))

    @pytest.mark.parametrize("filename", ["saved.jpg", "saved.py", "saved.pyw"])
    def test_disguised_tf_savedmodel_bypasses_skip_without_promoting_generic_protobuf(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        filename: str,
    ) -> None:
        monkeypatch.setattr(file_detection, "JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES", 64)
        disguised_savedmodel = tmp_path / filename
        generic_protobuf = tmp_path / "generic.jpg"
        disguised_savedmodel.write_bytes(_printable_unknown_proto_prefix(65) + _build_tf_savedmodel_bytes())
        generic_protobuf.write_bytes(b"\x12\x02\x08\x01")

        assert detect_file_format_for_skip_filter(str(disguised_savedmodel)) == "tf_savedmodel"
        assert not should_skip_file(str(disguised_savedmodel))
        assert detect_file_format_for_skip_filter(str(generic_protobuf)) == "unknown"
        assert should_skip_file(str(generic_protobuf))

    @pytest.mark.parametrize("comment", ["#" * 31, "# cafe\u00e9" + ("#" * 24)])
    def test_large_python_source_shaped_like_unknown_protobuf_stays_skipped(self, tmp_path: Path, comment: str) -> None:
        source = tmp_path / "large_source.py"
        source_line = f"z {comment}\n"
        source.write_text(source_line * ((2 * 1024 * 1024 // len(source_line.encode())) + 2), encoding="utf-8")

        compile(source.read_text(encoding="utf-8"), str(source), "exec")
        assert detect_file_format_for_skip_filter(str(source)) == "unknown"
        assert should_skip_file(str(source))

    def test_binary_python_suffix_with_oversized_tensorflow_candidate_is_preserved(self, tmp_path: Path) -> None:
        payload = tmp_path / "oversized-candidate.py"
        payload.write_bytes(b"\x08\x01" + b"\x12\x81\x80\x80\x0a" + (b"x" * (20 * 1024 * 1024 + 1)))

        assert detect_file_format_for_skip_filter(str(payload)) == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
        assert not should_skip_file(str(payload))

    def test_bounded_unknown_prefix_before_tf_graph_is_not_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_ROUTING_FIELDS", 2)
        disguised_metagraph = tmp_path / "budget-prefixed.jpg"
        disguised_metagraph.write_bytes(
            b"{" + (b"\x18\x00" * 3) + b"|" + b"z\x09\x81\xa6params\x80" + _build_tf_metagraph_bytes()
        )

        assert detect_file_format_for_skip_filter(str(disguised_metagraph)) == "tf_metagraph"
        assert not should_skip_file(str(disguised_metagraph))

    def test_prefixed_disguised_onnx_bypasses_skip_without_promoting_generic_protobuf(self, tmp_path: Path) -> None:
        pytest.importorskip("onnx")
        disguised_onnx = create_mock_onnx(tmp_path / "model.jpg")
        prefix_mock_onnx_with_unknown_field(disguised_onnx, value_size=0, count=4097, field_number=8)
        generic_protobuf = tmp_path / "generic.jpg"
        generic_protobuf.write_bytes(b"\xa2\x06\x04xxxx\x12\x02\x08\x01")

        assert detect_file_format_for_skip_filter(str(disguised_onnx)) == PROTOBUF_MODEL_CANDIDATE_FORMAT
        assert not should_skip_file(str(disguised_onnx))
        assert detect_file_format_for_skip_filter(str(generic_protobuf)) == "unknown"
        assert should_skip_file(str(generic_protobuf))

    def test_disguised_torch7_bypasses_default_skip(self, tmp_path: Path) -> None:
        disguised_torch7 = tmp_path / "payload.jpg"
        disguised_torch7.write_bytes(b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n")
        near_match = tmp_path / "source.jpg"
        near_match.write_text("import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n")

        assert detect_file_format_for_skip_filter(str(disguised_torch7)) == "torch7"
        assert not should_skip_file(str(disguised_torch7))
        assert detect_file_format_for_skip_filter(str(near_match)) == "unknown"
        assert should_skip_file(str(near_match))

    @pytest.mark.parametrize("embedded_format", ["cntk", "lightgbm"])
    def test_disguised_torch7_outranks_embedded_content_signatures(
        self,
        tmp_path: Path,
        embedded_format: str,
    ) -> None:
        disguised_torch7 = tmp_path / f"payload-{embedded_format}.jpg"
        payload = b"4\n1\n3\nV 1\n13\nnn.Sequential\n4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
        if embedded_format == "cntk":
            embedded_payload = tmp_path / "embedded.cmf"
            _write_cntkv2(embedded_payload)
            payload += embedded_payload.read_bytes()
        else:
            payload += b"\x00" + _build_lightgbm_text().encode("utf-8")
        disguised_torch7.write_bytes(payload)

        assert detect_file_format_for_skip_filter(str(disguised_torch7)) == "torch7"
        assert not should_skip_file(str(disguised_torch7))

    def test_disguised_llamafile_bypasses_default_skip(self, tmp_path: Path) -> None:
        disguised_llamafile = tmp_path / "payload.jpg"
        disguised_llamafile.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"llamafile runtime")
        near_match = tmp_path / "tool.jpg"
        near_match.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"llama-file runtime")

        assert detect_file_format_for_skip_filter(str(disguised_llamafile)) == "llamafile"
        assert not should_skip_file(str(disguised_llamafile))
        assert detect_file_format_for_skip_filter(str(near_match)) == "unknown"
        assert should_skip_file(str(near_match))

    def test_disguised_llamafile_probe_failure_is_preserved_for_full_scan(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = tmp_path / "payload.jpg"
        payload.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"llamafile runtime")

        def raise_os_error(_path: Path, _marker: bytes, _limit: int) -> bool:
            raise OSError("synthetic marker probe failure")

        monkeypatch.setattr("modelaudit.utils.file.detection._contains_casefolded_marker_in_prefix", raise_os_error)

        assert detect_file_format_for_skip_filter(str(payload)) == "llamafile_routing_inconclusive"
        assert not should_skip_file(str(payload))

    def test_executable_zip_with_out_of_window_llamafile_marker_stays_scannable(self, tmp_path: Path) -> None:
        payload = tmp_path / "payload.jpg"
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("payload.pkl", pickle.dumps({"safe": True}))
        payload.write_bytes(
            b"\x7fELF"
            + b"\x00" * 60
            + b"A" * LLAMAFILE_ROUTE_SCAN_BYTES
            + b"llamafile runtime"
            + b"B" * LLAMAFILE_ROUTE_TAIL_SCAN_BYTES
            + payload.read_bytes()
        )

        assert detect_file_format_for_skip_filter(str(payload)) == EXECUTABLE_ZIP_POLYGLOT_FORMAT
        assert not should_skip_file(str(payload))

    def test_prefixed_zip_with_central_directory_stub_stays_scannable(self, tmp_path: Path) -> None:
        disguised_zip = tmp_path / "archive.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            archive.writestr("payload.pkl", b"payload")
        disguised_zip.write_bytes(b"PK\x01\x02stub-prefix" + disguised_zip.read_bytes())

        assert not should_skip_file(str(disguised_zip))

    @pytest.mark.parametrize("filename", [".payload", "Makefile", "package.json", "CHANGELOG"])
    def test_content_recognized_payloads_bypass_default_hidden_and_basename_skips(
        self,
        tmp_path: Path,
        filename: str,
    ) -> None:
        """Supported payloads should survive default hidden and basename filters."""
        disguised_pickle = tmp_path / filename
        disguised_pickle.write_bytes(pickle.dumps({"safe": True}))

        assert not should_skip_file(str(disguised_pickle))

    def test_disguised_lightgbm_text_model_bypasses_default_skip(self, tmp_path: Path) -> None:
        """Default skip filtering must preserve supported text models under skipped suffixes."""
        disguised_lightgbm = tmp_path / "model.jpg"
        disguised_lightgbm.write_text(("# preface\n" * 64) + _build_lightgbm_text(), encoding="utf-8")
        near_match = tmp_path / "near_match.jpg"
        near_match.write_text("tree=0\nversion=v4\nnum_class=1\n", encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(disguised_lightgbm)) == "lightgbm"
        assert detect_file_format_for_skip_filter(str(near_match)) == "unknown"
        assert not should_skip_file(str(disguised_lightgbm))
        assert should_skip_file(str(near_match))

    def test_disguised_lightgbm_binary_prelude_bypasses_default_skip(self, tmp_path: Path) -> None:
        disguised_lightgbm = tmp_path / "binary-model.jpg"
        disguised_lightgbm.write_bytes(b"\x01opaque tree prelude\x00" + _build_lightgbm_text().encode("utf-8"))
        prose_prefixed = tmp_path / "notes.jpg"
        prose_prefixed.write_text("notes about a model\n" + _build_lightgbm_text(), encoding="utf-8")
        tree_prefixed_prose = tmp_path / "tree-notes.jpg"
        tree_prefixed_prose.write_text("tree model notes\n" + _build_lightgbm_text(), encoding="utf-8")
        tree_equals_prose = tmp_path / "tree-equals-notes.jpg"
        tree_equals_prose.write_text("tree=implementation notes\n" + _build_lightgbm_text(), encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(disguised_lightgbm)) == "lightgbm"
        assert detect_file_format_for_skip_filter(str(prose_prefixed)) == "unknown"
        assert detect_file_format_for_skip_filter(str(tree_prefixed_prose)) == "unknown"
        assert detect_file_format_for_skip_filter(str(tree_equals_prose)) == "unknown"
        assert not should_skip_file(str(disguised_lightgbm))
        assert should_skip_file(str(prose_prefixed))
        assert should_skip_file(str(tree_prefixed_prose))
        assert should_skip_file(str(tree_equals_prose))

    def test_disguised_cntk_model_bypasses_default_skip(self, tmp_path: Path) -> None:
        """Default skip filtering must preserve strict CNTK signatures under skipped suffixes."""
        disguised_cntk = tmp_path / "model.jpg"
        _write_cntkv2(disguised_cntk)
        near_match = tmp_path / "near_match.jpg"
        _write_cntkv2(near_match, include_structure=False)

        assert detect_file_format_for_skip_filter(str(disguised_cntk)) == "cntk"
        assert detect_file_format_for_skip_filter(str(near_match)) == "unknown"
        assert not should_skip_file(str(disguised_cntk))
        assert should_skip_file(str(near_match))

    def test_disguised_mxnet_symbol_bypasses_default_skip_without_promoting_json_near_match(
        self, tmp_path: Path
    ) -> None:
        """Structurally valid MXNet symbol JSON should survive skipped media suffixes."""
        disguised_symbol = create_mock_mxnet_symbol(tmp_path / "model.jpg")
        near_match = tmp_path / "graph.jpg"
        near_match.write_text(
            '{"nodes":[{"op":"Custom"}],"arg_nodes":[],"heads":[[0,0,0]]}',
            encoding="utf-8",
        )

        assert detect_file_format_for_skip_filter(str(disguised_symbol)) == "mxnet"
        assert not should_skip_file(str(disguised_symbol))
        assert detect_file_format_for_skip_filter(str(near_match)) == "unknown"
        assert should_skip_file(str(near_match))

    def test_strong_r_workspace_bypasses_skip_without_promoting_weak_near_match(self, tmp_path: Path) -> None:
        disguised_workspace = tmp_path / "workspace.jpg"
        disguised_workspace.write_bytes(b"RDX3\nX\nworkspace\nmodel")
        ambiguous_text = tmp_path / "notes.jpg"
        ambiguous_text.write_bytes(b"X\nordinary exported table\n")
        incomplete_workspace = tmp_path / "header-notes.jpg"
        incomplete_workspace.write_bytes(b"RDX3\nQ\nordinary exported table\n")

        assert detect_file_format_for_skip_filter(str(disguised_workspace)) == "r_serialized"
        assert not should_skip_file(str(disguised_workspace))
        assert detect_file_format_for_skip_filter(str(ambiguous_text)) == "unknown"
        assert should_skip_file(str(ambiguous_text))
        assert detect_file_format_for_skip_filter(str(incomplete_workspace)) == "unknown"
        assert should_skip_file(str(incomplete_workspace))

    def test_disguised_xml_models_with_long_prologs_bypass_default_skip(self, tmp_path: Path) -> None:
        """Skipped suffixes must not hide XML model roots after long benign prologs."""
        disguised_openvino = tmp_path / "openvino.txt"
        disguised_openvino.write_text(
            f"<?xml version='1.0'?><!--{'x' * 1024}--><net name='Model0' version='11'></net>",
            encoding="utf-8",
        )
        disguised_pmml = tmp_path / "pmml.txt"
        disguised_pmml.write_text(
            f"<?xml version='1.0'?><!--{'x' * 1024}--><PMML version='4.4'></PMML>",
            encoding="utf-8",
        )
        benign_xml = tmp_path / "notes.txt"
        benign_xml.write_text(
            f"<?xml version='1.0'?><!--{'x' * 1024}--><project><model name='safe'/></project>",
            encoding="utf-8",
        )

        assert detect_file_format_for_skip_filter(str(disguised_openvino)) == "openvino"
        assert detect_file_format_for_skip_filter(str(disguised_pmml)) == "pmml"
        assert detect_file_format_for_skip_filter(str(benign_xml)) == "unknown"
        assert not should_skip_file(str(disguised_openvino))
        assert not should_skip_file(str(disguised_pmml))
        assert should_skip_file(str(benign_xml))

    def test_oversized_disguised_safetensors_candidate_bypasses_default_skip(self, tmp_path: Path) -> None:
        """Oversized framing must survive filtering for scanner-level bounded handling."""
        disguised_safetensors = tmp_path / "weights.jpg"
        malformed_near_match = tmp_path / "framing-only.jpg"
        _write_sparse_oversized_safetensors_candidate(disguised_safetensors)
        # Keep the negative fixture outside the unrelated MessagePack route.
        header_len = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 0xC1
        with malformed_near_match.open("wb") as handle:
            handle.write(struct.pack("<Q", header_len))
            handle.write(b"\x00")
            handle.truncate(8 + header_len + 1)

        assert detect_file_format_for_skip_filter(str(disguised_safetensors)) == "safetensors"
        assert not should_skip_file(str(disguised_safetensors))
        assert detect_file_format_for_skip_filter(str(malformed_near_match)) == "unknown"
        assert should_skip_file(str(malformed_near_match))

    def test_disguised_pmml_with_oversized_doctype_subset_fails_closed(self, tmp_path: Path) -> None:
        """Incomplete oversized XML prologs should survive filtering for fail-closed handling."""
        disguised_pmml = tmp_path / "pmml.txt"
        disguised_pmml.write_text(
            "<?xml version='1.0'?><!DOCTYPE PMML [" + ("x" * ((1024 * 1024) + 64)) + "]><PMML version='4.4'></PMML>",
            encoding="utf-8",
        )

        assert detect_file_format_for_skip_filter(str(disguised_pmml)) == "xml_model_inconclusive"
        assert not should_skip_file(str(disguised_pmml))

    def test_executorch_payloads_bypass_extension_skip(self, tmp_path: Path) -> None:
        """Disguised ZIPs carrying supported ExecuTorch payloads should survive prefiltering."""
        disguised_zip = tmp_path / "executorch.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            archive.writestr("model.pte", b"executorch payload")

        assert not should_skip_file(str(disguised_zip))

    def test_rar_archives_bypass_extension_skip(self, tmp_path: Path) -> None:
        """RAR archives should be routed to the fail-closed unsupported scanner."""
        rar_path = tmp_path / "archive.rar"
        rar_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)

        assert not should_skip_file(str(rar_path))

    def test_docx_like_zip_remains_skipped(self, tmp_path: Path) -> None:
        """Common document ZIP containers should not be promoted into the scan set."""
        docx_path = tmp_path / "spec.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")

        assert should_skip_file(str(docx_path))

    def test_docx_with_embedded_ole_bin_remains_skipped(self, tmp_path: Path) -> None:
        """Office ZIPs with embedded OLE binaries should not be treated as model archives."""
        docx_path = tmp_path / "embedded.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr("word/embeddings/oleObject1.bin", b"embedded-ole")

        assert should_skip_file(str(docx_path))

    def test_docx_with_embedded_pk_near_match_bin_remains_skipped(self, tmp_path: Path) -> None:
        """PK-prefixed non-ZIP OLE binaries must not promote Office documents."""
        docx_path = tmp_path / "embedded-pk-near-match.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr("word/embeddings/oleObject1.bin", b"PKNOPE embedded-ole")

        assert should_skip_file(str(docx_path))

    def test_docx_with_unreadable_embedded_pickle_bin_is_preserved(self, tmp_path: Path) -> None:
        """Unreadable model-like .bin members must preserve Office ZIPs for full scanning."""
        docx_path = tmp_path / "embedded-corrupt.docx"
        member_name = "word/embeddings/oleObject1.bin"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr(member_name, pickle.dumps({"safe": True}, protocol=4))
        _corrupt_zip_member_crc(docx_path, member_name)

        assert not should_skip_file(str(docx_path))

    def test_docx_with_embedded_pickle_bin_bypasses_extension_skip(self, tmp_path: Path) -> None:
        """Office ZIPs with model-like .bin payloads should survive prefiltering."""
        docx_path = tmp_path / "embedded-model.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr("word/embeddings/oleObject1.bin", pickle.dumps({"safe": True}, protocol=4))

        assert not should_skip_file(str(docx_path))

    def test_config_only_keras_zip_bypasses_extension_skip(self, tmp_path: Path) -> None:
        """Config-only Keras ZIPs should not depend on a .keras outer suffix."""
        keras_zip = tmp_path / "model.jpg"
        config = {"class_name": "Sequential", "config": {"layers": []}}
        with zipfile.ZipFile(keras_zip, "w") as archive:
            archive.writestr("config.json", json.dumps(config))

        assert not should_skip_file(str(keras_zip))

    def test_generic_config_zip_with_skipped_extension_remains_skipped(self, tmp_path: Path) -> None:
        """Generic config.json members must not promote arbitrary skipped-suffix ZIPs."""
        config_zip = tmp_path / "settings.jpg"
        config = {"name": "not-a-keras-model", "config": {"theme": "light"}}
        with zipfile.ZipFile(config_zip, "w") as archive:
            archive.writestr("config.json", json.dumps(config))

        assert should_skip_file(str(config_zip))

    def test_large_docx_like_zip_is_preserved_when_sniff_budget_is_exhausted(self, tmp_path: Path) -> None:
        """Large Office ZIPs should be preserved once the prefilter can no longer prove they are benign."""
        docx_path = tmp_path / "late-office.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            for index in range(_ZIP_MEMBER_SNIFF_LIMIT):
                archive.writestr(f"docs/{index}.txt", "filler")
            archive.writestr("word/document.xml", "<w:document></w:document>")

        assert not should_skip_file(str(docx_path))

    def test_large_docx_with_late_pickle_payload_is_preserved(self, tmp_path: Path) -> None:
        """Late payloads in Office-like ZIPs must survive bounded prefiltering."""
        docx_path = tmp_path / "late-payload.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            for index in range(_ZIP_MEMBER_SNIFF_LIMIT):
                archive.writestr(f"docs/{index}.txt", "filler")
            archive.writestr("payload.pkl", pickle.dumps({"safe": True}, protocol=4))

        assert not should_skip_file(str(docx_path))

    def test_large_ambiguous_zip_is_preserved_for_scanning(self, tmp_path: Path) -> None:
        """Ambiguous ZIPs should survive the prefilter when the sniff budget is exhausted."""
        disguised_zip = tmp_path / "archive.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            for index in range(_ZIP_MEMBER_SNIFF_LIMIT):
                archive.writestr(f"docs/{index}.txt", "filler")
            archive.writestr("payload.pkl", pickle.dumps({"safe": True}))

        assert not should_skip_file(str(disguised_zip))

    def test_custom_skip_extensions_are_respected_even_for_disguised_payloads(self, tmp_path: Path) -> None:
        """Explicit caller skip policies should not be bypassed by content sniffing."""
        disguised_pickle = tmp_path / "payload.jpg"
        disguised_pickle.write_bytes(pickle.dumps({"safe": True}))

        assert should_skip_file(str(disguised_pickle), skip_extensions={".jpg"})

    def test_content_sniff_failures_fail_open(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Content sniffing failures should preserve files for full scanning."""
        disguised_payload = tmp_path / "payload.jpg"
        disguised_payload.write_bytes(b"not-really-an-image")

        def raise_os_error(_path: str) -> str:
            raise OSError("synthetic sniff failure")

        monkeypatch.setattr("modelaudit.utils.file.detection.detect_file_format_for_skip_filter", raise_os_error)

        assert not should_skip_file(str(disguised_payload))
