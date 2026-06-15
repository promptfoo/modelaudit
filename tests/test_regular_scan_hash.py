"""Tests for content hash generation in regular scan mode."""

import builtins
import hashlib
import json
import os
import pickle
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, cast

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.integrations.sbom_generator import generate_sbom_pydantic
from modelaudit.models import AssetModel, FileHashesModel, FileMetadataModel, create_initial_audit_result
from modelaudit.scanner_results import MAX_MEMBER_FILE_HASH_RECORDS
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash
from tests.helpers import create_mock_pytorch_zip, write_mock_pytorch_zip_metadata


class _MaliciousPicklePayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("__import__('os').system('echo modelaudit-test')",))


def _pytorch_zip_with_pickle_members(
    path: Path,
    *,
    members: dict[str, bytes],
) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        write_mock_pytorch_zip_metadata(archive)
        for member_name, payload in members.items():
            archive.writestr(member_name, payload)
    return path


def _member_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _member_records_for_segments(metadata: dict[str, Any], path_segments: list[str]) -> list[dict[str, Any]]:
    member_hashes = metadata.get("member_file_hashes")
    assert isinstance(member_hashes, dict)
    return [
        record
        for record in member_hashes.values()
        if isinstance(record, dict) and record.get("path_segments") == path_segments
    ]


def _single_member_record(metadata: dict[str, Any], path_segments: list[str]) -> dict[str, Any]:
    records = _member_records_for_segments(metadata, path_segments)
    assert len(records) == 1
    return records[0]


_PYTORCH_LEGACY_MAGIC_NUMBER = 0x1950A86A20F9469CFC6C
_PYTORCH_LEGACY_PROTOCOL_VERSION = 1001


def _binunicode(value: bytes) -> bytes:
    return b"X" + len(value).to_bytes(4, "little") + value


def _legacy_pytorch_object_stream(
    storage_keys: tuple[str, ...],
    storage_size: int,
    *,
    object_padding: int = 0,
) -> bytes:
    object_stream = bytearray(b"\x80\x02]")
    for key in storage_keys:
        encoded_key = key.encode("ascii")
        object_stream += b"(" + _binunicode(b"storage")
        object_stream += b"ctorch\nByteStorage\n"
        object_stream += _binunicode(encoded_key) + _binunicode(b"cpu")
        object_stream += pickle.dumps(storage_size, protocol=2)[2:-1]
        object_stream += b"NtQa"
    if object_padding:
        object_stream += pickle.dumps("A" * object_padding, protocol=2)[2:-1] + b"a"
    object_stream += b"."
    return bytes(object_stream)


def _make_legacy_pytorch_container(
    storage_payload: bytes,
    *,
    sys_info_padding: int = 0,
    sys_info_protocol: int = 2,
    object_padding: int = 0,
) -> tuple[bytes, dict[str, int]]:
    sys_info: dict[str, object] = {
        "protocol_version": _PYTORCH_LEGACY_PROTOCOL_VERSION,
        "little_endian": True,
        "type_sizes": {"short": 2, "int": 4, "long": 8},
    }
    if sys_info_padding:
        sys_info["padding"] = "A" * sys_info_padding

    storage_keys = ("0",)
    control_streams = {
        "magic": pickle.dumps(_PYTORCH_LEGACY_MAGIC_NUMBER, protocol=2),
        "protocol": pickle.dumps(_PYTORCH_LEGACY_PROTOCOL_VERSION, protocol=2),
        "sys_info": pickle.dumps(sys_info, protocol=sys_info_protocol),
        "object": _legacy_pytorch_object_stream(
            storage_keys,
            len(storage_payload),
            object_padding=object_padding,
        ),
        "storage_keys": pickle.dumps(list(storage_keys), protocol=2),
    }
    offsets: dict[str, int] = {}
    cursor = 0
    for name, stream in control_streams.items():
        offsets[f"{name}_start"] = cursor
        cursor += len(stream)
        offsets[f"{name}_end"] = cursor
    offsets["storage_start"] = cursor
    storage_record = len(storage_payload).to_bytes(8, "little") + storage_payload
    return b"".join(control_streams.values()) + storage_record, offsets


def _make_malformed_legacy_pytorch_near_match() -> tuple[bytes, dict[str, int]]:
    control_streams = {
        "magic": pickle.dumps(_PYTORCH_LEGACY_MAGIC_NUMBER, protocol=2),
        "protocol": pickle.dumps(_PYTORCH_LEGACY_PROTOCOL_VERSION, protocol=2),
        "sys_info": pickle.dumps(
            {"protocol_version": _PYTORCH_LEGACY_PROTOCOL_VERSION, "little_endian": True},
            protocol=2,
        ),
    }
    offsets: dict[str, int] = {}
    cursor = 0
    for name, stream in control_streams.items():
        offsets[f"{name}_start"] = cursor
        cursor += len(stream)
        offsets[f"{name}_end"] = cursor
    offsets["object_start"] = cursor
    return b"".join(control_streams.values()) + b"\x80\x02]" + (b"A" * 2048), offsets


def _write_regular_scan_onnx_model(
    model_path: Path,
    *,
    external_location: str | None = None,
    external_size: int = 4,
    stale_inline_location: str | None = None,
) -> None:
    pytest.importorskip("onnx")
    import onnx
    from onnx import TensorProto, helper
    from onnx.onnx_ml_pb2 import StringStringEntryProto

    if external_location is not None:
        initializer = onnx.TensorProto()
        initializer.name = "W"
        initializer.data_type = TensorProto.UINT8
        initializer.dims.extend([external_size])
        initializer.data_location = TensorProto.EXTERNAL
        entry = StringStringEntryProto()
        entry.key = "location"
        entry.value = external_location
        initializer.external_data.append(entry)
    else:
        initializer = helper.make_tensor("W", TensorProto.FLOAT, [1], [1.0])
        if stale_inline_location is not None:
            entry = StringStringEntryProto()
            entry.key = "location"
            entry.value = stale_inline_location
            initializer.external_data.append(entry)

    input_info = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1])
    output_info = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1])
    node = helper.make_node("Relu", ["input"], ["output"], name="relu")
    graph = helper.make_graph([node], "graph", [input_info], [output_info], initializer=[initializer])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    onnx.save(model, str(model_path))


def _path_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _skip_path_during_directory_prefilter(monkeypatch: pytest.MonkeyPatch, skipped_path: Path) -> None:
    from modelaudit import core

    original_should_skip_file = core.should_skip_file
    skipped_path = skipped_path.resolve()

    def should_skip_file(path: str, *args: Any, **kwargs: Any) -> bool:
        if Path(path).resolve() == skipped_path:
            return True
        return original_should_skip_file(path, *args, **kwargs)

    monkeypatch.setattr(core, "should_skip_file", should_skip_file)


class _TrackingBinaryFile:
    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        self.max_position = 0

    def __enter__(self) -> "_TrackingBinaryFile":
        self._raw.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return self._raw.__exit__(exc_type, exc, traceback)

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        self.max_position = max(self.max_position, self._raw.tell())
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        position = self._raw.seek(offset, whence)
        self.max_position = max(self.max_position, position)
        return position

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def _track_binary_reads_for_path(monkeypatch: pytest.MonkeyPatch, path: Path) -> list[_TrackingBinaryFile]:
    original_open = cast(Any, builtins.open)
    trackers: list[_TrackingBinaryFile] = []

    def tracking_open(file: object, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        opened = original_open(file, mode, *args, **kwargs)
        if isinstance(file, (str, os.PathLike)) and Path(file) == path and "b" in mode:
            tracker = _TrackingBinaryFile(cast(BinaryIO, opened))
            trackers.append(tracker)
            return tracker
        return opened

    monkeypatch.setattr(builtins, "open", tracking_open)
    return trackers


class TestRegularScanContentHash:
    """Test content hash generation for regular (non-streaming) scans."""

    def test_single_file_generates_hash(self, tmp_path):
        """Test that scanning a single file generates a content hash."""
        # Create a simple pickle file
        test_file = tmp_path / "model.pkl"
        data = {"key": "value", "number": 42}
        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        result = scan_model_directory_or_file(str(test_file))

        # Verify content_hash is present and valid
        assert hasattr(result, "content_hash")
        assert result.content_hash is not None
        assert isinstance(result.content_hash, str)
        assert len(result.content_hash) == 64  # SHA-256 hex digest length

    def test_single_archive_hash_uses_outer_file_bytes(self, tmp_path: Path) -> None:
        """Archive scans must hash the scanned archive, not merged nested metadata."""
        archive_path = tmp_path / "model.zip"
        nested_payload = pickle.dumps({"nested": "payload"})
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("model.pkl", nested_payload)

        result = scan_model_directory_or_file(str(archive_path))

        outer_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        nested_hash = hashlib.sha256(nested_payload).hexdigest()
        assert result.content_hash == compute_aggregate_hash([outer_hash])
        assert result.content_hash != compute_aggregate_hash([nested_hash])

    def test_pytorch_member_hashes_are_namespaced_in_json_sarif_and_sbom(self, tmp_path: Path) -> None:
        benign_payload = pickle.dumps({"safe": True})
        malicious_payload = pickle.dumps(_MaliciousPicklePayload())
        model_path = _pytorch_zip_with_pickle_members(
            tmp_path / "model.pt",
            members={
                "data.pkl": benign_payload,
                "evil.pkl": malicious_payload,
            },
        )

        result = scan_model_directory_or_file(str(model_path), cache_enabled=False)
        outer_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        benign_hash = _member_sha256(benign_payload)
        malicious_hash = _member_sha256(malicious_payload)
        metadata = result.file_metadata[str(model_path)].model_dump(mode="json", exclude_none=True)

        assert metadata["file_hashes"]["sha256"] == outer_hash
        assert "file_hashes_complete" not in metadata
        assert "file_hashes_bytes_hashed" not in metadata
        assert metadata["file_hashes"]["sha256"] not in {benign_hash, malicious_hash}
        assert _single_member_record(metadata, ["data.pkl"])["file_hashes"]["sha256"] == benign_hash
        assert _single_member_record(metadata, ["evil.pkl"])["file_hashes"]["sha256"] == malicious_hash
        assert any(
            issue.location is not None
            and ":evil.pkl" in issue.location
            and issue.details.get("pickle_filename") == "evil.pkl"
            for issue in result.issues
        )

        json_payload = result.model_dump(mode="json", exclude_none=True)
        json_metadata = json_payload["file_metadata"][str(model_path)]
        assert json_metadata["file_hashes"]["sha256"] == outer_hash
        assert _single_member_record(json_metadata, ["evil.pkl"])["file_hashes"]["sha256"] == malicious_hash

        sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
        artifact = sarif_payload["runs"][0]["artifacts"][0]
        assert artifact["hashes"]["sha-256"] == outer_hash
        sarif_member_metadata = {"member_file_hashes": artifact["properties"]["memberFileHashes"]}
        assert _single_member_record(sarif_member_metadata, ["evil.pkl"])["file_hashes"]["sha256"] == malicious_hash

        sbom_payload = json.loads(generate_sbom_pydantic([str(model_path)], result))
        component = sbom_payload["components"][0]
        assert component["hashes"][0]["content"] == outer_hash
        member_hash_property = next(
            prop["value"] for prop in component["properties"] if prop["name"] == "modelaudit:member_file_hashes"
        )
        assert (
            _single_member_record({"member_file_hashes": json.loads(member_hash_property)}, ["evil.pkl"])[
                "file_hashes"
            ]["sha256"]
            == malicious_hash
        )

    def test_member_hash_truncation_summary_exports_to_sarif_and_sbom(self, tmp_path: Path) -> None:
        model_path = tmp_path / "bounded.pt"
        model_path.write_bytes(b"outer")
        outer_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        member_hash = hashlib.sha256(b"inner").hexdigest()
        member_identity = json.dumps({"occurrence": 1, "path": ["retained.pkl"]}, sort_keys=True, separators=(",", ":"))
        result = create_initial_audit_result()
        result.assets = [AssetModel(path=str(model_path), type="pytorch", size=model_path.stat().st_size)]
        result.file_metadata[str(model_path)] = FileMetadataModel(
            file_size=model_path.stat().st_size,
            file_hashes=FileHashesModel(sha256=outer_hash),
            member_file_hashes={
                member_identity: {
                    "file_hashes": {"sha256": member_hash},
                    "file_size": len(b"inner"),
                    "hash_complete": True,
                    "hash_status": "complete",
                    "path_segments": ["retained.pkl"],
                    "occurrence": 1,
                }
            },
            member_file_hashes_total=MAX_MEMBER_FILE_HASH_RECORDS + 2,
            member_file_hashes_truncated=True,
            member_file_hashes_omitted=2,
        )

        sarif_payload = json.loads(format_sarif_output(result, [str(model_path)]))
        artifact_properties = sarif_payload["runs"][0]["artifacts"][0]["properties"]
        assert artifact_properties["memberFileHashesTotal"] == MAX_MEMBER_FILE_HASH_RECORDS + 2
        assert artifact_properties["memberFileHashesTruncated"] is True
        assert artifact_properties["memberFileHashesOmitted"] == 2
        assert (
            _single_member_record({"member_file_hashes": artifact_properties["memberFileHashes"]}, ["retained.pkl"])[
                "file_hashes"
            ]["sha256"]
            == member_hash
        )

        sbom_payload = json.loads(generate_sbom_pydantic([str(model_path)], result))
        component_properties = {prop["name"]: prop["value"] for prop in sbom_payload["components"][0]["properties"]}
        assert component_properties["modelaudit:member_file_hashes_total"] == str(MAX_MEMBER_FILE_HASH_RECORDS + 2)
        assert component_properties["modelaudit:member_file_hashes_truncated"] == "true"
        assert component_properties["modelaudit:member_file_hashes_omitted"] == "2"

    def test_generic_zip_member_hash_identities_are_collision_free(self, tmp_path: Path) -> None:
        duplicate_payload = pickle.dumps({"duplicate": True})
        literal_colon_payload = pickle.dumps({"literal": "colon"})
        inner_payload = pickle.dumps({"nested": True})
        malicious_payload = pickle.dumps(_MaliciousPicklePayload())
        inner_zip_path = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner_zip_path, "w") as inner_zip:
            inner_zip.writestr("inner.pkl", inner_payload)
        archive_path = tmp_path / "collision.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("dup.pkl", duplicate_payload)
            archive.writestr("dup.pkl", duplicate_payload)
            archive.writestr("nested.zip:inner.pkl", literal_colon_payload)
            archive.write(inner_zip_path, "nested.zip")
            archive.writestr("evil.pkl", malicious_payload)

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)
        metadata = result.file_metadata[str(archive_path)].model_dump(mode="json", exclude_none=True)

        duplicate_records = sorted(
            _member_records_for_segments(metadata, ["dup.pkl"]),
            key=lambda record: record["occurrence"],
        )
        assert [record["occurrence"] for record in duplicate_records] == [1, 2]
        assert all(record["file_hashes"]["sha256"] == _member_sha256(duplicate_payload) for record in duplicate_records)
        assert _single_member_record(metadata, ["nested.zip:inner.pkl"])["file_hashes"]["sha256"] == _member_sha256(
            literal_colon_payload
        )
        assert _single_member_record(metadata, ["nested.zip", "inner.pkl"])["file_hashes"]["sha256"] == _member_sha256(
            inner_payload
        )
        assert any(issue.location is not None and ":evil.pkl" in issue.location for issue in result.issues)

    def test_tar_member_hashes_are_child_scoped(self, tmp_path: Path) -> None:
        payload = pickle.dumps({"safe": "tar"})
        archive_path = tmp_path / "model.tar"
        payload_path = tmp_path / "payload.pkl"
        payload_path.write_bytes(payload)
        with tarfile.open(archive_path, "w") as archive:
            archive.add(payload_path, arcname="payload.pkl")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)
        metadata = result.file_metadata[str(archive_path)].model_dump(mode="json", exclude_none=True)

        assert metadata["file_hashes"]["sha256"] == hashlib.sha256(archive_path.read_bytes()).hexdigest()
        assert _single_member_record(metadata, ["payload.pkl"])["file_hashes"]["sha256"] == _member_sha256(payload)

    def test_pytorch_member_hashes_survive_cache_round_trip(self, tmp_path: Path) -> None:
        reset_cache_manager()
        payload = pickle.dumps({"safe": "cache"})
        model_path = _pytorch_zip_with_pickle_members(tmp_path / "cached.pt", members={"data.pkl": payload})
        outer_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        member_hash = _member_sha256(payload)
        cache_dir = str(tmp_path / "cache")
        first = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=cache_dir,
            min_cache_file_size=0,
        )
        cache_manager = get_cache_manager(cache_dir, enabled=True)
        stats_after_first = cache_manager.get_stats()
        second = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=cache_dir,
            min_cache_file_size=0,
        )
        stats_after_second = cache_manager.get_stats()
        assert stats_after_second["cache_hits"] == stats_after_first["cache_hits"] + 1

        for result in (first, second):
            metadata = result.file_metadata[str(model_path)].model_dump(mode="json", exclude_none=True)
            assert metadata["file_hashes"]["sha256"] == outer_hash
            assert _single_member_record(metadata, ["data.pkl"])["file_hashes"]["sha256"] == member_hash
            assert _single_member_record(metadata, ["data.pkl"])["file_hashes"]["sha256"] != outer_hash

        reset_cache_manager()

    @pytest.mark.integration
    @pytest.mark.slow
    def test_real_hf_bert_large_rust_model_member_hash_is_namespaced(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if os.environ.get("MODELAUDIT_RUN_REAL_HF") != "1":
            pytest.skip("set MODELAUDIT_RUN_REAL_HF=1 to download the pinned Hugging Face artifact")

        from huggingface_hub import hf_hub_download

        repo_id = "google-bert/bert-large-uncased"
        revision = "6da4b6a26a1877e173fca3225479512db81a5e5b"
        member_name = "rust_model/code/__torch__.py.debug_pkl"
        expected_parent_sha = "9db92b28d6fb0e5ab770b24ed27bde941d1f314a3c5e8c28d698025cc1807d7f"
        expected_member_sha = "326da525ff54021be4bbeb601c3ff4ee74e0cee4e45a0fbe1b9ccde3ca16229c"
        monkeypatch.setenv("HF_HOME", str(tmp_path / "hf-cache"))
        model_path = Path(
            hf_hub_download(
                repo_id=repo_id,
                revision=revision,
                filename="rust_model.ot",
                local_dir=tmp_path / "hf-model",
            )
        )

        with zipfile.ZipFile(model_path) as archive:
            member_payload = archive.read(member_name)
        assert hashlib.sha256(model_path.read_bytes()).hexdigest() == expected_parent_sha
        assert len(member_payload) == 106
        assert _member_sha256(member_payload) == expected_member_sha

        result = scan_model_directory_or_file(str(model_path), cache_enabled=False)
        metadata = result.file_metadata[str(model_path)].model_dump(mode="json", exclude_none=True)

        assert metadata["file_hashes"]["sha256"] == expected_parent_sha
        assert _single_member_record(metadata, [member_name])["file_hashes"]["sha256"] == expected_member_sha

    def test_directory_generates_hash(self, tmp_path):
        """Test that scanning a directory generates an aggregate content hash."""
        # Create multiple pickle files
        for i in range(3):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i, "value": f"test_{i}"}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan the directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Verify content_hash is present and valid
        assert hasattr(result, "content_hash")
        assert result.content_hash is not None
        assert isinstance(result.content_hash, str)
        assert len(result.content_hash) == 64

    def test_hash_is_deterministic(self, tmp_path):
        """Test that scanning the same content produces the same hash."""
        # Create a test file
        test_file = tmp_path / "model.pkl"
        data = {"deterministic": "test"}
        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan twice
        result1 = scan_model_directory_or_file(str(test_file))
        result2 = scan_model_directory_or_file(str(test_file))

        # Hashes should be identical
        assert result1.content_hash == result2.content_hash

    def test_directory_hash_is_deterministic(self, tmp_path):
        """Test that scanning the same directory produces the same hash."""
        # Create multiple files
        for i in range(3):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan twice
        result1 = scan_model_directory_or_file(str(tmp_path))
        result2 = scan_model_directory_or_file(str(tmp_path))

        # Hashes should be identical
        assert result1.content_hash == result2.content_hash

    def test_different_content_different_hash(self, tmp_path):
        """Test that different content produces different hashes."""
        # Create first file
        file1 = tmp_path / "model1.pkl"
        with open(file1, "wb") as f:
            pickle.dump({"data": "first"}, f)

        # Create second file with different content
        file2 = tmp_path / "model2.pkl"
        with open(file2, "wb") as f:
            pickle.dump({"data": "second"}, f)

        # Scan both files
        result1 = scan_model_directory_or_file(str(file1))
        result2 = scan_model_directory_or_file(str(file2))

        # Hashes should be different
        assert result1.content_hash != result2.content_hash

    def test_hash_order_independence(self, tmp_path):
        """Test that file processing order doesn't affect the aggregate hash."""
        # Create files with different names to ensure different traversal order
        files = []
        for name in ["aaa.pkl", "zzz.pkl", "mmm.pkl"]:
            file_path = tmp_path / name
            with open(file_path, "wb") as f:
                pickle.dump({"name": name}, f)
            files.append(file_path)

        # Scan the directory multiple times to verify consistent hash
        # (os.walk might process in different order)
        result1 = scan_model_directory_or_file(str(tmp_path))
        result2 = scan_model_directory_or_file(str(tmp_path))

        # Hashes should be identical across scans (order-independent)
        # This is guaranteed by compute_aggregate_hash sorting the hashes
        assert result1.content_hash is not None
        assert result1.content_hash == result2.content_hash

    def test_duplicate_files_single_hash(self, tmp_path):
        """Test that duplicate files are deduplicated and contribute once to hash."""
        # Create identical files
        data = {"duplicate": "content"}
        for i in range(3):
            test_file = tmp_path / f"dup_{i}.pkl"
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan directory with duplicates
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a hash (deduplication means only one hash contributed)
        assert result.content_hash is not None

    def test_empty_directory_no_hash(self, tmp_path):
        """Test that an empty directory doesn't generate a content hash."""
        # Scan empty directory
        result = scan_model_directory_or_file(str(tmp_path))

        # content_hash should not be set (remains None) when no files are hashed
        assert result.content_hash is None

    def test_hash_consistency_with_streaming(self, tmp_path):
        """Test that regular and streaming modes produce compatible hashes."""
        # Create test files
        file_hashes = []
        for i in range(2):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

            # Compute individual file hash
            import hashlib

            hash_sha256 = hashlib.sha256()
            with open(test_file, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_sha256.update(chunk)
            file_hashes.append(hash_sha256.hexdigest())

        # Compute expected aggregate hash
        expected_hash = compute_aggregate_hash(file_hashes)

        # Scan directory with regular mode
        result = scan_model_directory_or_file(str(tmp_path))

        # Should match the expected aggregate
        assert result.content_hash == expected_hash

    def test_mixed_files_generates_hash(self, tmp_path):
        """Test that scanning a directory with mixed file types generates a hash."""
        # Create a model file
        model_file = tmp_path / "model.pkl"
        with open(model_file, "wb") as f:
            pickle.dump({"data": "model"}, f)

        # Create a text file (scanned for metadata but not with model scanners)
        text_file = tmp_path / "readme.txt"
        text_file.write_text("This is a readme")

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a content hash
        assert result.content_hash is not None
        # Both files are processed (readme.txt for metadata)
        assert result.files_scanned == 2


@pytest.mark.unit
class TestHashGenerationEdgeCases:
    """Test edge cases in hash generation."""

    def test_hash_with_nested_directories(self, tmp_path):
        """Test hash generation with nested directory structure."""
        # Create nested structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        file1 = tmp_path / "model.pkl"
        with open(file1, "wb") as f:
            pickle.dump({"level": 1}, f)

        file2 = subdir / "nested.pkl"
        with open(file2, "wb") as f:
            pickle.dump({"level": 2}, f)

        # Scan root directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should generate hash for all files
        assert result.content_hash is not None
        assert result.files_scanned == 2

    def test_hash_with_regular_files(self, tmp_path):
        """Test that regular files generate hash correctly."""
        # Create a regular file
        regular_file = tmp_path / "model.pkl"
        with open(regular_file, "wb") as f:
            pickle.dump({"type": "regular"}, f)

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        assert result.content_hash is not None
        assert result.files_scanned == 1

    def test_hash_files_by_path_reuses_hash_for_hardlinks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hardlinked paths should reuse the same read during the hash prepass."""
        from modelaudit import core

        source = tmp_path / "source.pkl"
        source.write_bytes(pickle.dumps({"hardlink": True}))
        linked_path = tmp_path / "linked.pkl"
        os.link(source, linked_path)

        hashed_paths: list[str] = []
        original_hash = core._calculate_file_hash

        def spy_hash(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", spy_hash)

        content_hashes = core._hash_files_by_path([str(source), str(linked_path)])

        assert content_hashes[str(source)] == content_hashes[str(linked_path)]
        assert hashed_paths == [str(source)]

    def test_directory_scan_does_not_hash_files_over_max_file_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Directory hash prepass should not read files regular scanning will reject."""
        from modelaudit import core

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(b"X" * 128)
        small = tmp_path / "small.pkl"
        small.write_bytes(pickle.dumps({"safe": True}))

        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def fail_if_oversized_hashed(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            if Path(path).name == oversized.name:
                raise AssertionError("oversized file was hashed before max_file_size rejection")
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", fail_if_oversized_hashed)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_file_size=64,
            cache_enabled=False,
        )

        hashed_names = {Path(path).name for path in hashed_paths}
        assert oversized.name not in hashed_names
        assert small.name in hashed_names
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)
        assert result.has_errors is True

    def test_single_file_scan_does_not_hash_files_over_max_file_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Single-file hashing should honor the same regular scan size budget."""
        from modelaudit import core

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(b"X" * 128)

        monkeypatch.setattr(
            core,
            "_calculate_file_hash",
            lambda _path: pytest.fail("oversized file was hashed before max_file_size rejection"),
        )

        result = scan_model_directory_or_file(
            str(oversized),
            max_file_size=64,
            cache_enabled=False,
        )

        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)
        assert result.has_errors is True

    def test_single_file_scan_bypasses_cache_hash_for_max_file_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cache lookup should not content-hash files regular scanning will reject."""
        from modelaudit.utils.helpers.secure_hasher import SecureFileHasher

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(b"X" * 128)

        def fail_if_cache_hashes_oversized(self: SecureFileHasher, path: str) -> str:
            if path == str(oversized):
                pytest.fail("oversized file was content-hashed for cache lookup before max_file_size rejection")
            return "a" * 64

        monkeypatch.setattr(SecureFileHasher, "hash_file", fail_if_cache_hashes_oversized)
        monkeypatch.setattr(
            SecureFileHasher,
            "hash_file_with_stat",
            lambda self, path, _stat: fail_if_cache_hashes_oversized(self, path),
        )

        result = scan_model_directory_or_file(
            str(oversized),
            max_file_size=64,
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            content_hash_threshold=1,
            max_cache_file_size=1024,
        )

        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)
        assert result.has_errors is True

    def test_hash_files_by_path_stops_hashing_at_max_total_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Directory hash prepasses should stop after crossing the aggregate scan budget."""
        from modelaudit import core

        first = tmp_path / "first.pkl"
        first.write_bytes(b"A" * 32)
        second = tmp_path / "second.pkl"
        second.write_bytes(b"B" * 33)
        third = tmp_path / "third.pkl"
        third.write_bytes(b"C")

        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def track_hash(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)

        content_hashes = core._hash_files_by_path(
            [str(first), str(second), str(third)],
            config={"max_total_size": 64},
        )

        assert hashed_paths == [str(first)]
        assert content_hashes[str(second)].startswith("unhashable_max_total_size_")
        assert content_hashes[str(third)].startswith("unhashable_max_total_size_")

    def test_hash_files_by_path_defers_oversized_pytorch_zip_read_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aggregate hashing must not full-read oversized ZIP-backed PyTorch containers."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "large.pt")
        with zip_path.open("ab") as handle:
            handle.write(b"A" * 2048)

        def fail_hash(path: str) -> str:
            if path == str(zip_path):
                pytest.fail("oversized PyTorch ZIP was content-hashed before bounded scan dispatch")
            return "a" * 64

        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        content_hashes = core._hash_files_by_path(
            [str(zip_path)],
            config={"max_file_read_size": 64},
        )

        assert content_hashes[str(zip_path)].startswith("unhashable_pytorch_zip_read_limit_")

    def test_hash_files_by_path_defers_file_backed_onnx(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit import core

        model_path = tmp_path / "model.onnx"
        later_path = tmp_path / "later.pkl"
        _write_regular_scan_onnx_model(model_path)
        later_path.write_bytes(pickle.dumps({"safe": True}))
        monkeypatch.setattr(
            core,
            "_calculate_file_hash",
            lambda *_args, **_kwargs: pytest.fail("files beyond the deferred ONNX budget must not be hashed"),
        )

        hashes = core._hash_files_by_path(
            [str(model_path), str(later_path)],
            config={
                "max_total_size": model_path.stat().st_size - 1,
                "onnx_raw_detector_max_bytes": 1,
            },
        )

        assert hashes[str(model_path)].startswith("unhashable_file_backed_onnx_")
        assert hashes[str(later_path)].startswith("unhashable_max_total_size_")

    def test_file_backed_onnx_hash_deferral_uses_bounded_content_routing(
        self,
        tmp_path: Path,
    ) -> None:
        from modelaudit.utils.file.detection import (
            PROTOBUF_MODEL_CANDIDATE_FORMAT,
            detect_file_format_for_skip_filter,
        )
        from modelaudit.utils.helpers.cache_decorator import should_defer_hash_for_file_backed_onnx

        renamed_model = tmp_path / "renamed"
        ambiguous_model = tmp_path / "ambiguous.conf"
        foreign_zip = tmp_path / "foreign.onnx"
        _write_regular_scan_onnx_model(renamed_model)
        _write_regular_scan_onnx_model(ambiguous_model)
        ambiguous_model.write_bytes((b"\x12\x01a" * 4097) + ambiguous_model.read_bytes())
        with zipfile.ZipFile(foreign_zip, "w") as archive:
            archive.writestr("payload.txt", "not ONNX")
        config = {"onnx_raw_detector_max_bytes": 1}

        assert should_defer_hash_for_file_backed_onnx(str(renamed_model), config)
        assert not should_defer_hash_for_file_backed_onnx(str(foreign_zip), config)
        assert detect_file_format_for_skip_filter(str(ambiguous_model)) == PROTOBUF_MODEL_CANDIDATE_FORMAT
        assert should_defer_hash_for_file_backed_onnx(
            str(ambiguous_model),
            {**config, "scanners": ["protobuf_model_candidate"]},
        )
        assert not should_defer_hash_for_file_backed_onnx(
            str(ambiguous_model),
            {**config, "scanners": ["metadata"]},
        )
        assert not should_defer_hash_for_file_backed_onnx(
            str(renamed_model),
            {**config, "scanners": ["metadata"]},
        )

        metadata_result = scan_model_directory_or_file(
            str(ambiguous_model),
            cache_enabled=False,
            scanners=["metadata"],
            skip_file_types=False,
            onnx_raw_detector_max_bytes=1,
        )
        expected_hash = compute_aggregate_hash([hashlib.sha256(ambiguous_model.read_bytes()).hexdigest()])
        assert metadata_result.content_hash == expected_hash

    def test_single_file_backed_onnx_bypasses_aggregate_and_cache_hashes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit import core
        from modelaudit.utils.helpers.secure_hasher import SecureFileHasher

        model_path = tmp_path / "model.onnx"
        _write_regular_scan_onnx_model(model_path)
        monkeypatch.setattr(
            core,
            "_calculate_file_hash",
            lambda *_args, **_kwargs: pytest.fail("file-backed ONNX must not be aggregate-hashed"),
        )
        monkeypatch.setattr(
            SecureFileHasher,
            "hash_file",
            lambda *_args, **_kwargs: pytest.fail("file-backed ONNX must not be cache-hashed"),
        )
        monkeypatch.setattr(
            SecureFileHasher,
            "hash_file_with_stat",
            lambda *_args, **_kwargs: pytest.fail("file-backed ONNX must not be cache-hashed"),
        )

        result = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            onnx_raw_detector_max_bytes=1,
        )

        assert result.content_hash is None
        assert result.file_metadata[str(model_path)]["onnx_structure_parse"]["parse_mode"] == "file_backed_structure"

    def test_directory_file_backed_onnx_omits_aggregate_but_hashes_other_files(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit import core

        model_path = tmp_path / "model.onnx"
        sidecar = tmp_path / "weights.data"
        safe_path = tmp_path / "safe.pkl"
        sidecar.write_bytes(b"W" * 4096)
        _write_regular_scan_onnx_model(
            model_path,
            external_location=sidecar.name,
            external_size=sidecar.stat().st_size,
        )
        _skip_path_during_directory_prefilter(monkeypatch, sidecar)
        safe_path.write_bytes(pickle.dumps({"safe": True}))
        original_hash = core._calculate_file_hash
        hashed: list[Path] = []

        def track_hash(path: str, *, deadline: float | None = None) -> str:
            hashed.append(Path(path))
            if Path(path) in {model_path, sidecar}:
                pytest.fail("file-backed ONNX owners and context sidecars must not be aggregate-hashed")
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            onnx_raw_detector_max_bytes=1,
        )

        assert safe_path in hashed
        assert model_path not in hashed
        assert sidecar not in hashed
        assert result.bytes_scanned == sum(path.stat().st_size for path in (model_path, sidecar, safe_path))
        assert result.content_hash is None

    def test_hash_files_by_path_defers_oversized_pytorch_zip_ckpt_read_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All PyTorchZipScanner suffixes should use bounded ZIP hash deferral."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "large.ckpt")
        with zip_path.open("ab") as handle:
            handle.write(b"A" * 2048)

        def fail_hash(path: str) -> str:
            if path == str(zip_path):
                pytest.fail("oversized PyTorch ZIP .ckpt was content-hashed before bounded scan dispatch")
            return "a" * 64

        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        content_hashes = core._hash_files_by_path(
            [str(zip_path)],
            config={"max_file_read_size": 64},
        )

        assert content_hashes[str(zip_path)].startswith("unhashable_pytorch_zip_read_limit_")

    @pytest.mark.parametrize("read_size", [None, "invalid", -1])
    def test_hash_files_by_path_uses_default_for_invalid_pytorch_read_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read_size: object
    ) -> None:
        """Invalid read-limit config should mirror scanner defaults before aggregate hashing."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "large.pt")
        with zip_path.open("ab") as handle:
            handle.write(b"A" * 2048)

        def fail_hash(path: str) -> str:
            if path == str(zip_path):
                pytest.fail("invalid max_file_read_size should still use default bounded PyTorch deferral")
            return "a" * 64

        monkeypatch.setattr(core.BaseScanner, "default_max_file_read_size", 256)
        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        content_hashes = core._hash_files_by_path(
            [str(zip_path)],
            config={"max_file_read_size": read_size},
        )

        assert content_hashes[str(zip_path)].startswith("unhashable_pytorch_zip_read_limit_")

    def test_hash_files_by_path_treats_bool_pytorch_read_limit_as_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Boolean read-limit config must not be coerced to a one-byte cap."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "small.pt")
        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def track_hash(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core.BaseScanner, "default_max_file_read_size", 1_000_000)
        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)

        content_hashes = core._hash_files_by_path(
            [str(zip_path)],
            config={"max_file_read_size": True},
        )

        assert hashed_paths == [str(zip_path)]
        assert content_hashes[str(zip_path)] == original_hash(str(zip_path))

    @pytest.mark.parametrize(
        ("padding_target", "read_limit_offset"),
        [
            ("sys_info", "sys_info_start"),
            ("object", "object_start"),
        ],
    )
    def test_hash_files_by_path_defers_valid_long_legacy_pytorch_control_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        padding_target: str,
        read_limit_offset: str,
    ) -> None:
        """Valid incomplete legacy PyTorch control metadata must not be full-hashed."""
        from modelaudit import core

        payload, offsets = _make_legacy_pytorch_container(
            b"A" * 256,
            sys_info_padding=1024 if padding_target == "sys_info" else 0,
            object_padding=1024 if padding_target == "object" else 0,
        )
        legacy_path = tmp_path / f"long-{padding_target}.pt"
        legacy_path.write_bytes(payload)
        read_limit = offsets[read_limit_offset] + 8

        def fail_hash(path: str) -> str:
            if path == str(legacy_path):
                pytest.fail("valid long legacy PyTorch control metadata was content-hashed")
            return "a" * 64

        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        content_hashes = core._hash_files_by_path(
            [str(legacy_path)],
            config={"max_file_read_size": read_limit},
        )

        assert content_hashes[str(legacy_path)].startswith("unhashable_pytorch_zip_read_limit_")

    @pytest.mark.parametrize("sys_info_protocol", [2, 3, 4, 5])
    def test_hash_files_by_path_defers_long_legacy_pytorch_sys_info_protocols(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        sys_info_protocol: int,
    ) -> None:
        """Incomplete legacy PyTorch sys_info metadata must defer for protocols 2-5."""
        from modelaudit import core

        payload, offsets = _make_legacy_pytorch_container(
            b"A" * 256,
            sys_info_padding=1024,
            sys_info_protocol=sys_info_protocol,
        )
        legacy_path = tmp_path / f"long-sys-info-protocol-{sys_info_protocol}.pt"
        legacy_path.write_bytes(payload)
        read_limit = offsets["sys_info_start"] + 8
        assert read_limit < offsets["sys_info_end"]

        def fail_hash(path: str) -> str:
            if path == str(legacy_path):
                pytest.fail("valid long legacy PyTorch sys_info metadata was content-hashed")
            return "a" * 64

        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        content_hashes = core._hash_files_by_path(
            [str(legacy_path)],
            config={"max_file_read_size": read_limit},
        )

        assert content_hashes[str(legacy_path)].startswith("unhashable_pytorch_zip_read_limit_")

    @pytest.mark.parametrize("sys_info_protocol", [2, 3, 4, 5])
    def test_single_file_scan_bypasses_cache_hash_for_valid_long_legacy_pytorch_control(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sys_info_protocol: int
    ) -> None:
        """Cache lookup must not full-hash a bounded valid legacy PyTorch control."""
        from modelaudit import core
        from modelaudit.cache import reset_cache_manager
        from modelaudit.utils.helpers.secure_hasher import SecureFileHasher

        payload, offsets = _make_legacy_pytorch_container(
            b"A" * 256,
            sys_info_padding=1024,
            sys_info_protocol=sys_info_protocol,
        )
        legacy_path = tmp_path / f"long-control-cache-protocol-{sys_info_protocol}.pt"
        legacy_path.write_bytes(payload)
        read_limit = offsets["sys_info_start"] + 8
        assert read_limit < offsets["sys_info_end"]

        def fail_cache_hash(self: SecureFileHasher, path: str) -> str:
            if path == str(legacy_path):
                pytest.fail("valid long legacy PyTorch control was cache-hashed")
            return "a" * 64

        monkeypatch.setattr(SecureFileHasher, "hash_file", fail_cache_hash)
        monkeypatch.setattr(
            SecureFileHasher,
            "hash_file_with_stat",
            lambda self, path, _stat: fail_cache_hash(self, path),
        )

        reset_cache_manager()
        try:
            result = core.scan_file(
                str(legacy_path),
                config={
                    "cache_enabled": True,
                    "cache_dir": str(tmp_path / "cache"),
                    "min_cache_file_size": 0,
                    "max_cache_file_size": 10_000_000,
                    "max_file_read_size": read_limit,
                },
            )
        finally:
            reset_cache_manager()

        assert result.metadata["file_size"] == len(payload)
        assert result.metadata["legacy_pytorch_bounded_analysis"] is True
        assert result.metadata["legacy_pytorch_storage_payload_skipped"] is True
        assert result.metadata["file_hashes"]["sha256_prefix"]
        assert "sha256" not in result.metadata["file_hashes"]

    def test_directory_scan_omits_content_hash_for_valid_long_legacy_pytorch_deferral(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aggregate content hashes must be omitted when a legacy PyTorch hash is deferred."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        legacy_payload, offsets = _make_legacy_pytorch_container(b"A" * 256, object_padding=1024)
        legacy_path = tmp_path / "long-control.pt"
        legacy_path.write_bytes(legacy_payload)
        safe_path = tmp_path / "safe.pkl"
        safe_path.write_bytes(pickle.dumps({"safe": True}, protocol=4))
        read_limit = offsets["object_start"] + 8
        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def track_hash(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            if path == str(legacy_path):
                pytest.fail("deferred legacy PyTorch file was included in aggregate content hashing")
            return original_hash(path, deadline=deadline)

        def successful_scan(path: str, _config: dict[str, object]) -> ScanResult:
            scan_result = ScanResult(scanner_name="bounded_test")
            scan_result.bytes_scanned = Path(path).stat().st_size
            scan_result.finish(success=True)
            return scan_result

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)
        monkeypatch.setattr(core, "scan_file", successful_scan)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_file_read_size=read_limit,
            cache_enabled=False,
        )

        hashed_names = {Path(path).name for path in hashed_paths}
        assert safe_path.name in hashed_names
        assert legacy_path.name not in hashed_names
        assert result.success is True
        assert result.content_hash is None

    def test_legacy_pytorch_hash_deferral_does_not_read_beyond_configured_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A complete valid control probe should defer without reading storage headers past the cap."""
        from modelaudit.scanners.pickle_scanner import PickleScanner
        from modelaudit.utils.helpers.cache_decorator import should_defer_hash_for_pytorch_read_limit

        PickleScanner()
        payload, offsets = _make_legacy_pytorch_container(b"A" * 256)
        legacy_path = tmp_path / "bounded-control.pt"
        legacy_path.write_bytes(payload)
        read_limit = offsets["storage_start"]
        trackers = _track_binary_reads_for_path(monkeypatch, legacy_path)

        assert should_defer_hash_for_pytorch_read_limit(
            str(legacy_path),
            {"max_file_read_size": read_limit},
            file_size=len(payload),
        )
        assert trackers
        assert max(tracker.max_position for tracker in trackers) <= read_limit

    def test_malformed_legacy_pytorch_near_match_does_not_defer_or_overread(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Malformed preamble near-matches must not bypass full hashing or exceed the read cap."""
        from modelaudit.scanners.pickle_scanner import PickleScanner
        from modelaudit.utils.helpers.cache_decorator import should_defer_hash_for_pytorch_read_limit

        PickleScanner()
        payload, offsets = _make_malformed_legacy_pytorch_near_match()
        malformed_path = tmp_path / "malformed-near-match.pt"
        malformed_path.write_bytes(payload)
        read_limit = offsets["object_start"] + 8
        trackers = _track_binary_reads_for_path(monkeypatch, malformed_path)

        assert (
            should_defer_hash_for_pytorch_read_limit(
                str(malformed_path),
                {"max_file_read_size": read_limit},
                file_size=len(payload),
            )
            is False
        )
        assert trackers
        assert max(tracker.max_position for tracker in trackers) <= read_limit

    def test_single_file_scan_defers_oversized_pytorch_zip_content_hash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Single-file scans must not publish aggregate hashes for prefix-hashed PyTorch ZIPs."""
        from modelaudit import core

        zip_path = create_mock_pytorch_zip(tmp_path / "large.pt")
        with zip_path.open("ab") as handle:
            handle.write(b"A" * 2048)

        def fail_hash(path: str) -> str:
            if path == str(zip_path):
                pytest.fail("oversized PyTorch ZIP was content-hashed before bounded scan dispatch")
            return "a" * 64

        monkeypatch.setattr(core.BaseScanner, "default_max_file_read_size", 256)
        monkeypatch.setattr(core, "_calculate_file_hash", fail_hash)

        result = scan_model_directory_or_file(
            str(zip_path),
            max_file_size=10_000,
            cache_enabled=False,
        )

        assert result.success is True
        assert result.content_hash is None
        file_hashes = result.file_metadata[str(zip_path)].file_hashes
        assert file_hashes is not None
        assert file_hashes.sha256_prefix
        assert file_hashes.sha256 is None

    def test_directory_scan_omits_content_hash_when_max_total_hashing_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Successful scans must not publish aggregate hashes for only a prefix of files."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        first = tmp_path / "first.pkl"
        first.write_bytes(b"A" * 32)
        second = tmp_path / "second.pkl"
        second.write_bytes(b"B" * 33)
        third = tmp_path / "third.pkl"
        third.write_bytes(b"C")
        original_walk = core.os.walk

        original_hash = core._calculate_file_hash
        hashed_paths: list[str] = []

        def unsorted_walk(
            top: str,
            topdown: bool = True,
            onerror: Callable[[OSError], None] | None = None,
            followlinks: bool = False,
        ) -> Iterator[tuple[str, list[str], list[str]]]:
            if Path(top) == tmp_path:
                yield str(tmp_path), [], ["third.pkl", "first.pkl", "second.pkl"]
                return
            yield from original_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks)

        def track_hash(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            return original_hash(path, deadline=deadline)

        def successful_scan(_path: str, _config: dict[str, object]) -> ScanResult:
            scan_result = ScanResult(scanner_name="bounded_test")
            scan_result.bytes_scanned = 1
            scan_result.finish(success=True)
            return scan_result

        monkeypatch.setattr(core.os, "walk", unsorted_walk)
        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)
        monkeypatch.setattr(core, "scan_file", successful_scan)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_total_size=64,
            cache_enabled=False,
        )

        assert [Path(path).name for path in hashed_paths] == [first.name]
        assert result.content_hash is None
        assert result.success is True

    def test_directory_scan_omits_content_hash_when_max_file_size_hashing_incomplete(
        self,
        tmp_path: Path,
    ) -> None:
        """Directory scans must not publish hashes that omit oversized rejected files."""
        small = tmp_path / "small.pkl"
        small.write_bytes(pickle.dumps(1))
        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(pickle.dumps({"safe": True}) + b"X" * 128)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_file_size=64,
            cache_enabled=False,
        )

        assert result.content_hash is None
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("File too large to scan") for issue in result.issues)

    def test_directory_scan_omits_content_hash_when_expanded_scan_bytes_exceed_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scan stopped by expanded bytes must not publish its precomputed aggregate hash."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        first = tmp_path / "first.pkl"
        first.write_bytes(b"A")
        second = tmp_path / "second.pkl"
        second.write_bytes(b"B")
        scanned_paths: list[str] = []

        def expanded_scan(path: str, _config: dict[str, object]) -> ScanResult:
            scanned_paths.append(path)
            scan_result = ScanResult(scanner_name="bounded_test")
            scan_result.bytes_scanned = 128
            scan_result.finish(success=True)
            return scan_result

        monkeypatch.setattr(core, "scan_file", expanded_scan)

        result = scan_model_directory_or_file(
            str(tmp_path),
            max_total_size=64,
            cache_enabled=False,
        )

        assert [Path(path).name for path in scanned_paths] == [first.name]
        assert result.content_hash is None
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("Total scan size limit exceeded") for issue in result.issues)

    def test_single_file_scan_fails_closed_after_max_total_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Single-file scans should fail closed after measured budget overflow."""
        from modelaudit import core
        from modelaudit.scanner_results import ScanResult

        oversized = tmp_path / "oversized.pkl"
        oversized.write_bytes(pickle.dumps({"safe": True}) + b"X" * 128)
        scan_result = ScanResult(scanner_name="bounded_test")
        scan_result.bytes_scanned = 128
        scan_result.finish(success=True)

        hashed_paths: list[str] = []
        original_hash = core._calculate_file_hash

        def track_hash(path: str, *, deadline: float | None = None) -> str:
            hashed_paths.append(path)
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)
        monkeypatch.setattr(core, "scan_file", lambda _path, _config: scan_result)

        result = scan_model_directory_or_file(
            str(oversized),
            max_total_size=64,
            cache_enabled=False,
        )

        assert hashed_paths == []
        assert determine_exit_code(result) == 2
        assert any(issue.message.startswith("Total scan size limit exceeded") for issue in result.issues)
        assert result.has_errors is True
        assert result.content_hash is None

    def test_unhashable_files_excluded_from_hash(self, tmp_path, monkeypatch):
        """Test that files failing to hash are excluded from aggregate hash."""
        # Create a valid file
        valid_file = tmp_path / "valid.pkl"
        with open(valid_file, "wb") as f:
            pickle.dump({"data": "valid"}, f)

        # Create a file that will fail to hash
        bad_file = tmp_path / "bad.pkl"
        with open(bad_file, "wb") as f:
            pickle.dump({"data": "bad"}, f)

        # Mock _calculate_file_hash to fail for bad.pkl
        from modelaudit import core

        original_hash = core._calculate_file_hash

        def mock_hash(path: str, *, deadline: float | None = None) -> str:
            if "bad.pkl" in str(path):
                raise OSError("Simulated hash failure")
            return original_hash(path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", mock_hash)

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a hash based only on the valid file
        assert result.content_hash is not None
        # files_scanned should include both files
        assert result.files_scanned == 2

    def test_hash_generation_performance(self, tmp_path):
        """Test that hash generation doesn't significantly impact performance."""
        import time

        # Create multiple files
        for i in range(10):
            test_file = tmp_path / f"model_{i}.pkl"
            with open(test_file, "wb") as f:
                pickle.dump({"id": i}, f)

        # Measure scan time
        start = time.time()
        result = scan_model_directory_or_file(str(tmp_path))
        duration = time.time() - start

        # Should complete quickly (under 2 seconds for 10 small files)
        assert duration < 2.0
        assert result.content_hash is not None
        assert result.files_scanned == 10


class TestOnnxExternalDataContentHash:
    def test_directory_hash_is_deferred_when_onnx_sidecar_discovery_is_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bounded discovery failure must not produce a partial aggregate hash."""
        from modelaudit.scanners import onnx_scanner

        model_path = tmp_path / "model.onnx"
        sidecar = tmp_path / "weights.data"
        sidecar.write_bytes(b"\x01\x02\x03\x04")
        _write_regular_scan_onnx_model(
            model_path,
            external_location=sidecar.name,
            external_size=sidecar.stat().st_size,
        )
        _skip_path_during_directory_prefilter(monkeypatch, sidecar)

        def fail_bounded_discovery(*_args: Any, **_kwargs: Any) -> Any:
            raise onnx_scanner._OnnxStructureParseError(
                "retained_object_limit_exceeded",
                "bounded discovery exhausted its retained-object budget",
            )

        monkeypatch.setattr(onnx_scanner, "_load_onnx_structure_file_backed", fail_bounded_discovery)

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["onnx"],
        )

        assert result.content_hash is None

    def test_directory_hash_ignores_stale_external_data_on_inline_tensor(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Inline tensors with stale external_data metadata must not pull stale sidecars into hashes."""
        model_path = tmp_path / "model.onnx"
        stale_sidecar = tmp_path / "stale.bin"
        stale_sidecar.write_bytes(b"stale sidecar bytes")
        _write_regular_scan_onnx_model(model_path, stale_inline_location=stale_sidecar.name)
        _skip_path_during_directory_prefilter(monkeypatch, stale_sidecar)

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["onnx"],
        )

        assert result.bytes_scanned == model_path.stat().st_size
        assert result.content_hash == compute_aggregate_hash([_path_sha256(model_path)])
        assert str(stale_sidecar) not in result.file_metadata

    def test_directory_hash_includes_renamed_onnx_external_data_sidecar(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Content-routed ONNX files should hash declared sidecars even when sidecars are skipped entries."""
        model_path = tmp_path / "renamed"
        sidecar = tmp_path / "weights.data"
        sidecar.write_bytes(b"\x01\x02\x03\x04")
        _write_regular_scan_onnx_model(model_path, external_location=sidecar.name, external_size=sidecar.stat().st_size)
        _skip_path_during_directory_prefilter(monkeypatch, sidecar)
        onnx = pytest.importorskip("onnx")
        monkeypatch.setattr(
            onnx,
            "load",
            lambda *_args, **_kwargs: pytest.fail("directory sidecar discovery must not preload ONNX"),
        )

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["onnx"],
        )

        assert result.bytes_scanned == model_path.stat().st_size + sidecar.stat().st_size
        assert result.content_hash == compute_aggregate_hash([_path_sha256(model_path), _path_sha256(sidecar)])
        assert str(sidecar) not in result.file_metadata

    def test_directory_hash_does_not_double_count_top_level_onnx_sidecar(self, tmp_path: Path) -> None:
        """External data sidecars that are scanned as entries should not be added again as ONNX context."""
        model_path = tmp_path / "renamed"
        sidecar = tmp_path / "weights.pkl"
        sidecar.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
        _write_regular_scan_onnx_model(model_path, external_location=sidecar.name, external_size=sidecar.stat().st_size)

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.bytes_scanned == model_path.stat().st_size + sidecar.stat().st_size
        assert result.content_hash == compute_aggregate_hash([_path_sha256(model_path), _path_sha256(sidecar)])
        assert str(sidecar) in result.file_metadata

    def test_directory_hash_omits_hash_when_onnx_sidecar_exceeds_max_file_size(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sidecars discovered from ONNX metadata must obey the same max_file_size hash completeness rule."""
        model_path = tmp_path / "renamed"
        sidecar = tmp_path / "weights.data"
        sidecar.write_bytes(b"W" * 2048)
        _write_regular_scan_onnx_model(model_path, external_location=sidecar.name, external_size=sidecar.stat().st_size)
        _skip_path_during_directory_prefilter(monkeypatch, sidecar)

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["onnx"],
            max_file_size=model_path.stat().st_size,
        )

        assert result.bytes_scanned == model_path.stat().st_size
        assert result.content_hash is None

    def test_directory_hash_omits_hash_when_onnx_sidecar_hash_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A present but unreadable declared sidecar must not leave a model-only aggregate hash."""
        from modelaudit import core

        model_path = tmp_path / "renamed"
        sidecar = tmp_path / "weights.data"
        sidecar.write_bytes(b"\x01\x02\x03\x04")
        _write_regular_scan_onnx_model(model_path, external_location=sidecar.name, external_size=sidecar.stat().st_size)
        _skip_path_during_directory_prefilter(monkeypatch, sidecar)
        original_hash = core._calculate_file_hash

        def fail_sidecar_hash(file_path: str, *, deadline: float | None = None) -> str:
            if Path(file_path).resolve() == sidecar.resolve():
                raise OSError("simulated sidecar hash failure")
            return original_hash(file_path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", fail_sidecar_hash)

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["onnx"],
        )

        assert result.bytes_scanned == model_path.stat().st_size + sidecar.stat().st_size
        assert result.content_hash is None

    @pytest.mark.parametrize("defer_owner_hash", [False, True])
    def test_directory_hash_omits_hash_when_onnx_sidecar_exceeds_max_total_size(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        defer_owner_hash: bool,
    ) -> None:
        """Sidecar bytes should participate in max_total_size accounting."""
        from modelaudit import core

        model_path = tmp_path / "renamed"
        sidecar = tmp_path / "weights.data"
        sidecar.write_bytes(b"\x01\x02\x03\x04")
        _write_regular_scan_onnx_model(model_path, external_location=sidecar.name, external_size=sidecar.stat().st_size)
        _skip_path_during_directory_prefilter(monkeypatch, sidecar)
        original_hash = core._calculate_file_hash

        def track_hash(file_path: str, *, deadline: float | None = None) -> str:
            if Path(file_path).resolve() == sidecar.resolve():
                pytest.fail("ONNX external_data sidecar must not be hashed past max_total_size")
            return original_hash(file_path, deadline=deadline)

        monkeypatch.setattr(core, "_calculate_file_hash", track_hash)

        result = scan_model_directory_or_file(
            str(tmp_path),
            cache_enabled=False,
            scanners=["onnx"],
            max_total_size=model_path.stat().st_size,
            onnx_raw_detector_max_bytes=1 if defer_owner_hash else 512 * 1024 * 1024,
        )

        assert result.bytes_scanned == model_path.stat().st_size + sidecar.stat().st_size
        assert result.content_hash is None
        assert determine_exit_code(result) == 2
