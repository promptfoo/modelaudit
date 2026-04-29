"""Tests for directory scanning with file filtering."""

import bz2
import gzip
import json
import lzma
import pickle
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from modelaudit.core import _is_huggingface_cache_file, determine_exit_code, scan_model_directory_or_file


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


class TestDirectoryFileFiltering:
    """Test directory scanning with file filtering."""

    def test_skip_file_types_enabled(self):
        """Test that non-model files are skipped when skip_file_types=True."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create various file types
            (Path(tmp_dir) / "README.md").write_text("Documentation")
            (Path(tmp_dir) / "script.py").write_text("print('hello')")
            (Path(tmp_dir) / "style.css").write_text("body { color: red; }")
            (Path(tmp_dir) / "model.pkl").write_bytes(b"fake pickle data")
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
            (Path(tmp_dir) / "model.pkl").write_bytes(b"fake pickle data")
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
            (Path(tmp_dir) / ".model.pkl").write_bytes(b"hidden model")
            (Path(tmp_dir) / "visible.pkl").write_bytes(b"visible model")

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
            (Path(tmp_dir) / "model1.pkl").write_bytes(b"model 1")

            # Subdirectory files
            (sub_dir / "README.md").write_text("Sub readme")
            (sub_dir / "model2.pkl").write_bytes(b"model 2")
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
            (Path(tmp_dir) / "model1.pkl").write_bytes(b"model 1")
            (Path(tmp_dir) / "model2.h5").write_bytes(b"model 2")

            # Scan with filtering should be faster
            results = scan_model_directory_or_file(tmp_dir)

            # Should only scan the 2 model files
            assert results["files_scanned"] == 2
            assert results["success"] is True

            # Duration should be reasonable (not checking exact time to avoid flakiness)
            assert "duration" in results
