"""Tests for directory scanning with file filtering."""

import bz2
import gzip
import lzma
import tarfile
import tempfile
import zipfile
from pathlib import Path

from modelaudit.core import _is_huggingface_cache_file, scan_model_directory_or_file


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

    def test_only_huggingface_bookkeeping_metadata_is_skipped(self, tmp_path: Path) -> None:
        """Local .metadata files should be scanned unless they are in HuggingFace cache layouts."""
        local_metadata = tmp_path / "model.metadata"
        local_cache_shaped_metadata = (
            tmp_path / "project" / "huggingface" / "hub" / "models--org--repo" / "model.metadata"
        )
        local_snapshots_metadata = (
            tmp_path / "project" / "hub" / "models--org--repo" / "snapshots" / "abc123" / "model.metadata"
        )
        hf_cache_metadata = (
            tmp_path
            / ".cache"
            / "huggingface"
            / "hub"
            / "models--org--repo"
            / "snapshots"
            / "abc123"
            / "model.metadata"
        )
        hf_download_metadata = tmp_path / ".cache" / "huggingface" / "download" / "model.metadata"

        assert _is_huggingface_cache_file(str(local_metadata)) is False
        assert _is_huggingface_cache_file(str(local_cache_shaped_metadata)) is False
        assert _is_huggingface_cache_file(str(local_snapshots_metadata)) is False
        assert _is_huggingface_cache_file(str(hf_cache_metadata)) is True
        assert _is_huggingface_cache_file(str(hf_download_metadata)) is True

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
