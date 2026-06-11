"""Test HuggingFace cache symlink handling."""

import json
import os
from pathlib import Path

import pytest

from modelaudit.core import scan_model_directory_or_file
from modelaudit.scanner_results import CheckStatus
from modelaudit.scanners.base import IssueSeverity


@pytest.mark.usefixtures("requires_symlinks")
class TestHuggingFaceSymlinks:
    """Test that HuggingFace cache symlinks are handled correctly."""

    @pytest.fixture
    def mock_hf_cache(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """Create a mock HuggingFace cache structure with symlinks."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        # Create HuggingFace cache structure
        cache_dir = hf_home / "hub" / "models--test-model"
        snapshots_dir = cache_dir / "snapshots" / "abc123"
        blobs_dir = cache_dir / "blobs"

        # Create directories
        snapshots_dir.mkdir(parents=True)
        blobs_dir.mkdir(parents=True)

        # Create blob files
        blob1_path = blobs_dir / "blob1234567890"
        blob2_path = blobs_dir / "blob0987654321"

        with open(blob1_path, "w") as f:
            f.write("Model data")

        with open(blob2_path, "w") as f:
            f.write("Config data")

        # Create symlinks in snapshots directory
        model_link = snapshots_dir / "model.safetensors"
        config_link = snapshots_dir / "config.json"

        # Create relative symlinks (as HuggingFace does)
        os.symlink("../../blobs/blob1234567890", model_link)
        os.symlink("../../blobs/blob0987654321", config_link)

        return snapshots_dir

    def test_hf_cache_symlinks_no_path_traversal_warnings(self, mock_hf_cache):
        """Test that HuggingFace cache symlinks don't trigger path traversal warnings."""
        # Scan the snapshots directory
        results = scan_model_directory_or_file(str(mock_hf_cache))

        # Check that files were scanned
        assert results.files_scanned == 2

        # Check that there are no path traversal warnings
        path_traversal_issues = [
            issue for issue in results.issues if "path traversal" in getattr(issue, "message", "").lower()
        ]
        assert len(path_traversal_issues) == 0

    def test_hf_home_cache_symlinks_no_path_traversal_warnings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Custom HF_HOME cache roots should preserve allowed snapshot-to-blob symlinks."""
        monkeypatch.setenv("HF_HOME", str(tmp_path / "custom-hf-home"))
        cache_dir = tmp_path / "custom-hf-home" / "hub" / "models--test-model"
        snapshots_dir = cache_dir / "snapshots" / "abc123"
        blobs_dir = cache_dir / "blobs"
        snapshots_dir.mkdir(parents=True)
        blobs_dir.mkdir(parents=True)

        blob_path = blobs_dir / "blob1234567890"
        blob_path.write_text("Model data")
        model_link = snapshots_dir / "model.safetensors"
        os.symlink("../../blobs/blob1234567890", model_link)

        results = scan_model_directory_or_file(str(snapshots_dir))

        path_traversal_issues = [
            issue for issue in results.issues if "path traversal" in getattr(issue, "message", "").lower()
        ]
        assert results.files_scanned == 1
        assert len(path_traversal_issues) == 0

    def test_hf_orbax_owner_symlink_blob_scanned_once(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Trusted HF owner aliases should not duplicate backing blob accounting or findings."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        cache_dir = hf_home / "hub" / "models--org--orbax"
        snapshots_dir = cache_dir / "snapshots" / "abc123"
        blobs_dir = cache_dir / "blobs"
        snapshots_dir.mkdir(parents=True)
        blobs_dir.mkdir(parents=True)

        metadata_blob = blobs_dir / "metadata-blob"
        metadata_payload = json.dumps(
            {"type": "orbax_checkpoint", "restore_fn": "os.system"},
            separators=(",", ":"),
        )
        metadata_blob.write_text(metadata_payload, encoding="utf-8")
        metadata_link = snapshots_dir / "metadata.json"
        os.symlink("../../blobs/metadata-blob", metadata_link)

        results = scan_model_directory_or_file(str(snapshots_dir))

        restore_checks = [check for check in results.checks if check.name == "Orbax Restore Function Check"]
        assert results.files_scanned == 1
        assert results.bytes_scanned == metadata_blob.stat().st_size
        assert len(restore_checks) == 1
        assert restore_checks[0].status == CheckStatus.FAILED
        assert restore_checks[0].severity == IssueSeverity.CRITICAL
        assert restore_checks[0].location == str(metadata_link)
        assert restore_checks[0].details["restore_fn"] == "os.system"

    def test_malicious_symlink_outside_cache(self, tmp_path):
        """Test that symlinks pointing outside the cache structure are still caught."""
        # Create a directory structure
        scan_dir = tmp_path / "scan_me"
        scan_dir.mkdir()

        # Create a file outside the scan directory
        outside_file = tmp_path / "outside.txt"
        with open(outside_file, "w") as f:
            f.write("Malicious content")

        # Create a symlink pointing outside
        symlink = scan_dir / "bad_link.txt"
        os.symlink(str(outside_file), symlink)

        # Scan the directory
        results = scan_model_directory_or_file(str(scan_dir))

        # Should have path traversal warning
        path_traversal_issues = [
            issue for issue in results.issues if "path traversal" in getattr(issue, "message", "").lower()
        ]
        assert len(path_traversal_issues) == 1

    def test_nested_hf_cache_structure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test more complex nested HuggingFace cache structures."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        # Create nested cache structure
        cache_dir = hf_home / "hub" / "models--org--model-name"
        snapshots_dir = cache_dir / "snapshots" / "commit123456"
        blobs_dir = cache_dir / "blobs"
        refs_dir = cache_dir / "refs"

        # Create all directories
        for d in [snapshots_dir, blobs_dir, refs_dir]:
            d.mkdir(parents=True)

        # Create various files
        blob_files = []
        for i, (name, content) in enumerate(
            [
                ("model.bin", "PyTorch model"),
                ("config.json", '{"model_type": "bert"}'),
                ("tokenizer.json", '{"vocab_size": 30522}'),
            ]
        ):
            blob_path = blobs_dir / f"blob{i:010d}"
            with open(blob_path, "w") as f:
                f.write(content)
            blob_files.append((name, blob_path))

            # Create symlink
            link_path = snapshots_dir / name
            os.symlink(f"../../blobs/{blob_path.name}", link_path)

        # Create refs (these should be skipped)
        with open(refs_dir / "main", "w") as f:
            f.write("commit123456")

        # Scan
        results = scan_model_directory_or_file(str(snapshots_dir))

        # Should scan the actual model files, not refs
        assert results.files_scanned == 3

        # No path traversal warnings
        path_traversal_issues = [
            issue for issue in results.issues if "path traversal" in getattr(issue, "message", "").lower()
        ]
        assert len(path_traversal_issues) == 0

    def test_broken_symlink_warning(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Broken HuggingFace symlinks should produce a warning."""
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        cache_root = hf_home / "hub" / "models--test"
        snapshots = cache_root / "snapshots" / "abc"
        snapshots.mkdir(parents=True)

        broken_link = snapshots / "model.bin"
        os.symlink("../../blobs/missing", broken_link)

        def lexical_resolve(path: Path, strict: bool = False) -> Path:
            del strict
            return Path(os.path.abspath(path))

        monkeypatch.setattr(Path, "resolve", lexical_resolve)

        def _raise(path: str) -> str:  # pragma: no cover - simulate error
            raise OSError("dangling link")

        monkeypatch.setattr(os, "readlink", _raise)

        results = scan_model_directory_or_file(str(snapshots))

        broken_issues = [i for i in results.issues if "broken symlink" in getattr(i, "message", "").lower()]
        assert len(broken_issues) == 1
        # Broken symlinks are informational (INFO or WARNING) - not security critical
        assert broken_issues[0].severity in (IssueSeverity.WARNING, IssueSeverity.INFO)
