"""Tests for directory scanning with file filtering."""

import tempfile
from pathlib import Path

from modelaudit.core import scan_model_directory_or_file


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

            # Should only scan model files
            assert results["files_scanned"] == 2  # model.pkl and config.json
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

            # Should only scan .pkl files
            assert results["files_scanned"] == 2  # model1.pkl and model2.pkl
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
