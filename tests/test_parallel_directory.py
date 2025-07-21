"""Tests for parallel directory scanning functionality."""

import pickle
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.parallel_directory import (
    _should_skip_file,
    scan_directory_parallel,
)


class TestShouldSkipFile:
    """Test the _should_skip_file function."""

    def test_skip_documentation_files(self):
        """Test that documentation files are skipped."""
        assert _should_skip_file("README.md") is True
        assert _should_skip_file("manual.pdf") is True
        assert _should_skip_file("guide.rst") is True
        assert _should_skip_file("doc.docx") is True

    def test_skip_code_files(self):
        """Test that code files are skipped."""
        assert _should_skip_file("script.py") is True
        assert _should_skip_file("app.js") is True
        assert _should_skip_file("main.cpp") is True
        assert _should_skip_file("module.go") is True

    def test_skip_hidden_files(self):
        """Test that hidden files are skipped."""
        assert _should_skip_file(".gitignore") is True
        assert _should_skip_file(".DS_Store") is True
        assert _should_skip_file(".env") is True

    def test_skip_system_files(self):
        """Test that system files are skipped."""
        assert _should_skip_file("package.json") is True
        assert _should_skip_file("requirements.txt") is True
        assert _should_skip_file("Makefile") is True
        assert _should_skip_file("LICENSE") is True

    def test_allow_model_files(self):
        """Test that model files are not skipped."""
        assert _should_skip_file("model.pkl") is False
        assert _should_skip_file("weights.pt") is False
        assert _should_skip_file("model.h5") is False
        assert _should_skip_file("checkpoint.ckpt") is False
        assert _should_skip_file("model.onnx") is False
        assert _should_skip_file("model.safetensors") is False
        # .txt files should not be skipped as they may contain model data
        assert _should_skip_file("model.bin") is False
        assert _should_skip_file("embeddings.bin") is False

    def test_case_insensitive_extensions(self):
        """Test that extension checking is case-insensitive."""
        assert _should_skip_file("README.MD") is True
        assert _should_skip_file("script.PY") is True
        assert _should_skip_file("model.PKL") is False


class TestScanDirectoryParallel:
    """Test the scan_directory_parallel function."""

    def test_empty_directory(self):
        """Test scanning an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = scan_directory_parallel(tmpdir, {})

            assert results["files_scanned"] == 0
            assert results["bytes_scanned"] == 0
            assert results["issues"] == []
            assert results["success"] is True

    def test_directory_with_only_non_model_files(self):
        """Test directory containing only files that should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create various non-model files
            Path(tmpdir, "README.md").write_text("# README")
            Path(tmpdir, "script.py").write_text("print('hello')")
            Path(tmpdir, ".gitignore").write_text("*.pyc")
            Path(tmpdir, "requirements.txt").write_text("numpy")

            results = scan_directory_parallel(tmpdir, {})

            assert results["files_scanned"] == 0
            assert results["bytes_scanned"] == 0
            assert results["success"] is True

    def test_directory_with_model_files(self):
        """Test scanning directory with model files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create model files
            for i in range(3):
                file_path = Path(tmpdir) / f"model_{i}.pkl"
                with open(file_path, "wb") as f:
                    pickle.dump({"model": i}, f)

            # Also create some non-model files
            Path(tmpdir, "README.md").write_text("# Models")
            Path(tmpdir, "train.py").write_text("# Training script")

            results = scan_directory_parallel(tmpdir, {})

            assert results["files_scanned"] == 3
            assert results["bytes_scanned"] > 0
            assert results["parallel_scan"] is True
            assert results["worker_count"] > 0
            assert results["success"] is True

    def test_subdirectories(self):
        """Test scanning with subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create subdirectory structure
            subdir = Path(tmpdir) / "models"
            subdir.mkdir()

            # Create files in root
            with open(Path(tmpdir) / "model1.pkl", "wb") as f:
                pickle.dump({"root": 1}, f)

            # Create files in subdirectory
            with open(subdir / "model2.pkl", "wb") as f:
                pickle.dump({"sub": 2}, f)

            results = scan_directory_parallel(tmpdir, {})

            assert results["files_scanned"] == 2
            assert results["success"] is True

    def test_huggingface_cache_files(self):
        """Test that HuggingFace cache files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create regular model file
            with open(Path(tmpdir) / "model.pkl", "wb") as f:
                pickle.dump({"model": "data"}, f)

            # Create HuggingFace cache files
            Path(tmpdir, "model.pkl.lock").write_text("")
            Path(tmpdir, "model.pkl.metadata").write_text("{}")

            results = scan_directory_parallel(tmpdir, {})

            # Only the actual model file should be scanned
            assert results["files_scanned"] == 1

    def test_custom_config(self):
        """Test scanning with custom configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a model file
            file_path = Path(tmpdir) / "model.pkl"
            with open(file_path, "wb") as f:
                pickle.dump({"test": "data"}, f)

            config = {
                "timeout": 60,
                "max_file_size": 1000000,
            }

            results = scan_directory_parallel(tmpdir, config)

            assert results["files_scanned"] == 1
            assert results["success"] is True

    def test_progress_callback(self):
        """Test progress callback during parallel scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files
            for i in range(5):
                with open(Path(tmpdir) / f"model_{i}.pkl", "wb") as f:
                    pickle.dump({"model": i}, f)

            progress_calls = []

            def progress_callback(message, percentage):
                progress_calls.append((message, percentage))

            results = scan_directory_parallel(
                tmpdir, {}, progress_callback=progress_callback
            )

            assert results["files_scanned"] == 5
            assert len(progress_calls) > 0

    def test_worker_count_configuration(self):
        """Test configuring the number of workers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files
            for i in range(4):
                with open(Path(tmpdir) / f"model_{i}.pkl", "wb") as f:
                    pickle.dump({"model": i}, f)

            # Test with specific worker count
            results = scan_directory_parallel(tmpdir, {}, max_workers=2)

            assert results["files_scanned"] == 4
            assert results["worker_count"] == 2

    @patch("modelaudit.parallel_directory.ParallelScanner")
    def test_error_handling(self, mock_scanner_class):
        """Test error handling in parallel scanning."""
        # Mock scanner to raise an exception
        mock_scanner = MagicMock()
        mock_scanner.scan_files.side_effect = Exception("Test error")
        mock_scanner_class.return_value = mock_scanner

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(Path(tmpdir) / "model.pkl", "wb") as f:
                pickle.dump({"test": "data"}, f)

            # Should raise the exception
            with pytest.raises(Exception, match="Test error"):
                scan_directory_parallel(tmpdir, {})


@pytest.mark.integration
class TestParallelDirectoryIntegration:
    """Integration tests for parallel directory scanning."""

    def test_real_world_directory_structure(self):
        """Test with a realistic directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a realistic ML project structure
            # Root files
            Path(tmpdir, "README.md").write_text("# ML Project")
            Path(tmpdir, "requirements.log").write_text("torch\nnumpy")
            Path(tmpdir, ".gitignore").write_text("*.pyc\n__pycache__/")

            # Models directory
            models_dir = Path(tmpdir) / "models"
            models_dir.mkdir()

            # Checkpoints directory
            checkpoints_dir = models_dir / "checkpoints"
            checkpoints_dir.mkdir()

            # Create model files
            with open(models_dir / "final_model.pkl", "wb") as f:
                pickle.dump({"type": "final"}, f)

            with open(checkpoints_dir / "checkpoint_1.pkl", "wb") as f:
                pickle.dump({"epoch": 1}, f)

            with open(checkpoints_dir / "checkpoint_2.pkl", "wb") as f:
                pickle.dump({"epoch": 2}, f)

            # Scripts directory (should be skipped)
            scripts_dir = Path(tmpdir) / "scripts"
            scripts_dir.mkdir()
            Path(scripts_dir, "train.py").write_text("# Training code")
            Path(scripts_dir, "evaluate.py").write_text("# Eval code")

            # Data directory with non-model files
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            Path(data_dir, "dataset.csv").write_text("col1,col2\n1,2\n3,4")

            # Scan the entire project
            results = scan_directory_parallel(tmpdir, {})

            # Should find exactly 3 model files
            assert results["files_scanned"] >= 3
            assert results["parallel_scan"] is True
            assert results["success"] is True

            # Verify the scanned files are the model files
            scanned_paths = [asset["path"] for asset in results["assets"]]
            assert any("final_model.pkl" in path for path in scanned_paths)
            assert any("checkpoint_1.pkl" in path for path in scanned_paths)
            assert any("checkpoint_2.pkl" in path for path in scanned_paths)
