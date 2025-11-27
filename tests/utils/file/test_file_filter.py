"""Tests for file filtering functionality."""

from modelaudit.utils.file_filter import (
    should_skip_file,
)


class TestFileFilter:
    """Test file filtering functionality."""

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
            "archive.tar",
            "backup.bak",
        ]

        for file in skip_files:
            assert should_skip_file(file), f"Should skip {file}"

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
