"""Tests for file filtering functionality."""

import pickle
import zipfile
from pathlib import Path

import pytest

from modelaudit.utils.file.filtering import (
    _ZIP_MEMBER_SNIFF_LIMIT,
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

        disguised_zip = tmp_path / "archive.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            archive.writestr("payload.pkl", pickle.dumps({"safe": True}))

        real_image = tmp_path / "cover.jpg"
        real_image.write_bytes(b"\xff\xd8\xff\xe0" + b"jpeg")

        assert not should_skip_file(str(disguised_pickle))
        assert not should_skip_file(str(disguised_zip))
        assert should_skip_file(str(real_image))

    def test_executorch_payloads_bypass_extension_skip(self, tmp_path: Path) -> None:
        """Disguised ZIPs carrying supported ExecuTorch payloads should survive prefiltering."""
        disguised_zip = tmp_path / "executorch.jpg"
        with zipfile.ZipFile(disguised_zip, "w") as archive:
            archive.writestr("model.pte", b"executorch payload")

        assert not should_skip_file(str(disguised_zip))

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

    def test_docx_like_zip_remains_skipped_when_office_markers_appear_late(self, tmp_path: Path) -> None:
        """Office ZIP detection should not depend on member order within the sniff budget."""
        docx_path = tmp_path / "late-office.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            for index in range(_ZIP_MEMBER_SNIFF_LIMIT):
                archive.writestr(f"docs/{index}.txt", "filler")
            archive.writestr("word/document.xml", "<w:document></w:document>")

        assert should_skip_file(str(docx_path))

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

        monkeypatch.setattr("modelaudit.utils.file.detection.detect_file_format", raise_os_error)

        assert not should_skip_file(str(disguised_payload))
