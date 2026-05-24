"""Tests for file filtering functionality."""

import json
import pickle
import zipfile
from pathlib import Path

import pytest

from modelaudit.utils.file import filtering
from modelaudit.utils.file.detection import detect_file_format_for_skip_filter
from modelaudit.utils.file.filtering import (
    _ZIP_MEMBER_SNIFF_LIMIT,
    should_skip_file,
)
from tests.helpers.file_creators import create_v7_tar_archive


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

    def test_disguised_jax_json_checkpoint_bypasses_skip_without_routing_ajax_near_match(self, tmp_path: Path) -> None:
        checkpoint_path = tmp_path / "checkpoint.jpg"
        near_match_path = tmp_path / "ajax.jpg"
        checkpoint_path.write_text(json.dumps({"framework": "jax", "orbax_version": "0.1.0"}), encoding="utf-8")
        near_match_path.write_text(json.dumps({"framework": "ajax", "format": "checkpoint"}), encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(checkpoint_path)) == "jax_checkpoint"
        assert not should_skip_file(str(checkpoint_path))
        assert detect_file_format_for_skip_filter(str(near_match_path)) == "unknown"
        assert should_skip_file(str(near_match_path))

    def test_pk_prefix_near_match_stays_skipped(self, tmp_path: Path) -> None:
        near_match = tmp_path / "pknope.jpg"
        near_match.write_bytes(b"PKNO harmless text")

        assert should_skip_file(str(near_match))

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
        disguised_lightgbm = tmp_path / "model.txt"
        disguised_lightgbm.write_text(("# preface\n" * 64) + _build_lightgbm_text(), encoding="utf-8")

        assert detect_file_format_for_skip_filter(str(disguised_lightgbm)) == "lightgbm"
        assert not should_skip_file(str(disguised_lightgbm))

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
