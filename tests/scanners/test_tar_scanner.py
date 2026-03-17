import os
import tarfile
import tempfile
from pathlib import Path
from typing import Literal

import pytest

from modelaudit import core
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.tar_scanner import DEFAULT_MAX_TAR_ENTRY_SIZE, TarScanner


class TestTarScanner:
    """Test the TAR scanner"""

    def setup_method(self):
        """Set up test fixtures"""
        self.scanner = TarScanner()

    def test_can_handle_tar_files(self):
        """Test that the scanner correctly identifies TAR files"""
        # Test uncompressed tar
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                info = tarfile.TarInfo("test.txt")
                content = b"Hello World"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            assert TarScanner.can_handle(tmp_path) is True
            assert TarScanner.can_handle("/path/to/file.txt") is False
            assert TarScanner.can_handle("/path/to/file.pkl") is False
        finally:
            os.unlink(tmp_path)

    def test_can_handle_compressed_tar_files(self):
        """Test that the scanner correctly identifies compressed TAR files"""
        # Test tar.gz
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            with tarfile.open(tmp.name, "w:gz") as t:
                info = tarfile.TarInfo("test.txt")
                content = b"Hello World"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path_gz = tmp.name

        # Test tar.bz2
        with tempfile.NamedTemporaryFile(suffix=".tar.bz2", delete=False) as tmp:
            with tarfile.open(tmp.name, "w:bz2") as t:
                info = tarfile.TarInfo("test.txt")
                content = b"Hello World"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path_bz2 = tmp.name

        try:
            assert TarScanner.can_handle(tmp_path_gz) is True
            assert TarScanner.can_handle(tmp_path_bz2) is True
        finally:
            os.unlink(tmp_path_gz)
            os.unlink(tmp_path_bz2)

    def test_scan_simple_tar(self):
        """Test scanning a simple TAR file with text files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add a file with content
                readme_info = tarfile.TarInfo("readme.txt")
                readme_content = b"This is a readme file"
                readme_info.size = len(readme_content)
                t.addfile(readme_info, tarfile.io.BytesIO(readme_content))  # type: ignore[attr-defined]

                # Add another file
                data_info = tarfile.TarInfo("data.json")
                data_content = b'{"key": "value"}'
                data_info.size = len(data_content)
                t.addfile(data_info, tarfile.io.BytesIO(data_content))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            # Debug: print issues if any
            if result.issues:
                for issue in result.issues:
                    print(f"Issue: {issue.message}")
            assert result.success is True
            assert result.bytes_scanned > 0
            # Filter out DEBUG issues for unknown formats (txt, json files)
            non_debug_issues = [i for i in result.issues if i.severity != IssueSeverity.DEBUG]
            assert len(non_debug_issues) == 0
        finally:
            os.unlink(tmp_path)

    def test_path_traversal_detection(self):
        """Test detection of path traversal attempts"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add file with path traversal
                info = tarfile.TarInfo("../../evil.txt")
                content = b"malicious content"
                info.size = len(content)
                t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            path_traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
            assert len(path_traversal_issues) > 0
            assert any(i.severity == IssueSeverity.CRITICAL for i in path_traversal_issues)
        finally:
            os.unlink(tmp_path)

    def test_symlink_outside_extraction_root(self):
        """Symlinks resolving outside the extraction root should be flagged"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Create a symlink pointing outside
                info = tarfile.TarInfo("link.txt")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../../etc/passwd"
                t.addfile(info)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert len(symlink_issues) > 0
            assert any("outside" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_symlink_to_critical_path(self):
        """Symlinks targeting critical system paths should be flagged"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Create a symlink to critical path
                info = tarfile.TarInfo("etc_passwd")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert any("critical system" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_nested_tar_scanning(self):
        """Test scanning TAR files containing other TAR files"""
        # Create inner tar
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as inner_tmp:
            with tarfile.open(inner_tmp.name, "w") as inner_tar:
                info = tarfile.TarInfo("inner.txt")
                content = b"Inner content"
                info.size = len(content)
                inner_tar.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            inner_path = inner_tmp.name

        # Create outer tar containing inner tar
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as outer_tmp:
            with tarfile.open(outer_tmp.name, "w") as outer_tar:
                outer_tar.add(inner_path, "nested.tar")
            outer_path = outer_tmp.name

        try:
            result = self.scanner.scan(outer_path)
            assert result.success is True
            # Check that nested content was scanned
            assert "contents" in result.metadata
            assert len(result.metadata["contents"]) > 0
        finally:
            os.unlink(inner_path)
            os.unlink(outer_path)

    def test_max_depth_limit(self):
        """Test that maximum nesting depth is enforced"""
        # Create deeply nested tars
        tar_paths: list[str] = []
        content = b"Deep content"

        for i in range(7):  # Create 7 levels of nesting (exceeds default max of 5)
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                with tarfile.open(tmp.name, "w") as t:
                    if i == 0:
                        # Innermost tar
                        info = tarfile.TarInfo("deep.txt")
                        info.size = len(content)
                        t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
                    else:
                        # Add previous tar
                        t.add(tar_paths[-1], f"level{i}.tar")
                tar_paths.append(tmp.name)

        try:
            result = self.scanner.scan(tar_paths[-1])
            depth_issues = [i for i in result.issues if "maximum" in i.message.lower() and "depth" in i.message.lower()]
            assert len(depth_issues) > 0
        finally:
            for path in tar_paths:
                if os.path.exists(path):
                    os.unlink(path)

    def test_scan_tar_with_pickle_file(self):
        """Test scanning TAR containing pickle files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add a safe pickle file
                import pickle

                data = pickle.dumps({"key": "value"})
                info = tarfile.TarInfo("data.pkl")
                info.size = len(data)
                t.addfile(info, tarfile.io.BytesIO(data))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            # Should have scanned the pickle file inside
            assert result.bytes_scanned > 0
        finally:
            os.unlink(tmp_path)

    def test_scan_tar_with_proto0_pickle_preserves_archive_context(self, tmp_path: Path) -> None:
        """Malicious TAR members should surface critical findings with archive-qualified locations."""
        archive_path = tmp_path / "proto0_payload.tar"
        payload = b'cos\nsystem\n(S"echo pwned"\ntR.'

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.txt")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.has_errors is True
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert any(
            "os.system" in issue.message.lower() or "posix.system" in issue.message.lower() for issue in critical_issues
        )
        assert any(issue.location == f"{archive_path}:payload.txt" for issue in critical_issues)

    def test_invalid_tar_file(self):
        """Test handling of invalid TAR files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            # Write invalid data
            tmp.write(b"This is not a valid tar file")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            assert any("not a valid tar file" in i.message.lower() for i in result.issues)
        finally:
            os.unlink(tmp_path)

    def test_nested_compressed_tar_scanning(self):
        """Test scanning TAR files containing compressed TAR files"""
        # Create inner tar.gz
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as inner_tmp:
            with tarfile.open(inner_tmp.name, "w:gz") as inner_tar:
                info = tarfile.TarInfo("inner.txt")
                content = b"Inner compressed content"
                info.size = len(content)
                inner_tar.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]
            inner_path = inner_tmp.name

        # Create outer tar containing inner tar.gz
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as outer_tmp:
            with tarfile.open(outer_tmp.name, "w") as outer_tar:
                outer_tar.add(inner_path, "nested.tar.gz")
            outer_path = outer_tmp.name

        try:
            result = self.scanner.scan(outer_path)
            assert result.success is True
            # Check that nested compressed tar was scanned
            assert "contents" in result.metadata
            assert len(result.metadata["contents"]) > 0
            # Should find the nested.tar.gz in contents
            nested_found = any("nested.tar.gz" in content.get("path", "") for content in result.metadata["contents"])
            assert nested_found
        finally:
            os.unlink(inner_path)
            os.unlink(outer_path)

    def test_tar_bytes_scanned(self):
        """Ensure bytes scanned equals the sum of embedded files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                import pickle

                data1 = pickle.dumps({"a": 1})
                data2 = pickle.dumps({"b": 2})

                info1 = tarfile.TarInfo("one.pkl")
                info1.size = len(data1)
                t.addfile(info1, tarfile.io.BytesIO(data1))  # type: ignore[attr-defined]

                info2 = tarfile.TarInfo("two.pkl")
                info2.size = len(data2)
                t.addfile(info2, tarfile.io.BytesIO(data2))  # type: ignore[attr-defined]
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            expected = len(data1) + len(data2)
            assert result.bytes_scanned == expected
        finally:
            os.unlink(tmp_path)

    def test_get_max_entry_size_uses_bounded_default(self) -> None:
        """Unconfigured TAR entry extraction should still have a bounded default."""
        assert TarScanner()._get_max_entry_size() == DEFAULT_MAX_TAR_ENTRY_SIZE

    def test_get_max_entry_size_prefers_explicit_file_size_limit(self) -> None:
        """The top-level file-size limit should remain the hard extraction cap."""
        scanner = TarScanner(config={"max_file_size": 4096, "max_entry_size": 128})
        assert scanner._get_max_entry_size() == 4096

    def test_get_max_entry_size_uses_entry_limit_when_file_size_is_unlimited(self) -> None:
        """An explicit TAR-entry limit should apply when the top-level file size is unlimited."""
        scanner = TarScanner(config={"max_file_size": 0, "max_entry_size": 128})
        assert scanner._get_max_entry_size() == 128

    def test_get_max_entry_size_uses_bounded_default_when_max_file_size_is_unlimited(self) -> None:
        """A top-level unlimited file-size config should not disable TAR member extraction limits."""
        scanner = TarScanner(config={"max_file_size": 0})
        assert scanner._get_max_entry_size() == DEFAULT_MAX_TAR_ENTRY_SIZE

    def test_extract_member_to_tempfile_streams_in_chunks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Large TAR entries should be copied in bounded chunks instead of buffered in memory."""
        content = b"A" * 10_000
        archive_path = tmp_path / "payload.tar"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(content)
            archive.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]

        read_sizes: list[int | None] = []
        original_read = tarfile.ExFileObject.read

        def tracked_read(self: tarfile.ExFileObject, size: int | None = None) -> bytes:
            read_sizes.append(size)
            return original_read(self, size)

        monkeypatch.setattr(tarfile.ExFileObject, "read", tracked_read)

        with tarfile.open(archive_path, "r") as archive:
            member = archive.getmember("payload.bin")
            extracted_path, total_size = self.scanner._extract_member_to_tempfile(
                archive,
                member,
                suffix="_payload.bin",
            )

        try:
            assert total_size == len(content)
            assert Path(extracted_path).read_bytes() == content
            assert len(read_sizes) > 1
            assert set(read_sizes) == {4096}
        finally:
            os.unlink(extracted_path)

    def test_scan_rejects_oversized_tar_member(self, tmp_path: Path) -> None:
        """Entries exceeding the configured limit should fail the scan before full extraction."""
        scanner = TarScanner(config={"max_entry_size": 64})
        archive_path = tmp_path / "oversized.tar"
        payload = b"B" * 128

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = scanner.scan(str(archive_path))

        assert result.success is False
        oversize_checks = [check for check in result.checks if check.name == "TAR File Scan"]
        assert len(oversize_checks) == 1
        assert "tar entry payload.bin exceeds maximum size of 64 bytes" in oversize_checks[0].message.lower()

    def test_scan_respects_max_file_size_over_entry_limit(self, tmp_path: Path) -> None:
        """A stricter top-level size limit should still fail TAR extraction before scan_file runs."""
        scanner = TarScanner(config={"max_file_size": 64, "max_entry_size": 1024})
        archive_path = tmp_path / "precedence.tar"
        payload = b"C" * 128

        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = scanner.scan(str(archive_path))

        assert result.success is False
        oversize_checks = [check for check in result.checks if check.name == "TAR File Scan"]
        assert len(oversize_checks) == 1
        assert "tar entry payload.bin exceeds maximum size of 64 bytes" in oversize_checks[0].message.lower()

    def test_scan_skips_non_regular_tar_members(self, tmp_path: Path) -> None:
        """Valid non-file TAR members should not abort scanning later regular files."""
        archive_path = tmp_path / "fifo-first.tar"
        payload = b"payload"

        with tarfile.open(archive_path, "w") as archive:
            fifo = tarfile.TarInfo("named_pipe")
            fifo.type = tarfile.FIFOTYPE
            archive.addfile(fifo)

            info = tarfile.TarInfo("data.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.bytes_scanned == len(payload)
        assert all("named_pipe" not in issue.message for issue in result.issues)

    def test_scan_empty_tar(self, tmp_path: Path) -> None:
        """An empty TAR archive should scan successfully with no critical issues."""
        archive_path = tmp_path / "empty.tar"
        with tarfile.open(archive_path, "w"):
            pass  # create empty archive

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.bytes_scanned == 0
        # No CRITICAL issues expected for an empty archive
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_scan_tar_with_multiple_model_formats(self, tmp_path: Path) -> None:
        """TAR containing multiple model-format files should scan all of them."""
        import pickle

        archive_path = tmp_path / "multi_format.tar"

        pkl_data = pickle.dumps({"weights": [1, 2, 3]})
        json_data = b'{"model_type": "linear", "version": "1.0"}'
        pt_data = pickle.dumps({"state_dict": {}})  # .pt files are pickle-based

        with tarfile.open(archive_path, "w") as t:
            for name, data in [
                ("model.pkl", pkl_data),
                ("config.json", json_data),
                ("weights.pt", pt_data),
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, tarfile.io.BytesIO(data))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        # All three files were scanned
        assert result.bytes_scanned == len(pkl_data) + len(json_data) + len(pt_data)
        # Each file should appear in the contents metadata
        contents_paths = {c.get("path", "") for c in result.metadata.get("contents", [])}
        assert any("model.pkl" in p for p in contents_paths)
        assert any("config.json" in p for p in contents_paths)
        assert any("weights.pt" in p for p in contents_paths)

    def test_scan_tar_with_very_long_filename(self, tmp_path: Path) -> None:
        """TAR members with very long filenames should be handled without crashing."""
        archive_path = tmp_path / "long_name.tar"
        long_name = "a" * 200 + ".pkl"  # 204-character filename
        import pickle

        payload = pickle.dumps({"key": "value"})

        with tarfile.open(archive_path, "w") as t:
            info = tarfile.TarInfo(long_name)
            info.size = len(payload)
            t.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = self.scanner.scan(str(archive_path))

        # Scan must not crash; success is expected for a benign payload
        assert result.success is True
        assert result.bytes_scanned == len(payload)

    def test_scan_truncated_tar(self, tmp_path: Path) -> None:
        """A truncated (corrupted) TAR file should fail gracefully."""
        # Build a real archive, then truncate it
        archive_path = tmp_path / "truncated.tar"
        content = b"some content"

        with tarfile.open(archive_path, "w") as t:
            info = tarfile.TarInfo("file.txt")
            info.size = len(content)
            t.addfile(info, tarfile.io.BytesIO(content))  # type: ignore[attr-defined]

        full_data = archive_path.read_bytes()
        truncated_path = tmp_path / "truncated_cut.tar"
        truncated_path.write_bytes(full_data[:520])

        result = self.scanner.scan(str(truncated_path))

        assert result.success is False
        format_checks = [check for check in result.checks if check.name == "TAR File Format Validation"]
        assert len(format_checks) == 1
        assert "not a valid tar file" in format_checks[0].message.lower()
        assert any("not a valid tar file" in issue.message.lower() for issue in result.issues)

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.gz", "w:gz"),
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_compressed_tar_enforces_decompression_ratio_limit(
        self, tmp_path: Path, suffix: str, mode: Literal["w:gz", "w:bz2", "w:xz"]
    ) -> None:
        """Compressed TAR wrappers should enforce decompression ratio limits across supported codecs."""
        archive_path = tmp_path / f"ratio_limit{suffix}"
        payload = b"A" * 1_000_000

        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompression_ratio": 2.0})
        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.gz", "w:gz"),
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_compressed_tar_enforces_decompressed_size_limit(
        self, tmp_path: Path, suffix: str, mode: Literal["w:gz", "w:bz2", "w:xz"]
    ) -> None:
        """Compressed TAR wrappers should enforce size limits across supported codecs."""
        archive_path = tmp_path / f"size_limit{suffix}"
        payload = b"B" * 10_000

        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompressed_bytes": 1024})
        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompressed size exceeded" in limit_checks[0].message.lower()

    @pytest.mark.parametrize(
        ("suffix", "mode"),
        [
            (".tar.gz", "w:gz"),
            (".tar.bz2", "w:bz2"),
            (".tar.xz", "w:xz"),
        ],
    )
    def test_scan_compressed_tar_within_limits_passes_decompression_checks(
        self, tmp_path: Path, suffix: str, mode: Literal["w:gz", "w:bz2", "w:xz"]
    ) -> None:
        """Compressed TAR wrappers within safe bounds should produce a passing decompression check."""
        archive_path = tmp_path / f"within_limit{suffix}"
        payload = b"safe-payload"

        with tarfile.open(archive_path, mode) as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(
            config={
                "compressed_max_decompression_ratio": 1_000.0,
                "compressed_max_decompressed_bytes": 20_000,
            }
        )
        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.PASSED

    def test_scan_compressed_tar_accounts_for_tar_record_padding(self, tmp_path: Path) -> None:
        """Wrapper limits should account for TAR record padding, even on tiny archives."""
        archive_path = tmp_path / "tiny.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            payload = b"tiny"
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompressed_bytes": 4_096})
        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompressed size exceeded" in limit_checks[0].message.lower()

    def test_scan_tar_preflight_streams_members_without_getmembers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Preflight should stream TAR members instead of materializing them with getmembers()."""
        archive_path = tmp_path / "streamed.tar.gz"

        with tarfile.open(archive_path, "w:gz") as archive:
            for index in range(3):
                info = tarfile.TarInfo(f"payload-{index}.bin")
                payload = f"payload-{index}".encode()
                info.size = len(payload)
                archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        def fail_getmembers(self: tarfile.TarFile) -> list[tarfile.TarInfo]:
            raise AssertionError("TarScanner should not call getmembers() during preflight")

        monkeypatch.setattr(tarfile.TarFile, "getmembers", fail_getmembers)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        entry_checks = [check for check in result.checks if check.name == "Entry Count Limit Check"]
        assert len(entry_checks) == 1
        assert entry_checks[0].status == CheckStatus.PASSED

    def test_scan_compressed_tar_detects_wrapper_by_content_not_suffix(self, tmp_path: Path) -> None:
        """Compressed TARs with plain .tar suffix should still enforce wrapper limits by magic bytes."""
        archive_path = tmp_path / "disguised_compressed.tar"
        payload = b"C" * 1_000_000

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        scanner = TarScanner(config={"compressed_max_decompression_ratio": 2.0})
        result = scanner.scan(str(archive_path))

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()

    def test_core_routes_disguised_compressed_tar_without_tar_suffix(self, tmp_path: Path) -> None:
        """Compressed TAR wrappers renamed to generic suffixes should still route to TarScanner."""
        archive_path = tmp_path / "disguised_payload.bin"
        payload = b"D" * 1_000_000

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("payload.bin")
            info.size = len(payload)
            archive.addfile(info, tarfile.io.BytesIO(payload))  # type: ignore[attr-defined]

        result = core.scan_file(
            str(archive_path),
            config={"compressed_max_decompression_ratio": 2.0},
        )

        limit_checks = [check for check in result.checks if check.name == "Compressed Wrapper Decompression Limits"]
        assert result.scanner_name == "tar"
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert "decompression ratio exceeded" in limit_checks[0].message.lower()
