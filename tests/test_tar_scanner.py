import os
import tarfile
import tempfile

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tar_scanner import TarScanner


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
                t.addfile(tarfile.TarInfo("test.txt"), b"Hello World")
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
                t.addfile(tarfile.TarInfo("test.txt"), b"Hello World")
            tmp_path_gz = tmp.name

        # Test tar.bz2
        with tempfile.NamedTemporaryFile(suffix=".tar.bz2", delete=False) as tmp:
            with tarfile.open(tmp.name, "w:bz2") as t:
                t.addfile(tarfile.TarInfo("test.txt"), b"Hello World")
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
                t.addfile(readme_info, tarfile.io.BytesIO(readme_content))

                # Add another file
                data_info = tarfile.TarInfo("data.json")
                data_content = b'{"key": "value"}'
                data_info.size = len(data_content)
                t.addfile(data_info, tarfile.io.BytesIO(data_content))
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
                t.addfile(info, tarfile.io.BytesIO(content))
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
                inner_tar.addfile(info, tarfile.io.BytesIO(content))
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
        tar_paths = []
        content = b"Deep content"

        for i in range(7):  # Create 7 levels of nesting (exceeds default max of 5)
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                with tarfile.open(tmp.name, "w") as t:
                    if i == 0:
                        # Innermost tar
                        info = tarfile.TarInfo("deep.txt")
                        info.size = len(content)
                        t.addfile(info, tarfile.io.BytesIO(content))
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

    def test_max_entries_limit(self):
        """Test that maximum entries limit is enforced"""
        scanner = TarScanner(config={"max_tar_entries": 5})

        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add more files than the limit
                for i in range(10):
                    info = tarfile.TarInfo(f"file{i}.txt")
                    content = f"Content {i}".encode()
                    info.size = len(content)
                    t.addfile(info, tarfile.io.BytesIO(content))
            tmp_path = tmp.name

        try:
            result = scanner.scan(tmp_path)
            entries_issues = [i for i in result.issues if "too many entries" in i.message.lower()]
            assert len(entries_issues) > 0
        finally:
            os.unlink(tmp_path)

    def test_scan_tar_with_pickle_file(self):
        """Test scanning TAR containing pickle files"""
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as t:
                # Add a safe pickle file
                import pickle

                data = pickle.dumps({"key": "value"})
                info = tarfile.TarInfo("data.pkl")
                info.size = len(data)
                t.addfile(info, tarfile.io.BytesIO(data))
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            # Should have scanned the pickle file inside
            assert result.bytes_scanned > 0
        finally:
            os.unlink(tmp_path)

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
                inner_tar.addfile(info, tarfile.io.BytesIO(content))
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
                t.addfile(info1, tarfile.io.BytesIO(data1))

                info2 = tarfile.TarInfo("two.pkl")
                info2.size = len(data2)
                t.addfile(info2, tarfile.io.BytesIO(data2))
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            expected = len(data1) + len(data2)
            assert result.bytes_scanned == expected
        finally:
            os.unlink(tmp_path)
