import io
import os
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.zip_scanner import ZipScanner


class TestZipScanner:
    """Test the ZIP scanner"""

    def setup_method(self):
        """Set up test fixtures"""
        self.scanner = ZipScanner()

    def test_can_handle_zip_files(self):
        """Test that the scanner correctly identifies ZIP files"""
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                z.writestr("test.txt", "Hello World")
            tmp_path = tmp.name

        try:
            assert ZipScanner.can_handle(tmp_path) is True
            assert ZipScanner.can_handle("/path/to/file.txt") is False
            assert ZipScanner.can_handle("/path/to/file.pkl") is False
        finally:
            os.unlink(tmp_path)

    def test_symlink_outside_extraction_root(self):
        """Symlinks resolving outside the extraction root should be flagged."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                import stat

                info = zipfile.ZipInfo("link.txt")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "../evil.txt")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert any("outside" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_symlink_to_critical_path(self):
        """Symlinks targeting critical system paths should be flagged."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                import stat

                info = zipfile.ZipInfo("etc_passwd")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "/etc/passwd")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
            assert any("critical system" in i.message.lower() for i in symlink_issues)
        finally:
            os.unlink(tmp_path)

    def test_duplicate_symlink_names_validate_current_entry_target(self, tmp_path: Path) -> None:
        """Duplicate symlink entries should validate each ZipInfo target, not the last name alias."""
        import stat

        archive_path = tmp_path / "duplicate_symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            first_info = zipfile.ZipInfo("link.txt")
            first_info.create_system = 3
            first_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(first_info, "/etc/passwd")

            second_info = zipfile.ZipInfo("link.txt")
            second_info.create_system = 3
            second_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(second_info, "safe-target.txt")

        result = self.scanner.scan(str(archive_path))

        failed_symlink_checks = [
            check
            for check in result.checks
            if check.name == "Symlink Safety Validation" and check.status == CheckStatus.FAILED
        ]
        assert len(failed_symlink_checks) == 1
        assert failed_symlink_checks[0].details == {
            "entry": "link.txt",
            "target": "/etc/passwd",
        }
        assert any(
            issue.rule_code == "S406"
            and issue.details.get("entry") == "link.txt"
            and issue.details.get("target") == "/etc/passwd"
            and "critical system path" in issue.message.lower()
            for issue in result.issues
        )

    def test_zip_bytes_scanned_single_count(self):
        """Ensure bytes scanned equals the sum of embedded files once."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                import pickle

                data1 = pickle.dumps({"a": 1})
                data2 = pickle.dumps({"b": 2})
                z.writestr("one.pkl", data1)
                z.writestr("two.pkl", data2)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            expected = len(data1) + len(data2)
            assert result.bytes_scanned == expected
        finally:
            os.unlink(tmp_path)

    def test_scan_simple_zip(self):
        """Test scanning a simple ZIP file with text files"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                z.writestr("readme.txt", "This is a readme file")
                z.writestr("data.json", '{"key": "value"}')
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            assert result.bytes_scanned > 0
            # May have some debug/info issues about unknown formats
            error_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(error_issues) == 0
        finally:
            os.unlink(tmp_path)

    def test_scan_zip_with_pickle(self):
        """Test scanning a ZIP file containing a pickle file"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                # Create a simple pickle file
                import pickle

                pickle_data = pickle.dumps({"safe": "data"})
                z.writestr("model.pkl", pickle_data)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True
            assert result.bytes_scanned > 0
            # The pickle scanner was run on the embedded file
            # Check that we scanned the pickle data
            assert result.bytes_scanned >= len(pickle_data)
        finally:
            os.unlink(tmp_path)

    def test_scan_nested_zip(self):
        """Test scanning nested ZIP files"""
        # Create inner zip
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as inner_tmp:
            with zipfile.ZipFile(inner_tmp.name, "w") as inner_z:
                inner_z.writestr("inner.txt", "Inner file content")
            inner_path = inner_tmp.name

        try:
            # Create outer zip containing inner zip
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as outer_tmp:
                with zipfile.ZipFile(outer_tmp.name, "w") as outer_z:
                    outer_z.write(inner_path, "nested.zip")
                outer_path = outer_tmp.name

            result = self.scanner.scan(outer_path)
            assert result.success is True
            # Should have scanned the nested content
            assert (
                any("nested.zip" in str(issue.location) for issue in result.issues if hasattr(issue, "location"))
                or result.bytes_scanned > 0
            )
        finally:
            os.unlink(inner_path)
            os.unlink(outer_path)

    def test_scan_alternating_zip_tar_enforces_shared_depth_limit(self, tmp_path: Path) -> None:
        """Archive depth should not reset when recursion alternates between ZIP and TAR."""
        inner_zip = tmp_path / "inner.zip"
        with zipfile.ZipFile(inner_zip, "w") as archive:
            archive.writestr("payload.txt", "deep content")

        middle_tar = tmp_path / "middle.tar"
        with tarfile.open(middle_tar, "w") as archive:
            archive.add(inner_zip, arcname="inner.zip")

        outer_zip = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip, "w") as archive:
            archive.write(middle_tar, arcname="middle.tar")

        scanner = ZipScanner(config={"max_zip_depth": 2, "max_tar_depth": 2})
        result = scanner.scan(str(outer_zip))

        depth_checks = [
            check
            for check in result.checks
            if check.name == "ZIP Depth Bomb Protection" and check.status == CheckStatus.FAILED
        ]
        assert len(depth_checks) == 1
        assert "maximum zip nesting depth (2) exceeded" in depth_checks[0].message.lower()
        assert depth_checks[0].location == f"{outer_zip}:middle.tar:inner.zip"

    def test_scan_nested_mar_enforces_shared_depth_limit(self, tmp_path: Path) -> None:
        """Archive depth should not reset when ZIP recursion enters TorchServe MAR files."""
        nested_mar = tmp_path / "model.mar"
        with zipfile.ZipFile(nested_mar, "w") as archive:
            archive.writestr(
                "MAR-INF/MANIFEST.json",
                '{"model": {"handler": "handler.py", "serializedFile": "weights.bin"}}',
            )
            archive.writestr("handler.py", "def handle(data, context):\n    return data\n")
            archive.writestr("weights.bin", "weights")

        outer_zip = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip, "w") as archive:
            archive.write(nested_mar, arcname="model.mar")

        scanner = ZipScanner(config={"max_mar_depth": 1})
        result = scanner.scan(str(outer_zip))

        depth_checks = [
            check
            for check in result.checks
            if check.name == "TorchServe MAR Depth Limit" and check.status == CheckStatus.FAILED
        ]
        assert len(depth_checks) == 1
        assert "maximum .mar recursion depth (1) exceeded" in depth_checks[0].message.lower()
        assert depth_checks[0].location == f"{outer_zip}:model.mar"

    def test_scan_extensionless_nested_zip_recurses(self, tmp_path: Path) -> None:
        """Extensionless ZIP members should be recursively scanned by content."""
        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as inner_archive:
            inner_archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as outer_archive:
            outer_archive.writestr("nested", inner_zip.getvalue())

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.has_errors is True
        assert any(
            check.details.get("zip_entry") == "nested:payload.pkl"
            and check.location == f"{archive_path}:nested:payload.pkl"
            for check in result.checks
        ), f"Expected nested extensionless ZIP checks, got: {[(c.location, c.details) for c in result.checks]}"
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("zip_entry") == "nested:payload.pkl"
            and issue.location == f"{archive_path}:nested:payload.pkl"
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        ), (
            "Expected critical nested pickle finding, got: "
            f"{[(i.location, i.message, i.details) for i in result.issues]}"
        )

    def test_nested_keras_member_routes_through_core_dispatch(self, tmp_path: Path) -> None:
        """Nested ZIP-based model members should keep ZIP depth and use core dispatch."""
        nested_keras = io.BytesIO()
        with zipfile.ZipFile(nested_keras, "w"):
            pass

        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as outer_archive:
            outer_archive.writestr("nested_model.keras", nested_keras.getvalue())

        dispatched_result = ScanResult(scanner_name="keras_zip")
        dispatched_result.metadata["file_size"] = len(nested_keras.getvalue())
        dispatched_result.finish(success=True)

        with patch("modelaudit.core.scan_file", return_value=dispatched_result) as mock_scan_file:
            result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert mock_scan_file.call_count == 1

        scan_path, scan_config = mock_scan_file.call_args.args
        assert scan_path.endswith(".keras")
        assert scan_config["_zip_depth"] == 1

        assert result.metadata["contents"] == [
            {
                "path": f"{archive_path}:nested_model.keras",
                "type": "keras_zip",
                "size": len(nested_keras.getvalue()),
            }
        ]

    def test_max_depth_limit_on_extensionless_nested_zip_chain(self, tmp_path: Path) -> None:
        """Extensionless nested ZIP chains should still honor max_zip_depth."""
        nested_zip_bytes = io.BytesIO()
        with zipfile.ZipFile(nested_zip_bytes, "w") as nested_archive:
            nested_archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        for entry_name in ("level2", "level1", "level0"):
            parent_zip_bytes = io.BytesIO()
            with zipfile.ZipFile(parent_zip_bytes, "w") as parent_archive:
                parent_archive.writestr(entry_name, nested_zip_bytes.getvalue())
            nested_zip_bytes = parent_zip_bytes

        archive_path = tmp_path / "outer.zip"
        archive_path.write_bytes(nested_zip_bytes.getvalue())

        result = ZipScanner(config={"max_zip_depth": 2}).scan(str(archive_path))

        assert result.success is True
        assert any(
            issue.message == "Maximum ZIP nesting depth (2) exceeded"
            and issue.location == f"{archive_path}:level0:level1"
            and issue.details.get("zip_entry") == "level0:level1"
            and issue.details.get("depth") == 2
            and issue.details.get("max_depth") == 2
            for issue in result.issues
        ), f"Expected extensionless depth issue, got: {[(i.location, i.message, i.details) for i in result.issues]}"
        assert not any(
            issue.severity == IssueSeverity.CRITICAL
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        ), f"Depth limit should stop payload scan, got: {[(i.location, i.message) for i in result.issues]}"

    def test_directory_traversal_detection(self):
        """Test detection of directory traversal attempts in ZIP files"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                # Create entries with directory traversal attempts
                z.writestr("../../../etc/passwd", "malicious content")
                z.writestr("/etc/passwd", "malicious content")
                z.writestr("safe.txt", "safe content")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True

            # Should have detected directory traversal attempts
            traversal_issues = [
                i
                for i in result.issues
                if "path traversal" in i.message.lower() or "directory traversal" in i.message.lower()
            ]
            assert len(traversal_issues) >= 2

            # Check severity
            for issue in traversal_issues:
                assert issue.severity == IssueSeverity.CRITICAL
        finally:
            os.unlink(tmp_path)

    def test_windows_traversal_detection(self):
        """Ensure Windows-style path traversal is caught"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                z.writestr("..\\evil.txt", "malicious")
                z.writestr("safe.txt", "ok")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
            assert len(traversal_issues) >= 1
            for issue in traversal_issues:
                assert issue.severity == IssueSeverity.CRITICAL
        finally:
            os.unlink(tmp_path)

    def test_zip_bomb_detection(self):
        """Test detection of potential zip bombs (high compression ratio)"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as z:
                # Create a highly compressible file (potential zip bomb indicator)
                # Keep highly compressible but smaller to speed CI
                large_content = "A" * 300000  # 300KB of repeated 'A's
                z.writestr("suspicious.txt", large_content)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is True

            # Should detect high compression ratio
            compression_issues = [i for i in result.issues if "compression ratio" in i.message.lower()]
            assert len(compression_issues) >= 1
        finally:
            os.unlink(tmp_path)

    def test_max_depth_limit(self):
        """Test that maximum nesting depth is enforced"""
        # Create deeply nested zips
        current_path = None
        paths_to_delete = []

        try:
            # Create 10 levels of nested zips
            for i in range(10):
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    with zipfile.ZipFile(tmp.name, "w") as z:
                        if current_path:
                            z.write(current_path, f"level{i}.zip")
                        else:
                            z.writestr("deepest.txt", "Deep content")
                    paths_to_delete.append(tmp.name)
                    current_path = tmp.name

            # Scan the outermost zip
            assert current_path is not None  # Should be set by the loop above
            scanner = ZipScanner(config={"max_zip_depth": 3})
            result = scanner.scan(current_path)

            assert result.success is True
            # Should have a warning about max depth
            depth_issues = [i for i in result.issues if "depth" in i.message.lower()]
            assert len(depth_issues) >= 1
        finally:
            for path in paths_to_delete:
                if os.path.exists(path):
                    os.unlink(path)

    def test_scan_zip_with_dangerous_pickle(self):
        """Test scanning a ZIP file containing a dangerous pickle"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, "w") as z:
                # Create a pickle with suspicious content
                import os as os_module
                import pickle

                class DangerousClass:
                    def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
                        return (os_module.system, ("echo pwned",))

                dangerous_obj = DangerousClass()
                pickle_data = pickle.dumps(dangerous_obj)
                z.writestr("dangerous.pkl", pickle_data)
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            # The scan should complete even if there are errors in the pickle scanner
            assert result.success is True

            # Check that we at least tried to scan the pickle
            assert result.bytes_scanned > 0

            # May have error issues due to the bug in pickle scanner with string_stack
            # or it may detect the dangerous content
            # Either way, it should have scanned the file
        finally:
            os.unlink(tmp_path)

    def test_scan_zip_with_proto0_pickle_disguised_as_text(self, tmp_path: Path) -> None:
        """Protocol 0 pickle in .txt entry should still be detected as pickle content."""
        archive_path = tmp_path / "proto0_payload.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("payload.txt", b'cos\nsystem\n(S"echo pwned"\ntR.')

        result = self.scanner.scan(str(archive_path))
        assert result.success is True
        assert result.has_errors is True

        critical_messages = [
            issue.message.lower() for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
        ]
        assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
            f"Expected critical os/posix.system issue, got: {critical_messages}"
        )

    def test_scan_zip_with_prefixed_proto0_pickle_disguised_as_text(self, tmp_path: Path) -> None:
        """Protocol 0 pickles with MARK/LIST prefixes in .txt entries should be detected."""
        archive_path = tmp_path / "proto0_prefixed_payload.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("payload.txt", b'(lp0\n0cos\nsystem\n(S"echo pwned"\ntR.')

        result = self.scanner.scan(str(archive_path))
        assert result.success is True
        assert result.has_errors is True

        critical_messages = [
            issue.message.lower() for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
        ]
        assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
            f"Expected critical os/posix.system issue, got: {critical_messages}"
        )

    def test_scan_npz_with_object_member_recurses_into_pickle(self, tmp_path: Path) -> None:
        import numpy as np

        class _ExecPayload:
            def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
                return (exec, ("print('owned')",))

        archive_path = tmp_path / "payload.npz"
        np.savez(archive_path, safe=np.arange(3), payload=np.array([_ExecPayload()], dtype=object))

        result = self.scanner.scan(str(archive_path))
        assert result.success is True

        failed_checks = [c for c in result.checks if c.status.value == "failed"]
        assert any("cve-2019-6446" in (c.name + c.message).lower() for c in failed_checks)
        assert any(
            c.details.get("zip_entry") == "payload.npy" and c.location == f"{archive_path}:payload.npy"
            for c in failed_checks
        ), f"Expected rewritten check context for payload.npy, got: {[(c.location, c.details) for c in failed_checks]}"
        assert any("exec" in i.message.lower() and i.details.get("zip_entry") == "payload.npy" for i in result.issues)

    def test_scan_outer_zip_preserves_nested_npz_member_context(self, tmp_path: Path) -> None:
        import numpy as np

        class _ExecPayload:
            def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
                return (exec, ("print('owned')",))

        inner_npz = tmp_path / "inner.npz"
        np.savez(
            inner_npz,
            payload_a=np.array([_ExecPayload()], dtype=object),
            payload_b=np.array([_ExecPayload()], dtype=object),
        )

        archive_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.write(inner_npz, arcname="inner.npz")

        result = self.scanner.scan(str(archive_path))
        failed_checks = [c for c in result.checks if c.status.value == "failed"]

        assert any(
            c.details.get("zip_entry") == "inner.npz:payload_a.npy"
            and c.location
            and f"{archive_path}:inner.npz:payload_a.npy" in c.location
            for c in failed_checks
        )
        assert any(
            c.details.get("zip_entry") == "inner.npz:payload_b.npy"
            and c.location
            and f"{archive_path}:inner.npz:payload_b.npy" in c.location
            for c in failed_checks
        )

    def test_scan_zip_with_plain_text_global_prefix_not_treated_as_pickle(self, tmp_path: Path) -> None:
        """Plain text entries that start with GLOBAL-like bytes should not trigger pickle parse warnings."""
        archive_path = tmp_path / "plain_text_payload.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("notes.txt", b"c\nthis is plain text\nnot a pickle stream")

        result = self.scanner.scan(str(archive_path))
        assert result.success is True
        noisy_pickle_warnings = [
            issue for issue in result.issues if "incomplete or corrupted pickle file" in issue.message.lower()
        ]
        assert not noisy_pickle_warnings, (
            f"Expected no noisy pickle warning for plain text, got: {[i.message for i in noisy_pickle_warnings]}"
        )

    def test_scan_zip_with_proto0_pickle_with_single_comment_token_bypass_regression(self, tmp_path: Path) -> None:
        """Single comment-token prefix must not suppress proto0 payload detection."""
        archive_path = tmp_path / "proto0_comment_prefixed_payload.zip"
        payload = b"#" + b'cos\nsystem\n(S"echo pwned"\ntR.'
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("payload.txt", payload)

        result = self.scanner.scan(str(archive_path))
        assert result.success is True
        assert result.has_errors is True

        critical_messages = [
            issue.message.lower() for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
        ]
        assert any("os.system" in msg or "posix.system" in msg for msg in critical_messages), (
            f"Expected critical os/posix.system issue, got: {critical_messages}"
        )

    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist"""
        result = self.scanner.scan("/nonexistent/file.zip")
        assert result.success is False
        assert len(result.issues) > 0
        assert any("does not exist" in issue.message for issue in result.issues)

    def test_scan_invalid_zip(self):
        """Test scanning a file that's not a valid ZIP"""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(b"This is not a zip file")
            tmp_path = tmp.name

        try:
            result = self.scanner.scan(tmp_path)
            assert result.success is False
            assert len(result.issues) > 0
            assert any("not a valid zip" in issue.message.lower() for issue in result.issues)
        finally:
            os.unlink(tmp_path)

    def test_scan_empty_zip(self, tmp_path: Path) -> None:
        """An empty ZIP archive should scan successfully with no critical issues."""
        archive_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(archive_path, "w"):
            pass  # empty archive

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        assert result.bytes_scanned == 0
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_scan_zip_with_multiple_model_formats(self, tmp_path: Path) -> None:
        """ZIP containing multiple model-format files should scan all of them."""
        import pickle

        archive_path = tmp_path / "multi_format.zip"

        pkl_data = pickle.dumps({"weights": [1, 2, 3]})
        json_data = b'{"model_type": "linear", "version": "1.0"}'
        pt_data = pickle.dumps({"state_dict": {}})  # .pt files are pickle-based

        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("model.pkl", pkl_data)
            z.writestr("config.json", json_data)
            z.writestr("weights.pt", pt_data)

        result = self.scanner.scan(str(archive_path))

        assert result.success is True
        # All three file payloads should have been scanned
        assert result.bytes_scanned == len(pkl_data) + len(json_data) + len(pt_data)
        contents_paths = {c.get("path", "") for c in result.metadata.get("contents", [])}
        assert any("model.pkl" in p for p in contents_paths)
        assert any("config.json" in p for p in contents_paths)
        assert any("weights.pt" in p for p in contents_paths)

    def test_scan_zip_with_very_long_filename(self, tmp_path: Path) -> None:
        """ZIP entries with very long filenames should be handled without crashing."""
        import pickle

        archive_path = tmp_path / "long_name.zip"
        long_name = "a" * 200 + ".pkl"  # 204-character filename
        payload = pickle.dumps({"key": "value"})

        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr(long_name, payload)

        result = self.scanner.scan(str(archive_path))

        # Scan must not crash; success is expected for a benign payload
        assert result.success is True
        assert result.bytes_scanned == len(payload)

    def test_scan_truncated_zip(self, tmp_path: Path) -> None:
        """A truncated (corrupted) ZIP file should fail gracefully."""
        archive_path = tmp_path / "valid.zip"
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("file.txt", "some content")

        full_data = archive_path.read_bytes()
        truncated_path = tmp_path / "truncated.zip"
        truncated_path.write_bytes(full_data[: len(full_data) // 2])

        result = self.scanner.scan(str(truncated_path))

        # A truncated archive is invalid — scan must not raise an unhandled exception
        assert result.success is False
        assert len(result.issues) > 0
